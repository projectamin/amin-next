package Amin::AXA::HTTP;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Encode qw(encode decode encode_utf8);

use Amin;
use Amin::Handler::HTML;
use Amin::Handler::Text;
use Amin::Log::Standard;
use Amin::Machine::MachineSpec;
use Amin::Machine::Dispatcher;
use Amin::AXA::App;
use Amin::AXA::Store;
use Amin::AXA::Session;
use Amin::AXA::FormCodec;

# The loop-native HTTP adapter core (axa-plan §4.1): a parsed request in, a
# response out.  Dumb plumbing — no `if $element eq`, no role table, no
# allow-list (§5.6).  It does framing and transport hygiene only: body cap,
# content-type, method/path matrix, Origin + CSRF.  What a principal may cause
# to run lives in the chain's permanent region, exactly as over stdin.
#
# Where Amin::Proxy::HTTP answers from a backend the chain selected, this
# answers from render filters.  Both are adapters over the same one chain.
#
# The transport (Amin::AXA::Serve) owns the socket; this module never touches
# one.  It is fed a plain request hash — the handful of fields Serve fills in
# from the wire — and returns either a buffered triple
# `[$status, \@headers, $body_bytes]` or, when streaming, a coderef the server
# drives (see render_stream).
#
# Boot does the expensive things once (§4.8): the machine spec is resolved a
# single time and carried in the returned context (never a path — a request
# that re-reads machine_spec.xml is a bug), the bundle's own filter
# declarations are merged machine-first, and one warm-up chain build loads
# every spec filter class.  Chain instances stay per request (§4.9).

use constant SHOP_NS  => 'urn:projectamin:example:shop';
use constant AMIN_NS  => 'http://projectamin.org/ns/2026/';
use constant BODY_CAP => 262_144;    # 256 KiB (M2 acceptance)

# ── boot ────────────────────────────────────────────────────────────────────

# Everything a request needs, computed once.  The transport holds this for the
# life of the process and hands it to handle() per request.
sub boot ($class, %opts) {
    die "axa: app_dir required\n" unless $opts{app_dir};
    my $app = Amin::AXA::App->load($opts{app_dir});
    Amin::AXA::App->set_default($app);
    # The store is injected, never chosen here: the serve path hands in an
    # off-heap adapter (Amin::AXA::Store::SQLite), because a forked worker gets
    # its own copy of any in-process hash and the cart would diverge between
    # workers.  Anything with get/set/delete/session_ids works.
    Amin::AXA::Store->set_default($opts{store} // Amin::AXA::Store->new);

    my $spec = $opts{machine_spec} // Amin::Machine::MachineSpec->new(
        (exists $opts{machine_spec_path} ? (path => $opts{machine_spec_path}) : ()),
    )->spec;

    # The bundle's OWN filters, declared in its machine_spec.xml (app-bundle
    # contract).  Merged machine-first (§5.2): the bundle's entries are appended,
    # so a bundle cannot remove, reorder, or shadow a machine filter.  A bundle
    # may not declare a `permanent` filter — that region is the machine's alone,
    # and app code there would sit outside the trust boundary — so it is refused
    # at load rather than silently skipped (§5.2).  `allowed` is the union, so a
    # runtime-registered bundle class is still admitted.
    my $bundle_spec = "$opts{app_dir}/machine_spec.xml";
    if (-f $bundle_spec) {
        my $extra = Amin::Machine::MachineSpec->new(path => $bundle_spec)->spec;
        for my $f ($extra->{filters}->@*) {
            die "axa: app bundle may not declare a permanent filter: $f->{class}\n"
                if ($f->{meta}{position} // '') eq 'permanent';
            push $spec->{filters}->@*, $f;
        }
        $spec->{allowed} = { $spec->{allowed}->%*, $extra->{allowed}->%* };
    }

    # The bundle's own filters, merged machine-first (§5.2's shape).  Registered
    # ONCE at boot — §4.9: nothing registers after the first request is served.
    push $spec->{filters}->@*, (
        { class => 'Amin::Example::Shop', meta => { position => 'middle',
            element => 'request', namespace => SHOP_NS, permissions => '' } },
        { class => 'Amin::Example::Shop', meta => { position => 'middle',
            element => 'action',  namespace => SHOP_NS, permissions => '' } },
    );

    # §4.8 step 3: one warm-up chain build loads all 291+ filter classes so the
    # first real request pays only ->new per filter.
    Amin::Machine::Dispatcher->run(
        mode           => 'render',
        machine_spec   => $spec,
        source_xml     => '<amin:profile xmlns:amin="' . AMIN_NS . '"/>',
        late_filters_enable => { map => 1, ui => 1 },
        ui_os          => 'html',
    );

    return { app => $app, spec => $spec, stream => $opts{stream} // 0 };
}

# ── one request ─────────────────────────────────────────────────────────────

# $req is the transport's parsed request:
#   method, path, query, version, headers => [[name, value], ...],
#   header => { lc name => value }, host, scheme, peer,
#   body => $decoded_bytes, body_overflow => $bool
# Returns a buffered triple, or a coderef when the response streams.
sub handle ($class, $ctx, $req, %o) {
    my $app    = $ctx->{app};
    my $spec   = $ctx->{spec};
    my $stream = $o{stream} // $ctx->{stream} // 0;
    my $method = $req->{method};
    my $path   = $req->{path} // '/';
    my $store  = Amin::AXA::Store->default;

    # framing first (§5.6): cheap transport checks before any work
    if ($method eq 'POST') {
        return $class->err(413 => 'payload too large') if $req->{body_overflow};
        my $ct = $req->{header}{'content-type'} // '';
        return $class->err(415 => 'unsupported media type')
            unless $ct =~ m{^application/x-www-form-urlencoded\b}i;
    }

    my ($sid, $rec, $minted) = $class->session($req, $store);

    # Streaming commits response headers at the status latch, so anything that
    # must appear on a 200 (the session cookie) has to be known BEFORE render.
    # done() appends it afterwards for the buffered path; that is too late here.
    my $cookie_headers = ($minted && defined $sid)
        ? ['Set-Cookie' => Amin::AXA::Session->set_cookie($sid)]
        : [];
    my $res;

    if ($method eq 'GET' || $method eq 'HEAD') {
        if (my ($r, $rparams) = $app->get_route($path)) {
            my %values = (%{ $class->_params($req) }, %$rparams);
            my $vals = { %values, sid => $sid, csrf => $rec->{csrf} };  # reserved, applied last
            my $type = $r->{type} // 'text/html';
            # Only GET streams: a HEAD response must carry headers but no body,
            # and the streaming latch cannot know to suppress it.
            $res = ($stream && $method eq 'GET')
                ? $class->render_stream($spec, $r->{fragment}, $vals, $cookie_headers, $type)
                : $class->render($spec, $r->{fragment}, $vals, $type);
        }
        elsif ($app->routes_at($path) || $app->actions_at($path)) {
            $res = $class->err(405 => 'method not allowed');
        }
        else {
            $res = $class->err(404 => 'not found');
        }
    }
    elsif ($method eq 'POST') {
        my $params   = $class->_params($req);
        my $feasible = $app->actions_at($path)
                    || grep { $_->{method} eq 'POST' } $app->routes_at($path);
        if (!$feasible) {
            $res = ($app->routes_at($path) || $app->actions_at($path))
                ? $class->err(405 => 'method not allowed')
                : $class->err(404 => 'not found');
        }
        else {
            my $name   = $params->{'axa.action'} // '';
            my $action = length $name ? $app->action_named($name) : undef;
            # An action is selected by name AND must be declared at the request's
            # path — matched as a template, so its captured segments reach the
            # fragment exactly as a GET route's do.
            my $aparam = $action ? $app->match_path($action->{path}, $path) : undef;
            if (!$action || !defined $aparam) {
                $res = $class->err(422 => 'unknown action');
            }
            elsif ($req->{header}{origin}
                   && !$class->same_origin($req->{header}{origin}, $req)) {
                $res = $class->err(403 => 'forbidden origin');
            }
            elsif (!defined $params->{'axa.csrf'}
                   || $params->{'axa.csrf'} ne ($rec->{csrf} // '')) {
                $res = $class->err(403 => 'bad csrf token');
            }
            else {
                my %values = %$params;
                delete $values{$_} for qw(axa.action axa.csrf);
                for my $k (keys %values) {
                    if ($k =~ /^axa\.param\.(.+)$/) { $values{$1} = delete $values{$k} }
                }
                my $vals = { %values, %$aparam, sid => $sid, csrf => $rec->{csrf} };
                my $type = $action->{type} // 'text/html';
                $res = $stream
                    ? $class->render_stream($spec, $action->{fragment}, $vals, $cookie_headers, $type)
                    : $class->render($spec, $action->{fragment}, $vals, $type);
            }
        }
    }
    else {
        $res = ($app->routes_at($path) || $app->actions_at($path))
            ? $class->err(405 => 'method not allowed')
            : $class->err(404 => 'not found');
    }

    return $class->done($res, $minted, $sid);
}

# session record: the cookie only selects which store record to use; it is
# never a principal (§5.3).  A stale/unknown cookie is replaced by a mint.
sub session ($class, $req, $store) {
    my $sid = Amin::AXA::Session->cookie_sid($req->{header}{cookie});
    my $rec = $sid ? $store->get($sid) : undef;
    return ($sid, $rec, 0) if $rec;
    ($sid, my $csrf) = Amin::AXA::Session->mint;
    $rec = { csrf => $csrf, cart => {} };
    $store->set($sid, $rec);
    return ($sid, $rec, 1);
}

sub same_origin ($class, $origin, $req) {
    my ($hostpart) = $origin =~ m{^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/]+)};
    my $host = $req->{header}{host} // '';
    return defined $hostpart && length $hostpart && $hostpart eq $host;
}

# ── rendering ───────────────────────────────────────────────────────────────

# The response media type selects the serializer, and the media type is a
# property of the ROUTE (`type=`), never of a filter — so any route, under any
# composed filter set, can choose how its profile is served.  `text/plain`
# takes the byte-exact serializer (Amin::Handler::Text) that emits character
# data verbatim and ignores markup: that is what an ACME HTTP-01 key
# authorization needs.  Everything else renders HTML.
sub _handler ($class, $type, %o) {
    my $hclass = ($type // '') =~ m{^text/plain\b}i
        ? 'Amin::Handler::Text' : 'Amin::Handler::HTML';
    return $hclass->new(%o);
}

sub _content_type ($class, $type) {
    return ($type // '') =~ m{^text/plain\b}i
        ? 'text/plain; charset=utf-8' : 'text/html; charset=utf-8';
}

sub render ($class, $spec, $fragment, $values, $type = 'text/html') {
    # the bundle declares the fragment, the codec only substitutes values (§4.2)
    $fragment = Amin::AXA::FormCodec->inflate($fragment, $values // {});
    my $doc = '<amin:profile xmlns:amin="' . AMIN_NS . '" xmlns:shop="' . SHOP_NS . '">'
            . $fragment . "\n</amin:profile>";
    my $body;
    {
        local $@;
        my $ok = eval {
            $body = Amin->new(
                Mode    => 'render',
                Handler => $class->_handler($type),
                Log     => Amin::Log::Standard->new(stderr => 0),
                machine_spec        => $spec,
                late_filters_enable => { map => 1, ui => 1 },
                ui_os               => 'html',
            )->parse($doc);
            1;
        };
        unless ($ok) {
            warn "[axa] render failed: $@";
            return $class->err(500 => 'internal error');
        }
    }
    return [200, ['Content-Type' => $class->_content_type($type)], encode_utf8($body // '')];
}

# ── streaming variant (plan §4.8) ─────────────────────────────────────
# Returns a coderef the transport drives: it calls it with a responder, calling
# the responder commits the status line, and every chunk after that goes
# straight to the socket.  Nothing accumulates — Handler::HTML's sink emits per
# element, so a large page costs O(1) memory instead of O(page).
#
# The latch is the whole design: the first emitted byte is what commits 200.
# Before that, a failure can still answer a real 500.  After it, the status
# line is already on the wire, so a mid-stream failure can only close — the
# client sees a truncated page rather than a wrong status.  That is inherent to
# streaming, not a shortcut.
sub render_stream ($class, $spec, $fragment, $values, $extra_headers = [], $type = 'text/html') {
    $fragment = Amin::AXA::FormCodec->inflate($fragment, $values // {});
    my $doc = '<amin:profile xmlns:amin="' . AMIN_NS . '" xmlns:shop="' . SHOP_NS . '">'
            . $fragment . "\n</amin:profile>";
    my $ctype = $class->_content_type($type);

    return sub ($responder) {
        my ($writer, $latched) = (undef, 0);
        my $handler = $class->_handler($type, sink => sub {
            my $chunk = encode_utf8($_[0]);
            unless ($latched) {
                # status latch: the first byte out commits the response
                $writer = $responder->([200, [
                    'Content-Type' => $ctype, @$extra_headers,
                ]]);
                $latched = 1;
                $writer->write($chunk);
                return;
            }
            $writer->write($chunk);
        });

        my $ok = eval {
            Amin->new(
                Mode    => 'render',
                Handler => $handler,
                Log     => Amin::Log::Standard->new(stderr => 0),
                machine_spec        => $spec,
                late_filters_enable => { map => 1, ui => 1 },
                ui_os               => 'html',
            )->parse($doc);
            1;
        };
        unless ($ok) {
            warn "[axa] render failed: $@";
            unless ($latched) {
                # nothing committed yet — a genuine 500 is still possible
                $writer = $responder->([500, [
                    'Content-Type' => 'text/plain; charset=utf-8',
                    'Connection'   => 'close',
                ]]);
                $writer->write("500 internal error\n");
            }
            # already latched: the status is on the wire; only close
        }
        $writer and $writer->close;
        # Defensive: a text handler emits on characters, an HTML handler on
        # start_document; either normally latches.  If a future handler ever
        # emits nothing at all, still commit a response rather than leave the
        # client with no status line — a silent socket is far worse.
        unless ($latched) {
            $writer = $responder->([200, [
                'Content-Type' => $ctype,
                'Content-Length' => 0,
            ]]);
            $writer->close;
        }
        return;
    };
}

# ── parameters ──────────────────────────────────────────────────────────────

# Query for any method, plus the body for a POST (≈ Plack's
# ->parameters->flatten, last wins).  Byte-for-byte the Rust peer's `params`.
sub _params ($class, $req) {
    my %h;
    $class->_parse_form($req->{query}, \%h);
    if (($req->{method} // '') eq 'POST') {
        $class->_parse_form($req->{body}, \%h);
    }
    return \%h;
}

sub _parse_form ($class, $s, $h) {
    return unless defined $s && length $s;
    $s = _utf8_lossy($s);
    for my $pair (split /&/, $s, -1) {
        next if $pair eq '';
        my ($k, $v) = split /=/, $pair, 2;
        $v = '' unless defined $v;
        $h->{ $class->_decode_form($k) } = $class->_decode_form($v);
    }
    return;
}

# Percent-decode one form component: `+` → space, `%XX` → byte, else verbatim;
# the result is then read as UTF-8 (lossily), exactly as decode_form does.
sub _decode_form ($class, $s) {
    my $b   = _utf8_bytes($s);
    my $out = '';
    my $i   = 0;
    my $len = length $b;
    while ($i < $len) {
        my $ch = substr($b, $i, 1);
        if ($ch eq '+') { $out .= ' '; $i += 1 }
        elsif ($ch eq '%' && $i + 2 < $len) {
            my $hi = _hexval(substr($b, $i + 1, 1));
            my $lo = _hexval(substr($b, $i + 2, 1));
            if (defined $hi && defined $lo) { $out .= chr($hi * 16 + $lo); $i += 3 }
            else { $out .= '%'; $i += 1 }
        }
        else { $out .= $ch; $i += 1 }
    }
    return _utf8_lossy($out);
}

sub _hexval ($c) {
    return ord($c) - ord('0') if $c ge '0' && $c le '9';
    return ord($c) - ord('a') + 10 if $c ge 'a' && $c le 'f';
    return ord($c) - ord('A') + 10 if $c ge 'A' && $c le 'F';
    return undef;
}

# A string as its UTF-8 bytes, whichever of the two Perl string kinds it is.
sub _utf8_bytes ($s) {
    return $s unless utf8::is_utf8($s);
    return encode('UTF-8', $s);
}

# Decode bytes as UTF-8, replacing malformed sequences (≈ String::from_utf8_lossy).
sub _utf8_lossy ($s) {
    my $b = _utf8_bytes($s);
    return decode('UTF-8', $b, Encode::FB_DEFAULT());
}

# ── responses ───────────────────────────────────────────────────────────────

sub err ($class, $code, $msg) {
    return [$code, ['Content-Type' => 'text/plain; charset=utf-8'], encode_utf8("$code $msg\n")];
}

sub done ($class, $res, $minted, $sid) {
    # A streaming response already committed its headers at the latch, with the
    # cookie folded in up front.  Pushing onto it here would be too late.
    return $res if ref $res eq 'CODE';
    push $res->[1]->@*, 'Set-Cookie' => Amin::AXA::Session->set_cookie($sid)
        if $minted && defined $sid;
    return $res;
}

1;

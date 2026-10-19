package Amin::AXA::PSGI;
use v5.38; use warnings; use utf8;
use Class::Tiny;
use Plack::Request;
use Encode qw(encode_utf8);

use Amin;
use Amin::Handler::HTML;
use Amin::Log::Standard;
use Amin::Machine::MachineSpec;
use Amin::Machine::Dispatcher;
use Amin::AXA::App;
use Amin::AXA::Store;
use Amin::AXA::Session;
use Amin::AXA::FormCodec;

# The HTTP adapter: read body → feed the dispatcher → write status/headers/
# body (plan §4.1).  Dumb plumbing — no `if $element eq`, no role table, no
# allow-list (§5.6).  It does framing and transport hygiene only: body cap,
# content-type, method/path matrix, Origin + CSRF.  What a principal may
# cause to run lives in the chain's permanent region, exactly as over stdin.
#
# Boot does the expensive things once (§4.8): the machine spec is resolved a
# single time and injected per request (never a path — a request that
# re-reads machine_spec.xml is a bug), the bundle's own filter declarations
# are merged machine-first, and one warm-up chain build loads every spec
# filter class.  Chain instances stay per request (§4.9).

use constant SHOP_NS  => 'urn:projectamin:example:shop';
use constant AMIN_NS  => 'http://projectamin.org/ns/2026/';
use constant BODY_CAP => 262_144;    # 256 KiB (M2 acceptance)

sub app ($class, %opts) {
    die "axa: app_dir required\n" unless $opts{app_dir};
    my $app = Amin::AXA::App->load($opts{app_dir});
    Amin::AXA::App->set_default($app);
    # The store is injected, never chosen here: a prefork server must hand in
    # an off-heap adapter (Amin::AXA::Store::SQLite), because a forked worker
    # gets its own copy of any in-process hash and the cart would diverge
    # between requests.  Anything with get/set/delete/session_ids works.
    Amin::AXA::Store->set_default($opts{store} // Amin::AXA::Store->new);

    my $spec = $opts{machine_spec} // Amin::Machine::MachineSpec->new(
        (exists $opts{machine_spec_path} ? (path => $opts{machine_spec_path}) : ()),
    )->spec;

    # The bundle's own filters, merged machine-first (§5.2's shape; the
    # full M1 merge lands in Amin::AXA::App later).  Registered ONCE at
    # boot — §4.9: nothing registers after the first request is served.
    push $spec->{filters}->@*, (
        { class => 'Amin::Example::Shop', meta => { position => 'late',
            element => 'request', namespace => SHOP_NS, permissions => '' } },
        { class => 'Amin::Example::Shop', meta => { position => 'late',
            element => 'action',  namespace => SHOP_NS, permissions => '' } },
    );

    # §4.8 step 3: one warm-up chain build loads all 291+ filter classes so
    # the first real request pays only ->new per filter.
    Amin::Machine::Dispatcher->run(
        mode           => 'render',
        machine_spec   => $spec,
        source_xml     => '<amin:profile xmlns:amin="' . AMIN_NS . '"/>',
        late_filters_enable => { map => 1, ui => 1 },
    );

    my $stream = $opts{stream} // 0;
    return sub ($env) { $class->handle($env, $app, $spec, $stream) };
}

sub handle ($class, $env, $app, $spec, $stream = 0) {
    my $req    = Plack::Request->new($env);
    my $method = uc($env->{REQUEST_METHOD} // 'GET');
    my $path   = $env->{PATH_INFO} // '/';
    my $store  = Amin::AXA::Store->default;

    # framing first (§5.6): cheap transport checks before any work
    if ($method eq 'POST') {
        my $len = $env->{CONTENT_LENGTH} // 0;
        return $class->done($class->err(413 => 'payload too large'), 0, undef)
            if $len > BODY_CAP;
        my $ct = $env->{CONTENT_TYPE} // '';
        return $class->done($class->err(415 => 'unsupported media type'), 0, undef)
            unless $ct =~ m{^application/x-www-form-urlencoded\b}i;
    }

    my ($sid, $rec, $minted) = $class->session($env, $store);

    # Streaming commits response headers at the status latch, so anything that
    # must appear on a 200 (the session cookie) has to be known BEFORE render.
    # done() appends it afterwards for the buffered path; that is too late here.
    my $cookie_headers = ($minted && defined $sid)
        ? ['Set-Cookie' => Amin::AXA::Session->set_cookie($sid)]
        : [];
    my $res;

    if ($method eq 'GET' || $method eq 'HEAD') {
        if (my $r = $app->get_route($path)) {
            my %values = %{ $class->_params($req) };
            my $vals = { %values, sid => $sid, csrf => $rec->{csrf} };  # reserved, applied last
            # Only GET streams: a HEAD response must carry headers but no body,
            # and the streaming latch cannot know to suppress it.
            $res = ($stream && $method eq 'GET')
                ? $class->render_stream($spec, $r->{fragment}, $vals, $cookie_headers)
                : $class->render($spec, $r->{fragment}, $vals);
        }
        elsif ($app->routes_at($path) || $app->actions_at($path)) {
            $res = $class->err(405 => 'method not allowed');
        }
        else {
            $res = $class->err(404 => 'not found');
        }
    }
    elsif ($method eq 'POST') {
        my $params    = $class->_params($req);
        my $feasible  = $app->actions_at($path)
                     || grep { $_->{method} eq 'POST' } $app->routes_at($path);
        if (!$feasible) {
            $res = ($app->routes_at($path) || $app->actions_at($path))
                ? $class->err(405 => 'method not allowed')
                : $class->err(404 => 'not found');
        }
        else {
            my $name   = $params->{'axa.action'} // '';
            my $action = length $name ? $app->action_named($name) : undef;
            if (!$action || $action->{path} ne $path) {
                $res = $class->err(422 => 'unknown action');
            }
            elsif ($env->{HTTP_ORIGIN} && !$class->same_origin($env->{HTTP_ORIGIN}, $env)) {
                $res = $class->err(403 => 'forbidden origin');
            }
            elsif (!defined $params->{'axa.csrf'} || $params->{'axa.csrf'} ne ($rec->{csrf} // '')) {
                $res = $class->err(403 => 'bad csrf token');
            }
            else {
                my %values = %$params;
                delete $values{$_} for qw(axa.action axa.csrf);
                for my $k (keys %values) {
                    if ($k =~ /^axa\.param\.(.+)$/) { $values{$1} = delete $values{$k} }
                }
                my $vals = { %values, sid => $sid, csrf => $rec->{csrf} };
                $res = $stream
                    ? $class->render_stream($spec, $action->{fragment}, $vals, $cookie_headers)
                    : $class->render($spec, $action->{fragment}, $vals);
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
sub session ($class, $env, $store) {
    my $sid = Amin::AXA::Session->cookie_sid($env->{HTTP_COOKIE});
    my $rec = $sid ? $store->get($sid) : undef;
    return ($sid, $rec, 0) if $rec;
    ($sid, my $csrf) = Amin::AXA::Session->mint;
    $rec = { csrf => $csrf, cart => {} };
    $store->set($sid, $rec);
    return ($sid, $rec, 1);
}

sub same_origin ($class, $origin, $env) {
    my ($hostpart) = $origin =~ m{^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/]+)};
    return defined $hostpart && length $hostpart
           && $hostpart eq ($env->{HTTP_HOST} // '');
}

sub render ($class, $spec, $fragment, $values) {
    # the bundle declares the fragment, the codec only substitutes values (§4.2)
    $fragment = Amin::AXA::FormCodec->inflate($fragment, $values // {});
    my $doc = '<amin:profile xmlns:amin="' . AMIN_NS . '" xmlns:shop="' . SHOP_NS . '">'
            . $fragment . "\n</amin:profile>";
    my $html;
    {
        local $@;
        my $ok = eval {
            $html = Amin->new(
                Mode    => 'render',
                Handler => Amin::Handler::HTML->new,
                Log     => Amin::Log::Standard->new(stderr => 0),
                machine_spec        => $spec,
                late_filters_enable => { map => 1, ui => 1 },
            )->parse($doc);
            1;
        };
        unless ($ok) {
            warn "[axa] render failed: $@";
            return $class->err(500 => 'internal error');
        }
    }
    return [200, ['Content-Type' => 'text/html; charset=utf-8'], [encode_utf8($html // '')]];
}

# ── streaming variant (plan §4.8) ─────────────────────────────────────
# Returns a PSGI streaming coderef: the server calls it with a responder,
# calling the responder commits the status line, and every chunk after that
# goes straight to the socket.  Nothing accumulates — Handler::HTML's sink
# emits per element, so a large page costs O(1) memory instead of O(page).
#
# The latch is the whole design: the first emitted byte is what commits 200.
# Before that, a failure can still answer a real 500.  After it, the status
# line is already on the wire, so a mid-stream failure can only close — the
# client sees a truncated page rather than a wrong status.  That is inherent
# to streaming, not a shortcut.
sub render_stream ($class, $spec, $fragment, $values, $extra_headers = []) {
    $fragment = Amin::AXA::FormCodec->inflate($fragment, $values // {});
    my $doc = '<amin:profile xmlns:amin="' . AMIN_NS . '" xmlns:shop="' . SHOP_NS . '">'
            . $fragment . "\n</amin:profile>";

    return sub ($responder) {
        my ($writer, $latched) = (undef, 0);
        my $handler = Amin::Handler::HTML->new(sink => sub {
            my $chunk = encode_utf8($_[0]);
            unless ($latched) {
                # status latch: the first byte out commits the response
                $writer = $responder->([200, [
                    'Content-Type' => 'text/html; charset=utf-8', @$extra_headers,
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
        # Defensive: start_document always emits the doctype, so the latch
        # normally fires on the first element.  If a future handler ever emits
        # nothing at all, still commit a response rather than leave the client
        # with no status line — a silent socket is far worse than an empty page.
        unless ($latched) {
            $writer = $responder->([200, [
                'Content-Type' => 'text/html; charset=utf-8',
                'Content-Length' => 0,
            ]]);
            $writer->close;
        }
        return;
    };
}

# Hash::MultiValue 0.16 has no as_hash; flatten gives all pairs in order,
# so assigning into a hash yields last-wins — the same semantics.
sub _params ($class, $req) { my %h = $req->parameters->flatten; return \%h }

sub err ($class, $code, $msg) {
    return [$code, ['Content-Type' => 'text/plain; charset=utf-8'], [encode_utf8("$code $msg\n")]];
}

sub done ($class, $res, $minted, $sid) {
    # A streaming response already committed its headers at the latch, with
    # the cookie folded in up front.  Pushing onto it here would be too late.
    return $res if ref $res eq 'CODE';
    push $res->[1]->@*, 'Set-Cookie' => Amin::AXA::Session->set_cookie($sid)
        if $minted && defined $sid;
    return $res;
}

1;

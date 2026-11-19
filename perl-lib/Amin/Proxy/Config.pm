package Amin::Proxy::Config;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use Amin qw(NS);
require Amin::Bitcache::Reference;
use Digest::SHA3 ();
use Encode qw(encode);
use Class::Tiny qw(source listen tls cert key max_conns read_timeout rate_limit), {
    backends => sub { {} },   # id => backend record
    routes   => sub { [] },   # compiled route records, most-specific first
};

# The proxy's own declaration: <amin:proxy> holds one <amin:backend> table and
# one <amin:route> table (proxy-plan §4.1).  The document is read with the same
# SAX generator a profile is — never a DOM — and compiled once at boot into a
# frozen matcher, so the request path never touches the config (§5.3).
#
# The document may itself be a local path or a signed bitcache:// ref (§5.13):
# a signed ref is fetched and verified here, and a ref that does not verify
# refuses to load — there is no unaddressed fallback for an addressed config.
#
# What this compiles is the *routing vocabulary*: hosts, paths, backend ids,
# one transport per route.  The listener/TLS contract (listen=, tls=, cert=,
# key=) is carried for the adapter but validated there, and each route's
# `spec=` is validated by shape (a path that exists, or an addressed ref) —
# building the warm Amin provider from it is the listener's boot step (§5.3).

sub load ($class, %o) {
    my $ref = $o{ref} // $o{path};
    die "proxy config: no ref\n" unless defined $ref && length $ref;

    my $xml = _document($ref, %o);
    require Amin::Generator::XML;
    my $c  = Amin::Proxy::Config::Collector->new;
    my $ok = eval { Amin::Generator::XML->new(Handler => $c)->parse_string($xml); 1 };
    die "proxy config: not valid XML: $@" unless $ok;
    return _compile($class, $ref, $c, %o);
}

# The document bytes: a verified CAS object for a bitcache:// ref, else a file.
sub _document ($ref, %o) {
    if (Amin::Bitcache::Reference::is_reference($ref)) {
        my $r = Amin::Bitcache::Reference->new(
            uri => $ref,
            map { $_ => $o{$_} }
                grep { defined $o{$_} } qw(slab_path bctool_path trust_anchor_dir),
        )->parse;
        die "proxy config: not an addressed ref: $ref\n" unless $r->addressed;
        my $bytes = $r->resolve;
        die "proxy config: ref did not verify, refusing to start: $ref\n"
            unless defined $bytes && length $bytes;
        return $bytes;
    }
    die "proxy config: not found: $ref\n" unless -f $ref;
    open(my $fh, '<:encoding(UTF-8)', $ref) or die "proxy config: open $ref: $!\n";
    local $/;
    my $xml = <$fh>;
    close $fh;
    die "proxy config: empty: $ref\n" unless defined $xml && length $xml;
    return $xml;
}

sub _bool ($v, $what) {
    return 0 unless defined $v && length $v;
    return 1 if $v =~ /^(?:1|on|true|yes)$/i;
    return 0 if $v =~ /^(?:0|off|false|no)$/i;
    die "proxy config: $what must be on/off, got '$v'\n";
}

# Per-IP rate limit (§P5): a token bucket, `rps=<tokens/sec>;burst=<bucket>`.
# `rps=0` means no refill — a fixed lifetime quota of `burst` requests per client
# IP.  Both keys are required; `burst` must be >= 1.  The returned record keeps
# `rps`/`burst` for the front's bucket and a key-order-normalised `spec` for the
# fingerprint, so `rps=10;burst=20` and `burst=20;rps=10` are one profile.
sub _rate_limit ($v) {
    return undef unless defined $v && length $v;
    my %kv;
    for my $part (split /\s*;\s*/, $v) {
        next unless length $part;
        my ($k, $val) = split /\s*=\s*/, $part, 2;
        die "proxy config: rate-limit: bad term '$part'\n"
            unless defined $k && defined $val && $k =~ /\A(?:rps|burst)\z/;
        die "proxy config: rate-limit: duplicate '$k'\n" if exists $kv{$k};
        $kv{$k} = $val;
    }
    die "proxy config: rate-limit: rps required\n"   unless exists $kv{rps};
    die "proxy config: rate-limit: burst required\n" unless exists $kv{burst};
    die "proxy config: rate-limit: rps must be a number >= 0, got '$kv{rps}'\n"
        unless $kv{rps} =~ /\A\d+(?:\.\d+)?\z/;
    die "proxy config: rate-limit: burst must be an integer >= 1, got '$kv{burst}'\n"
        unless $kv{burst} =~ /\A\d+\z/ && $kv{burst} >= 1;
    return {
        rps   => $kv{rps} + 0,
        burst => $kv{burst} + 0,
        spec  => "rps=$kv{rps};burst=$kv{burst}",
    };
}

# Host matching is by shape, fixed at compile: '*' any, '*.suffix' suffix,
# anything else exact.  A rank makes most-specific-first ordering explicit.
sub _host_shape ($host) {
    return ('any',    0) if $host eq '*';
    return ('suffix', 1) if $host =~ /^\*\.(.+)$/;
    return ('exact',  2);
}

sub _compile ($class, $source, $c, %o) {
    my %backends;
    for my $b ($c->{backends}->@*) {
        my $id = $b->{id};
        die "proxy backend: missing id\n" unless defined $id && length $id;
        die "proxy backend '$id': duplicate id\n" if $backends{$id};
        my ($peer, $addr) = ($b->{peer}, $b->{addr});
        my $has_peer = defined $peer && length $peer;
        my $has_addr = defined $addr && length $addr;
        die "proxy backend '$id': exactly one of peer/addr required\n"
            unless $has_peer xor $has_addr;
        my $transport = $b->{transport};
        die "proxy backend '$id': missing transport\n"
            unless defined $transport && length $transport;
        die "proxy backend '$id': unknown transport '$transport'\n"
            unless $transport eq 'awp3' || $transport eq 'http';
        $backends{$id} = {
            id        => $id,
            transport => $transport,
            ($has_peer ? (peer => $peer) : (addr => $addr)),
            (defined $b->{hc} && length $b->{hc} ? (hc => $b->{hc}) : ()),
        };
    }

    die "proxy config: no routes declared\n" unless $c->{routes}->@*;

    my @routes;
    my $idx = 0;
    for my $r ($c->{routes}->@*) {
        my $host = $r->{host};
        die "proxy route: missing host\n" unless defined $host && length $host;
        (my $lc = $host) =~ s/[A-Z]/lc $&/ge;
        my ($shape, $rank) = _host_shape($lc);

        my $to = $r->{to};
        die "proxy route (host $host): missing to\n" unless defined $to && length $to;
        my @ids = grep { length } split /\s*,\s*/, $to;
        die "proxy route (host $host): empty to\n" unless @ids;
        my @to = map {
            $backends{$_} // die "proxy route (host $host): unknown backend '$_'\n"
        } @ids;
        my %transports = map { $_->{transport} => 1 } @to;
        die "proxy route (host $host): mixed transports in to='$to'\n"
            if keys(%transports) > 1;

        my $path = $r->{path} // '';
        my $spec = $r->{spec};
        _validate_spec($spec) if defined $spec && length $spec;

        my $policy = $r->{policy};
        push @routes, {
            host         => $lc,
            host_shape   => $shape,
            host_rank    => $rank,
            path         => $path,
            to           => \@to,
            policy       => (defined $policy && $policy =~ /\S/) ? $policy : 'p2c_ewma',
            strip_prefix => _bool($r->{'strip-prefix'}, 'strip-prefix'),
            ws           => _bool($r->{ws}, 'ws'),
            spec_ref     => (defined $spec && length $spec ? $spec : undef),
            _idx         => $idx++,
        };
    }

    # Most-specific-first: longest path, then most-specific host, then the order
    # the profile declared.  match() then takes the first hit, so "longest wins"
    # and "exact beats wildcard" need no per-request sorting.
    @routes = sort {
        length($b->{path}) <=> length($a->{path})
            || $b->{host_rank} <=> $a->{host_rank}
            || $a->{_idx}      <=> $b->{_idx}
    } @routes;

    my $attrs = $c->{proxy};
    my %rename = ('max-conns' => 'max_conns', 'read-timeout' => 'read_timeout');
    my %carry;
    for my $k (qw(listen tls cert key max-conns read-timeout)) {
        my $v = $attrs->{$k};
        $carry{ $rename{$k} // $k } = $v if defined $v && length $v;
    }
    my $rate = _rate_limit($attrs->{'rate-limit'});
    return $class->new(
        source   => $source,
        backends => \%backends,
        routes   => \@routes,
        (defined $rate ? (rate_limit => $rate) : ()),
        %carry,
    );
}

# A route spec is referenced, not built, at compile: a path must exist, and a
# bitcache:// ref must be a well-formed addressed reference.  Fetching and
# verifying it is the warm-provider step, at boot of the listener (§5.3/§5.13).
sub _validate_spec ($spec) {
    if (Amin::Bitcache::Reference::is_reference($spec)) {
        my $r = eval { Amin::Bitcache::Reference->new(uri => $spec)->parse };
        die "proxy route spec: bad bitcache ref '$spec'\n" unless $r && $r->addressed;
        return;
    }
    die "proxy route spec: not found: $spec\n" unless -f $spec;
    return;
}

# ── The compiled-profile fingerprint (proxy-plan §P5) ───────────────────────
#
# X-Amin-Profile-SHA3 lets a response be traced to the exact profile + filter
# chain that produced it.  What is hashed is the *compiled* profile — the frozen
# matcher both fronts build — under a purpose-built, injective encoding: every
# field is `name <byte-len> <value>\n`, maps are written in a fixed order
# (backends sorted by id, routes in compiled order), and the config's *source*
# is excluded (the profile's content, not its location, is the identity).  The
# encoding is byte-identical to the Rust `amin_proxy::fingerprint::canonical`
# for the same profile, so the Perl and Rust fronts agree on the value (§7).
sub canonical ($self) {
    my @out = ('amin-proxy-profile/1');
    my $field = sub ($name, $value) {
        my $bytes = encode('UTF-8', defined $value ? $value : '');
        push @out, "$name " . length($bytes) . " $bytes";
    };
    $field->('listen',       $self->listen);
    $field->('tls',          $self->tls);
    $field->('cert',         $self->cert);
    $field->('key',          $self->key);
    $field->('max-conns',    $self->max_conns);
    $field->('read-timeout', $self->read_timeout);
    $field->('rate-limit',   $self->rate_limit ? $self->rate_limit->{spec} : undef);

    my $backends = $self->backends;
    push @out, 'backend-count ' . scalar(keys %$backends);
    for my $id (sort keys %$backends) {          # fixed order, not hash order
        my $b = $backends->{$id};
        my ($ekey, $eval) = exists $b->{peer} ? ('peer', $b->{peer}) : ('addr', $b->{addr});
        $field->('id',             $b->{id});
        $field->('transport',      $b->{transport});
        $field->('endpoint',       $ekey);
        $field->('endpoint-value', $eval);
        $field->('hc',             $b->{hc});
    }

    my $routes = $self->routes;
    push @out, 'route-count ' . scalar($routes->@*);
    for my $r ($routes->@*) {                    # already most-specific-first
        $field->('route-host',         $r->{host});
        $field->('route-path',         $r->{path});
        $field->('route-to',           join(',', map { $_->{id} } $r->{to}->@*));
        $field->('route-policy',       $r->{policy});
        $field->('route-strip-prefix', $r->{strip_prefix} ? '1' : '0');
        $field->('route-ws',           $r->{ws} ? '1' : '0');
        $field->('route-spec',         $r->{spec_ref});
    }
    return join("\n", @out) . "\n";
}

# SHA3-256 of the canonical bytes, lowercase hex — the X-Amin-Profile-SHA3
# value.  Memoised: the profile is frozen at boot, so the digest cannot change.
sub profile_sha3 ($self) {
    return $self->{_profile_sha3}
        //= Digest::SHA3->new(256)->add($self->canonical)->hexdigest;
}

sub backend ($self, $id) { $self->backends->{$id} }

# The compiled matcher: the first route whose host shape and path prefix accept
# the request, or undef (closed-world — an unmatched request is denied, never
# defaulted to a backend).
sub match ($self, %req) {
    my $host = $req{host} // '';
    (my $lc = $host) =~ s/[A-Z]/lc $&/ge;
    my $path = $req{path} // '/';
    for my $r ($self->routes->@*) {
        next unless _host_ok($r, $lc);
        next unless _path_ok($r, $path);
        return $r;
    }
    return undef;
}

sub _host_ok ($r, $host) {
    my $shape = $r->{host_shape};
    return 1 if $shape eq 'any';
    return $host eq $r->{host} if $shape eq 'exact';
    my ($suffix) = $r->{host} =~ /^\*\.(.+)$/;
    return defined $suffix
        && length($host) > length($suffix) + 1
        && substr($host, -1 - length $suffix) eq ".$suffix";
}

sub _path_ok ($r, $path) {
    return 1 unless length $r->{path};
    return index($path, $r->{path}) == 0;
}

1;

package Amin::Proxy::Config::Collector;
use v5.38; use warnings; use utf8; use experimental 'signatures';

# SAX collector for <amin:proxy>: three flat tables, no tree.  Attributes are
# read by local name (the amin: prefix is the namespace, not the key), and any
# element outside the closed vocabulary is a hard error — a typo'd element must
# not silently become a no-op table entry.
sub new ($class) {
    return bless { proxy => {}, backends => [], routes => [] }, $class;
}

sub start_document ($self, @) { return }
sub end_document   ($self, @) { return }
sub characters     ($self, @) { return }

sub start_element ($self, $el) {
    my $ln = $el->{LocalName} // $el->{Name} // '';
    return unless length $ln;
    my $ns = $el->{NamespaceURI} // '';
    die "proxy config: foreign namespace '$ns' on <$ln>\n"
        if length($ns) && $ns ne Amin::NS();
    my %a = _surface($el);
    if    ($ln eq 'proxy')   { $self->{proxy} = { %{ $self->{proxy} }, %a } }
    elsif ($ln eq 'backend') { push $self->{backends}->@*, \%a }
    elsif ($ln eq 'route')   { push $self->{routes}->@*, \%a }
    else                     { die "proxy config: unknown element <amin:$ln>\n" }
    return;
}

sub _surface ($el) {
    my %a;
    for my $k (keys %{ $el->{Attributes} // {} }) {
        my $h = $el->{Attributes}{$k} // {};
        my $n = $h->{LocalName} // $h->{Name} // $k;
        $a{$n} = $h->{Value};
    }
    return %a;
}

1;

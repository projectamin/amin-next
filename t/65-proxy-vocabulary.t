#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Cwd        qw(abs_path);
use File::Temp qw(tempdir);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Log::Standard;
use Amin::Machine::Dispatcher;
use Amin::Proxy::Config;
use Amin::Test::StreamCapture;

my $NS = 'http://projectamin.org/ns/2026/';
my $tmp = tempdir(CLEANUP => 1);

sub write_cfg ($name, $xml) {
    my $path = "$tmp/$name";
    open(my $fh, '>:encoding(UTF-8)', $path) or die "write $path: $!";
    print $fh $xml;
    close $fh;
    return $path;
}

# Attribute lookup that does not care how the SAX key is spelled (Clark or
# {ns}local), so assertions read the contract, not the driver's bookkeeping.
sub aval ($el, $want) {
    my $A = $el->{Attributes} // {};
    for my $k (keys %$A) {
        my $h = $A->{$k} // {};
        my $ln = $h->{LocalName} // '';
        if (!length $ln) { (my $kk = $k) =~ s/^\{[^}]*\}//; $ln = $kk }
        return $h->{Value} if $ln eq $want;
    }
    return undef;
}

# Feed one <amin:request> through the REAL chain (bundled machine_spec.xml,
# so Amin::Proxy::Route is registered) with the compiled config injected, and
# return the events the final handler saw.
sub route_events ($cfg, %req) {
    my $attrs = join ' ', map { qq{amin:$_="$req{$_}"} } sort keys %req;
    my $xml = <<"XML";
<?xml version="1.0" encoding="UTF-8"?>
<amin:root xmlns:amin="$NS" xmlns:proxy="http://projectamin.org/ns/proxy/1">
  <amin:request $attrs />
</amin:root>
XML
    my $cap = Amin::Test::StreamCapture->new;
    Amin::Machine::Dispatcher->run(
        Handler => $cap,
        Log     => Amin::Log::Standard->new(stderr => 0),
        proxy   => $cfg,
        source_xml => $xml,
        mode    => 'run',
        ui_os   => 'tty',
    );
    return $cap->captured->@*;
}

sub starts_of ($events, $local) {
    return grep { $_->[0] eq 'start_element' && ($_->[1]{LocalName} // '') eq $local } @$events;
}

my $SAMPLE = <<'XML';
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/"
            amin:listen="0.0.0.0:8443" amin:tls="files"
            amin:cert="/etc/amin/tls/fullchain.pem"
            amin:key="/etc/amin/tls/privkey.pem"
            amin:max-conns="4096" amin:read-timeout="30">
  <amin:backend amin:id="shop-a" amin:peer="shop-a.mesh" amin:transport="awp3"
                amin:hc="tcp_ack_3rst=auto_drain"/>
  <amin:backend amin:id="shop-b" amin:peer="shop-b.mesh" amin:transport="awp3"/>
  <amin:backend amin:id="legacy" amin:addr="10.0.0.20:80" amin:transport="http"/>
  <amin:route amin:host="shop.example" amin:path="/api/" amin:to="shop-a,shop-b"
              amin:policy="p2c_ewma" amin:ws="on"/>
  <amin:route amin:host="legacy.example" amin:to="legacy"/>
  <amin:route amin:host="*" amin:to="shop-a"/>
</amin:proxy>
XML

# ── 1. compile: backends ────────────────────────────────────────────────────
{
    my $cfg = Amin::Proxy::Config->load(ref => write_cfg('p1.xml', $SAMPLE));
    isa_ok $cfg, ['Amin::Proxy::Config'], 'load returns a compiled config';
    is $cfg->listen, '0.0.0.0:8443',      'proxy listen= carried';
    is $cfg->max_conns, '4096',           'max-conns renamed to max_conns';
    is $cfg->read_timeout, '30',          'read-timeout renamed to read_timeout';
    is $cfg->tls, 'files',                'tls= carried';

    is scalar(keys %{ $cfg->backends }), 3, 'three backends compiled';
    is $cfg->backend('shop-a')->{peer}, 'shop-a.mesh', 'peer backend keeps its mesh identity';
    is $cfg->backend('shop-a')->{transport}, 'awp3',   'peer backend is awp3';
    is $cfg->backend('shop-a')->{hc}, 'tcp_ack_3rst=auto_drain', 'backend hc carried';
    is $cfg->backend('legacy')->{addr}, '10.0.0.20:80', 'addr backend keeps host:port';
    is $cfg->backend('legacy')->{transport}, 'http',    'addr backend is http';
    ok !exists $cfg->backend('legacy')->{peer}, 'addr backend has no peer';
}

# ── 2. compile: routes, most-specific-first ─────────────────────────────────
{
    my $cfg = Amin::Proxy::Config->load(ref => write_cfg('p1.xml', $SAMPLE));
    my @r = $cfg->routes->@*;
    is scalar(@r), 3, 'three routes compiled';
    is [map { $_->{host} } @r], ['shop.example', 'legacy.example', '*'],
        'longest path then most-specific host then declaration order';

    my $api = $r[0];
    is [map { $_->{id} } $api->{to}->@*], ['shop-a', 'shop-b'], 'to= is backend ids, in order';
    is $api->{policy}, 'p2c_ewma', 'route policy carried';
    is $api->{ws}, 1, 'ws=on parsed';
    is $api->{strip_prefix}, 0, 'strip-prefix defaults off';
    is $api->{path}, '/api/', 'route path prefix carried';

    my $legacy = $r[1];
    is $legacy->{policy}, 'p2c_ewma', 'policy defaults to p2c_ewma when omitted';
    is $legacy->{host_shape}, 'exact', 'exact host shape';
    is $r[2]{host_shape}, 'any', 'catch-all host shape';
}

# ── 3. match: longest prefix + exact beats wildcard + deny ─────────────────
{
    my $cfg = Amin::Proxy::Config->load(ref => write_cfg('p1.xml', $SAMPLE));
    my $r = $cfg->match(host => 'shop.example', path => '/api/v1/items');
    is $r->{host}, 'shop.example', 'shop.example /api/... matches the api route';
    is [map { $_->{id} } $r->{to}->@*], ['shop-a', 'shop-b'], 'api route sends to both shops';

    is $cfg->match(host => 'legacy.example', path => '/')->{host}, 'legacy.example',
        'legacy host matches its own route, not the catch-all';
    is $cfg->match(host => 'other.example', path => '/x')->{host}, '*',
        'unknown host falls to the catch-all';
    is $cfg->match(host => 'SHOP.EXAMPLE', path => '/api/')->{host}, 'shop.example',
        'host match is case-insensitive';

    # shop.example + a non-/api path is NOT covered: the catch-all is reached
    # only because its path is empty, and host '*' accepts anything.
    is $cfg->match(host => 'shop.example', path => '/other')->{host}, '*',
        'path prefix is honoured: /other does not take the /api/ route';

    # Closed-world: with no catch-all, an unmatched request is denied.
    my $strict = write_cfg('strict.xml', <<'XML');
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:backend amin:id="only" amin:addr="127.0.0.1:80" amin:transport="http"/>
  <amin:route amin:host="one.example" amin:path="/one/" amin:to="only"/>
</amin:proxy>
XML
    my $sc = Amin::Proxy::Config->load(ref => $strict);
    ok defined $sc->match(host => 'one.example', path => '/one/x'), 'matching request resolves';
    is $sc->match(host => 'one.example', path => '/two/'), undef, 'non-matching path -> denyless (undef)';
    is $sc->match(host => 'two.example', path => '/one/'), undef, 'non-matching host -> undef';

    # Wildcard suffix.
    my $wild = write_cfg('wild.xml', <<'XML');
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:backend amin:id="w" amin:peer="w.mesh" amin:transport="awp3"/>
  <amin:route amin:host="*.example.com" amin:to="w"/>
</amin:proxy>
XML
    my $wc = Amin::Proxy::Config->load(ref => $wild);
    ok defined $wc->match(host => 'api.example.com', path => '/'), 'suffix wildcard matches a subdomain';
    is $wc->match(host => 'example.com', path => '/'), undef, 'suffix wildcard does not match the apex';
    is $wc->match(host => 'notexample.com', path => '/'), undef, 'suffix wildcard does not match a lookalike';
}

# ── 4. compiled once: the matcher is reused, never rebuilt per request ─────
{
    my $cfg = Amin::Proxy::Config->load(ref => write_cfg('p1.xml', $SAMPLE));
    my $a = $cfg->match(host => 'shop.example', path => '/api/');
    my $b = $cfg->match(host => 'shop.example', path => '/api/');
    ok $a == $b, 'match returns the SAME route record each time (compiled once)';
    ok $cfg->backends == $cfg->backends, 'backend table is one frozen hash';
    is $cfg->source, "$tmp/p1.xml", 'source recorded for diagnostics';
}

# ── 5. validation is fail-closed ───────────────────────────────────────────
{
    my @bad = (
        ['duplicate ids', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="awp3"/>
                            <amin:backend amin:id="a" amin:peer="b.mesh" amin:transport="awp3"/>
                            <amin:route amin:host="*" amin:to="a"/>}, qr/duplicate id/],
        ['peer and addr both', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:addr="1.2.3.4:80" amin:transport="awp3"/>
                                 <amin:route amin:host="*" amin:to="a"/>}, qr/exactly one of peer\/addr/],
        ['neither peer nor addr', q{<amin:backend amin:id="a" amin:transport="awp3"/>
                                    <amin:route amin:host="*" amin:to="a"/>}, qr/exactly one of peer\/addr/],
        ['unknown transport', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="grpc"/>
                                <amin:route amin:host="*" amin:to="a"/>}, qr/unknown transport/],
        ['missing transport', q{<amin:backend amin:id="a" amin:peer="a.mesh"/>
                                <amin:route amin:host="*" amin:to="a"/>}, qr/missing transport/],
        ['unknown backend in to=', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="awp3"/>
                                     <amin:route amin:host="*" amin:to="nope"/>}, qr/unknown backend 'nope'/],
        ['mixed transports in one route',
            q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="awp3"/>
              <amin:backend amin:id="b" amin:addr="1.2.3.4:80" amin:transport="http"/>
              <amin:route amin:host="*" amin:to="a,b"/>}, qr/mixed transports/],
        ['route missing host', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="awp3"/>
                                 <amin:route amin:to="a"/>}, qr/missing host/],
        ['route missing to', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="awp3"/>
                               <amin:route amin:host="*"/>}, qr/missing to/],
        ['no routes', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="awp3"/>},
            qr/no routes declared/],
        ['unknown element', q{<amin:upstream amin:id="a"/>
                              <amin:route amin:host="*" amin:to="a"/>}, qr/unknown element <amin:upstream>/],
        ['bad strip-prefix', q{<amin:backend amin:id="a" amin:peer="a.mesh" amin:transport="awp3"/>
                               <amin:route amin:host="*" amin:to="a" amin:strip-prefix="maybe"/>},
            qr/strip-prefix must be on\/off/],
    );
    for my $c (@bad) {
        my ($what, $body, $re) = @$c;
        my $xml = qq{<?xml version="1.0" encoding="UTF-8"?>\n}
                . qq{<amin:proxy xmlns:amin="$NS">$body</amin:proxy>};
        my $path = write_cfg('bad.xml', $xml);
        like dies { Amin::Proxy::Config->load(ref => $path) }, $re, "rejects: $what";
    }
    like dies { Amin::Proxy::Config->load(ref => "$tmp/nope.xml") },
        qr/not found/, 'missing config file is fatal';
}

# ── 6. the filter: one <proxy:backend> per candidate, in order ─────────────
{
    my $cfg = Amin::Proxy::Config->load(ref => write_cfg('p1.xml', $SAMPLE));
    my @ev = route_events($cfg, host => 'shop.example', path => '/api/v1/items', method => 'GET');

    my @dec = starts_of(\@ev, 'backend');
    is scalar(@dec), 2, 'two candidate backends -> two decision elements';
    is [map { aval($_->[1], 'id') } @dec], ['shop-a', 'shop-b'], 'decision order follows to=';
    is aval($dec[0]->[1], 'transport'), 'awp3', 'decision carries transport';
    is aval($dec[0]->[1], 'peer'), 'shop-a.mesh', 'decision carries the mesh peer';
    is aval($dec[0]->[1], 'policy'), 'p2c_ewma', 'decision carries the route policy';
    is aval($dec[0]->[1], 'strip-prefix'), 'false', 'strip-prefix emitted as a boolean string';
    is aval($dec[0]->[1], 'ws'), 'on', 'ws emitted';
    is $dec[0]->[1]{NamespaceURI}, 'http://projectamin.org/ns/proxy/1',
        'decision lives in the proxy namespace';
    ok !aval($dec[0]->[1], 'addr'), 'a peer backend emits no addr';
}

# ── 7. http backend decision carries addr, not peer ────────────────────────
{
    my $cfg = Amin::Proxy::Config->load(ref => write_cfg('p1.xml', $SAMPLE));
    my @ev = route_events($cfg, host => 'legacy.example', path => '/', method => 'GET');
    my @dec = starts_of(\@ev, 'backend');
    is scalar(@dec), 1, 'single-backend route -> one decision element';
    is aval($dec[0]->[1], 'addr'), '10.0.0.20:80', 'addr backend emits addr';
    ok !aval($dec[0]->[1], 'peer'), 'addr backend emits no peer';
    is aval($dec[0]->[1], 'ws'), 'off', 'ws defaults off';
}

# ── 8. no match -> closed-world -6150 status ───────────────────────────────
{
    my $strict = write_cfg('strict.xml', <<'XML');
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:backend amin:id="only" amin:addr="127.0.0.1:80" amin:transport="http"/>
  <amin:route amin:host="one.example" amin:path="/one/" amin:to="only"/>
</amin:proxy>
XML
    my $cfg = Amin::Proxy::Config->load(ref => $strict);
    my @ev = route_events($cfg, host => 'other.example', path => '/nowhere');
    is scalar(starts_of(\@ev, 'backend')), 0, 'no decision element for an unmatched request';
    my @st = starts_of(\@ev, 'status');
    is scalar(@st), 1, 'exactly one denial status';
    is aval($st[0]->[1], 'rc'), '-6150', 'denial rc is -6150';
    is aval($st[0]->[1], 'exit_kind'), 'no_route', 'denial names the reason';
}

# ── 9. tables are injected, never re-streamed ──────────────────────────────
{
    my $cfg = Amin::Proxy::Config->load(ref => write_cfg('p1.xml', $SAMPLE));
    my @ev = route_events($cfg, host => 'shop.example', path => '/api/', method => 'GET');
    is scalar(grep { ($_->[1]{LocalName} // '') =~ /^(?:route|backend)$/
                     && ($_->[1]{NamespaceURI} // '') eq $NS } @ev), 0,
        'no <amin:route>/<amin:backend> events on the request path (tables injected, not streamed)';

    my @e2 = route_events($cfg, host => 'shop.example', path => '/api/', method => 'GET');
    my @ids1 = map { aval($_->[1], 'id') } starts_of(\@ev, 'backend');
    my @ids2 = map { aval($_->[1], 'id') } starts_of(\@e2, 'backend');
    is \@ids1, \@ids2, 'two dispatches over one config give byte-identical decisions';
}

# ── 10. no config injected -> fail-closed, not "pass everything" ───────────
{
    my @ev = route_events(undef, host => 'shop.example', path => '/api/');
    is scalar(starts_of(\@ev, 'backend')), 0, 'no config -> no decision (never a default backend)';
    my @st = starts_of(\@ev, 'status');
    is scalar(@st), 1, 'no config -> denial status';
    is aval($st[0]->[1], 'exit_kind'), 'no_proxy_config', 'denial names the missing config';
}

# ── 11. per-IP rate limit: parse, normalise, fail-closed ───────────────────
{
    my $mk = sub ($attrs) {
        write_cfg('rl.xml', qq{<?xml version="1.0" encoding="UTF-8"?>\n}
            . qq{<amin:proxy xmlns:amin="$NS" $attrs>}
            . q{<amin:backend amin:id="a" amin:addr="127.0.0.1:80" amin:transport="http"/>}
            . q{<amin:route amin:host="*" amin:to="a"/>}
            . q{</amin:proxy>});
    };

    my $cfg = Amin::Proxy::Config->load(ref => $mk->('amin:rate-limit="rps=10;burst=20"'));
    is $cfg->rate_limit->{rps},   10, 'rps parsed';
    is $cfg->rate_limit->{burst}, 20, 'burst parsed';
    is $cfg->rate_limit->{spec}, 'rps=10;burst=20', 'spec is canonical rps=<raw>;burst=<raw>';

    # Key order is normalised: either spelling compiles to one spec (§7).
    my $flip = Amin::Proxy::Config->load(ref => $mk->('amin:rate-limit="burst=20;rps=10"'));
    is $flip->rate_limit->{spec}, $cfg->rate_limit->{spec}, 'key order is not identity';

    # Absent -> undef (no limiter).
    is Amin::Proxy::Config->load(ref => $mk->(''))->rate_limit, undef,
        'no rate-limit declaration -> no limiter';

    # rps=0 is legal: a fixed lifetime quota of burst.
    is Amin::Proxy::Config->load(ref => $mk->('amin:rate-limit="rps=0;burst=3"'))->rate_limit->{rps},
        0, 'rps=0 is legal (no refill)';

    my @bad = (
        ['missing rps',   'amin:rate-limit="burst=20"',             qr/rate-limit: rps required/],
        ['missing burst', 'amin:rate-limit="rps=1"',               qr/rate-limit: burst required/],
        ['burst zero',    'amin:rate-limit="rps=1;burst=0"',       qr/burst must be an integer >= 1/],
        ['rps negative',  'amin:rate-limit="rps=-1;burst=1"',      qr/rps must be a number >= 0/],
        ['duplicate rps', 'amin:rate-limit="rps=1;rps=2;burst=1"', qr/duplicate 'rps'/],
        ['unknown term',  'amin:rate-limit="rps=1;burst=1;junk=9"', qr/bad term 'junk=9'/],
    );
    for my $c (@bad) {
        my ($what, $attrs, $re) = @$c;
        like dies { Amin::Proxy::Config->load(ref => $mk->($attrs)) }, $re, "rejects: $what";
    }
}

done_testing;

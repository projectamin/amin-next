#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Cwd        qw(abs_path);
use File::Temp qw(tempdir);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Log::Standard;
use Amin::Machine::Dispatcher;
use Amin::Handler::Writer;
use Amin::Proxy::Config;
use Amin::Test::StreamCapture;

# Perl ↔ Rust parity, byte for byte (proxy-plan §7/§8 P0): one <amin:proxy>
# profile through the Perl routing filter (Amin::Proxy::Route serialised by the
# real Amin::Handler::Writer) and through the Rust router (amin_proxy, driven
# by the proxydump helper) must produce identical <proxy:backend> decisions.
#
# The comparison is real bytes, not structure: the Rust side prints the exact
# strings amin_proxy::decision_element emits; the Perl side is the Writer's own
# output. The one shape adjustment is documented inline — the Writer streams an
# open tag and a closing tag (it cannot self-close mid-stream), so its start
# tag is canonicalised to the self-closed form the decision element uses.
# Everything else — element name, attribute names, ordering, values, escaping —
# is compared untouched.

my $DUMP = abs_path(dirname(__FILE__) . '/../rust/target/debug/proxydump');
unless (-x $DUMP) {
    skip_all "proxydump not compiled; run `cargo build -p amin-proxy` at ./rust";
}

require IPC::Run;

my $NS  = 'http://projectamin.org/ns/2026/';
my $tmp = tempdir(CLEANUP => 1);

sub write_file ($name, $data) {
    my $path = "$tmp/$name";
    open(my $fh, '>:encoding(UTF-8)', $path) or die "write $path: $!";
    print $fh $data;
    close $fh;
    return $path;
}

# Run the profile through the REAL chain (bundled machine_spec.xml, so
# Amin::Proxy::Route is registered) with the compiled matcher injected, and
# return the <proxy:backend> decisions serialised by Amin::Handler::Writer.
sub perl_decisions ($cfg, %req) {
    my $attrs = join ' ', map { qq{amin:$_="$req{$_}"} } sort keys %req;
    my $xml = <<"XML";
<?xml version="1.0" encoding="UTF-8"?>
<amin:root xmlns:amin="$NS" xmlns:proxy="http://projectamin.org/ns/proxy/1">
  <amin:request $attrs />
</amin:root>
XML
    my $cap = Amin::Test::StreamCapture->new;
    Amin::Machine::Dispatcher->run(
        Handler    => $cap,
        Log        => Amin::Log::Standard->new(stderr => 0),
        proxy      => $cfg,
        source_xml => $xml,
        mode       => 'run',
        ui_os      => 'tty',
    );

    my $w = Amin::Handler::Writer->new(indent => 0);
    $w->start_document;
    for my $e ($cap->captured->@*) {
        next unless $e->[0] eq 'start_element';
        my $el = $e->[1];
        next unless ($el->{LocalName} // '') eq 'backend';
        $w->start_element($el);
        $w->end_element($el);
    }

    my @tags = grep { m{^<proxy:backend\b} } split /\n/, $w->output;
    # The Writer emits `<proxy:backend …>` then `</proxy:backend>` on the next
    # line; the decision element is the self-closed `<proxy:backend …/>`.
    s{>$}{/>} for @tags;
    return @tags;
}

# The Rust side: proxydump prints one `decision_element` per line.
sub rust_decisions ($profile, %req) {
    my @argv = ($DUMP, '--profile', $profile,
                '--host', $req{host} // '', '--path', $req{path} // '/');
    my ($out, $err) = ('', '');
    my $h = IPC::Run::harness(\@argv, \undef, \$out, \$err, debug => 0);
    IPC::Run::start($h); IPC::Run::finish($h);
    my $rc = $? >> 8;
    die "proxydump rc=$rc: $err" unless $rc == 0;
    return grep { length } split /\n/, $out;
}

# The Rust side's profile fingerprint (`X-Amin-Profile-SHA3`).
sub rust_fingerprint ($profile) {
    my @argv = ($DUMP, '--profile', $profile, '--fingerprint');
    my ($out, $err) = ('', '');
    my $h = IPC::Run::harness(\@argv, \undef, \$out, \$err, debug => 0);
    IPC::Run::start($h); IPC::Run::finish($h);
    my $rc = $? >> 8;
    die "proxydump --fingerprint rc=$rc: $err" unless $rc == 0;
    $out =~ s/\s+\z//;
    return $out;
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
  <amin:route amin:host="legacy.example" amin:to="legacy" amin:strip-prefix="on"/>
  <amin:route amin:host="*" amin:to="shop-a"/>
</amin:proxy>
XML

subtest 'one profile → Perl and Rust emit byte-identical decisions' => sub {
    my $path = write_file('proxy.xml', $SAMPLE);
    my $cfg  = Amin::Proxy::Config->load(ref => $path);

    for my $case (
        { host => 'shop.example',   path => '/api/v1/items', what => 'multi-backend route' },
        { host => 'legacy.example', path => '/',             what => 'http addr backend' },
        { host => 'other.example',  path => '/x',            what => 'catch-all route' },
    ) {
        my @perl = perl_decisions($cfg, host => $case->{host}, path => $case->{path}, method => 'GET');
        my @rust = rust_decisions($path, host => $case->{host}, path => $case->{path});
        is \@perl, \@rust, "byte-identical <proxy:backend> — $case->{what} ($case->{host})";
    }
};

subtest 'the canonical decision element is self-closed and sorted' => sub {
    my $path = write_file('proxy.xml', $SAMPLE);
    my @rust = rust_decisions($path, host => 'shop.example', path => '/api/');
    is $rust[0],
        '<proxy:backend amin:id="shop-a" amin:peer="shop-a.mesh" amin:policy="p2c_ewma"'
      . ' amin:strip-prefix="false" amin:transport="awp3" amin:ws="on"/>',
        'attributes sorted by name, self-closed, amin: namespaced';
};

subtest 'no route → both sides emit nothing (closed-world)' => sub {
    my $strict = write_file('strict.xml', <<'XML');
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:backend amin:id="only" amin:addr="127.0.0.1:80" amin:transport="http"/>
  <amin:route amin:host="one.example" amin:path="/one/" amin:to="only"/>
</amin:proxy>
XML
    my $cfg = Amin::Proxy::Config->load(ref => $strict);
    my @perl = perl_decisions($cfg, host => 'other.example', path => '/nowhere');
    my @rust = rust_decisions($strict, host => 'other.example', path => '/nowhere');
    is \@perl, [], 'Perl emits no decision for an unmatched request';
    is \@rust, [], 'Rust emits no decision for an unmatched request';
};

subtest 'Writer attribute order is deterministic across runs' => sub {
    my $path = write_file('proxy.xml', $SAMPLE);
    my $cfg  = Amin::Proxy::Config->load(ref => $path);
    my @a = perl_decisions($cfg, host => 'shop.example', path => '/api/', method => 'GET');
    my @b = perl_decisions($cfg, host => 'shop.example', path => '/api/', method => 'GET');
    is \@a, \@b, 'same events → same bytes every time (canonical attribute order)';
};

# P5 (§7/§P5): X-Amin-Profile-SHA3 is the SHA3-256 of the *compiled* profile
# under a shared canonical encoding.  Both fronts stamp it on proxied responses,
# so the two language streams must agree on the value byte for byte.
subtest 'one profile → Perl and Rust agree on X-Amin-Profile-SHA3' => sub {
    my $path = write_file('proxy.xml', $SAMPLE);
    my $cfg  = Amin::Proxy::Config->load(ref => $path);

    my $perl = $cfg->profile_sha3;
    my $rust = rust_fingerprint($path);

    like $perl, qr/\A[0-9a-f]{64}\z/, 'Perl yields 64 lowercase hex chars';
    is $perl, $rust, 'byte-identical profile fingerprint across Perl and Rust';

    # The digest is a property of the profile's *content*: a routing change must
    # move it, and re-loading the same file must not.
    is $cfg->profile_sha3, $perl, 'stable across calls (memoised, content-derived)';
    my $other = write_file('proxy2.xml', ($SAMPLE =~ s{amin:path="/api/"}{amin:path="/v2/"}r));
    my $changed = Amin::Proxy::Config->load(ref => $other)->profile_sha3;
    isnt $changed, $perl, 'a routing change moves the digest';
    is rust_fingerprint($other), $changed, 'Rust tracks the same content change';
};

# P5 (§P5): the per-IP rate limit is part of the profile's identity, and its
# canonical form is key-order-normalised, so either spelling of one limit is the
# same profile on both fronts.
subtest 'one profile → Perl and Rust agree on a rate-limited fingerprint' => sub {
    my $mk = sub ($name, $rl) {
        write_file($name, ($SAMPLE =~ s{amin:max-conns="4096"}{amin:max-conns="4096" amin:rate-limit="$rl"}r));
    };
    my $a = $mk->('rl-a.xml', 'rps=0;burst=5');
    my $b = $mk->('rl-b.xml', 'burst=5;rps=0');
    my $c = $mk->('rl-c.xml', 'rps=0;burst=6');

    is Amin::Proxy::Config->load(ref => $a)->profile_sha3, rust_fingerprint($a),
        'byte-identical rate-limited profile fingerprint across Perl and Rust';
    is rust_fingerprint($b), rust_fingerprint($a),
        'Rust normalises the key order to one identity';
    is Amin::Proxy::Config->load(ref => $b)->profile_sha3, rust_fingerprint($a),
        'Perl agrees both spellings are one profile';
    isnt rust_fingerprint($c), rust_fingerprint($a),
        'a limit change moves the digest (Rust)';
};

done_testing;

#!/usr/bin/env perl
# ACME (RFC 8555), the app-level HTTP-01 filter: "Responder + client".
#
# ACME is not a proxy concern (proxy-plan §5.5) — the front only ever sees an
# already-provisioned cert/key.  It is a *filter* an app declares in its own
# machine_spec.xml, and this test proves the three halves of that capability:
#
#   Part A — the account key (Amin::Acme::Key, ES256): the JWK, the RFC 7638
#   thumbprint, the HTTP-01 key authorization, and a JWS whose signature the
#   openssl CLI re-verifies against the account public key.  Pure crypto, no
#   socket.
#
#   Part B — the Responder, driven through the real adapter (Amin::AXA::HTTP).
#   The CA fetches `/.well-known/acme-challenge/<token>` and must be answered
#   `token "." thumbprint(account key)` as the byte-exact `text/plain` body.
#   The route's `type="text/plain"` is what makes the emitted characters BE the
#   body — the same mechanism a plain-text route uses anywhere.
#
#   Part C — the client (Amin::Acme::Client), against a real mock CA over a
#   real socket: the full RFC 8555 walk (directory → nonce → account → order →
#   authorization → trigger → poll → finalize → certificate).  The mock is
#   deliberately dumb, but it records every request it saw, so the assertion is
#   about the *sequence and shape* the client produced, not about a stub.
#
# Nothing here is a live CA: the point is the framing and the flow the client
# emits, plus the byte-exact crypto the responder answers with.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use Path::Tiny qw(path);
use IPC::Run qw(run);
use POSIX ();
use Digest::SHA ();
use JSON::PP ();
use MIME::Base64 ();
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Acme::Key;
use Amin::Acme::Client;
use Amin::AXA::HTTP;
use Amin::AXA::App;

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $tmp  = tempdir(CLEANUP => 1);

my ($openssl) = grep { -x "$_/openssl" } split /:/, $ENV{PATH} // '';
skip_all 'openssl CLI not found on PATH (Amin::Acme::Key shells out to it)'
    unless $openssl;

# ── small helpers ───────────────────────────────────────────────────────────
sub b64url ($b) {
    my $s = MIME::Base64::encode_base64($b // '', '');
    $s =~ tr{+/}{-_};
    $s =~ s/=+$//;
    return $s;
}
sub b64d ($s) {
    $s //= '';
    $s =~ tr{-_}{+/};
    $s .= '=' x ((4 - length($s) % 4) % 4);
    return MIME::Base64::decode_base64($s);
}

# raw JWS ES256 signature (R||S) → the ASN.1 DER openssl verifies.
sub _der_len ($n) {
    return chr $n if $n < 0x80;
    my $b = '';
    while ($n) { $b = chr($n & 0xFF) . $b; $n >>= 8 }
    return chr(0x80 | length $b) . $b;
}
sub _der_int ($bn) {
    $bn =~ s/^\x00+//;
    $bn = "\x00" if $bn eq '';
    $bn = "\x00" . $bn if ord(substr($bn, 0, 1)) & 0x80;
    return "\x02" . _der_len(length $bn) . $bn;
}
sub raw_to_der ($raw) {
    my $body = _der_int(substr($raw, 0, 32)) . _der_int(substr($raw, 32, 32));
    return "\x30" . _der_len(length $body) . $body;
}

# ── Part A: the account key (Amin::Acme::Key) ───────────────────────────────

my $acct = "$tmp/acct.key";
Amin::Acme::Key->gen_ec($acct);
ok(-f $acct, 'account key generated (prime256v1)');
my $key = Amin::Acme::Key->new(path => $acct);

my $jwk = $key->jwk;
is($jwk->{kty}, 'EC',    'JWK kty is EC');
is($jwk->{crv}, 'P-256', 'JWK crv is P-256');
like($jwk->{x}, qr/^[A-Za-z0-9_-]{43}$/, 'JWK x is a 32-byte base64url coordinate');
like($jwk->{y}, qr/^[A-Za-z0-9_-]{43}$/, 'JWK y is a 32-byte base64url coordinate');

# RFC 7638: the thumbprint is SHA-256 of the canonical JWK (exact member order,
# no whitespace) — the one string both fronts must agree on (§7).
my $canon = sprintf '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}',
    @{$jwk}{qw(crv kty x y)};
my $tp = $key->thumbprint;
is(b64url(Digest::SHA::sha256($canon)), $tp,
    'thumbprint is SHA-256 of the RFC 7638 canonical JWK');
like($tp, qr/^[A-Za-z0-9_-]{43}$/, 'thumbprint is 32 bytes base64url');

# RFC 8555 §8.1: the HTTP-01 answer is `token "." thumbprint`.
is($key->key_authorization('tokABC'), "tokABC.$tp",
    'key_authorization = token "." thumbprint');

# RFC 7515 flattened JWS, ES256.
my $prot = { alg => 'ES256', nonce => 'n-1', url => 'https://ca.example/acct',
             jwk => $jwk };
my $jws = $key->jws($prot, '{"hello":"world"}');
my $j   = JSON::PP->new->decode($jws);
ok($j->{protected} && $j->{payload} && $j->{signature},
    'JWS carries protected / payload / signature');
my $ph = JSON::PP->new->decode(b64d($j->{protected}));
is($ph->{alg}, 'ES256', 'protected header declares ES256');
is(b64d($j->{payload}), '{"hello":"world"}', 'payload is the request body verbatim');
my $sig = b64d($j->{signature});
is(length $sig, 64, 'ES256 signature is the raw 64-byte R||S');

# The signature really is valid: re-verify it with openssl against the account
# public key (the raw R||S is transcoded back to the DER openssl wants).
my $pub = "$tmp/acct.pub";
system 'openssl', 'ec', '-in', $acct, '-pubout', '-out', $pub;
my $sigfile = "$tmp/sig.der";
path($sigfile)->spew_raw(raw_to_der($sig));
my $input = $j->{protected} . '.' . $j->{payload};
my $verified = run ['openssl', 'dgst', '-sha256', '-verify', $pub, '-signature', $sigfile],
    \$input, \my $vout, \my $verr;
ok($verified, 'openssl verifies the JWS ES256 signature against the account key')
    or diag("$vout$verr");

# A POST-as-GET (RFC 8555 §6.3) is a JWS whose payload is the empty string.
my $pag = JSON::PP->new->decode($key->jws({ alg => 'ES256', nonce => 'n', url => 'u' }, ''));
is($pag->{payload}, '', 'POST-as-GET payload is the empty octet string');

# ── Part B: the Responder, through the adapter ──────────────────────────────

my $dir = "$tmp/acme-bundle";
mkdir $dir or die "mkdir $dir: $!";
my $rkey = "$tmp/responder.key";
Amin::Acme::Key->gen_ec($rkey);
my $rkey_obj = Amin::Acme::Key->new(path => $rkey);

path("$dir/axa.xml")->spew_utf8(<<~"XML");
    <?xml version="1.0" encoding="UTF-8"?>
    <axa:app xmlns:axa="http://projectamin.org/ns/axa/1"
             xmlns:amin="http://projectamin.org/ns/2026/"
             id="io.projectamin.test.acme" name="acme-test">
      <axa:route path="/.well-known/acme-challenge/:token" method="GET" type="text/plain"><amin:acme-challenge token="{token}"/></axa:route>
    </axa:app>
    XML
# The filter is declared at the APP level (never the proxy level) — the bundle's
# own machine_spec.xml, merged machine-first by the adapter (§5.2).
path("$dir/machine_spec.xml")->spew_utf8(<<~"XML");
    <?xml version="1.0" encoding="UTF-8"?>
    <amin:machine xmlns:amin="http://projectamin.org/ns/2026/">
      <filter class="Amin::Filter::Acme" position="middle"
              element="acme-challenge" namespace="http://projectamin.org/ns/2026/"
              key="$rkey" />
    </amin:machine>
    XML

my $ctx = Amin::AXA::HTTP->boot(app_dir => $dir);
my $req = {
    method => 'GET', path => '/.well-known/acme-challenge/tok123', query => undef,
    version => '1.1', headers => [['Host' => 'localhost']], header => { host => 'localhost' },
    host => 'localhost', scheme => 'http', peer => '127.0.0.1', body => '', body_overflow => 0,
};
my $res = Amin::AXA::HTTP->handle($ctx, $req, stream => 0);
is(ref $res, 'ARRAY', 'challenge route answers buffered');
is($res->[0], 200, 'GET /.well-known/acme-challenge/tok123 → 200');
my %rh;
for (my $i = 0; $i + 1 < @{ $res->[1] }; $i += 2) { $rh{ lc $res->[1][$i] } = $res->[1][$i + 1] }
like($rh{'content-type'}, qr{^text/plain}, 'challenge is served as text/plain');
is($res->[2], $rkey_obj->key_authorization('tok123') . "\n",
    'the body IS the key authorization (the responder emitted it as characters)');

# The bundle that ships in-tree declares the same route.
my $ex = Amin::AXA::App->load("$ROOT/examples/apps/acme-http01");
my ($eroute, $eparams) = $ex->get_route('/.well-known/acme-challenge/abc123');
ok($eroute, 'examples/apps/acme-http01 declares the HTTP-01 challenge route');
is($eparams->{token}, 'abc123', 'the :token segment is captured from the path');

# ── Part C: the client, against a real mock CA ──────────────────────────────

my $mock = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 5, ReuseAddr => 1,
) or die "cannot pick a port: $!";
my $port = $mock->sockport;
close $mock;
my $base = "http://127.0.0.1:$port";
my $log  = "$tmp/ca.log";

our $authz_hits = 0;
sub _enc ($h) { return JSON::PP->new->encode($h) }

sub _respond ($method, $path, $base) {
    my %json = ('Content-Type' => 'application/json');
    if ($path eq '/directory') {
        return (200, { %json }, _enc({
            newNonce   => "$base/new-nonce",
            newAccount => "$base/new-account",
            newOrder   => "$base/new-order",
        }));
    }
    return (200, { 'Replay-Nonce' => 'n-1' }, '') if $path eq '/new-nonce';
    if ($path eq '/new-account') {
        return (201, { 'Location' => "$base/acct/1", 'Replay-Nonce' => 'n-2', %json }, '{}');
    }
    if ($path eq '/new-order') {
        return (201, { 'Location' => "$base/order/1", 'Replay-Nonce' => 'n-3', %json },
            _enc({ status => 'pending', authorizations => ["$base/authz/1"],
                   finalize => "$base/finalize" }));
    }
    if ($path eq '/authz/1') {
        $authz_hits++;
        return (200, { 'Replay-Nonce' => 'n-5', %json },
            _enc({ status => 'valid', identifier => { type => 'dns', value => 'example.test' } }))
            if $authz_hits > 1;
        return (200, { 'Replay-Nonce' => 'n-4', %json }, _enc({
            status => 'pending',
            identifier => { type => 'dns', value => 'example.test' },
            challenges => [ { type => 'http-01', url => "$base/chal/1", token => 'tok-abc' } ],
        }));
    }
    return (200, { 'Replay-Nonce' => 'n-6', %json }, '{}') if $path eq '/chal/1';
    if ($path eq '/finalize') {
        return (200, { 'Replay-Nonce' => 'n-7', %json },
            _enc({ status => 'valid', certificate => "$base/cert/1" }));
    }
    if ($path eq '/cert/1') {
        return (200, { 'Content-Type' => 'application/pem-certificate-chain' },
            "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n");
    }
    return (404, { %json }, '{}');
}

# Serve one connection: read the request head+body, log it, answer, close.
sub _serve ($c, $lf) {
    my $buf = '';
    while (index($buf, "\r\n\r\n") < 0) {
        my $n = sysread($c, my $chunk, 4096);
        return unless defined $n && $n > 0;
        $buf .= $chunk;
    }
    my ($head, $rest) = split /\r\n\r\n/, $buf, 2;
    my @lines = split /\r\n/, $head;
    my ($method, $path) = split ' ', (shift @lines) // '';
    $path //= '';
    $path =~ s/\?.*//;
    my %h;
    for my $l (@lines) { my ($k, $v) = split /:\s*/, $l, 2; $h{ lc $k } = $v if defined $v }
    my $clen = $h{'content-length'} // 0;
    my $body = $rest // '';
    while (length($body) < $clen) {
        my $n = sysread($c, my $chunk, 4096);
        last unless defined $n && $n > 0;
        $body .= $chunk;
    }

    # Record the request, tagged with the JWS shape it carried: `jwk` vs `kid`,
    # and `pag` for a POST-as-GET (empty payload).
    my $tag = '';
    if ($method eq 'POST' && ($h{'content-type'} // '') =~ m{jose\+json}) {
        my $jws = eval { JSON::PP->new->utf8->decode($body) };
        if ($jws && $jws->{protected}) {
            my $pj = eval { JSON::PP->new->utf8->decode(b64d($jws->{protected})) };
            if ($pj) {
                my @t;
                push @t, $pj->{jwk} ? 'jwk' : 'kid';
                push @t, 'pag' unless length($jws->{payload} // '');
                $tag = ' [' . join(' ', @t) . ']';
            }
        }
    }
    print {$lf} "$method $path$tag\n";

    my ($code, $hdrs, $rbody) = _respond($method, $path, $base);
    $rbody //= '';
    $hdrs->{'Content-Length'} = ($method eq 'HEAD' ? 0 : length $rbody);
    $hdrs->{'Connection'} = 'close';
    my $status = { 200 => 'OK', 201 => 'Created' }->{$code} // 'OK';
    my $out = "HTTP/1.1 $code $status\r\n";
    $out .= "$_: $hdrs->{$_}\r\n" for sort keys %$hdrs;
    $out .= "\r\n";
    $out .= $rbody unless $method eq 'HEAD';
    print {$c} $out;
    return;
}

my $pid = fork();
die "fork failed: $!" unless defined $pid;
if ($pid == 0) {
    open my $lf, '>', $log or POSIX::_exit(127);
    $lf->autoflush(1);
    my $srv = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => $port, Listen => 16, ReuseAddr => 1,
    ) or POSIX::_exit(127);
    for (1 .. 40) {
        my $c = $srv->accept or next;
        _serve($c, $lf);
        close $c;
    }
    POSIX::_exit(0);   # _exit: skip Test2's END hooks inherited across the fork
}
END { kill 'TERM', $pid if $pid }

my $ready;
for (1 .. 150) {
    $ready = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1);
    last if $ready;
    sleep 0.1;
}
ok($ready, "mock CA listening on 127.0.0.1:$port")
    or do { diag('mock CA never came up'); done_testing(); exit 1 };
close $ready;

my $ca_acct  = "$tmp/ca-acct.key";
Amin::Acme::Key->gen_ec($ca_acct);
my $cert_key = "$tmp/example.test.key";

my $cli = Amin::Acme::Client->new(
    directory => "$base/directory",
    key       => $ca_acct,
    contact   => ['mailto:ops@example.test'],
);
my $pem = $cli->issue(['example.test'], $cert_key);
like($pem, qr/-----BEGIN CERTIFICATE-----/, 'issue() returned the PEM certificate chain');
ok(-f $cert_key, 'the certificate key was created for the order');
like($cli->kid // '', qr{/acct/1$}, 'account kid was recorded from the Location header');

kill 'TERM', $pid;
$pid = 0;
my @seen = grep { length } split /\n/, path($log)->slurp;

is(\@seen, [
    'GET /directory',
    'HEAD /new-nonce',
    'POST /new-account [jwk]',
    'POST /new-order [kid]',
    'POST /authz/1 [kid pag]',
    'POST /chal/1 [kid]',
    'POST /authz/1 [kid pag]',
    'POST /finalize [kid]',
    'POST /cert/1 [kid pag]',
], 'the client walked the RFC 8555 flow in order, with the right JWS shape at each step');

done_testing();

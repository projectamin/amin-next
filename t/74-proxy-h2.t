#!/usr/bin/env perl
# P5 hardening (proxy-plan §5.5/§5.6): HTTP/2 inbound on the Rust front.
#
# H2 is an *inbound* transport only — the backend hop stays HTTP/1.1 (§5.6) — so
# this file starts real `amin-proxyd` processes behind real sockets and a real
# HTTP/1.1 origin, and drives the front with real `curl`.  Two negotiation paths
# reach the same backend over the same HTTP/1.1 hop, so two fronts are started:
#
#   * a plaintext front — `--http2-prior-knowledge` opens with the connection
#     preface, which the front detects and hands to the H2 driver;
#   * a TLS front — `--http2` negotiates `h2` by ALPN and the front steers by it,
#     while `--http1.1` falls back to the H1.1 path on the same socket.
#
# Nothing here is mocked: the bytes over the wire are the contract.
use v5.38; use warnings; use utf8;
use Test2::V0;
use Cwd        qw(abs_path);
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use POSIX      qw(WIFEXITED);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT   = abs_path(dirname(__FILE__) . '/..');
my $DAEMON = "$ROOT/rust/target/debug/amin-proxyd";

skip_all "amin-proxyd not compiled; run `cargo build -p amin-proxy` at ./rust"
    unless -x $DAEMON;

my $curl_version = `curl --version 2>/dev/null` // '';
skip_all 'curl with HTTP2 support is required'
    unless $curl_version =~ /^\s*Features:.*\bHTTP2\b/m;

my $openssl = `openssl version 2>/dev/null` // '';
skip_all 'openssl is required to mint the test certificate'
    unless $openssl =~ /OpenSSL/;

require IPC::Run;

my $tmp  = tempdir(CLEANUP => 1);
my $BODY = "hello-from-the-origin\n";

my (@pids, @logs);

END {
    for my $p (@pids) { kill 'TERM', $p if defined $p }
    for my $p (@pids) { waitpid $p, 0 if defined $p }
    # Reaping our own children leaves $? = the SIGTERM we sent; clear it so the
    # test harness does not read it as the test itself dying.
    $? = 0;
}

# ── a real HTTP/1.1 origin on an ephemeral loopback port ────────────────────
# The listening socket is opened here and inherited by the child, so there is no
# window between choosing the port and binding it.
my $origin_ls = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp',
    Listen    => 32, ReuseAddr => 1,
) or die "origin bind: $!";
my $origin_port = $origin_ls->sockport;

my $origin_pid = fork();
die "fork: $!" unless defined $origin_pid;
if ($origin_pid == 0) {
    while (my $c = $origin_ls->accept) {
        my $buf = '';
        while (index($buf, "\r\n\r\n") < 0) {
            my $n = sysread($c, my $chunk, 4096);
            last if !defined $n || $n == 0;
            $buf .= $chunk;
        }
        my $head = "HTTP/1.1 200 OK\r\n"
            . "Content-Type: text/plain; charset=utf-8\r\n"
            . 'Content-Length: ' . length($BODY) . "\r\n"
            . "Connection: close\r\n\r\n";
        syswrite($c, $head . $BODY);
        close $c;
    }
    exit 0;
}
close $origin_ls;
push @pids, $origin_pid;

# ── mint a self-signed cert for shop.example (and 127.0.0.1) ────────────────
my $cert = "$tmp/fullchain.pem";
my $key  = "$tmp/privkey.pem";
my $ossl = `openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout $key -out $cert -subj '/CN=shop.example' -addext 'subjectAltName=DNS:shop.example,IP:127.0.0.1' 2>&1`;
ok(-s $cert && -s $key, 'openssl minted the test certificate and key')
    or diag($ossl);

# ── pick a listen port by probe (the daemon binds it) ───────────────────────
sub pick_port () {
    my $probe = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp',
        Listen => 5, ReuseAddr => 1,
    ) or die "probe bind: $!";
    my $port = $probe->sockport;
    close $probe;
    return $port;
}

# Write a profile and start a front on it; returns the pid.
sub start_front ($profile, $n) {
    my $err = "$tmp/front$n.stderr";
    push @logs, $err;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDOUT, '>', $err or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec $DAEMON, '--profile', $profile;
        exit 127;
    }
    push @pids, $pid;
    return $pid;
}

sub wait_listen ($port) {
    for (1 .. 150) {
        my $s = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1,
        );
        # IO::Socket::INET 1.52 with Timeout hands back a socket for a refused
        # connect, so the handle alone is not proof of a listener.
        return 1 if $s && $s->connected;
        sleep 0.1;
    }
    return 0;
}

# ── the plaintext front: no TLS, so the preface path is what steers H2 ──────
my $plain_port = pick_port();
my $plain_xml  = "$tmp/plain.xml";
open my $pf, '>:encoding(UTF-8)', $plain_xml or die "profile: $!";
print $pf <<"XML";
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/"
            amin:listen="127.0.0.1:$plain_port">
  <amin:backend amin:id="origin" amin:addr="127.0.0.1:$origin_port" amin:transport="http"/>
  <amin:route amin:host="shop.example" amin:to="origin"/>
</amin:proxy>
XML
close $pf;
start_front($plain_xml, 1);

# ── the TLS front: ALPN decides the driver; cert/key from the profile ───────
my $tls_port = pick_port();
my $tls_xml  = "$tmp/tls.xml";
open my $tf, '>:encoding(UTF-8)', $tls_xml or die "profile: $!";
print $tf <<"XML";
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/"
            amin:listen="127.0.0.1:$tls_port" amin:tls="files"
            amin:cert="$cert" amin:key="$key"
            amin:max-conns="64" amin:read-timeout="30">
  <amin:backend amin:id="origin" amin:addr="127.0.0.1:$origin_port" amin:transport="http"/>
  <amin:route amin:host="shop.example" amin:to="origin"/>
</amin:proxy>
XML
close $tf;
start_front($tls_xml, 2);

my $ok_plain = wait_listen($plain_port);
my $ok_tls   = wait_listen($tls_port);
ok($ok_plain && $ok_tls, 'both fronts accept connections')
    or do {
        for my $l (@logs) {
            diag("$l:\n" . do { open my $fh, '<', $l; local $/; <$fh> // '' });
        }
        done_testing();
        exit 1;
    };

# ── curl helper: (exit code, "<version> <status>", stderr, body, headers) ───
sub curl_get ($url, @extra) {
    my $body = "$tmp/body.$$";
    my $hdrs = "$tmp/hdrs.$$";
    my ($out, $err) = ('', '');
    my @argv = ('curl', '-sS', '-o', $body, '-D', $hdrs, '-w', '%{http_version} %{http_code}', @extra, $url);
    my $h = IPC::Run::harness(\@argv, \undef, \$out, \$err);
    IPC::Run::start($h);
    IPC::Run::finish($h);
    my $rc = $? >> 8;
    my $data = '';
    if (-e $body) {
        open my $fh, '<:raw', $body or die "body: $!";
        local $/; $data = <$fh>;
        close $fh;
    }
    my $headers = '';
    if (-e $hdrs) {
        open my $fh, '<', $hdrs or die "headers: $!";
        local $/; $headers = <$fh>;
        close $fh;
    }
    unlink $body, $hdrs;
    return ($rc, $out, $err, $data, $headers);
}

subtest 'plaintext HTTP/2 with prior knowledge (connection preface)' => sub {
    my ($rc, $meta, $err, $body) =
        curl_get("http://127.0.0.1:$plain_port/product?sku=3",
                 '--http2-prior-knowledge', '-H', 'Host: shop.example');
    is $rc, 0, 'curl exited cleanly' or diag($err);
    is $meta, '2 200', 'the preface steered the stream to H2 and it answered 200';
    is $body, $BODY, 'the origin body arrived intact over the H2 DATA frames';
};

# P5 (§P5): every proxied response carries the compiled-profile fingerprint, so
# a page can be traced to the exact profile that served it.  Over H2 the field
# name is lowercase (RFC 9113 §8.2).
subtest 'proxied H2 responses carry X-Amin-Profile-SHA3' => sub {
    my ($rc, $meta, $err, undef, $headers) =
        curl_get("http://127.0.0.1:$plain_port/product?sku=3",
                 '--http2-prior-knowledge', '-H', 'Host: shop.example');
    is $rc, 0, 'curl exited cleanly' or diag($err);
    like $headers, qr{^x-amin-profile-sha3:\s*[0-9a-f]{64}\r?$}mi,
        'the profile fingerprint rides on the H2 response as lowercase hex';
};

subtest 'plaintext HTTP/1.1 still works on the same front' => sub {
    my ($rc, $meta, $err, $body) =
        curl_get("http://127.0.0.1:$plain_port/product?sku=3",
                 '--http1.1', '-H', 'Host: shop.example');
    is $rc, 0, 'curl exited cleanly' or diag($err);
    is $meta, '1.1 200', 'a non-preface client stays on the H1.1 path';
    is $body, $BODY, 'the origin body arrived intact over the H1.1 hop';
};

subtest 'TLS HTTP/2 via ALPN (h2 negotiated)' => sub {
    my ($rc, $meta, $err, $body) =
        curl_get("https://shop.example:$tls_port/product?sku=3",
                 '--http2', '--cacert', $cert,
                 '--resolve', "shop.example:$tls_port:127.0.0.1");
    is $rc, 0, 'curl exited cleanly' or diag($err);
    is $meta, '2 200', 'ALPN selected h2 and the front answered 200';
    is $body, $BODY, 'the origin body arrived intact over the H2 DATA frames';
};

subtest 'TLS still serves HTTP/1.1 when the client does not offer h2' => sub {
    my ($rc, $meta, $err, $body) =
        curl_get("https://shop.example:$tls_port/product?sku=3",
                 '--http1.1', '--cacert', $cert,
                 '--resolve', "shop.example:$tls_port:127.0.0.1");
    is $rc, 0, 'curl exited cleanly' or diag($err);
    is $meta, '1.1 200', 'ALPN fell back to http/1.1 and the front answered 200';
    is $body, $BODY, 'the origin body arrived intact over the H1.1 hop';
};

subtest 'closed-world: an unrouted authority is refused, not defaulted' => sub {
    my ($rc, $meta, $err, $body) =
        curl_get("http://127.0.0.1:$plain_port/",
                 '--http2-prior-knowledge', '-H', 'Host: nope.example');
    is $rc, 0, 'curl exited cleanly' or diag($err);
    is $meta, '2 503', 'no route → 503 over HTTP/2 (never a silent default)';
    isnt $body, $BODY, 'the refusal is not the origin body';
};

done_testing;

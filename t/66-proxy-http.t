#!/usr/bin/env perl
# Loopback integration test for the L7 front (proxy-plan §8, P1): a real
# `bin/amin proxy serve` process, a real origin socket, and real bytes over the
# wire.  Nothing here is mocked.
#
# What it pins:
#   * request parse → chain → backend pick → stream, end to end;
#   * hop-by-hop headers dropped both directions (RFC 9110 §7.6.1);
#   * X-Forwarded-For/Proto/Host appended, prior XFF folded not replaced;
#   * end-to-end headers carried untouched;
#   * the client body streamed to the backend (Content-Length accounting);
#   * a request that matches no route is closed-world denied (-6150 → 503);
#   * a WebSocket upgrade is promoted to a raw byte splice (§5.8);
#   * a permanent-filter deny (-5121) yields a 4xx before any backend contact;
#   * TLS termination with a self-signed cert serves https:// (§5.5);
#   * two requests through one loop process equal a fresh single-request
#     process (isolation, §5.3 — the warm provider is compile-once).
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Spec ();
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';
use Amin::Proxy::Config;

my $ROOT = path(dirname(__FILE__))->parent->absolute;

sub free_port () {
    my $p = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 5, ReuseAddr => 1,
    ) or die "cannot pick a port: $!";
    my $port = $p->sockport;
    close $p;
    return $port;
}

sub wait_listen ($port, $tries = 150) {
    for (1 .. $tries) {
        my $s = IO::Socket::INET->new(
            PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1,
        );
        return 1 if $s;
        sleep 0.1;
    }
    return 0;
}

# Read from $s until $marker appears (or timeout).  Returns what was read.
sub read_until ($s, $marker, $timeout = 5) {
    my $buf = '';
    while (index($buf, $marker) < 0) {
        my $rin = ''; vec($rin, fileno($s), 1) = 1;
        last unless select(my $r = $rin, undef, undef, $timeout);
        my $n = sysread($s, my $chunk, 65536);
        last unless defined $n && $n > 0;
        $buf .= $chunk;
    }
    return $buf;
}

# Read exactly $n bytes (or timeout).
sub read_n ($s, $n, $timeout = 5) {
    my $buf = '';
    while (length($buf) < $n) {
        my $rin = ''; vec($rin, fileno($s), 1) = 1;
        last unless select(my $rd = $rin, undef, undef, $timeout);
        my $r = sysread($s, my $chunk, $n - length $buf);
        last unless defined $r && $r > 0;
        $buf .= $chunk;
    }
    return $buf;
}

# Send a raw request and read the whole response to EOF (proxy closes).
sub send_raw ($port, $raw, $timeout = 5) {
    my $s = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => $timeout,
    ) or return undef;
    print $s $raw;
    my $resp = '';
    while (1) {
        my $rin = ''; vec($rin, fileno($s), 1) = 1;
        last unless select(my $r = $rin, undef, undef, $timeout);
        my $n = sysread($s, my $chunk, 65536);
        last unless defined $n && $n > 0;
        $resp .= $chunk;
    }
    close $s;
    return $resp;
}

sub split_resp ($resp) {
    my ($head, $body) = split /\r\n\r\n/, $resp, 2;
    $head //= ''; $body //= '';
    my @lines = split /\r\n/, $head, -1;
    my $status = shift @lines // '';
    my %h;
    for my $l (@lines) {
        my ($n, $v) = $l =~ /^([^:]+):[ \t]*(.*)$/ or next;
        $h{lc $n} = $v;
    }
    return ($status, \%h, $body);
}

# ── The origin ──────────────────────────────────────────────────────────────
# A tiny forked HTTP/1.1 origin.  For a normal request it answers 200 with the
# exact upstream request head it received as the body (so the test can assert
# what the proxy forwarded) plus a hop-by-hop Keep-Alive (to prove stripping),
# and reports the body length it read in X-Origin-Body-Len.  For an upgrade it
# answers 101 and then echoes bytes verbatim, standing in for a WS endpoint.
my $origin_port = free_port();

my $origin = fork();
die "fork failed: $!" unless defined $origin;
if ($origin == 0) {
    my $lsn = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => $origin_port,
        Proto => 'tcp', Listen => 64, ReuseAddr => 1,
    ) or exit 127;
    $SIG{CHLD} = 'IGNORE';
    while (my $c = $lsn->accept) {
        my $pid = fork;
        if (!defined $pid) { close $c; next }
        if ($pid == 0) {
            close $lsn;
            _origin_handle($c);
            exit 0;
        }
        close $c;
    }
    exit 0;
}

sub _origin_handle ($c) {
    my $buf = read_until($c, "\r\n\r\n", 5);
    my $i = index($buf, "\r\n\r\n");
    return unless $i >= 0;
    my $head = substr($buf, 0, $i + 4);
    my $rest = substr($buf, $i + 4);

    my @lines = split /\r\n/, $head, -1;
    my $rl = shift @lines // '';
    my %h;
    for my $l (@lines) {
        last unless length $l;
        my ($n, $v) = $l =~ /^([^:]+):[ \t]*(.*)$/ or next;
        $h{lc $n} = $v;
    }

    if (defined $h{upgrade} && ($h{connection} // '') =~ /\bupgrade\b/i) {
        syswrite($c, "HTTP/1.1 101 Switching Protocols\r\n"
                   . "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        while (1) {
            my $n = sysread($c, my $chunk, 65536);
            last unless defined $n && $n > 0;
            syswrite($c, $chunk);
        }
        return;
    }

    my $cl = $h{'content-length'} // 0;
    my $body = $rest;
    while (length($body) < $cl) {
        my $n = sysread($c, my $chunk, 65536);
        last unless defined $n && $n > 0;
        $body .= $chunk;
    }

    syswrite($c, "HTTP/1.1 200 OK\r\n"
               . "Content-Type: text/plain\r\n"
               . 'Content-Length: ' . length($head) . "\r\n"
               . "Keep-Alive: timeout=5\r\n"
               . 'X-Origin-Body-Len: ' . length($body) . "\r\n"
               . "Connection: close\r\n\r\n"
               . $head);
    return;
}

ok(wait_listen($origin_port), "origin listening on 127.0.0.1:$origin_port")
    or do { done_testing(); exit 1 };

# ── The proxy ───────────────────────────────────────────────────────────────
my $proxy_port = free_port();
my $tmp    = tempdir(CLEANUP => 1);
my $cfg    = "$tmp/proxy.xml";
my $stderr = "$tmp/proxy.stderr";

# A front-local authorization filter, registered via --with-permanent, standing
# in for the permanent region's real filters (ZCap, an allowlist, …): it denies
# exactly one host with the ZCap scope-violation rc (-5121) and drops the
# <amin:request> so the routing filter below it never runs.  That proves the
# §5.7 property end to end — a permanent deny is a 4xx, and no backend is
# contacted — without building a full zcap token for the front (the front is
# authority-free, §5.12: it parses the request, it does not mint authority).
mkdir "$tmp/lib" or die "mkdir $tmp/lib: $!";
path("$tmp/lib/DenyPerm.pm")->spew_utf8(<<'PM');
package DenyPerm;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Test::Handler';
use Amin qw(NS);

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'request') {
        my %a;
        for my $k (keys %{ $el->{Attributes} // {} }) {
            my $h = $el->{Attributes}{$k} // {};
            $a{ $h->{LocalName} // $h->{Name} // $k } = $h->{Value};
        }
        if (($a{host} // '') eq 'deny.example') {
            my $h = $self->Handler or return;
            my $result = _ev('result');
            my $status = _ev('status', { rc => '-5121', exit_kind => 'zcap',
                                         msg => 'scope violation (test)' });
            $h->start_element($result);
            $h->start_element($status);
            $h->end_element($status);
            $h->end_element($result);
            return;   # drop <amin:request>: the wider chain never sees it
        }
    }
    return $self->SUPER::start_element($el);
}

sub _ev ($ln, $attrs = undef) {
    my %e = (NamespaceURI => NS(), LocalName => $ln, Name => "amin:$ln",
             Prefix => 'amin');
    if ($attrs) {
        my %A;
        for my $k (keys %$attrs) {
            $A{ NS() . $k } = {
                Name => "amin:$k", LocalName => $k, Prefix => 'amin',
                NamespaceURI => NS(), Value => '' . $attrs->{$k},
            };
        }
        $e{Attributes} = \%A;
    }
    return \%e;
}
1;
PM

path($cfg)->spew_utf8(<<"XML");
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/"
            amin:listen="127.0.0.1:$proxy_port"
            amin:max-conns="256" amin:read-timeout="10">
  <amin:backend amin:id="origin" amin:addr="127.0.0.1:$origin_port" amin:transport="http"/>
  <amin:route amin:host="only.example" amin:to="origin" amin:ws="on"/>
</amin:proxy>
XML

my $proxy = fork();
die "fork failed: $!" unless defined $proxy;
if ($proxy == 0) {
    open STDOUT, '>>', $stderr or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/amin",
         '--inc', "$tmp/lib", '--with-permanent=DenyPerm',
         'proxy', 'serve', $cfg;
    exit 127;
}

my $up = wait_listen($proxy_port);
ok($up, "proxy serving (config listen) on 127.0.0.1:$proxy_port")
    or do {
        kill 'TERM', $proxy, $origin;
        waitpid $_, 0 for $proxy, $origin;
        diag("proxy log:\n" . (-f $stderr ? path($stderr)->slurp : '(none)'));
        done_testing(); exit 1;
    };

# ── 1. GET through the front ─────────────────────────────────────────────────
my $get = send_raw($proxy_port,
    "GET /echo?x=1 HTTP/1.1\r\n"
  . "Host: only.example\r\n"
  . "X-Custom: keep-me\r\n"
  . "Proxy-Connection: keep-alive\r\n"
  . "Connection: keep-alive\r\n\r\n");

ok(defined $get && length $get, 'GET /echo produced a response');
my ($status, $rh, $body) = split_resp($get);
like($status, qr{^HTTP/1\.1 200}, 'served 200');
is($rh->{'content-type'}, 'text/plain', 'response content-type carried');
is($rh->{'x-origin-body-len'}, 0, 'no body reached the origin for a GET');
unlike($rh->{'keep-alive'}, qr/./, 'origin Keep-Alive stripped downstream (hop-by-hop)');
is($rh->{'x-amin-profile-sha3'},
   Amin::Proxy::Config->load(ref => $cfg)->profile_sha3,
   'X-Amin-Profile-SHA3 stamps the compiled profile on the proxied response (§P5)');

# The body is the upstream head the origin received — assert what the front sent.
like($body, qr{^GET /echo\?x=1 HTTP/1\.1}, 'origin-form target forwarded');
like($body, qr{\r\nHost: 127\.0\.0\.1:$origin_port\r\n}, 'Host rewritten to the backend authority');
like($body, qr{\r\nX-Custom: keep-me\r\n}, 'end-to-end header carried untouched');
like($body, qr{\r\nX-Forwarded-For: 127\.0\.0\.1\r\n}, 'X-Forwarded-For appended');
like($body, qr{\r\nX-Forwarded-Proto: http\r\n}, 'X-Forwarded-Proto appended');
like($body, qr{\r\nX-Forwarded-Host: only\.example\r\n}, 'X-Forwarded-Host appended');
like($body, qr{\r\nConnection: close\r\n}, 'front pins Connection: close upstream');
unlike($body, qr{Proxy-Connection}i, 'Proxy-Connection stripped (hop-by-hop)');
unlike($body, qr{\r\nKeep-Alive}i,  'Keep-Alive stripped (hop-by-hop)');

# ── 2. prior X-Forwarded-For is folded, not replaced ─────────────────────────
my $get2 = send_raw($proxy_port,
    "GET /xff HTTP/1.1\r\nHost: only.example\r\nX-Forwarded-For: 10.0.0.9\r\n\r\n");
my (undef, undef, $body2) = split_resp($get2 // '');
like($body2, qr{\r\nX-Forwarded-For: 10\.0\.0\.9, 127\.0\.0\.1\r\n},
    'prior X-Forwarded-For folded with the peer, not replaced');

# ── 3. client body streamed to the backend ───────────────────────────────────
my $payload = 'hello=world&n=42';
my $post = send_raw($proxy_port,
    "POST /submit HTTP/1.1\r\n"
  . "Host: only.example\r\n"
  . 'Content-Length: ' . length($payload) . "\r\n\r\n"
  . $payload);
my (undef, $ph, undef) = split_resp($post // '');
is($ph->{'x-origin-body-len'}, length($payload), 'the client body reached the origin intact');

# ── 4. closed-world: a request that matches no route → 503 ───────────────────
my $nope = send_raw($proxy_port, "GET / HTTP/1.1\r\nHost: nope.example\r\n\r\n");
my ($nstatus, undef, undef) = split_resp($nope // '');
like($nstatus, qr{^HTTP/1\.1 503}, 'no matching route → 503 (closed-world deny, -6150)');

# ── 5. WebSocket upgrade → raw splice (§5.8) ────────────────────────────────
my $ws = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1', PeerPort => $proxy_port, Proto => 'tcp', Timeout => 5,
);
ok($ws, 'opened a websocket client socket');
print $ws "GET /ws HTTP/1.1\r\nHost: only.example\r\n"
        . "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
my $wshead = read_until($ws, "\r\n\r\n", 5);
like($wshead, qr{^HTTP/1\.1 101}, '101 Switching Protocols relayed to the client');
like($wshead, qr{\r\nUpgrade: websocket\r\n}i, 'upgrade header relayed through the splice');
print $ws "ping-pong\n";
my $echo = read_n($ws, length "ping-pong\n", 5);
is($echo, "ping-pong\n", 'bytes spliced verbatim client→origin→client');
close $ws;

# ── 6. permanent-filter deny (-5121) → 4xx, no backend contact ───────────────
my $deny = send_raw($proxy_port, "GET / HTTP/1.1\r\nHost: deny.example\r\n\r\n");
my ($dstatus, undef, $dbody) = split_resp($deny // '');
like($dstatus, qr{^HTTP/1\.1 403}, 'permanent -5121 deny → 403 (a 4xx, not a 200)');
unlike($dbody, qr{^GET }, 'the 4xx is the front\'s own, not the origin echo: '
    . 'the deny fired before any backend was contacted');

# ── 7. isolation: one warm loop process == a fresh single-request process ────
# §5.3: the compiled table is injected, not re-streamed, and a request gets a
# fresh dispatcher, so a warm process must answer exactly as a cold one does.
my $iso_req = "GET /iso?n=1 HTTP/1.1\r\nHost: only.example\r\n\r\n";
my $warm1 = send_raw($proxy_port, $iso_req);
my $warm2 = send_raw($proxy_port, $iso_req);
is($warm1, $warm2, 'two requests through one warm loop process are byte-identical');

my $fresh_port = free_port();
my $fresh = fork();
die "fork failed: $!" unless defined $fresh;
if ($fresh == 0) {
    open STDOUT, '>>', "$tmp/fresh.stderr" or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/amin",
         '--inc', "$tmp/lib", '--with-permanent=DenyPerm',
         'proxy', 'serve', $cfg, '--listen', "127.0.0.1:$fresh_port";
    exit 127;
}
ok(wait_listen($fresh_port), "fresh proxy serving on 127.0.0.1:$fresh_port");
my $cold = send_raw($fresh_port, $iso_req);
is($cold, $warm1, 'a warm request equals a fresh single-request process (compile-once)');
kill 'TERM', $fresh;
waitpid $fresh, 0;

# ── 8. TLS termination (§5.5) ────────────────────────────────────────────────
subtest 'TLS termination serves https:// with a self-signed cert' => sub {
    my $have = eval { require IO::Socket::SSL; 1 };
    ok($have, 'IO::Socket::SSL is available');
    return unless $have;

    my ($cert, $key) = ("$tmp/tls-cert.pem", "$tmp/tls-key.pem");
    # openssl's keygen progress goes to stderr; keep the TAP stream clean by
    # reopening the real descriptors (a `local *STDERR` only redirects Perl's
    # own writes — a forked child still inherits the original fd 2).
    my $gen = do {
        open my $saved_out, '>&', \*STDOUT or die "dup STDOUT: $!";
        open my $saved_err, '>&', \*STDERR or die "dup STDERR: $!";
        open STDOUT, '>', File::Spec->devnull or die "open devnull: $!";
        open STDERR, '>&', \*STDOUT or die "redirect STDERR: $!";
        my $rc = system('openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', $key, '-out', $cert, '-days', '1', '-nodes',
            '-subj', '/CN=only.example');
        open STDOUT, '>&', $saved_out or die "restore STDOUT: $!";
        open STDERR, '>&', $saved_err or die "restore STDERR: $!";
        $rc == 0;
    };
    ok($gen, 'generated a self-signed test certificate');

    my $tls_port = free_port();
    my $tls_cfg  = "$tmp/tls.xml";
    path($tls_cfg)->spew_utf8(<<"XML");
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/"
            amin:listen="127.0.0.1:$tls_port"
            amin:tls="files" amin:cert="$cert" amin:key="$key">
  <amin:backend amin:id="origin" amin:addr="127.0.0.1:$origin_port" amin:transport="http"/>
  <amin:route amin:host="only.example" amin:to="origin"/>
</amin:proxy>
XML
    my $tls = fork();
    if (!defined $tls) { ok(0, 'fork'); return }
    if ($tls == 0) {
        open STDOUT, '>>', "$tmp/tls.stderr" or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/amin", 'proxy', 'serve', $tls_cfg;
        exit 127;
    }
    ok(wait_listen($tls_port), "tls proxy listening on 127.0.0.1:$tls_port");

    my $ssl = IO::Socket::SSL->new(
        PeerAddr => '127.0.0.1', PeerPort => $tls_port,
        SSL_verify_mode => 0, SSL_hostname => 'only.example', Timeout => 5,
    );
    ok($ssl, 'https client completed the TLS handshake');
    if ($ssl) {
        print $ssl "GET /secure HTTP/1.1\r\nHost: only.example\r\n\r\n";
        my $resp = '';
        while (1) {
            my $n = sysread($ssl, my $chunk, 65536);
            last unless defined $n && $n > 0;
            $resp .= $chunk;
        }
        close $ssl;
        my ($sstatus, undef, $sbody) = split_resp($resp);
        like($sstatus, qr{^HTTP/1\.1 200}, 'served 200 over TLS');
        like($sbody, qr{^GET /secure HTTP/1\.1},
            'the decrypted request was forwarded to the origin');
    }

    kill 'TERM', $tls;
    waitpid $tls, 0;
};

# ── teardown ────────────────────────────────────────────────────────────────
kill 'TERM', $proxy;
kill 'TERM', $origin;
waitpid $proxy, 0;
waitpid $origin, 0;

done_testing;

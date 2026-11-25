#!/usr/bin/env perl
# Perl ↔ Rust parity at the *listener* (proxy-plan §7/§8, P3): one <amin:proxy>
# profile served by the Perl front (`bin/amin proxy serve`) and by the Rust
# front (`amin-proxyd`), each fed the same raw requests over real sockets.
#
# The §7 parity rule is about the *upstream* stream: the two fronts must make
# byte-identical <proxy:backend> decisions and forward byte-identical upstream
# request heads.  t/73 already pins the decision *elements* (the routing filter
# output) byte for byte; this pins the decision *materialised* at the front —
# which backend the balancer chose (the Host rewrite), how the target was
# rewritten (prefix strip), how the caller authority material and the
# X-Forwarded-* fold came through, and the hop-by-hop strip.  The origin reveals
# all of it by echoing, as its response body, the exact head it received, so the
# two fronts' forwarded heads are compared directly, byte for byte.
#
# Nothing here is mocked: a real origin socket, two real front processes, and
# real bytes on the wire.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $RUST = "$ROOT/rust/target/debug/amin-proxyd";
unless (-x $RUST) {
    skip_all "amin-proxyd not compiled; run `cargo build -p amin-proxy` at ./rust";
}

# ── small socket helpers (mirrors t/66) ─────────────────────────────────────

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
        # IO::Socket::INET 1.52 with Timeout hands back a socket for a refused
        # connect, so the handle alone is not proof of a listener.
        return 1 if $s && $s->connected;
        sleep 0.1;
    }
    return 0;
}

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

# Send a raw request, read the whole response to EOF (both fronts close).
sub send_raw ($port, $raw, $timeout = 5) {
    my $s = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => $timeout,
    ) or return undef;
    return undef unless $s->connected;
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

# The response body is the upstream head the origin echoed; split it off.
sub upstream_head ($resp) {
    my (undef, $body) = split /\r\n\r\n/, $resp // '', 2;
    return $body // '';
}

# ── the origin ──────────────────────────────────────────────────────────────
# A tiny forked HTTP/1.1 origin that answers every request 200 with, as its
# body, the *exact upstream request head* it received.  No upgrade handling: at
# the origin an upgrade is only ever a request header, so echoing it back proves
# whether a front promoted or stripped it.
sub start_origin () {
    my $port = free_port();
    my $pid  = fork();
    die "fork failed: $!" unless defined $pid;
    if ($pid == 0) {
        my $lsn = IO::Socket::INET->new(
            LocalAddr => '127.0.0.1', LocalPort => $port,
            Proto => 'tcp', Listen => 64, ReuseAddr => 1,
        ) or exit 127;
        $SIG{CHLD} = 'IGNORE';
        while (my $c = $lsn->accept) {
            my $kid = fork;
            if (!defined $kid) { close $c; next }
            if ($kid == 0) { close $lsn; _origin_handle($c); exit 0 }
            close $c;
        }
        exit 0;
    }
    return ($port, $pid);
}

sub _origin_handle ($c) {
    my $buf = read_until($c, "\r\n\r\n", 5);
    my $i = index($buf, "\r\n\r\n");
    return unless $i >= 0;
    my $head = substr($buf, 0, $i + 4);
    my $rest = substr($buf, $i + 4);

    my @lines = split /\r\n/, $head, -1;
    shift @lines;
    my %h;
    for my $l (@lines) {
        last unless length $l;
        my ($n, $v) = $l =~ /^([^:]+):[ \t]*(.*)$/ or next;
        $h{lc $n} = $v;
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

# Two origins, so the chosen backend is observable in the forwarded Host.
my ($port_a, $origin_a) = start_origin();
my ($port_b, $origin_b) = start_origin();
ok(wait_listen($port_a) && wait_listen($port_b), 'both origins are listening')
    or do { done_testing(); exit 1 };

# ── the two fronts, one profile ─────────────────────────────────────────────
my $tmp        = tempdir(CLEANUP => 1);
my $cfg        = "$tmp/proxy.xml";
my $perl_port  = free_port();
my $rust_port  = free_port();
my $perl_log   = "$tmp/perl.stderr";
my $rust_log   = "$tmp/rust.stderr";

# No amin:listen in the profile — each front is pointed at its own port, so the
# very same compiled table serves both.
path($cfg)->spew_utf8(<<"XML");
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:backend amin:id="alpha" amin:addr="127.0.0.1:$port_a" amin:transport="http"/>
  <amin:backend amin:id="beta"  amin:addr="127.0.0.1:$port_b" amin:transport="http"/>
  <amin:route amin:host="only.example" amin:to="alpha" amin:ws="on"/>
  <amin:route amin:host="strip.example" amin:path="/api/" amin:to="beta" amin:strip-prefix="on"/>
  <amin:route amin:host="bal.example" amin:to="alpha,beta"/>
</amin:proxy>
XML

my $perl_front = fork();
die "fork failed: $!" unless defined $perl_front;
if ($perl_front == 0) {
    open STDOUT, '>>', $perl_log or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/amin",
         'proxy', 'serve', $cfg, '--listen', "127.0.0.1:$perl_port";
    exit 127;
}

my $rust_front = fork();
die "fork failed: $!" unless defined $rust_front;
if ($rust_front == 0) {
    open STDOUT, '>>', $rust_log or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    exec $RUST, '--profile', $cfg, '--listen', "127.0.0.1:$rust_port";
    exit 127;
}

my $up = wait_listen($perl_port) && wait_listen($rust_port);
ok($up, "perl front on :$perl_port and rust front on :$rust_port")
    or do {
        kill 'TERM', $perl_front, $rust_front, $origin_a, $origin_b;
        waitpid $_, 0 for $perl_front, $rust_front, $origin_a, $origin_b;
        diag('perl front log: ' . (-f $perl_log ? path($perl_log)->slurp : '(none)'));
        diag('rust front log: ' . (-f $rust_log ? path($rust_log)->slurp : '(none)'));
        done_testing(); exit 1;
    };

# Send the same raw bytes to both fronts; return the two full responses.
sub both ($raw) {
    return (send_raw($perl_port, $raw), send_raw($rust_port, $raw));
}

# ── 1. a routed GET: byte-identical decision + upstream head ─────────────────
subtest 'a routed GET forwards a byte-identical upstream head' => sub {
    my ($p, $r) = both(
        "GET /echo?x=1 HTTP/1.1\r\n"
      . "Host: only.example\r\n"
      . "X-Custom: keep-me\r\n"
      . "Proxy-Connection: keep-alive\r\n"
      . "Connection: keep-alive\r\n\r\n");

    is $p, $r, 'the two fronts returned byte-identical responses';
    my $head = upstream_head($p);
    like $head, qr{\A GET \s /echo\?x=1 \s HTTP/1\.1\r\n}x, 'origin-form target forwarded';
    like $head, qr{\r\nHost: 127\.0\.0\.1:$port_a\r\n}, 'decision materialised: routed to backend alpha';
    like $head, qr{\r\nX-Custom: keep-me\r\n}, 'end-to-end header carried untouched';
    like $head, qr{\r\nX-Forwarded-For: 127\.0\.0\.1\r\n}, 'X-Forwarded-For appended';
    like $head, qr{\r\nX-Forwarded-Proto: http\r\n}, 'X-Forwarded-Proto appended';
    like $head, qr{\r\nX-Forwarded-Host: only\.example\r\n}, 'X-Forwarded-Host appended';
    like $head, qr{\r\nConnection: close\r\n}, 'front pins Connection: close upstream';
    unlike $head, qr{Proxy-Connection}i, 'Proxy-Connection stripped (hop-by-hop)';
    unlike $head, qr{\r\nKeep-Alive}i,  'Keep-Alive stripped (hop-by-hop)';
};

# ── 2. a prior X-Forwarded-For is folded, not replaced ───────────────────────
subtest 'a prior X-Forwarded-For is folded on both fronts' => sub {
    my ($p, $r) = both(
        "GET /xff HTTP/1.1\r\nHost: only.example\r\nX-Forwarded-For: 10.0.0.9\r\n\r\n");
    is $p, $r, 'byte-identical responses';
    like upstream_head($p), qr{\r\nX-Forwarded-For: 10\.0\.0\.9, 127\.0\.0\.1\r\n},
        'prior X-Forwarded-For folded with the peer, not replaced';
};

# ── 3. strip-prefix routes the target the same way ───────────────────────────
subtest 'a strip-prefix route rewrites the target identically' => sub {
    my ($p, $r) = both(
        "GET /api/v1/items?n=2 HTTP/1.1\r\nHost: strip.example\r\n\r\n");
    is $p, $r, 'byte-identical responses';
    my $head = upstream_head($p);
    like $head, qr{\AGET /v1/items\?n=2 HTTP/1\.1\r\n}, 'the route prefix was stripped';
    like $head, qr{\r\nHost: 127\.0\.0\.1:$port_b\r\n}, 'decision materialised: routed to backend beta';
};

# ── 4. a client body streams through identically ─────────────────────────────
subtest 'a Content-Length body reaches the backend identically' => sub {
    my $payload = 'hello=world&n=42';
    my ($p, $r) = both(
        "POST /submit HTTP/1.1\r\n"
      . "Host: only.example\r\n"
      . 'Content-Length: ' . length($payload) . "\r\n\r\n"
      . $payload);
    is $p, $r, 'byte-identical responses';
    my ($len) = ($p // '') =~ /\r\nX-Origin-Body-Len: (\d+)\r\n/;
    is $len, length($payload), 'the client body reached the origin intact';
};

# ── 5. an upgrade is promoted / stripped identically ─────────────────────────
subtest 'an upgrade on a ws route is promoted identically' => sub {
    my ($p, $r) = both(
        "GET /ws HTTP/1.1\r\nHost: only.example\r\n"
      . "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    is $p, $r, 'byte-identical responses';
    my $head = upstream_head($p);
    like $head, qr{\r\nUpgrade: websocket\r\n}, 'Upgrade promoted past the hop-by-hop strip (ws route)';
    like $head, qr{\r\nConnection: Upgrade\r\n}, 'the front emits its own Connection: Upgrade';
};

subtest 'an upgrade on a non-ws route is stripped identically' => sub {
    my ($p, $r) = both(
        "GET /api/ws HTTP/1.1\r\nHost: strip.example\r\n"
      . "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    is $p, $r, 'byte-identical responses';
    my $head = upstream_head($p);
    unlike $head, qr{\r\nUpgrade}i, 'Upgrade stripped as hop-by-hop on a non-ws route';
    like $head, qr{\r\nConnection: close\r\n}, 'the front pins Connection: close instead';
};

# ── 6. closed-world: an unmatched request is denied the same way ─────────────
subtest 'an unmatched request is denied identically (closed-world)' => sub {
    my ($p, $r) = both("GET / HTTP/1.1\r\nHost: nope.example\r\n\r\n");
    my ($ps) = split /\r\n/, $p // '';
    my ($rs) = split /\r\n/, $r // '';
    # §7 governs the *forwarded* stream (upstream heads, decision elements), not
    # the front's own error envelope, so the 503 bodies are not compared byte
    # for byte — only the decision, which is the status line.
    is $ps, $rs, 'both fronts answer the same status line';
    like $ps, qr{\AHTTP/1\.1 503}, 'no matching route → 503 (-6150)';
};

# ── 7. a multi-backend route balances within the same declared set ───────────
subtest 'a multi-backend route balances within the same declared set' => sub {
    my %declared = map { $_ => 1 } "127.0.0.1:$port_a", "127.0.0.1:$port_b";
    my $raw = "GET /bal HTTP/1.1\r\nHost: bal.example\r\n\r\n";
    # The per-request pick is intentionally NOT compared: p2c_ewma is stochastic
    # across processes (each front converges on its own low-latency candidate),
    # so the exact backend may differ. The parity that §7 demands — a
    # byte-identical decision *profile* — is pinned by t/73; here both fronts
    # must simply choose from the same declared set.
    for my $side ([perl => $perl_port], [rust => $rust_port]) {
        my ($name, $port) = @$side;
        my @choice;
        for (1 .. 12) {
            my ($host) = upstream_head(send_raw($port, $raw)) =~ /\r\nHost: ([^\r\n]+)\r\n/;
            push @choice, $host if defined $host;
        }
        is scalar(@choice), 12, "the $name front answered every balanced request";
        my @stray = grep { !$declared{$_} } @choice;
        is \@stray, [], "the $name front chose only declared backends";
    }
};

# ── teardown ────────────────────────────────────────────────────────────────
kill 'TERM', $perl_front, $rust_front, $origin_a, $origin_b;
waitpid $_, 0 for $perl_front, $rust_front, $origin_a, $origin_b;

done_testing;

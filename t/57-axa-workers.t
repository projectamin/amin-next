#!/usr/bin/env perl
# Cross-worker session/cart persistence against the REAL server.
#
# This is the test that fails without the SQLite store.  Starman preforks, and
# a forked worker gets its own copy of any in-process hash — so with the old
# in-memory adapter, three adds issued over separate connections would land on
# different workers and the cart would silently lose most of them.
#
# It forks `bin/amin axa serve` (multiple workers), drives it over TCP with
# fresh connections so the kernel spreads load across the pool, and asserts the
# cart is complete on read-back.  Also covers the IPv6 bind and streaming
# framing, since both are easy to lose in a server swap.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::IP;
use HTTP::Tiny;
use Sys::Hostname ();
use Time::HiRes qw(sleep);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $APP  = "$ROOT/examples/apps/shop-ui";

my $ipv6_ok = do {
    my $s = IO::Socket::IP->new(
        LocalAddr => '::1', LocalPort => 0, Listen => 1,
        Proto => 'tcp', GetAddrInfoFlags => 0,
    );
    my $ok = $s ? 1 : 0;
    $s and close $s;
    $ok;
};

# free port
my $probe = IO::Socket::IP->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 5, ReuseAddr => 1,
) or die "cannot pick a port: $!";
my $port = $probe->sockport;
close $probe;

my $tmp    = tempdir(CLEANUP => 1);
my $stderr = "$tmp/serve.stderr";
my $db     = "$tmp/store.sqlite";

my $pid = fork();
die "fork failed: $!" unless defined $pid;
if ($pid == 0) {
    open STDOUT, '>>', $stderr or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    # AXA_STORE keeps the test's database inside its tempdir
    local $ENV{AXA_STORE} = $db;
    exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/amin",
        'axa', 'serve', $APP,
        '--listen', 'localhost:' . $port,
        '--workers', 4;
    exit 127;
}

END { kill 'TERM', $pid if $pid }

# wait for the listener (bounded)
my $ready;
for (1 .. 200) {
    $ready = IO::Socket::IP->new(
        PeerHost => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1,
    );
    last if $ready;
    sleep 0.1;
}
ok($ready, "server listening on 127.0.0.1:$port")
    or do { diag("server log:\n" . path($stderr)->slurp); done_testing(); exit 1 };
close $ready;

# the answering process is the one we spawned
ok(kill(0, $pid), 'the answering process is the one we spawned');

# ── IPv6: the browser path that a server swap can silently lose ─────────
SKIP: {
    skip 'no IPv6 loopback on this host', 2 unless $ipv6_ok;
    my $v6 = IO::Socket::IP->new(
        PeerHost => '::1', PeerPort => $port, Proto => 'tcp', Timeout => 3,
    );
    ok($v6, 'listens on IPv6 loopback (::1) too');
    if ($v6) {
        print $v6 "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        my $buf = '';
        $v6->blocking(0);
        for (1 .. 100) {
            my $n = sysread($v6, my $ch, 8192);
            $buf .= $ch if defined $n && $n > 0;
            last if $buf =~ m{</html>}s;
            sleep 0.05;
        }
        like($buf, qr{HTTP/1\.1 200}, 'and it serves the app over ::1');
        close $v6;
    }
}

# ── streaming framing: chunked, no Content-Length ───────────────────────
my $ua = HTTP::Tiny->new(timeout => 15, keep_alive => 0);
my $h1 = $ua->request(GET => "http://127.0.0.1:$port/");
is($h1->{status}, 200, 'GET / -> 200');
is($h1->{headers}{'transfer-encoding'}, 'chunked', 'response is chunked (streamed)');
ok(!defined $h1->{headers}{'content-length'},
   'no Content-Length on a streamed response')
   or diag 'content-length: ' . ($h1->{headers}{'content-length'} // 'undef');
like($h1->{content}, qr{^<!DOCTYPE html>}, 'doctype delivered');
like($h1->{content}, qr{</html>}, 'document delivered complete despite chunking');

# ── the point of the whole exercise: cart across workers ────────────────
# Fresh connection per request (keep_alive 0) so the 4 workers each get some.
my ($cookie) = ($h1->{headers}{'set-cookie'} // '') =~ /(axa_sid=[^;]+)/;
ok($cookie, 'session cookie minted');

my $get = sub {
    my ($method, $path, $body) = @_;
    my %h = ('Connection' => 'close');
    $h{Cookie} = $cookie if $cookie;
    $h{'Content-Type'} = 'application/x-www-form-urlencoded' if defined $body;
    return HTTP::Tiny->new(timeout => 15, keep_alive => 0)
        ->request($method, "http://127.0.0.1:$port$path",
                  { headers => \%h, content => $body });
};

# CSRF is session-bound: read it from a response that carried our cookie.
my $prod = $get->(GET => '/product?sku=sku-1');
my ($tag)  = $prod->{content} =~ m{(<input[^>]*name="axa\.csrf"[^>]*>)};
my ($csrf) = $tag =~ /value="([^"]+)"/;
ok($csrf, 'csrf token read with the session cookie');

my @skus = qw(sku-1 sku-2 sku-3);
my @codes;
for my $sku (@skus) {
    push @codes, $get->(POST => '/cart',
        "axa.action=cart.add&axa.param.sku=$sku&axa.csrf=$csrf")->{status};
}
is([ @codes ], [ (200) x @skus ], 'all three cart.add POSTs accepted');

my $cart = $get->(GET => '/cart');
is($cart->{status}, 200, 'cart page reads back 200');
my %seen;
$seen{$1}++ while $cart->{content} =~ m{<input[^>]*value="(sku-\d+)"}g;
ok(!$seen{$_}, "cart lost $_ across workers") for grep { !$seen{$_} } @skus;
ok($seen{$_}, "cart kept $_ across workers")   for @skus;
is([ sort keys %seen ], [ @skus ], 'all three skus present after separate-connection adds');

# quantity edit persists too
$get->(POST => '/cart', "axa.action=cart.set_qty&axa.param.sku=sku-1&axa.param.qty=7&axa.csrf=$csrf");
my ($qty) = $get->(GET => '/cart')->{content}
    =~ m{<input[^>]*type="number"[^>]*value="(\d+)"};
is($qty, 7, 'quantity edit persisted across workers');

# remove persists
$get->(POST => '/cart', "axa.action=cart.remove&axa.param.sku=sku-2&axa.csrf=$csrf");
unlike($get->(GET => '/cart')->{content}, qr{value="sku-2"}, 'remove persisted');

# ── a silent client must not take a worker down permanently ─────────────
my @silent;
for (1 .. 3) {
    push @silent, IO::Socket::IP->new(
        PeerHost => '127.0.0.1', PeerPort => $port, Proto => 'tcp') or last;
}
my $t0 = time;
my $after = $get->(GET => '/');
ok($after->{status} == 200, 'server still answers with idle connections open');
cmp_ok(time - $t0, '<', 5, '  and promptly') or diag 'took ' . (time - $t0) . 's';
$_->close for @silent;

# ── store is actually on disk (off the heap) ────────────────────────────
ok(-e $db, 'session store is a real file, not process memory');
ok(-s $db > 0, '  and it has content');

# ── nothing reachable off-box: never a wildcard bind ────────────────────
# `--listen localhost` must stay loopback-only on BOTH families.  Binding
# 0.0.0.0 or :: would fix an IPv4/IPv6 asymmetry by exposing a dev server to
# the whole LAN, so this is a security property, not a nicety.  Asserted
# against the REAL server here: the check that used to live in t/53 built a
# fresh listener of its own instead of inspecting what was actually running.
SKIP: {
    skip 'no /proc on this host', 1 unless -r '/proc/net/tcp';
    my @wild;
    for my $f (qw(/proc/net/tcp /proc/net/tcp6)) {
        next unless -r $f;
        open my $fh, '<', $f or next;
        while (my $line = <$fh>) {
            my ($laddr, $lport, $state) = $line =~
                /^\s*\d+:\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+([0-9A-Fa-f]+)/
                or next;
            next unless $state eq '0A';            # 0A == LISTEN
            next unless hex($lport) == $port;
            my $wildcard = $f =~ /tcp6$/
                ? '00000000000000000000000000000000' : '00000000';
            push @wild, "$f=$laddr" if lc($laddr) eq $wildcard;
        }
        close $fh;
    }
    is(\@wild, [], 'listening socket is per-address, never wildcard')
        or diag "wildcard bind: @wild";
}

# Portably: reach the port by its hostname.  A wildcard bind makes that
# succeed over a non-loopback address, which is exactly what must not happen.
my $hn     = eval { Sys::Hostname::hostname() } // '';
my $offbox = length $hn
    ? IO::Socket::IP->new(PeerHost => $hn, PeerPort => $port, Proto => 'tcp', Timeout => 2)
    : undef;
if ($offbox) {
    my $local = $offbox->sockhost // '';
    my $loop  = $local =~ /^127\./ || $local eq '::1' || $local eq '';
    ok($loop, "port is only reachable via loopback, not off-box (got $local)");
    close $offbox;
}
else {
    ok(1, "host address '$hn' cannot reach the port — off-box refused");
}

kill 'TERM', $pid;
waitpid $pid, 0;
$pid = 0;

done_testing;

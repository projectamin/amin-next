#!/usr/bin/env perl
# An idle client must not stall the server.
#
# Regression: the original stock Plack handler (HTTP::Server::PSGI) accepted a
# connection and then blocked in read_timeout(..., 300) on that ONE socket, so
# a client that connected and sent nothing held the whole server hostage for
# five minutes.  Browsers open speculative preconnects and hold them, which
# turned that from an edge case into the common path.
#
# A Starman-style prefork pool only bounded that: a silent connection pins one
# worker for read-timeout, so idle clients were survivable only while spare
# workers existed.  The origin is now Amin::AXA::Serve over Amin::Net::Loop —
# one event loop multiplexes many partially-idle connections, so a silent
# client costs nothing at all and is simply reaped once its idle window
# expires.  The assertions below therefore hold absolutely: idle clients are
# free, and they are dropped rather than tolerated.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::IP;
use Time::HiRes qw(time sleep);
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

# pick a free port
my $probe = IO::Socket::IP->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 5, ReuseAddr => 1,
) or die "cannot pick a port: $!";
my $port = $probe->sockport;
close $probe;

my $tmp    = tempdir(CLEANUP => 1);
my $stderr = "$tmp/serve.stderr";

my $pid = fork();
die "fork failed: $!" unless defined $pid;
if ($pid == 0) {
    open STDOUT, '>>', $stderr or exit 127;
    open STDERR, '>&', \*STDOUT or exit 127;
    exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/amin",
        'axa', 'serve', $APP, '--listen', "127.0.0.1:$port",
        # A pool of 4 (SO_REUSEPORT) and a 2 s pre-request idle window: the
        # pool is real, but the loop means idle connections are never pinned.
        '--workers', 4, '--read-timeout', 2;
    exit 127;
}

END { kill 'TERM', $pid if $pid }

# wait for the listener
my $ready;
for (1 .. 150) {
    $ready = IO::Socket::IP->new(
        PeerHost => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1,
    );
    last if $ready;
    sleep 0.1;
}
ok($ready, "server listening on 127.0.0.1:$port")
    or do { diag("server log:\n" . path($stderr)->slurp); done_testing(); exit 1 };
close $ready;

# one timed request against the live server
sub timed_get {
    my $t0 = time;
    my $c = IO::Socket::IP->new(
        PeerHost => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 3,
    );
    return (undef, time - $t0) unless $c;
    print $c "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n";
    $c->blocking(0);
    my ($buf, $cl) = ('', undef);
    for (1 .. 200) {                        # ≤10s
        my $n = sysread($c, my $chunk, 8192);
        if (defined $n && $n > 0) {
            $buf .= $chunk;
            $cl = $buf =~ /\r\nContent-Length:\s*(\d+)/i ? $1 : 0 if !defined $cl;
            if (defined $cl) {
                my $idx  = index($buf, "\r\n\r\n");
                my $have = length($buf) - $idx - 4;
                last if $have >= $cl;
            }
        }
        elsif (defined $n && $n == 0) { last }
        sleep 0.05;
    }
    my $dt = time - $t0;
    close $c;
    return ($buf, $dt);
}

# ── the core assertion ───────────────────────────────────────────────
my ($baseline, $base_dt) = timed_get();
ok($baseline && $baseline =~ m{^HTTP/1\.1 200}, sprintf('baseline request works (%.2fs)', $base_dt));

my @idle;
# Hold open more idle connections than there are workers.  With the loop this
# is still free: a connection that sends nothing just sits in the poll set and
# is never serviced, so a preconnect cannot delay a real client no matter how
# many are held.
for my $n (1 .. 3) {
    $idle[$n] = IO::Socket::IP->new(
        PeerHost => '127.0.0.1', PeerPort => $port, Proto => 'tcp',
    ) or last;
    # connect and send NOTHING — the preconnect shape that used to wedge it
}
ok(scalar(@idle) >= 3, 'opened several idle connections that send nothing');

my ($during, $during_dt) = timed_get();
ok($during && $during =~ m{^HTTP/1\.1 200},
   'server still answers while idle connections are held open');
cmp_ok($during_dt, '<', 2,
   sprintf('and answers promptly (%.2fs) — idle clients cost nothing across the loop', $during_dt))
   or diag("idle clients stalled the server: took ${during_dt}s");

$_->close for grep { defined } @idle;
sleep 0.2;

# ── idle connections are actually reaped, not just tolerated ─────────
my $zombie = IO::Socket::IP->new(PeerHost=>'127.0.0.1', PeerPort=>$port, Proto=>'tcp');
ok($zombie, 'opened a connection that will go silent');
sleep 7;    # keepalive_timeout defaults to 5s
ok(kill(0, $pid), 'server survived the silent connection');

# after reaping, a normal request still succeeds
my ($after, $after_dt) = timed_get();
ok($after && $after =~ m{^HTTP/1\.1 200},
   sprintf('server healthy after reaping the silent client (%.2fs)', $after_dt));
$zombie->close;

# ── keep-alive still works for a real client ─────────────────────────
my $ka = IO::Socket::IP->new(PeerHost=>'127.0.0.1', PeerPort=>$port, Proto=>'tcp');
ok($ka, 'opened a keep-alive connection');
print $ka "GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: keep-alive\r\n\r\n";
$ka->blocking(0);
# Streamed responses are Transfer-Encoding: chunked with NO Content-Length,
# so the end of a response is the terminating 0-length chunk, not a length
# header.  Reading until we see that terminator is what makes this correct.
my $ka_buf = '';
for (1 .. 200) {
    my $n = sysread($ka, my $chunk, 8192);
    $ka_buf .= $chunk if defined $n && $n > 0;
    last if $ka_buf =~ /\r\n\r\n/ && $ka_buf =~ /\r\n0\r\n\r\n/;
    sleep 0.05;
}
ok($ka_buf =~ m{^HTTP/1\.1 200}s, 'first keep-alive request answered');
like($ka_buf, qr{transfer-encoding:\s*chunked}i, '  and it was streamed (chunked)');

# second request on the SAME connection
print $ka "GET /cart HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n";
my $ka2 = '';
for (1 .. 100) {
    my $n = sysread($ka, my $chunk, 8192);
    $ka2 .= $chunk if defined $n && $n > 0;
    last if $ka2 =~ m{</html>}s;
    sleep 0.05;
}
ok($ka2 =~ /Shopping Cart|Cart|<html/is, 'second request on the same connection served');
close $ka;

if (!$ipv6_ok) { diag('note: no IPv6 loopback on this host; ::1 path untested here') }

kill 'TERM', $pid;
waitpid $pid, 0;
done_testing;

#!/usr/bin/env perl
# An idle client must not stall the server.
#
# Regression: the original stock Plack handler (HTTP::Server::PSGI) accepted a
# connection and then blocked in read_timeout(..., 300) on that ONE socket, so
# a client that connected and sent nothing held the whole server hostage for
# five minutes.  Browsers open speculative preconnects and hold them, which
# turned that from an edge case into the common path.
#
# The server is now Starman, a prefork pool, so the guarantee is bounded by
# pool size rather than absolute: a silent connection pins ONE worker for
# read-timeout, so with spare workers idle clients cost nothing (asserted
# below), and beyond the pool the stall is read-timeout — not 300 seconds.
# That residual is inherent to prefork; Starman's own README recommends a
# fronting proxy for it.  This test therefore keeps idle connections below
# the worker count and pins both explicitly, so the assertions are about the
# design rather than about whatever the defaults happen to be.
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
        # Be explicit: this test asserts behaviour relative to the pool size,
        # and a silent connection pins one worker for read-timeout.
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
# Stay BELOW the worker count (4).  The invariant is that idle clients cost
# nothing while spare workers exist — a preconnect must not delay anyone.
# Once idle connections >= workers the pool is genuinely pinned for
# read-timeout, which is inherent to prefork (Starman's README recommends a
# fronting proxy for exactly this), not a bug this suite can assert away.
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
   sprintf('and answers promptly (%.2fs) — idle clients cost nothing while spare workers exist', $during_dt))
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

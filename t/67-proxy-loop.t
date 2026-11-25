#!/usr/bin/env perl
# Unit test for the proxy's reactor (proxy-plan §5.4): one IO::Poll dispatch,
# non-blocking accept/read/write, bounded per-connection buffers, and
# *structural* backpressure — crossing the output high mark stops polling the
# socket for reads, draining below the low mark resumes it.
#
# This drives Amin::Net::Loop a tick at a time against a real loopback pair;
# nothing here needs a config or the front.
use v5.38; use warnings; use utf8;
use Test2::V0;
use IO::Socket::INET;
use IO::Poll qw(POLLIN);
use Scalar::Util qw(refaddr);
use Time::HiRes qw(time sleep);
use lib 'perl-lib';

use Amin::Net::Loop;
use constant { OUT_HIGH => 1 << 20, OUT_LOW => 1 << 17 };


# A small high/low pair makes the marks easy to cross without moving megabytes.
sub mk_loop () { Amin::Net::Loop->new(out_high => 4096, out_low => 1024) }

# Bind on an ephemeral port and return ($loop, $listener_sock, $port).
sub mk_listener ($loop) {
    my $sock = Amin::Net::Loop->listen(listen => '127.0.0.1:0');
    my $port = $sock->sockport;
    return ($sock, $port);
}

sub dial ($port) {
    my $c = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp',
    ) or die "client connect: $!";
    $c->blocking(0);
    return $c;
}

# Tick until the loop owns at least one connection (the accept happened).
sub accept_one ($loop, $tries = 100) {
    for (1 .. $tries) {
        $loop->tick(20);
        my @c = values %{ $loop->conns };
        return $c[0] if @c;
    }
    return undef;
}

# Read from $s (non-blocking) until the loop has flushed every queued byte.
# Returns the bytes gathered.  Drives the loop between reads.
sub drain ($loop, $s, $want, $timeout = 5) {
    my $got  = '';
    my $end  = time + $timeout;
    while (length($got) < $want && time < $end) {
        $loop->tick(20);
        while (1) {
            my $n = sysread($s, my $buf, 65536);
            last if !defined $n || $n == 0;
            $got .= $buf;
        }
    }
    return $got;
}

# ── accept ──────────────────────────────────────────────────────────────────

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    my ($accepted, @cb);
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {
        push @cb, [$conn, $l];
    });
    my $client = dial($port);
    my $conn = accept_one($loop);
    ok $conn, 'the loop accepted the client connection';
    is scalar(@cb), 1, 'on_accept fired exactly once';
    is refaddr($cb[0][1]), refaddr($loop), 'on_accept received the loop as second argument';
    ok $conn->fd >= 0, 'the connection has a live descriptor';
    close $client;
}

# ── read: bytes reach on_read, and take() pulls exactly what was parsed ──────

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    my $seen;
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {
        $conn->on(on_read => sub ($c) { $seen .= $c->take(5) });
    });
    my $client = dial($port);
    my $conn = accept_one($loop);
    syswrite($client, 'hello');
    $loop->tick(50);
    is $seen, 'hello', 'on_read saw the five bytes and take(5) consumed them';
    is $conn->in, '', 'the read buffer is empty after the consumption';
    close $client;
}

# ── write: queue() + POLLOUT flush, delivered whole ─────────────────────────

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {});
    my $client = dial($port);
    my $conn = accept_one($loop);
    $conn->write("world\n");
    my $got = drain($loop, $client, 6);
    is $got, "world\n", 'queued bytes were flushed to the peer intact';
    close $client;
}

# ── backpressure: high mark pauses reads, low mark resumes them ─────────────

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {});
    my $client = dial($port);
    my $conn = accept_one($loop);

    ok $conn->{want_in}, 'reads are polled before any queueing';

    my $blob = 'x' x 65536;             # 64 KiB, well past the 4 KiB high mark
    $conn->write($blob);

    is $conn->{paused},  1, 'crossing the high mark paused the connection';
    is $conn->{want_in}, 0, 'a paused connection stops polling for reads';
    is $conn->{want_out}, 1, 'a paused connection keeps polling for writes';

    my $got = drain($loop, $client, length($blob));
    is length($got), length($blob), 'the whole overflow was delivered';
    is $got, $blob, 'and delivered byte-for-byte';

    # One more tick lets the flush observe the empty queue and resume reads.
    $loop->tick(20);
    is $conn->{paused},  0, 'draining below the low mark resumed the connection';
    is $conn->{want_in}, 1, 'and reads are polled again';
    close $client;
}

# ── soft close: pending output is flushed before the descriptor is reaped ───

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    my ($closed, $drained);
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {
        $conn->on(on_close => sub { $closed = 1 }, on_drain => sub { $drained = 1 });
    });
    my $client = dial($port);
    my $conn = accept_one($loop);
    $conn->write("linger\n");
    $conn->close;                       # soft: there are queued bytes
    ok $conn->closed, 'a soft close on a non-empty queue marks the conn closing';
    ok !$conn->{reaped}, 'but does not reap it yet';

    my $got = drain($loop, $client, 7);
    is $got, "linger\n", 'the pending bytes still reached the peer';
    $loop->tick(20);
    ok $conn->{reaped}, 'the connection was reaped once the queue drained';
    ok $closed, 'on_close ran';
    close $client;
}

# ── hard close: reaped immediately, queued bytes dropped ────────────────────

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {});
    my $client = dial($port);
    my $conn = accept_one($loop);
    $conn->write('discarded');
    $conn->close(hard => 1);
    ok $conn->{reaped}, 'a hard close reaps the connection at once';
    is scalar(keys %{ $loop->conns }), 0, 'and removes it from the loop';
    close $client;
}

# ── EOF: the peer closing is observed as on_eof ─────────────────────────────

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    my $eof;
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {
        $conn->on(on_eof => sub { $eof = 1 });
    });
    my $client = dial($port);
    my $conn = accept_one($loop);
    close $client;
    for (1 .. 50) { last if $eof; $loop->tick(20) }
    ok $eof, 'on_eof fired when the peer closed';
}

# ── gated connds: the loop hands raw events to the owner, does no I/O ────────

{
    my $loop = mk_loop;
    my ($lsock, $port) = mk_listener($loop);
    my ($ready, $saw_read, $saw_in);
    $loop->add_listener($lsock, on_accept => sub ($conn, $l) {
        $conn->on(on_read => sub { $saw_read = 1 });
        $conn->gate(sub ($c, $rev) { ($ready, $saw_in) = (1, ($rev & POLLIN) ? 1 : 0) });
    });
    my $client = dial($port);
    my $conn = accept_one($loop);
    ok $conn->{gated}, 'the connection is gated';

    syswrite($client, 'owned');
    # Wait for the readable bit itself: a writable/-out event can fire first
    # (the gate is re-armed with the connection's full mask), so stopping at
    # the first event would race the platform's poll ordering.
    for (1 .. 50) { last if $saw_in; $loop->tick(20) }

    ok $ready, 'the owner callback received the poll event';
    ok $saw_in, 'the event carried the readable bit';
    ok !$saw_read, 'the loop did not read the bytes itself while gated';
    is $conn->in, '', 'no bytes were consumed into the buffer while gated';

    $conn->ungate;
    ok !$conn->{gated}, 'ungate clears the gate';
    $loop->tick(20);
    ok $saw_read, 'once ungated the loop reads normally again';
    is $conn->take, 'owned', 'and the held bytes are here to be parsed';
    close $client;
}

# ── thresholds: the default marks are the documented ones ───────────────────

{
    my $loop = Amin::Net::Loop->new;
    is $loop->{out_high}, OUT_HIGH, 'default output high mark is 1 MiB';
    is $loop->{out_low},  OUT_LOW,  'default output low mark is 128 KiB';
}

done_testing;

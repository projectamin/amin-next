package Amin::Net::Loop;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use IO::Poll qw(POLLIN POLLOUT POLLHUP POLLERR POLLNVAL);
use IO::Socket::INET;
use IO::Socket::IP;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Socket qw(getaddrinfo getnameinfo SOCK_STREAM IPPROTO_TCP AI_PASSIVE
              AF_INET AF_INET6 NI_NUMERICHOST);

# The proxy's event loop (proxy-plan §5.4): one process, IO::Poll (epoll on
# Linux), non-blocking sockets, bounded per-connection buffers.  Core Perl
# only — no CPAN event loop — because the whole module is one poll() dispatch
# and a socket may never block the others sharing it.
#
# Multicore is N processes, each with its own loop, sharing the listen socket
# via SO_REUSEPORT (`--workers`), not a prefork worker per in-flight request:
# a proxy's job is multiplexing many partially-idle client↔backend pairs.
#
# Backpressure is structural, not advisory.  Each connection has a queued
# output ceiling; past it the loop stops polling that socket for reads, so a
# slow peer stalls *its* producer instead of growing the queue without bound.
use constant {
    OUT_HIGH   => 1 << 20,   # 1 MiB   — pause reads above this
    OUT_LOW    => 1 << 17,   # 128 KiB — resume reads once drained below this
    READ_CHUNK => 1 << 16,   # 64 KiB  per sysread
};

sub new ($class, %o) {
    return bless {
        poll      => IO::Poll->new,
        conns     => {},          # fileno => Amin::Net::Loop::Conn
        listeners => {},          # fileno => { sock, on_accept }
        stop      => 0,
        out_high  => $o{out_high} // OUT_HIGH,
        out_low   => $o{out_low}  // OUT_LOW,
    }, $class;
}

# ── Listeners ───────────────────────────────────────────────────────────────

# Bind a non-blocking listening socket.  SO_REUSEPORT is requested so N
# processes can each run a loop against the same address; where the platform
# lacks it, fall back to a plain listen (one worker) rather than fail.
sub listen ($class, %o) {
    my $listen = $o{listen} // die "Amin::Net::Loop->listen needs listen => host:port\n";
    my ($host, $port) = $listen =~ /^(.*?):(\d+)$/
        or die "Amin::Net::Loop: listen must be host:port (got '$listen')\n";
    my $sock = IO::Socket::INET->new(
        LocalAddr => $host,
        LocalPort => $port,
        Proto     => 'tcp',
        Listen    => $o{backlog} // 128,
        ReuseAddr => 1,
    ) or die "Amin::Net::Loop: listen $listen: $!\n";
    _set_reuseport($sock);
    _nonblock($sock);
    return $sock;
}

# Bind every address a symbolic host resolves to.  `localhost` resolves to
# both ::1 and 127.0.0.1, and a browser tries ::1 first — so a v4-only listener
# stalls it.  Binding one socket per address family is what keeps the loopback
# usable from either resolution order.  Returns the listening sockets; the
# caller adds them all to one loop (one loop, several listen fds).
sub bind ($class, %o) {
    my $listen = $o{listen} // die "Amin::Net::Loop->bind needs listen => host:port\n";
    my ($host, $port) = $class->_split_listen($listen)
        or die "Amin::Net::Loop: listen must be host:port (got '$listen')\n";
    my $backlog = $o{backlog} // 128;

    my ($err, @res) = getaddrinfo($host, $port, { socktype => SOCK_STREAM });
    die "Amin::Net::Loop: cannot resolve '$host': " . Socket::gai_strerror($err) . "\n"
        if $err;

    my (@socks, %family);
    for my $r (@res) {
        next if $family{ $r->{family} }++;    # one socket per family
        # getnameinfo returns ($err, $host, $service); we want the numeric host.
        my (undef, $numhost) = getnameinfo($r->{addr}, NI_NUMERICHOST);
        my %args = (
            LocalAddr => $numhost,
            LocalPort => $port,
            Family    => $r->{family},
            Type      => SOCK_STREAM,
            Proto     => 'tcp',
            Listen    => $backlog,
            ReuseAddr => 1,
        );
        # SO_REUSEPORT must be requested at bind time, not afterwards: a
        # worker that binds first would otherwise own the address and the
        # rest would fail.  Older IO::Socket::IP has no ReusePort option, so
        # fall back to a plain single-listener bind there.
        my $sock = eval { IO::Socket::IP->new(%args, ReusePort => 1) }
            // IO::Socket::IP->new(%args)
            or next;
        _set_reuseport($sock);
        _nonblock($sock);
        push @socks, $sock;
    }
    die "Amin::Net::Loop: cannot bind $listen: $!\n" unless @socks;
    return @socks;
}

sub _split_listen ($class, $listen) {
    return ($1, $2) if $listen =~ /^\[(.+)\]:(\d+)$/;   # [::1]:8787
    return ($1, $2) if $listen =~ /^(.+):(\d+)$/;        # host:port
    return;
}

sub add_listener ($self, $sock, %cb) {
    my $fd = fileno $sock;
    $self->{listeners}{$fd} = { sock => $sock, on_accept => $cb{on_accept} };
    $self->{poll}->mask($sock, POLLIN);
    return $fd;
}

# ── Connections ─────────────────────────────────────────────────────────────

sub add_conn ($self, $conn) {
    $self->{conns}{ $conn->fd } = $conn;
    $self->{poll}->mask($conn->sock, $self->_events($conn));
    return $conn;
}

sub conns ($self) { $self->{conns} }
sub stop  ($self) { $self->{stop} = 1 }

# One poll() dispatch.  Returns the number of ready handles.  Tests drive the
# loop a tick at a time; run() is the production wrapper.
#
# IO::Poll::poll() takes its timeout in *seconds* (it scales to the millisecond
# poll(2) argument itself).  Our API — and the plan — speak milliseconds, so the
# conversion lives here; passing 1000 straight through would sleep a kilosecond.
sub tick ($self, $timeout_ms = 1000) {
    my $n = $self->{poll}->poll($timeout_ms / 1000);
    return 0 unless $n;
    for my $h ($self->{poll}->handles) {
        my $fd = fileno $h;
        my $revents = $self->{poll}->events($h);
        if ($self->{listeners}{$fd}) { $self->_accept($fd); next }
        my $conn = $self->{conns}{$fd} or next;
        $self->_service($conn, $revents);
    }
    return $n;
}

sub run ($self, %o) {
    my $timeout = $o{timeout} // 1000;
    my $until   = $o{until};
    my $on_tick = $o{on_tick};
    until ($self->{stop}) {
        $self->tick($timeout);
        $on_tick->($self) if $on_tick;
        last if $until && $until->($self);
    }
    return;
}

# ── Internals ───────────────────────────────────────────────────────────────

sub _accept ($self, $fd) {
    my $l = $self->{listeners}{$fd} or return;
    while (defined(my $peer = $l->{sock}->accept)) {
        _nonblock($peer);
        my $conn = Amin::Net::Loop::Conn->_new($self, $peer);
        $self->add_conn($conn);
        $l->{on_accept}->($conn, $self) if $l->{on_accept};
    }
    return;
}

sub _service ($self, $conn, $revents) {
    return if $conn->{reaped};
    # A gated connection is owned by its own state machine (TLS handshake,
    # non-blocking connect): normal read/flush would consume the very bytes the
    # state machine must see, so it is handed the poll events and nothing else.
    if ($conn->{gated}) {
        $conn->{on_ready}->($conn, $revents) if $conn->{on_ready};
        return;
    }
    if ($revents & (POLLERR | POLLNVAL)) { $self->_reap($conn); return }
    $self->_flush($conn) if $revents & POLLOUT;
    return if $conn->{reaped};
    $self->_read($conn)  if $revents & POLLIN;
    return if $conn->{reaped};
    if ($revents & POLLHUP) {
        $conn->{eof} = 1;
        $conn->{on_eof}->($conn) if $conn->{on_eof};
        $self->_reap($conn) if !$conn->{reaped} && !length($conn->{out});
    }
    return;
}

sub _read ($self, $conn) {
    my $n = sysread($conn->{sock}, my $buf, READ_CHUNK);
    if (!defined $n) {
        return if _would_block();
        $self->_reap($conn);
        return;
    }
    if ($n == 0) {
        $conn->{eof} = 1;
        $conn->{on_eof}->($conn) if $conn->{on_eof};
        $self->_reap($conn) if !$conn->{reaped} && !length($conn->{out});
        return;
    }
    $conn->{in} .= $buf;
    $conn->{on_read}->($conn) if $conn->{on_read};
    return;
}

sub _flush ($self, $conn) {
    while (length $conn->{out}) {
        my $n = syswrite($conn->{sock}, $conn->{out});
        if (!defined $n) {
            return if _would_block();
            $self->_reap($conn);
            return;
        }
        substr($conn->{out}, 0, $n, '');
    }
    $conn->{want_out} = 0;
    if ($conn->{paused} && length($conn->{out}) <= $self->{out_low}) {
        $conn->{paused}   = 0;
        $conn->{want_in}  = 1;
    }
    if ($conn->{closing} eq 'flush') { $self->_reap($conn); return }
    $self->{poll}->mask($conn->{sock}, $self->_events($conn));
    $conn->{on_drain}->($conn) if $conn->{on_drain};
    return;
}

# Queue bytes for sending.  Crossing the high mark pauses reads (backpressure);
# draining below the low mark resumes them.
sub queue ($self, $conn, $bytes) {
    return if $conn->{reaped} || !length $bytes;
    $conn->{out} .= $bytes;
    $conn->{want_out} = 1;
    if ($conn->{want_in} && length($conn->{out}) > $self->{out_high}) {
        $conn->{paused}  = 1;
        $conn->{want_in} = 0;
    }
    $self->{poll}->mask($conn->{sock}, $self->_events($conn));
    return;
}

sub close_conn ($self, $conn, %o) {
    return if $conn->{reaped};
    if (!$o{hard} && length $conn->{out}) {
        $conn->{closing} = 'flush';
        $conn->{want_in} = 0;
        $self->{poll}->mask($conn->{sock}, $self->_events($conn));
        return;
    }
    $self->_reap($conn);
    return;
}

sub _reap ($self, $conn) {
    return if $conn->{reaped};
    $conn->{reaped} = 1;
    $self->{poll}->remove($conn->{sock});
    delete $self->{conns}{ $conn->{fd} };
    close $conn->{sock};
    $conn->{on_close}->($conn) if $conn->{on_close};
    return;
}

sub _events ($self, $conn) {
    my $e = 0;
    $e |= POLLIN  if $conn->{want_in};
    $e |= POLLOUT if $conn->{want_out};
    return $e;
}

sub _would_block () {
    return $!{EAGAIN} || $!{EWOULDBLOCK} || $!{EINTR};
}

sub _nonblock ($fh) {
    my $fl = fcntl($fh, F_GETFL, 0) // return 0;
    return fcntl($fh, F_SETFL, $fl | O_NONBLOCK) ? 1 : 0;
}

sub _set_reuseport ($sock) {
    my $so_reuseport = eval { Socket::SO_REUSEPORT() };
    return 0 unless defined $so_reuseport;
    return setsockopt($sock, Socket::SOL_SOCKET(), $so_reuseport, pack('i', 1)) ? 1 : 0;
}

# ── A connection ────────────────────────────────────────────────────────────
package Amin::Net::Loop::Conn;
use v5.38; use warnings; use experimental 'signatures';

sub _new ($class, $loop, $sock) {
    return bless {
        loop => $loop, sock => $sock, fd => fileno($sock),
        in => '', out => '',
        want_in => 1, want_out => 0, paused => 0, eof => 0,
        closing => '', reaped => 0, gated => 0,
        on_read => undef, on_eof => undef, on_close => undef, on_drain => undef,
        on_ready => undef,
        data => {},
    }, $class;
}

sub loop ($self) { $self->{loop} }
sub sock ($self) { $self->{sock} }
sub fd   ($self) { $self->{fd} }
sub data ($self) { $self->{data} }
sub in   ($self) { $self->{in} }

# Consume the read buffer.  Callers pull exactly the bytes they parsed so a
# partial HTTP request stays in the buffer across reads.
sub take ($self, $n = undef) {
    if (defined $n) { return substr($self->{in}, 0, $n, '') }
    my $b = $self->{in};
    $self->{in} = '';
    return $b;
}

sub on ($self, %cb) {
    $self->{$_} = $cb{$_} for keys %cb;
    return $self;
}

# Detach the handle from the poller without closing it.  IO::Poll keys handles
# by their *stringified* form ("IO::Socket::INET=GLOB(0x..)"), and a TLS upgrade
# re-blesses the very same glob into IO::Socket::SSL ("IO::Socket::SSL=GLOB(..)")
# — so an entry masked under the old name can never be found again to remove it,
# leaving a stale handle in the poll set.  Drop it under the old name first.
sub unpoll ($self) {
    $self->{loop}->{poll}->remove($self->{sock});
    return $self;
}

# Swap the underlying handle without changing the fd (used when a plain
# accepted socket is upgraded to IO::Socket::SSL — same descriptor, TLS
# semantics).  Poll interest is re-masked against the new handle.
sub swap_sock ($self, $sock) {
    $self->{sock} = $sock;
    $self->{fd}   = fileno($sock);
    $self->{loop}->{poll}->mask($sock, $self->{loop}->_events($self));
    return $self;
}

# Gate the connection to a private state machine.  Until ungate(), the loop
# hands poll events to the callback and does no read/flush of its own; both
# directions are watched so a handshake can progress on either.
sub gate ($self, $cb) {
    $self->{gated}    = 1;
    $self->{on_ready} = $cb;
    $self->{want_in}  = 1;
    $self->{want_out} = 1;
    $self->{loop}->{poll}->mask($self->{sock}, $self->loop->_events($self));
    return $self;
}

sub ungate ($self) {
    $self->{gated}    = 0;
    $self->{on_ready} = undef;
    $self->{want_out} = 0;
    $self->{loop}->{poll}->mask($self->{sock}, $self->loop->_events($self));
    return $self;
}

sub want_in  ($self, $v = undef) {
    $self->{want_in} = $v ? 1 : 0 if defined $v;
    $self->{loop}->{poll}->mask($self->{sock}, $self->loop->_events($self));
    return $self->{want_in};
}

sub write ($self, $bytes) { $self->{loop}->queue($self, $bytes); return }
sub close ($self, %o)     { $self->{loop}->close_conn($self, %o); return }
sub closed ($self)        { $self->{reaped} || $self->{closing} ? 1 : 0 }
sub eof ($self)           { $self->{eof} }

1;

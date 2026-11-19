package Amin::Proxy::HTTP;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Socket qw(getaddrinfo SOCK_STREAM IPPROTO_TCP SOL_SOCKET SO_ERROR);
use Errno  qw(EINPROGRESS EWOULDBLOCK);
use Time::HiRes ();

use Amin qw(NS);
use Amin::Net::HTTP;
use Amin::Net::Loop;
use Amin::Proxy::Backend;
use Amin::Machine::Dispatcher;
use Amin::Log::Standard;

# The HTTP/1.1 front (proxy-plan §3/§5).  It is an *adapter*, exactly as
# Amin::AXA::HTTP is: it speaks a transport on one side and feeds the one
# chain on the other.  What differs is the far side — where the AXA origin
# answers from render filters, this answers from a backend the chain selected.
#
# Per request:
#   1. parse the request line + headers into <amin:request>;
#   2. run the same chain that would authorize the profile over stdin (§5.11)
#      — ZCap and any permanent filter run first, Proxy::Route splices in below
#      them as a begin candidate (§5.2);
#   3. read the <proxy:backend> decision elements the routing filter emitted;
#   4. pick one via p2c_ewma and open the backend hop;
#   5. pump bytes both ways, stripping hop-by-hop headers and appending
#      X-Forwarded-* — never touching the caller authority material (§5.12).
#
# The front is authority-free: it does not mint or widen authority and it never
# decides authorization.  A permanent filter that denies the request yields a
# 4xx here (§5.7) long before any backend is contacted.

# Closed hop-by-hop set (RFC 9110 §7.6.1) — the connection, not the message.
# Transfer-Encoding is deliberately NOT stripped: the body's framing is
# forwarded verbatim, and de-chunking would require buffering the whole body
# (§9 forbids full-body buffering).
my %HOP_BY_HOP = map { $_ => 1 } qw(
    connection keep-alive proxy-authenticate proxy-authorization
    proxy-connection te trailer upgrade
);

sub new ($class, %o) {
    # NB: `config => $o{config} // die "..."` would be wrong — `die` is a list
    # operator and would swallow the following `spec`/`log`/… hash pairs as its
    # own argument list, silently truncating the constructor.  Hoist it.
    my $config = $o{config}
        // die "Amin::Proxy::HTTP needs config =>\n";
    my $self = bless {
        config => $config,
        spec   => $o{spec},
        log    => $o{log} // Amin::Log::Standard->new(stderr => 1),
        loop   => $o{loop},
        done   => 0,
        tls    => undef,
    }, $class;
    $self->{balancer} = Amin::Proxy::Backend::Pool->new(
        config => $config,
        ($o{rand} ? (rand => $o{rand}) : ()),
    );
    $self->_configure_tls;
    return $self;
}

sub config   ($self) { $self->{config} }
sub loop     ($self) { $self->{loop} //= Amin::Net::Loop->new }
sub balancer ($self) { $self->{balancer} }
sub log      ($self) { $self->{log} }
sub tls      ($self) { $self->{tls} }
sub bound    ($self) { $self->{bound} }

sub _configure_tls ($self) {
    my $tls = $self->{config}->tls;
    return unless defined $tls && length $tls && $tls ne 'off';
    my $cert = $self->{config}->cert;
    my $key  = $self->{config}->key;
    die "proxy: tls=$tls but cert= is unset\n" unless defined $cert && length $cert;
    die "proxy: tls=$tls but key= is unset\n"  unless defined $key  && length $key;
    die "proxy: tls cert not found: $cert\n" unless -f $cert;
    die "proxy: tls key not found: $key\n"   unless -f $key;
    $self->{tls} = { cert => $cert, key => $key };
    return;
}

# ── Serving ─────────────────────────────────────────────────────────────────

# Bind and run.  workers > 1 forks N processes, each with its own loop and
# bound to the same address through SO_REUSEPORT (§5.4) — a proxy multiplexes
# many partially-idle pairs, so the unit of parallelism is the loop, not a
# worker pinned per request.
sub serve ($self, %o) {
    my $listen  = $o{listen}  // $self->{config}->listen // 'localhost:8787';
    my $workers = $o{workers} // 1;
    $self->{listen} = $listen;

    if ($workers > 1) {
        my @kids;
        for (1 .. $workers) {
            my $pid = fork // die "proxy: fork: $!";
            if ($pid == 0) { $self->_serve_once($listen, %o); exit 0 }
            push @kids, $pid;
        }
        local $SIG{TERM} = sub { kill 'TERM', @kids };
        local $SIG{INT}  = sub { kill 'TERM', @kids };
        waitpid $_, 0 for @kids;
        return;
    }
    return $self->_serve_once($listen, %o);
}

sub _serve_once ($self, $listen, %o) {
    my $loop = $self->loop;
    my $sock = Amin::Net::Loop->listen(listen => $listen);
    $self->{bound} = $sock->sockport;
    $loop->add_listener($sock, on_accept => sub ($conn, $l) { $self->_accept($conn) });

    local $SIG{TERM} = sub { $loop->stop };
    local $SIG{INT}  = sub { $loop->stop };
    $loop->run(
        timeout => $o{timeout} // 1000,
        until   => sub { ($o{once} // 0) && $self->{done} ? 1 : 0 },
    );
    return;
}

sub stop ($self) { $self->{stop} = 1; $self->{loop} && $self->{loop}->stop }

# ── Accept / TLS ────────────────────────────────────────────────────────────

sub _accept ($self, $conn) {
    my $peer = eval { $conn->sock->peerhost } // '0.0.0.0';
    $conn->{data} = {
        phase => 'headers', peer => $peer, scheme => 'http',
        req => undef, up => undef, rt => undef, route => undef,
    };
    if ($self->{tls}) {
        $conn->{data}{scheme} = 'https';
        return $self->_tls_handshake($conn);
    }
    $self->_client_ready($conn);
    return;
}

# TLS termination in-process (§5.5).  The handshake is driven by the loop, not
# by a blocking accept: the plain socket is upgraded to IO::Socket::SSL and the
# connection is gated to a one-step-per-event handshake so a slow client cannot
# stall the other sockets.
sub _tls_handshake ($self, $conn) {
    require IO::Socket::SSL;
    # Detach the plain socket from the poller *before* start_SSL re-blesses it
    # into IO::Socket::SSL: IO::Poll keys handles by their stringified form,
    # which the re-bless changes (Loop::Conn::unpoll documents this).
    $conn->unpoll;
    my $ssl = IO::Socket::SSL->start_SSL($conn->sock,
        SSL_server         => 1,
        SSL_startHandshake => 0,
        SSL_cert_file      => $self->{tls}{cert},
        SSL_key_file       => $self->{tls}{key},
    ) or do {
        $self->{log}->warn('proxy: TLS setup failed: ' . IO::Socket::SSL::errstr());
        $conn->close(hard => 1);
        return;
    };
    $conn->swap_sock($ssl);
    $conn->gate(sub ($c, $rev) {
        # accept_SSL's non-blocking contract: truthy = handshake complete,
        # undef = the handshake needs more I/O (SSL_WANT_READ/SSL_WANT_WRITE —
        # both directions are watched, so just wait for the next event), die =
        # a fatal handshake error.  There is no portable SSL_ERROR accessor to
        # read the want-flag, so the return/die split is the whole contract.
        my $ok  = eval { $c->sock->accept_SSL };
        my $err = $@;
        unless ($ok) {
            if ($err) {
                $err =~ s/\s+\z//;
                $self->{log}->warn("proxy: TLS handshake failed: $err");
                $c->close(hard => 1);
            }
            return;
        }
        $c->ungate;
        $self->_client_ready($c);
    });
    return;
}

sub _client_ready ($self, $conn) {
    $conn->{data}{phase} = 'headers';
    $conn->on(
        on_read => sub ($c) { $self->_client_read($c) },
        on_eof  => sub ($c) { $self->_client_eof($c) },
    );
    return;
}

# ── Request parsing ─────────────────────────────────────────────────────────

sub _client_read ($self, $conn) {
    my $phase = $conn->{data}{phase};
    return $self->_read_head($conn)  if $phase eq 'headers';
    return $self->_pump_body($conn)  if $phase eq 'body';
    return;
}

sub _read_head ($self, $conn) {
    my $i = Amin::Net::HTTP::head_end($conn->in);
    return unless $i >= 0;   # incomplete — wait for more
    my $head = substr($conn->in, 0, $i);
    $conn->take($i + 4);

    my ($method, $target, $version, $headers) = Amin::Net::HTTP::parse_request_head($head);
    unless (defined $method) {
        return $self->_fail($conn, 400, 'Bad Request', "malformed request head\n");
    }

    my $host = '';
    for my $h (@$headers) { $host = $h->[1] if lc($h->[0]) eq 'host' }
    my ($authority) = split /\s*,\s*/, $host;
    my $hostname = $authority // '';
    if ($hostname =~ /^\[?([^\]]+?)\]?(?::\d+)?$/) { $hostname = $1 }

    my ($path, $query) = split /\?/, $target, 2;
    $path //= '/';

    my %h;
    for my $h (@$headers) { $h{lc $h->[0]} = $h->[1] }

    $conn->{data}{phase} = 'pending';
    $conn->{data}{req} = {
        method  => $method,
        target  => $target,
        path    => $path,
        query   => $query,
        version => $version,
        headers => $headers,
        host    => $hostname,
        scheme  => $conn->{data}{scheme},
        peer    => $conn->{data}{peer},
        body    => Amin::Net::HTTP::body_plan(\%h),
    };
    $self->_dispatch($conn);
    return;
}

# ── Dispatch: the chain, then the backend ───────────────────────────────────

sub _dispatch ($self, $conn) {
    my $r   = $conn->{data}{req};

    # The per-IP rate limit is a decision, so it lives in the chain, not here:
    # Amin::Proxy::RateLimit is a begin filter that sheds an over-budget request
    # before routing (§P5).  The adapter only maps its rc to a status below.
    my $dec = $self->_run_chain($r);

    my @be = $dec->backends->@*;
    unless (@be) {
        my $st   = $dec->status;
        my $rc   = $st ? $st->{rc} : undef;
        my $code = _rc_to_http($rc);
        my $why  = $st ? ($st->{exit_kind} // 'denied') : 'no_route';
        $self->{log}->warn("proxy: denied $r->{method} $r->{path} ($why)")
            if $code >= 500;
        return $self->_fail($conn, $code, _reason($code), "proxy: no backend ($why)\n");
    }

    my $first = $be[0];
    my @ids   = grep { defined && length } map { $_->{id} } @be;
    my $rt    = $self->balancer->pick(@ids)
        or return $self->_fail($conn, 503, 'Service Unavailable', "proxy: no backend\n");

    $conn->{data}{route} = {
        strip_prefix => ($first->{'strip-prefix'} // 'false') eq 'true' ? 1 : 0,
        ws           => ($first->{ws} // 'off') eq 'on' ? 1 : 0,
    };

    if ($rt->transport ne 'http') {
        # awp3 is P2 (§6).  Until it lands an Amin backend cannot be spoken, and
        # a silent fallback to HTTP would be a lie about the trust boundary.
        my $t = $rt->transport;
        return $self->_fail($conn, 502, 'Bad Gateway',
            "proxy: transport '$t' not available in this build\n");
    }
    my $addr = $rt->addr;
    return $self->_fail($conn, 502, 'Bad Gateway', "proxy: backend has no addr\n")
        unless defined $addr && length $addr;
    my ($bhost, $bport) = $addr =~ /^(.+):(\d+)$/;
    return $self->_fail($conn, 502, 'Bad Gateway', "proxy: bad addr '$addr'\n")
        unless defined $bport;

    my $sock = _tcp_connect($bhost, $bport);
    return $self->_fail($conn, 502, 'Bad Gateway', "proxy: cannot reach $addr\n")
        unless $sock;

    my $loop = $self->loop;
    my $up   = Amin::Net::Loop::Conn->_new($loop, $sock);
    $loop->add_conn($up);
    $up->{data} = {
        phase    => 'connect',
        client   => $conn,
        backend  => $rt->id,
        started  => [ Time::HiRes::gettimeofday() ],
        req_head => $self->_upstream_head($conn->{data}, $rt),
    };
    $conn->{data}{up} = $up;
    $conn->{data}{rt} = $rt;
    $conn->want_in(0);          # stop reading the client until the backend is up
    $up->gate(sub ($u, $rev) { $self->_up_connect($u) });
    return;
}

sub _run_chain ($self, $r) {
    my $attrs = join ' ', map { qq{amin:$_="} . _esc($r->{$_}) . '"' }
        grep { defined $r->{$_} }
        qw(host method path scheme peer);
    my $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
            . '<amin:profile xmlns:amin="' . NS() . '">' . "\n"
            . "  <amin:request $attrs />\n</amin:profile>\n";

    my $dec = Amin::Proxy::HTTP::Decision->new;
    my %spec = defined $self->{spec} ? (machine_spec => $self->{spec}) : ();
    Amin::Machine::Dispatcher->run(
        Handler    => $dec,
        Log        => $self->{log},
        proxy      => $self->{config},
        source_xml => $xml,
        mode       => 'run',
        ui_os      => 'tty',
        %spec,
    );
    return $dec;
}

# The upstream request head: origin-form target, backend authority as Host,
# hop-by-hop headers dropped, X-Forwarded-* appended.  The caller's authority
# material (Authorization, cookies, …) is carried untouched (§5.12).
sub _upstream_head ($self, $d, $rt) {
    my $r = $d->{req};
    my $target = $r->{path};
    if ($d->{route}{strip_prefix}) {
        my $route = $self->{config}->match(host => $r->{host}, path => $r->{path});
        if ($route && length $route->{path} && index($target, $route->{path}) == 0) {
            $target = substr($target, length $route->{path});
            $target = "/$target" unless $target =~ m{^/};
        }
    }
    $target .= "?$r->{query}" if defined $r->{query} && length $r->{query};

    # An upgrade is a CONNECT-like promotion: Connection/Upgrade are hop-by-hop
    # in general, but here they ARE the mechanism, so Upgrade must survive when
    # the route allows ws and the client actually asked to upgrade (§5.8).  The
    # client's Connection header is still dropped — we emit our own below — so
    # exactly one Connection line leaves the front.
    my $upgrade = 0;
    if ($d->{route}{ws}) {
        my %ch;
        for my $h ($r->{headers}->@*) { $ch{ lc $h->[0] } = $h->[1] }
        $upgrade = 1
            if defined $ch{upgrade}
            && defined $ch{connection} && $ch{connection} =~ /\bupgrade\b/i;
    }

    my @prior_xff;
    my @out = ("$r->{method} $target HTTP/1.1", "Host: $rt->{addr}");
    for my $h ($r->{headers}->@*) {
        my ($n, $v) = @$h;
        my $ln = lc $n;
        # Host is the backend authority and is emitted above; the client's own
        # Host must be *replaced*, not duplicated (RFC 9110 §7.2 — exactly one).
        next if $ln eq 'host';
        next if $HOP_BY_HOP{$ln} && !($upgrade && $ln eq 'upgrade');
        if ($ln eq 'x-forwarded-for') { push @prior_xff, $v; next }
        next if $ln eq 'x-forwarded-proto' || $ln eq 'x-forwarded-host';
        push @out, "$n: $v";
    }
    push @out, 'X-Forwarded-For: ' . join(', ', grep { length } @prior_xff, $r->{peer});
    push @out, "X-Forwarded-Proto: $r->{scheme}";
    push @out, "X-Forwarded-Host: $r->{host}";
    push @out, $upgrade ? 'Connection: Upgrade' : 'Connection: close';
    return join("\r\n", @out) . "\r\n\r\n";
}

sub _up_connect ($self, $up) {
    my $raw = getsockopt($up->sock, SOL_SOCKET, SO_ERROR);
    my $err = defined $raw ? unpack('i', $raw) : 1;
    if ($err) {
        $self->balancer->get($up->{data}{backend})->fail;
        my $c = $up->{data}{client};
        $self->_finish($up);
        $self->_fail($c, 502, 'Bad Gateway', "proxy: upstream connect failed\n") if $c;
        return;
    }
    my $d = $up->{data};
    $d->{phase} = 'resp_head';
    $d->{rt}    = $self->balancer->get($d->{backend});
    $d->{rt} && $d->{rt}->begin;
    my $c = $d->{client};

    $up->ungate;
    $up->on(
        on_read => sub ($u) { $self->_up_read($u) },
        on_eof  => sub ($u) { $self->_up_eof($u) },
    );
    $up->write($d->{req_head});

    if ($c->{data}{req}{body}) {
        $c->{data}{phase} = 'body';
        $c->want_in(1);
        $self->_pump_body($c);   # forward any body bytes already buffered
    }
    else {
        $c->{data}{phase} = 'response';
    }
    return;
}

# Stream the client body to the backend as it arrives — accounting only for
# framing; the bytes are never held.
sub _pump_body ($self, $conn) {
    my $d    = $conn->{data};
    my $plan = $d->{req}{body} or return;
    my $up   = $d->{up}        or return;
    my $bytes = $conn->in;
    return unless length $bytes;
    $conn->take(length $bytes);
    $up->write($bytes);

    my $done = ref $plan->{chunked}
        ? $plan->{chunked}->feed($bytes)
        : (($plan->{left} -= length $bytes) <= 0 ? 1 : 0);
    return unless $done;
    $conn->want_in(0);          # body complete — no more client reads
    $d->{phase} = 'response';
    return;
}

sub _up_read ($self, $up) {
    my $d = $up->{data};
    my $c = $d->{client};
    if ($d->{phase} eq 'resp_head') {
        my $i = index($up->in, "\r\n\r\n");
        return unless $i >= 0;
        my $head = substr($up->in, 0, $i);
        $up->take($i + 4);
        my ($code, $reason, $hl) = Amin::Net::HTTP::parse_status_head($head);
        if (!defined $code) {
            $self->_finish($up);
            return $self->_fail($c, 502, 'Bad Gateway', "malformed upstream response\n");
        }
        if ($code == 101 && $c->{data}{route}{ws}) {
            return $self->_splice($c, $up, $head);
        }
        $d->{phase} = 'resp_body';
        $c->write($self->_downstream_head($code, $reason, $hl));
    }
    my $payload = $up->in;
    return unless length $payload;
    $up->take(length $payload);
    $c->write($payload);
    return;
}

sub _up_eof ($self, $up) {
    my $d = $up->{data};
    my $c = $d->{client};
    my $lat = _elapsed($up);
    $d->{rt} && $d->{rt}->done($lat);
    my $payload = $up->in;
    $self->_finish($up);
    if ($c) {
        $c->write($payload) if length $payload;
        $self->_finish($c);
    }
    return;
}

# WebSocket / Upgrade: past a 101 the adapter stops being an HTTP proxy and
# becomes a byte splice between the two sockets (§5.8).
sub _splice ($self, $c, $up, $head) {
    $c->write($head . "\r\n\r\n");
    my $pending = $up->in;
    if (length $pending) { $up->take(length $pending); $c->write($pending) }

    # Reads were suspended while the backend came up; past 101 the client's
    # frames must flow again, so re-arm the client for input.
    $c->want_in(1);
    $c->on(
        on_read => sub ($x) { my $b = $x->take(length $x->in); $up->write($b) if length $b },
        on_eof  => sub { $self->_finish($up); $self->_finish($c) },
    );
    $up->on(
        on_read => sub ($x) { my $b = $x->take(length $x->in); $c->write($b) if length $b },
        on_eof  => sub { $self->_finish($c); $self->_finish($up) },
    );
    return;
}

sub _client_eof ($self, $c) {
    my $phase = $c->{data}{phase};
    if ($phase eq 'headers' || $phase eq 'pending') {
        return $self->_finish($c);
    }
    # Mid-exchange: the backend owns completion.  Stop polling for reads so a
    # half-closed client does not make poll report a permanent EOF.
    $c->want_in(0);
    return;
}

# ── Responses ───────────────────────────────────────────────────────────────

# The downstream response head: hop-by-hop headers dropped, the profile
# fingerprint stamped, the front pinning Connection: close (§5.8/§P5).  The
# X-Amin-Profile-SHA3 line and its position (just before Connection) match the
# Rust front byte for byte, so t/70's two-front comparison holds (§7).
sub _downstream_head ($self, $code, $reason, $hl) {
    my @out = ("HTTP/1.1 $code $reason");
    for my $l ($hl->@*) {
        next if $HOP_BY_HOP{ lc $l->[0] };
        push @out, "$l->[0]: $l->[1]";
    }
    push @out, 'X-Amin-Profile-SHA3: ' . $self->{config}->profile_sha3;
    push @out, 'Connection: close';
    return join("\r\n", @out) . "\r\n\r\n";
}

sub _fail ($self, $conn, $code, $reason, $body = undef) {
    return if !$conn || $conn->closed;
    $body //= "$code $reason\n";
    my $head = "HTTP/1.1 $code $reason\r\n"
             . "Content-Type: text/plain; charset=utf-8\r\n"
             . 'Content-Length: ' . length($body) . "\r\n"
             . "Connection: close\r\n\r\n";
    $conn->want_in(0);
    $conn->write($head . $body);
    $conn->close;    # flush, then reap — the response is still delivered
    return;
}

sub _finish ($self, $conn) {
    return if !$conn || $conn->closed;
    $conn->close;
    $self->{done} = 1;
    return;
}

# ── helpers ─────────────────────────────────────────────────────────────────

sub _elapsed ($conn) {
    my $t = $conn->{data}{started} or return undef;
    return Time::HiRes::tv_interval($t);
}

# rc (the Amin status vocabulary) → HTTP.  A negative rc is a deny: the
# authorization region speaks in the -5xxx band, the routing region in -6xxx,
# and the throttle region in -7xxx (a rate shed → 429).
sub _rc_to_http ($rc) {
    return 503 unless defined $rc && $rc =~ /^-?\d+$/;   # no decision at all
    return 429 if $rc == -7100;                          # rate limited (e.g. §P5)
    return 503 if $rc <= -6100;                          # routing (e.g. -6150)
    return 403 if $rc < 0;                               # auth (e.g. -5121)
    return 500;
}

sub _reason ($code) {
    return {
        400 => 'Bad Request', 403 => 'Forbidden', 404 => 'Not Found',
        405 => 'Method Not Allowed', 413 => 'Payload Too Large',
        429 => 'Too Many Requests',
        500 => 'Internal Server Error', 502 => 'Bad Gateway',
        503 => 'Service Unavailable', 504 => 'Gateway Timeout',
    }->{$code} // 'Error';
}

sub _esc ($s) {
    $s = '' unless defined $s;
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g; $s =~ s/'/&#39;/g;
    return $s;
}

# Non-blocking TCP connect to host:port.  The socket is returned in either the
# connected or in-progress state; the caller gates it and waits for writability.
sub _tcp_connect ($host, $port) {
    my ($err, @res) = getaddrinfo($host, $port, { socktype => SOCK_STREAM });
    return undef if $err;
    for my $r (@res) {
        my $sock;
        socket($sock, $r->{family}, SOCK_STREAM, IPPROTO_TCP) or next;
        my $fl = fcntl($sock, F_GETFL, 0);
        fcntl($sock, F_SETFL, $fl | O_NONBLOCK);
        if (connect($sock, $r->{addr})) { return $sock }        # immediate
        return $sock if $! == EINPROGRESS || $! == EWOULDBLOCK;
        close $sock;
    }
    return undef;
}

1;

# ── The decision collector ──────────────────────────────────────────────────
package Amin::Proxy::HTTP::Decision;
use v5.38; use warnings; use utf8; use experimental 'signatures';

# Captures the adapter-facing decision from the chain: the <proxy:backend>
# elements the routing filter emitted, plus any <amin:status>.  Everything
# else is adapter-invisible and dropped — the front is a pump, not a renderer.
sub new ($class) { return bless { backends => [], status => undef }, $class }

sub backends ($self) { $self->{backends} }
sub status   ($self) { $self->{status} }

sub start_element ($self, $el) {
    my $ln = $el->{LocalName} // $el->{Name} // '';
    my $ns = $el->{NamespaceURI} // '';
    my $a  = _attrs($el);
    if ($ns eq 'http://projectamin.org/ns/proxy/1' && $ln eq 'backend') {
        push $self->{backends}->@*, $a;
    }
    elsif ($ln eq 'status' && defined $a->{rc}) {
        $self->{status} = $a;
    }
    return 1;
}

# Any other handler method a filter may call is adapter-invisible.  Swallow it
# rather than let a render-only event take the whole request down.
sub AUTOLOAD ($self, @a) {
    my $m = our $AUTOLOAD;
    $m =~ s/.*:://;
    return if $m eq 'DESTROY';
    return 1;
}

sub _attrs ($el) {
    my %a;
    for my $k (keys %{ $el->{Attributes} // {} }) {
        my $h = $el->{Attributes}{$k} // {};
        my $n = $h->{LocalName} // $h->{Name} // $k;
        $a{$n} = $h->{Value};
    }
    return \%a;
}

1;

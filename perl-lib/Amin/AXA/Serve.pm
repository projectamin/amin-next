package Amin::AXA::Serve;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Time::HiRes ();

use Amin::Net::Loop;
use Amin::Net::HTTP;
use Amin::AXA::HTTP;
use Amin::AXA::Session;
use Amin::Log::Standard;

# The loop-native AXA origin (axa-plan §4.1/§4.8).  Same shape as
# Amin::Proxy::HTTP's front — one process, one IO::Poll loop, N workers sharing
# the listen socket via SO_REUSEPORT — but where the front pumps to a backend
# the chain selected, this answers from render filters.  It is ONLY transport:
# parse a request, cap and de-chunk the body, hand it to Amin::AXA::HTTP, write
# the response back.  Every decision lives in the core, not here.
#
# It replaces Starman.  A general-purpose prefork server pins one worker per
# in-flight connection (and a SILENT preconnect pins it for the whole read
# timeout); a loop multiplexes many partially-idle connections and costs
# nothing while a client sits silent.  HTTP/1.1 keep-alive and a per-connection
# idle timeout are all this needs to be a real origin (proxy-plan §5.4).
#
# Streaming (§4.8) is the reason to own the loop: the core's render_stream
# commits the status line at the first emitted byte and every element after it
# goes straight out as a chunk, so a page costs O(1) memory and the client
# starts receiving it immediately.  Chunked transfer-coding is therefore the
# default framing here — the response length is not known until the last byte.

use constant BODY_CAP => 262_144;   # 256 KiB — the app-parse ceiling (M2 §5.6)
use constant HEAD_CAP => 65_536;    # request-head ceiling; past it, 431

sub new ($class, %o) {
    # Not `ctx => $o{ctx} // die ...` inline: `die LIST` in a hash constructor
    # eats the following comma-separated entries as its own argument list, so
    # every field after it silently vanishes.  Bind it first.
    my $ctx = $o{ctx}
        // die "Amin::AXA::Serve needs ctx => Amin::AXA::HTTP->boot(...)\n";
    return bless {
        ctx   => $ctx,
        log    => $o{log} // Amin::Log::Standard->new(stderr => 1),
        stream => exists $o{stream} ? $o{stream} : 1,
        # Poll timeout: how long the loop sleeps when nothing is ready.  Short
        # enough that the idle sweep runs promptly, long enough not to spin.
        timeout           => $o{timeout}           // 250,
        # A silent connection before any request (a browser preconnect) is
        # dropped after read_timeout; an idle keep-alive connection after
        # keepalive_timeout.  Both are bounded, so one peer cannot hold a
        # connection forever.
        read_timeout      => $o{read_timeout}      // 2,
        keepalive_timeout => $o{keepalive_timeout} // 5,
        loop  => $o{loop},
        once  => $o{once} // 0,
        stop  => 0,
        done  => 0,
        served => 0,
    }, $class;
}

sub ctx    ($self) { $self->{ctx} }
sub loop   ($self) { $self->{loop} //= Amin::Net::Loop->new }
sub log    ($self) { $self->{log} }
sub bound  ($self) { $self->{bound} }
sub served ($self) { $self->{served} }

sub stop ($self) {
    $self->{stop} = 1;
    $self->{loop} && $self->{loop}->stop;
    return;
}

# ── Serving ─────────────────────────────────────────────────────────────────

# Bind and run.  workers > 1 forks N processes, each with its own loop, sharing
# the listen socket via SO_REUSEPORT — the same model as the proxy front.
sub serve ($self, %o) {
    my $listen  = $o{listen}  // 'localhost:8787';
    my $workers = $o{workers} // 1;
    $self->{listen} = $listen;

    if ($workers > 1) {
        my @kids;
        for (1 .. $workers) {
            my $pid = fork // die "axa: fork: $!\n";
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
    my $loop  = $self->loop;
    my @socks = Amin::Net::Loop->bind(
        listen => $listen,
        ($o{backlog} ? (backlog => $o{backlog}) : ()),
    );
    # One loop, several listen fds: `localhost` binds ::1 and 127.0.0.1 so a
    # browser that resolves v6 first is not stalled (see Amin::Net::Loop->bind).
    for my $sock (@socks) {
        $loop->add_listener($sock, on_accept => sub ($conn, $l) { $self->_accept($conn) });
    }
    $self->{bound} = $socks[0];

    local $SIG{TERM} = sub { $loop->stop };
    local $SIG{INT}  = sub { $loop->stop };
    $loop->run(
        timeout => $self->{timeout},
        on_tick => sub { $self->_sweep },
        until   => sub { $self->{done} ? 1 : 0 },
    );
    return;
}

# ── Accept ──────────────────────────────────────────────────────────────────

sub _accept ($self, $conn) {
    $conn->{data} = {
        phase       => 'headers',
        peer        => eval { $conn->sock->peerhost } // '0.0.0.0',
        idle_at     => Time::HiRes::time(),
        keepalive   => 1,
        close_after => 0,
        served      => 0,
    };
    $conn->on(
        on_read => sub ($c) { $self->_client_read($c) },
        on_eof  => sub ($c) { $self->_client_eof($c) },
    );
    return;
}

# ── Request state machine ───────────────────────────────────────────────────
# phases: headers → body (only when the request declares one) → ready
#         → (dispatch writes the response, then) headers again or closed.

sub _client_read ($self, $conn) {
    return if $conn->closed;
    my $d = $conn->{data};
    $d->{idle_at} = Time::HiRes::time();

    # Loop, not a single pass: one read may complete a request and still hold
    # the first bytes of the next (pipelining), so keep advancing until the
    # buffer is exhausted or a phase needs more input.
    while (!$conn->closed) {
        my $phase = $d->{phase};
        if ($phase eq 'headers') {
            if (length($conn->in) > HEAD_CAP) {
                $self->_fail($conn, 431, 'Request Header Fields Too Large');
                last;
            }
            last unless $self->_read_head($conn);
            next;
        }
        if ($phase eq 'body') {
            last unless $self->_read_body($conn);
            next;
        }
        if ($phase eq 'ready') { $self->_dispatch($conn); next }
        last;
    }
    return;
}

# Parse one request head.  Returns true once the phase has advanced (to `body`
# or `ready`); false while the head is still incomplete.
sub _read_head ($self, $conn) {
    my $i = Amin::Net::HTTP::head_end($conn->in);
    return 0 if $i < 0;                       # incomplete — wait for more
    my $head = substr($conn->in, 0, $i);
    $conn->take($i + 4);

    my ($method, $target, $version, $headers) = Amin::Net::HTTP::parse_request_head($head);
    unless (defined $method) {
        $self->_fail($conn, 400, 'Bad Request', "malformed request head\n");
        return 1;
    }
    my $folded = Amin::Net::HTTP::fold_headers($headers);

    my $host = '';
    for my $h (@$headers) { $host = $h->[1] if lc($h->[0]) eq 'host' }
    my ($authority) = split /\s*,\s*/, $host;
    my $hostname = $authority // '';
    $hostname = $1 if $hostname =~ /^\[?([^\]]+?)\]?(?::\d+)?$/;

    my ($path, $query) = split /\?/, $target, 2;
    $path //= '/';

    my $d = $conn->{data};
    $d->{req} = {
        method  => $method,
        target  => $target,
        path    => $path,
        query   => $query,
        version => $version,
        headers => $headers,
        header  => $folded,
        host    => $hostname,
        scheme  => 'http',
        peer    => $d->{peer},
        body    => '',
        body_overflow => 0,
    };
    $d->{keepalive} = _want_keepalive($version, $folded);

    my $plan = Amin::Net::HTTP::body_plan($folded);
    if ($plan && exists $plan->{left} && $plan->{left} > BODY_CAP) {
        # Declared length over the cap: reject without reading.  The unread
        # body would be misparsed as the next request, so this closes.
        $d->{req}{body_overflow} = 1;
        $d->{keepalive} = 0;
        $d->{phase} = 'ready';
        return 1;
    }
    if ($plan) {
        $d->{plan}  = $plan;
        $d->{phase} = 'body';
    }
    else {
        $d->{phase} = 'ready';
    }
    return 1;
}

# Consume the body the head declared.  Returns true once complete (phase →
# `ready`); false while more bytes are needed.  Length-framed bodies are capped
# as they arrive; chunked bodies are decoded (the cap measures decoded bytes,
# not framing overhead).
sub _read_body ($self, $conn) {
    my $d    = $conn->{data};
    my $plan = $d->{plan} or return 1;
    my $b    = $plan->{state} //= (ref $plan->{chunked}
        ? { mode => 'chunked', rest => '', left => undef }
        : { mode => 'length',  left => $plan->{left} });

    if ($b->{mode} eq 'length') {
        my $have = length $conn->in;
        my $take = $have < $b->{left} ? $have : $b->{left};
        $d->{req}{body} .= $conn->take($take) if $take;
        $b->{left} -= $take;
        if (length($d->{req}{body}) > BODY_CAP) {
            $d->{req}{body_overflow} = 1;
            $d->{keepalive} = 0;
            $d->{phase} = 'ready';
            return 1;
        }
        return 0 if $b->{left} > 0;
        $d->{phase} = 'ready';
        return 1;
    }

    # chunked
    $b->{rest} .= $conn->take(length $conn->in);
    while (1) {
        if (!defined $b->{left}) {
            my $i = index($b->{rest}, "\r\n");
            return 0 if $i < 0;
            my $line = substr($b->{rest}, 0, $i, '');
            substr($b->{rest}, 0, 2, '');
            my ($hex) = $line =~ /^([0-9a-fA-F]+)/;
            return 0 unless defined $hex;
            my $n = hex $hex;
            if ($n == 0) {
                # Consume the CRLF that ends the body; anything after it is a
                # pipelined request, so put it back (trailers are not read).
                substr($b->{rest}, 0, 2, '') if substr($b->{rest}, 0, 2) eq "\r\n";
                $conn->{in} = $b->{rest} . $conn->{in} if length $b->{rest};
                $d->{phase} = 'ready';
                return 1;
            }
            $b->{left} = $n;
        }
        else {
            return 0 if length($b->{rest}) < $b->{left} + 2;
            $d->{req}{body} .= substr($b->{rest}, 0, $b->{left}, '');
            substr($b->{rest}, 0, 2, '');                      # trailing CRLF
            $b->{left} = undef;
            if (length($d->{req}{body}) > BODY_CAP) {
                $d->{req}{body_overflow} = 1;
                $d->{keepalive} = 0;
                $d->{phase} = 'ready';
                return 1;
            }
        }
    }
}

# ── Dispatch ────────────────────────────────────────────────────────────────

sub _dispatch ($self, $conn) {
    my $d   = $conn->{data};
    my $req = $d->{req};

    $d->{served}++;
    $self->{served}++;
    $d->{close_after} = $d->{keepalive} ? 0 : 1;

    my $res = eval { Amin::AXA::HTTP->handle($self->{ctx}, $req, stream => $self->{stream}) };
    if ($@) {
        warn "[axa] handle failed: $@";
        $res = Amin::AXA::HTTP->err(500 => 'internal error');
    }

    if (ref $res eq 'CODE') {
        # Streaming: the core drives the whole body through our responder,
        # committing the status line at the first byte (the latch, §4.8).
        $res->(sub ($triple) { $self->_start_stream($conn, $triple) });
    }
    else {
        $self->_write_buffered($conn, $req, $res);
    }
    return;
}

# The responder for a streaming response.  It commits the header the moment the
# core latches, then hands back a writer the core pushes chunks into.  Framing
# is chunked unless the core pinned an explicit length (the empty-response
# fallback does), because the total size is unknown until the last chunk.
sub _start_stream ($self, $conn, $triple) {
    my ($status, $headers) = ($triple->[0] // 500, $triple->[1] // []);
    my %h;
    for (my $i = 0; $i + 1 < @$headers; $i += 2) { $h{ lc $headers->[$i] } = 1 }
    my $chunked = !(exists $h{'content-length'} || exists $h{'transfer-encoding'});

    my @out = ("HTTP/1.1 $status " . _reason($status));
    push @out, "$headers->[$_]: $headers->[$_ + 1]" for grep { $_ % 2 == 0 } 0 .. $#$headers;
    push @out, 'Transfer-Encoding: chunked' if $chunked;
    push @out, $conn->{data}{close_after} ? 'Connection: close' : 'Connection: keep-alive';
    $conn->write(join("\r\n", @out) . "\r\n\r\n");
    _flush_now($conn);

    return Amin::AXA::Serve::Writer->new($conn, $chunked, sub { $self->_response_done($conn) });
}

sub _write_buffered ($self, $conn, $req, $res) {
    my ($status, $headers, $body) = @$res;
    $body //= '';
    $body = $body->[0] if ref $body eq 'ARRAY';

    my %seen;
    for (my $i = 0; $i + 1 < @$headers; $i += 2) { $seen{ lc $headers->[$i] } = 1 }

    my @out = ("HTTP/1.1 $status " . _reason($status));
    push @out, "$headers->[$_]: $headers->[$_ + 1]" for grep { $_ % 2 == 0 } 0 .. $#$headers;
    push @out, 'Content-Length: ' . length($body)
        unless $seen{'content-length'} || $seen{'transfer-encoding'};
    push @out, $conn->{data}{close_after} ? 'Connection: close' : 'Connection: keep-alive';
    $conn->write(join("\r\n", @out) . "\r\n\r\n");
    # A HEAD response advertises the length a GET would return but carries no
    # body (RFC 9110 §9.3.2) — the buffered render path produces the body, so
    # it is dropped here, metre and all.
    $conn->write($body) if length $body && ($req->{method} // '') ne 'HEAD';

    $self->_response_done($conn);
    return;
}

# A render runs synchronously inside one _dispatch: the core parses the whole
# chain before handle() returns, and the loop only gets to flush between ticks.
# Without a flush here every chunk of a streamed page would sit in the
# connection queue until the turn finished — the browser would show nothing
# until the last token.  syswrite is non-blocking, so a slow peer just leaves
# bytes queued (the loop's own backpressure bounds them).
sub _flush_now ($conn) {
    return if $conn->{reaped};
    $conn->{loop}->_flush($conn);
    return;
}

sub _response_done ($self, $conn) {
    return if $conn->closed;
    my $d = $conn->{data};
    $self->{done} = 1 if $self->{once};
    if ($d->{close_after}) { $conn->close; return }   # flush, then reap
    # keep-alive: back to waiting for the next request on this connection
    $d->{phase}  = 'headers';
    $d->{req}    = undef;
    $d->{plan}   = undef;
    $d->{idle_at} = Time::HiRes::time();
    return;
}

sub _client_eof ($self, $conn) {
    $conn->close unless $conn->closed;
    return;
}

# ── Idle sweep ──────────────────────────────────────────────────────────────

sub _sweep ($self) {
    my $now = Time::HiRes::time();
    # Snapshot: close() deletes from the loop's conns hash mid-iteration.
    my @conns = values %{ $self->loop->conns };
    for my $conn (@conns) {
        next if $conn->closed || $conn->{gated};
        my $d = $conn->{data} or next;
        my $limit = ($d->{phase} // '') eq 'headers' && ($d->{served} // 0)
            ? $self->{keepalive_timeout}
            : $self->{read_timeout};
        $conn->close(hard => 1) if $now - ($d->{idle_at} // $now) >= $limit;
    }
    return;
}

# ── Responses ───────────────────────────────────────────────────────────────

sub _fail ($self, $conn, $code, $reason, $body = undef) {
    return if $conn->closed;
    $body //= "$code $reason\n";
    my $head = "HTTP/1.1 $code $reason\r\n"
             . "Content-Type: text/plain; charset=utf-8\r\n"
             . 'Content-Length: ' . length($body) . "\r\n"
             . "Connection: close\r\n\r\n";
    $conn->{data}{close_after} = 1;
    $conn->want_in(0);
    $conn->write($head . $body);
    $conn->close;
    return;
}

sub _want_keepalive ($version, $folded) {
    my $c = $folded->{connection} // '';
    return 0 if $c =~ /\bclose\b/i;
    return 1 if $version eq '1.1';
    return $c =~ /\bkeep-alive\b/i ? 1 : 0;
}

sub _reason ($code) {
    return {
        200 => 'OK', 204 => 'No Content', 301 => 'Moved Permanently',
        302 => 'Found', 304 => 'Not Modified', 400 => 'Bad Request',
        403 => 'Forbidden', 404 => 'Not Found', 405 => 'Method Not Allowed',
        408 => 'Request Timeout', 413 => 'Payload Too Large',
        415 => 'Unsupported Media Type', 422 => 'Unprocessable Content',
        429 => 'Too Many Requests', 431 => 'Request Header Fields Too Large',
        500 => 'Internal Server Error', 502 => 'Bad Gateway',
        503 => 'Service Unavailable', 504 => 'Gateway Timeout',
    }->{$code} // 'Error';
}

# ── A streaming writer ──────────────────────────────────────────────────────
package Amin::AXA::Serve::Writer;
use v5.38; use warnings; use experimental 'signatures';

# The handle the core's render_stream writes into.  Each write is one chunk
# when the response is chunked (so nothing accumulates), and close emits the
# terminating zero-length chunk before the connection is resumed or closed.
sub new ($class, $conn, $chunked, $on_close) {
    return bless { conn => $conn, chunked => $chunked, on_close => $on_close, closed => 0 }, $class;
}

sub write ($self, $bytes) {
    return unless defined $bytes && length $bytes;
    if ($self->{chunked}) {
        $self->{conn}->write(sprintf("%x\r\n", length($bytes)) . $bytes . "\r\n");
    }
    else {
        $self->{conn}->write($bytes);
    }
    Amin::AXA::Serve::_flush_now($self->{conn});
    return;
}

sub close ($self) {
    return if $self->{closed};
    $self->{closed} = 1;
    $self->{conn}->write("0\r\n\r\n") if $self->{chunked};
    Amin::AXA::Serve::_flush_now($self->{conn});
    $self->{on_close}->();
    return;
}

1;

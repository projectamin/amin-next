#!/usr/bin/env perl
# P5 hardening (proxy-plan §P5): the per-IP rate limit, on both fronts.
#
# A token bucket sized `burst` and refilled at `rps` tokens/second, keyed by
# client IP; a request costs one token.  `rps=0` never refills, so a client gets
# exactly `burst` requests for the front's life.  This starts real fronts — the
# Perl `bin/amin proxy serve` and the Rust `amin-proxyd` — behind real sockets in
# front of a real origin, and drives them with real requests.  Nothing is mocked:
# the bytes over the wire are the contract.
#
# With `rps=0;burst=3` both fronts must serve the first three requests and shed
# the fourth with `429 Too Many Requests`, and they must agree on which request
# is shed and how it is refused (§7).  With no `amin:rate-limit` at all, nothing
# is ever shed — the limiter is opt-in.
use v5.38; use warnings; use utf8;
use Test2::V0;
use Cwd        qw(abs_path);
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use Time::HiRes qw(sleep);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT   = abs_path(dirname(__FILE__) . '/..');
my $DAEMON = "$ROOT/rust/target/debug/amin-proxyd";

skip_all "amin-proxyd not compiled; run `cargo build -p amin-proxy` at ./rust"
    unless -x $DAEMON;

my $tmp = tempdir(CLEANUP => 1);
my (@pids, @logs);

END {
    for my $p (@pids) { kill 'TERM', $p if defined $p }
    for my $p (@pids) { waitpid $p, 0 if defined $p }
    # Reaping our own children leaves $? = the SIGTERM we sent; clear it so the
    # test harness does not read it as the test itself dying.
    $? = 0;
}

# Pick a listen port by probe (the front binds it).
sub pick_port () {
    my $probe = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp',
        Listen => 5, ReuseAddr => 1,
    ) or die "probe bind: $!";
    my $port = $probe->sockport;
    close $probe;
    return $port;
}

# ── a real HTTP/1.1 origin on an ephemeral loopback port ────────────────────
my $origin_ls = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp',
    Listen    => 32, ReuseAddr => 1,
) or die "origin bind: $!";
my $origin_port = $origin_ls->sockport;
my $BODY = "ok\n";

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

# A profile binding $port on 127.0.0.1, routing only.example to the origin, with
# the given `amin:rate-limit` (omitted when $rl is undef).
sub write_profile ($name, $port, $rl) {
    my $path = "$tmp/$name";
    my $attr = defined $rl ? qq{ amin:rate-limit="$rl"} : '';
    open my $fh, '>:encoding(UTF-8)', $path or die "profile: $!";
    print $fh <<"XML";
<?xml version="1.0" encoding="UTF-8"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/"
            amin:listen="127.0.0.1:$port"$attr>
  <amin:backend amin:id="origin" amin:addr="127.0.0.1:$origin_port" amin:transport="http"/>
  <amin:route amin:host="only.example" amin:to="origin"/>
</amin:proxy>
XML
    close $fh;
    return $path;
}

sub start_perl ($profile, $n) {
    my $err = "$tmp/perl$n.stderr";
    push @logs, $err;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDOUT, '>', $err or exit 127;
        open STDERR, '>&', \*STDOUT or exit 127;
        exec $^X, '-I', "$ROOT/perl-lib", "$ROOT/bin/amin", 'proxy', 'serve', $profile;
        exit 127;
    }
    push @pids, $pid;
    return $pid;
}

sub start_rust ($profile, $n) {
    my $err = "$tmp/rust$n.stderr";
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

# Send one GET on a fresh connection and return its status line (or undef).
sub status_line_of ($port, $path = '/') {
    my $s = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 5,
    ) or return undef;
    return undef unless $s->connected;
    print $s "GET $path HTTP/1.1\r\nHost: only.example\r\nConnection: close\r\n\r\n";
    my $resp = '';
    while (1) {
        my $rin = ''; vec($rin, fileno($s), 1) = 1;
        last unless select(my $r = $rin, undef, undef, 5);
        my $n = sysread($s, my $chunk, 65536);
        last unless defined $n && $n > 0;
        $resp .= $chunk;
    }
    close $s;
    $resp =~ s/\r\n.*\z//s;
    return length $resp ? $resp : undef;
}

sub code_of ($line) {
    return $line =~ / (\d{3}) / ? $1 : undef;
}

# ── bring up the four fronts ────────────────────────────────────────────────
my %front;
my @order;
for my $spec (
    ['perl_rl',  'perl', 'rps=0;burst=3'],
    ['rust_rl',  'rust', 'rps=0;burst=3'],
    ['perl_off', 'perl', undef],
    ['rust_off', 'rust', undef],
) {
    my ($name, $kind, $rl) = @$spec;
    my $port    = pick_port();
    my $profile = write_profile("$name.xml", $port, $rl);
    $kind eq 'perl' ? start_perl($profile, scalar @order + 1)
                    : start_rust($profile, scalar @order + 1);
    $front{$name} = $port;
    push @order, $name;
}

my $up = 1;
$up &&= wait_listen($front{$_}) for @order;
ok($up, 'all four fronts accept connections')
    or do {
        for my $l (@logs) {
            diag("$l:\n" . do { open my $fh, '<', $l; local $/; <$fh> // '' });
        }
        done_testing();
        exit 1;
    };

# ── the burst: the first three pass, the fourth is shed ─────────────────────
my %lines;
for my $name (qw(perl_rl rust_rl)) {
    $lines{$name} = [ map { status_line_of($front{$name}) } 1 .. 4 ];
}
is [ map { code_of($_) } @{ $lines{perl_rl} } ], [200, 200, 200, 429],
    'Perl front: rps=0;burst=3 → 200,200,200,429 (fourth shed)';
is [ map { code_of($_) } @{ $lines{rust_rl} } ], [200, 200, 200, 429],
    'Rust front: rps=0;burst=3 → 200,200,200,429 (fourth shed)';
is $lines{perl_rl}, $lines{rust_rl},
    'both fronts shed the same request with the same status line (§7)';
is $lines{perl_rl}[3], 'HTTP/1.1 429 Too Many Requests',
    'the shed response is a 429 Too Many Requests';

# The bucket is per-process and `rps=0` never refills: even much later the IP
# stays over budget.  (Guards against an accidental refill for rps=0.)
sleep 0.2;
is code_of(status_line_of($front{perl_rl})), 429,
    'Perl: rps=0 never refills — still 429 after a pause';
is code_of(status_line_of($front{rust_rl})), 429,
    'Rust: rps=0 never refills — still 429 after a pause';

# ── the limiter is opt-in: no declaration → nothing is shed ─────────────────
for my $name (qw(perl_off rust_off)) {
    my @codes = map { code_of(status_line_of($front{$name})) } 1 .. 5;
    is \@codes, [200, 200, 200, 200, 200],
        "$name: no amin:rate-limit → every request is served";
}

done_testing;

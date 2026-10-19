#!/usr/bin/env perl
# Loopback smoke test (plan M2): `bin/amin axa serve` is a real persistent
# process — a real socket, a real HTTP client, and the process answering is
# the one this test started.  No mocks anywhere in this file.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use IO::Socket::INET;
use HTTP::Tiny;
use Time::HiRes qw(sleep);
use POSIX qw(WIFEXITED);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $APP  = "$ROOT/examples/apps/shop-ui";

# pick a free port by binding and releasing it
my $probe = IO::Socket::INET->new(
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
        'axa', 'serve', $APP, '--listen', "127.0.0.1:$port";
    exit 127;
}

# wait for the listener (bounded)
my $sock;
for (1 .. 150) {
    $sock = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => $port, Proto => 'tcp', Timeout => 1,
    );
    last if $sock;
    sleep 0.1;
}
ok($sock, "listener accepts connections on 127.0.0.1:$port")
    or do { kill 'TERM', $pid; waitpid $pid, 0; diag("server log:\n" . path($stderr)->slurp); done_testing(); exit 1 };
close $sock;

ok(kill(0, $pid), 'the answering process is the one we spawned');

$ENV{no_proxy} = join ',', grep { length } ($ENV{no_proxy} // ''), '127.0.0.1', 'localhost';
my $ua  = HTTP::Tiny->new(timeout => 10);
my $res = $ua->get("http://127.0.0.1:$port/");

is($res->{status}, 200, 'GET / → 200 over a real socket');
is($res->{headers}{'content-type'}, 'text/html; charset=utf-8', 'served as text/html');
like($res->{content}, qr/^<!DOCTYPE html>/, 'doctype over the wire');
like($res->{content}, qr/Amin Ceramic Mug/, 'catalogue content over the wire');
unlike($res->{content}, qr{</?shop:}, 'no app-dialect leakage over the wire');

my $res2 = $ua->get("http://127.0.0.1:$port/product?sku=sku-3");
is($res2->{status}, 200, 'navigation: product route answers');
like($res2->{content}, qr/Namespace Stickers/, 'product content over the wire');

# ── stop only the process we started ──────────────────────────────────
kill 'TERM', $pid;
my $reaped = waitpid $pid, 0;
is($reaped, $pid, 'waitpid reaped our child');
ok(WIFEXITED($?) || $? > 0, 'child exited after TERM');

done_testing;

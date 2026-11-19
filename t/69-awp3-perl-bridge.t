#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::ToolPaths qw(awp3_lib);

# The Perl↔Rust bridge contract (proxy-plan §6/§7/§8 P2).  Perl never
# re-implements AWP/3: Amin::Net::AWP3 binds the rust/crates/awp3 cdylib with
# FFI::Platypus and drives its fixed-size C ABI.  Because one implementation
# produces every byte, Perl and Rust are byte-identical by construction; what
# this file proves empirically is that the *binding* is a faithful pass-through
# — correct symbol resolution, exact fixed sizes, unchanged bytes across the
# FFI boundary (embedded NULs and high bytes), a complete error table, and
# deterministic output for a fixed seed.

skip_all 'awp3 cdylib not built; run `cargo build -p awp3`'
    unless length awp3_lib();
eval { require FFI::Platypus; 1 } or skip_all 'FFI::Platypus is not installed';
require Amin::Net::AWP3;

subtest 'Amin::ToolPaths resolves the cdylib' => sub {
    my $lib = awp3_lib();
    ok length($lib), 'awp3_lib() resolves a path';
    ok -f $lib,      'the resolved path is an existing file';
    like $lib, qr/libawp3\.(?:so|dylib|dll)$/, 'the filename matches the host platform';
};

subtest 'the ABI sizes are the frozen wire constants' => sub {
    my $f = Amin::Net::AWP3::_ffi();
    is $f->{bundle_len}->(),     6574, 'bundle_len';
    is $f->{msg1_len}->(),       6510, 'msg1_len';
    is $f->{msg2_len}->(),       3406, 'msg2_len';
    is $f->{receipt_len}->(),    3373, 'receipt_len == ML-DSA-65(3309) + Ed25519(64)';
    is $f->{frame_overhead}->(), 70,   'frame_overhead == header(38) + nonce(16) + tag(16)';
};

subtest 'the bridge is a deterministic pass-through' => sub {
    # The bundle depends only on the responder seed, and msg1 only on
    # (bundle, initiator seed) — no process entropy leaks into either, so two
    # independent constructions must be byte-identical.
    my $b1 = Amin::Net::AWP3->responder(seed => "\x5a" x 32)->bundle;
    my $b2 = Amin::Net::AWP3->responder(seed => "\x5a" x 32)->bundle;
    is $b1, $b2, 'same seed -> identical bundle';

    my $m1a = Amin::Net::AWP3->client(bundle => $b1, seed => "\x22" x 32)->msg1;
    my $m1b = Amin::Net::AWP3->client(bundle => $b1, seed => "\x22" x 32)->msg1;
    is $m1a, $m1b, 'same (bundle, seed) -> identical msg1';

    my $different = Amin::Net::AWP3->client(bundle => $b1, seed => "\x23" x 32)->msg1;
    isnt $m1a, $different, 'a different initiator seed -> a different msg1';
};

subtest 'every byte crosses the FFI boundary unchanged' => sub {
    my $r = Amin::Net::AWP3->responder(seed => "\x11" x 32);
    my $c = Amin::Net::AWP3->client(bundle => $r->bundle, seed => "\x22" x 32);
    my $m2 = $r->accept($c->msg1);
    $c->finish($m2);

    # Every byte value, repeated: exercises embedded NULs, 0x7f and 0x80-0xff.
    my $payload = pack('C*', 0 .. 255) x 4;
    my $f = $c->seal($payload);
    is length($f), length($payload) + 70, 'frame length tracks the exact payload length';
    is $r->open($f), $payload, 'all 1024 bytes are recovered unchanged';
};

subtest 'the error table covers every Awp3Error code' => sub {
    my %want = (
        -1 => 'invalid key material',        -2 => 'signature verification failed',
        -3 => 'aead authentication failed',  -4 => 'ml-kem-768 operation failed',
        -5 => 'malformed handshake message', -6 => 'malformed or out-of-order frame',
        -7 => 'session already closed',      -8 => 'output buffer too small',
        -9 => 'invalid argument',
    );
    for my $code (sort { $a <=> $b } keys %want) {
        like dies { Amin::Net::AWP3::_ok($code, 'op') },
            qr/:\s\Q$want{$code}\E\s\($code\)/, "code $code -> $want{$code}";
    }
    is Amin::Net::AWP3::_ok(0, 'op'),    0,    'zero bytes is success, not an error';
    is Amin::Net::AWP3::_ok(4321, 'op'), 4321, 'a positive byte count passes through';
};

subtest 'a half-open handshake cannot frame' => sub {
    my $r = Amin::Net::AWP3->responder(seed => "\x11" x 32);
    my $c = Amin::Net::AWP3->client(bundle => $r->bundle, seed => "\x22" x 32);
    $r->accept($c->msg1);   # responder goes live, initiator never receives msg2
    like dies { $c->seal('x') }, qr/malformed handshake message \(-5\)/,
        'sealing before finish() is -5 (not a default session)';
};

subtest 'lifetime: free and DESTROY are safe and idempotent' => sub {
    {
        my $r = Amin::Net::AWP3->responder(seed => "\x11" x 32);
        my $c = Amin::Net::AWP3->client(bundle => $r->bundle, seed => "\x22" x 32);
        is $c->role, 'client', 'live client before scope exit';
    }   # both opaque handles must be released here without error
    pass 'both sessions released at scope exit';

    my $r = Amin::Net::AWP3->responder(seed => "\x11" x 32);
    ok defined $r->{h}, 'a handle is present';
    $r->free;
    ok !defined $r->{h}, 'free() clears the handle';
    ok lives { $r->free }, 'a second free() is a no-op';
};

done_testing;

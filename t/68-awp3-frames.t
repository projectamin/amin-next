#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::ToolPaths qw(awp3_lib);

# Perl owns no AWP/3 framing (proxy-plan §6/§7): every byte asserted below is
# produced and consumed by the rust/crates/awp3 cdylib through Amin::Net::AWP3,
# so these assertions ARE the wire contract — version, frame kinds, the
# BLAKE3-chained ordering rule, AEAD tamper rejection and the signed close
# receipt.

skip_all 'awp3 cdylib not built; run `cargo build -p awp3`'
    unless length awp3_lib();
eval { require FFI::Platypus; 1 } or skip_all 'FFI::Platypus is not installed';
require Amin::Net::AWP3;

# Frozen AWP/3 structure sizes (rust/crates/awp3: handshake.rs / sign.rs /
# framing.rs).  Pinning them here is the regression guard for the wire layout.
my $BUNDLE_LEN  = 6574;   # 1 + X25519(32) + ML-KEM-768 ek(1184) + composite vk(1984) + sig(3373)
my $MSG1_LEN    = 6510;   # 1 + X25519(32) + ML-KEM-768 ct(1088) + composite vk(1984) + X25519(32) + sig(3373)
my $MSG2_LEN    = 3406;   # 1 + X25519(32) + sig(3373)
my $RECEIPT_LEN = 3373;   # composite signature: ML-DSA-65(3309) + Ed25519(64)
my $OVERHEAD    = 70;     # header(38) + ASCON nonce(16) + ASCON tag(16)

my $VERSION    = 0x03;    # header byte 0
my $KIND_DATA  = 0x00;    # header byte 1
my $KIND_CLOSE = 0x01;

sub linked_pair (%o) {
    my $r = Amin::Net::AWP3->responder(seed => $o{r_seed} // ("\x11" x 32));
    my $c = Amin::Net::AWP3->client(bundle => $r->bundle,
                                    seed   => $o{c_seed} // ("\x22" x 32));
    my $m2 = $r->accept($c->msg1);
    $c->finish($m2);
    return ($r, $c);
}

subtest 'identity and handshake sizing' => sub {
    my $r = Amin::Net::AWP3->responder(seed => "\x11" x 32);
    is $r->role, 'responder', 'responder role';
    is length($r->bundle), $BUNDLE_LEN, "self-signed bundle is $BUNDLE_LEN bytes";

    my $c = Amin::Net::AWP3->client(bundle => $r->bundle, seed => "\x22" x 32);
    is $c->role, 'client', 'client role';

    my $m1 = $c->msg1;
    is length($m1), $MSG1_LEN, "initiator msg1 is $MSG1_LEN bytes";
    my $m2 = $r->accept($m1);
    is length($m2), $MSG2_LEN, "responder msg2 is $MSG2_LEN bytes";
    ok $c->finish($m2) == $c, 'finish() returns the handshaken initiator';
};

subtest 'frames round-trip in both directions' => sub {
    my ($r, $c) = linked_pair();

    my $f = $c->seal('hello amin');
    is length($f), length('hello amin') + $OVERHEAD, 'DATA frame length = payload + overhead';
    is ord(substr($f, 0, 1)), $VERSION,   'header byte 0 carries VERSION 0x03';
    is ord(substr($f, 1, 1)), $KIND_DATA, 'header byte 1 is KIND_DATA';
    is $r->open($f), 'hello amin', 'responder recovers the initiator payload';

    my $g = $r->seal('world');
    is $c->open($g), 'world', 'initiator recovers the responder payload';
};

subtest 'an empty payload is a legal DATA frame' => sub {
    my ($r, $c) = linked_pair();
    my $f = $c->seal;
    is length($f), $OVERHEAD, 'empty DATA frame is exactly the overhead';
    is $r->open($f), '', 'empty payload round-trips as the empty string';
};

subtest 'the chain advances across a long duplex run' => sub {
    my ($r, $c) = linked_pair();
    for my $i (1 .. 8) {
        is $r->open($c->seal("c$i")), "c$i", "initiator frame $i in order";
        is $c->open($r->seal("r$i")), "r$i", "responder frame $i in order";
    }
};

subtest 'frames are chained: out-of-order delivery is rejected' => sub {
    my ($r, $c) = linked_pair();
    my $f1 = $c->seal('one');
    my $f2 = $c->seal('two');

    like dies { $r->open($f2) }, qr/out-of-order frame \(-6\)/,
        'delivering frame 2 before frame 1 is -6';
    is $r->open($f1), 'one', 'the rejected frame did not advance the chain (frame 1 still opens)';
    is $r->open($f2), 'two', 'frame 2 then opens in order';
};

subtest 'tampering is detected before it is trusted' => sub {
    my ($r, $c) = linked_pair();
    my $f = $c->seal('a payload long enough to flip a ciphertext byte');

    # Byte 60 is past AAD_LEN(54): a ciphertext/tag byte, so the AEAD fails.
    substr($f, 60, 1) = chr(ord(substr($f, 60, 1)) ^ 0x01);
    like dies { $r->open($f) }, qr/aead authentication failed \(-3\)/,
        'a flipped ciphertext byte is -3, never delivered';

    my ($r2, $c2) = linked_pair();
    my $g = $c2->seal('x');
    # Bytes 6..38 are the 32-byte chain: the append-only check fires first.
    substr($g, 10, 1) = chr(ord(substr($g, 10, 1)) ^ 0x01);
    like dies { $r2->open($g) }, qr/out-of-order frame \(-6\)/,
        'a flipped chain byte is -6 before the AEAD is even reached';
};

subtest 'close terminates the chain with a signed receipt' => sub {
    my ($r, $c) = linked_pair();

    my $last = $c->seal('last words');
    is $r->open($last), 'last words', 'the final DATA frame is delivered before the close';

    my ($cf, $receipt) = $c->close;
    is length($cf), $OVERHEAD,      'CLOSE frame is exactly the overhead';
    is ord(substr($cf, 1, 1)), $KIND_CLOSE, 'header byte 1 is KIND_CLOSE';
    is length($receipt), $RECEIPT_LEN,
        "receipt is a $RECEIPT_LEN-byte composite signature over the final chain";

    is $r->open($cf), undef, 'the peer opens the CLOSE frame (no payload)';

    like dies { $c->seal('after') }, qr/session already closed \(-7\)/,
        'the initiator refuses to seal after close';
    like dies { $r->seal('after') }, qr/session already closed \(-7\)/,
        'the responder is closed by the CLOSE frame too';
};

subtest 'constructor validation is fail-closed at the boundary' => sub {
    like dies { Amin::Net::AWP3->client(bundle => 'too short') },
        qr/bundle must be \Q$BUNDLE_LEN\E bytes/, 'a short bundle is rejected';

    like dies { Amin::Net::AWP3->responder(seed => 'short') },
        qr/seed must be 32 bytes/, 'a short responder seed is rejected';

    my $r = Amin::Net::AWP3->responder(seed => "\x11" x 32);
    like dies { Amin::Net::AWP3->client(bundle => $r->bundle, seed => 'short') },
        qr/seed must be 32 bytes/, 'a short initiator seed is rejected';

    like dies { $r->accept('short') },
        qr/msg1 must be \Q$MSG1_LEN\E bytes/, 'accept() rejects a short msg1 without reading past it';
};

subtest 'each connection is an independent session' => sub {
    my ($ra, $ca) = linked_pair(r_seed => "\x01" x 32, c_seed => "\x02" x 32);
    my ($rb, $cb) = linked_pair(r_seed => "\x03" x 32, c_seed => "\x04" x 32);

    isnt $ra->bundle, $rb->bundle, 'distinct seeds give distinct responder identities';

    my $fa = $ca->seal('for a');
    is $ra->open($fa), 'for a', 'session A carries its own frame';
    like dies { $rb->open($fa) }, qr/out-of-order frame \(-6\)/,
        'session B refuses session A\'s frame (no shared key)';
};

done_testing;

#!/usr/bin/env perl
# t/73-trust-golden.t — Perl/Rust symmetry for the trust layer.
#
# t/data/trust-golden-v1.tsv is shared with rust/crates/bitcache/tests/golden.rs.
# Rust drives each row through the C ABI; this test drives the same rows through
# Amin::Crypto::Verify (the FFI binding Perl actually uses).  Same file, same
# verdicts: if the two languages ever disagree about a byte, one suite fails.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';
use MIME::Base64 qw(decode_base64);

use Amin::Crypto::Verify qw(mldsa87_verify zcap_verify instrument_verify nodecert_verify
                          tlog_leaf_hash tlog_verify_inclusion tlog_verify_consistency ckpt_verify snapshot_verify receipt_verify iot_leaf_verify iot_leaf_key iot_report_build iot_report_check);
use Amin::Crypto::ML_DSA;
use Amin::Auth::ZCap;

plan skip_all => 'libbitcache not built (cargo build -p bitcache)'
    unless Amin::Crypto::Verify::available();

my $file = dirname(__FILE__) . '/data/trust-golden-v1.tsv';
open my $fh, '<:raw', $file or die "open $file: $!";
my @rows = grep { !/^#/ && length } map { chomp; $_ } <$fh>;
close $fh;
ok(@rows >= 99, 'golden set loaded: ' . scalar(@rows) . ' rows');

sub b ($s) { length($s // '') ? decode_base64($s) : '' }

for my $line (@rows) {
    my ($kind, $name, $want, @f) = split /\t/, $line, -1;
    my $label = "$kind/$name";
    if ($kind eq 'mldsa87') {
        my ($vk, $sig, $msg) = map { b($_) } @f[0..2];
        # Perl's wrapper rejects wrong lengths itself; the verdict is "not valid" either way
        my $ok = mldsa87_verify($vk, $sig, $msg);
        is($ok, $want == 0 ? 1 : 0, "$label: Crypto::Verify");
        is(Amin::Crypto::ML_DSA::verify_87($vk, $sig, $msg), $want == 0 ? 1 : 0, "$label: ML_DSA::verify_87");
    }
    elsif ($kind eq 'zcap') {
        my $tok = b($f[0]);
        my @anchors = map { b($_) } grep { length } split /,/, ($f[1] // '');
        is(zcap_verify($tok, \@anchors), $want, "$label: Crypto::Verify");
        # and through the real document-level trust path
        my $z = Amin::Auth::ZCap->new;
        my ($ok, $code) = $z->_verify_token(MIME::Base64::encode_base64($tok, ''), \@anchors);
        is($ok ? 1 : 0, $want == 0 ? 1 : 0, "$label: Amin::Auth::ZCap accepts iff Rust accepts");
    }
    elsif ($kind eq 'instrument') {
        my ($mk, $py, $am, $kd, $sq) = @f[0..4];
        is(instrument_verify($mk, $py, $am, $kd, $sq, b($f[5]), b($f[6])), $want, "$label: Crypto::Verify");
    }
    elsif ($kind eq 'nodecert') {
        my ($cert, $vk, $pos, $hash_hex, $bc) = (b($f[0]), b($f[1]), $f[2], $f[3], $f[4]);
        my ($rc, $h, $boot) = nodecert_verify($cert, $vk, $pos);
        is($rc, $want, "$label: Crypto::Verify");
        if ($want == 0) {
            is($h, $hash_hex, "$label: certified key hash");
            is($boot, $bc,    "$label: boot counter");
        }
    }
    elsif ($kind eq 'tlog-incl') {
        my ($leaf, $idx, $size, $path, $root) = (b($f[0]), $f[1], $f[2], $f[3], b($f[4]));
        my @p = map { b($_) } grep { length } split /,/, $path;
        is(tlog_verify_inclusion($leaf, $idx, $size, \@p, $root), $want, "$label: Crypto::Verify");
        # Perl's leaf hash of the original entry equals the Rust leaf in the vector
        is(tlog_leaf_hash("golden-entry-$1"), $leaf, "$label: leaf hash symmetric") if $name =~ /^valid-(\d+)$/;
    }
    elsif ($kind eq 'tlog-cons') {
        my ($a, $ar, $bsz, $br, $proof) = ($f[0], b($f[1]), $f[2], b($f[3]), $f[4]);
        my @p = map { b($_) } grep { length } split /,/, $proof;
        is(tlog_verify_consistency($a, $ar, $bsz, $br, \@p), $want, "$label: Crypto::Verify");
    }
    elsif ($kind eq 'ckpt') {
        my ($wire, $avk, $pos, $roster, $q, $size, $root_hex, $origin) =
            (b($f[0]), b($f[1]), $f[2], $f[3], $f[4], $f[5], $f[6], $f[7]);
        my @r = map { b($_) } grep { length } split /,/, $roster;
        my ($rc, $sz, $root, $org) = ckpt_verify($wire, $avk, $pos, \@r, $q);
        is($rc, $want, "$label: Crypto::Verify");
        if ($want == 0) {
            is($sz, $size, "$label: size");
            is(unpack('H*', $root), $root_hex, "$label: root");
            is($org, $origin, "$label: origin");
        }
    }
    elsif ($kind eq 'snapshot') {
        my ($snap, $avk, $pos, $roster, $q, $size, $root_hex, $origin) =
            (b($f[0]), b($f[1]), $f[2], $f[3], $f[4], $f[5], $f[6], $f[7]);
        my @r = map { b($_) } grep { length } split /,/, $roster;
        my ($rc, $sz, $root, $org) = snapshot_verify($snap, $avk, $pos, \@r, $q);
        is($rc, $want, "$label: Crypto::Verify");
        if ($want == 0) {
            is($sz, $size, "$label: size");
            is(unpack('H*', $root), $root_hex, "$label: root");
            is($org, $origin, "$label: origin");
        }
    }
    elsif ($kind eq 'receipt') {
        my ($rcpt, $auths, $pos) = (b($f[0]), $f[1], $f[2]);
        my @a = map { b($_) } grep { length } split /,/, $auths;
        my ($rc, $sz, $root, $org, $id) = receipt_verify($rcpt, \@a, $pos);
        is($rc, $want, "$label: Crypto::Verify");
        if ($want == 0) {
            is($sz, $f[3], "$label: size");
            is(unpack('H*', $root), $f[4], "$label: root");
            is($org, $f[5], "$label: origin");
            is(unpack('H*', $id), $f[6], "$label: entry id");
        }
    }
    elsif ($kind eq 'iotkey') {
        my ($master, $leaf, $want_key) = (b($f[0]), $f[1], b($f[2]));
        is(iot_leaf_key($master, $leaf), $want_key, "$label: leaf key derivation");
    }
    elsif ($kind eq 'iotreport') {
        my ($key, $wire, $leaf, $ctr, $payload) = (b($f[0]), b($f[1]), $f[2], $f[3], b($f[4]));
        my ($rc, $got) = iot_report_check($key, $wire);
        is($rc, $want, "$label: Crypto::Verify");
        if ($want == 0) {
            is($got, $ctr, "$label: counter");
            is(iot_report_build($key, $leaf, $ctr, $payload), $wire, "$label: Perl builds the Rust bytes");
        }
    }
    elsif ($kind eq 'iotleaf') {
        my ($rcpt, $auths, $pos) = (b($f[0]), $f[1], $f[2]);
        my @a = map { b($_) } grep { length } split /,/, $auths;
        my ($rc, $sz, $root, $org, $id, $leaf) = iot_leaf_verify($rcpt, \@a, $pos);
        is($rc, $want, "$label: Crypto::Verify");
        if ($want == 0) {
            is($sz, $f[3], "$label: size");
            is(unpack('H*', $root), $f[4], "$label: root");
            is($org, $f[5], "$label: origin");
            is(unpack('H*', $id), $f[6], "$label: batch entry id");
            is(unpack('H*', $leaf), $f[7], "$label: report leaf hash");
        }
    }
    else { fail("unknown vector kind $kind") }
}

is(tlog_verify_inclusion(undef, 0, 1, [], "\0" x 32), Amin::Crypto::Verify::RC_BAD_ARG(), 'undef leaf → bad arg');
is((ckpt_verify(undef, 'x', 1, [], 0))[0], Amin::Crypto::Verify::RC_BAD_ARG(), 'undef checkpoint → bad arg');

# bad-argument and missing-library behaviour is a rejection, never a pass
is(zcap_verify(undef, []), Amin::Crypto::Verify::RC_BAD_ARG(), 'undef token → bad arg');
is(zcap_verify("x", undef), Amin::Crypto::Verify::RC_BAD_ARG(), 'undef anchors → bad arg');
is(mldsa87_verify(undef, 'a', 'b'), 0, 'undef vk → 0');
is(mldsa87_verify("\x{100}" x 2592, 'a', 'b'), 0, 'wide-char vk → 0');

done_testing;

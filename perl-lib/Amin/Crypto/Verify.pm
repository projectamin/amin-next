package Amin::Crypto::Verify;

# ═══════════════════════════════════════════════════════════════════════════
# Perl binding for the Amin trust-layer verifiers (rust/crates/bitcache cdylib).
#
# Perl owns no cryptography and no trust decision of its own.  ML-DSA-87,
# zcap.v1 and UCC instrument verification all run the Rust implementation
# (bitcache::trust) through FFI::Platypus, so Perl and Rust accept and reject
# exactly the same bytes.
#
# FAIL CLOSED, everywhere: a missing library, a bad argument, a short buffer
# or any internal error is a rejection.  Nothing in this module can return
# success except the Rust verifier answering 0.
# ═══════════════════════════════════════════════════════════════════════════

use v5.38; use warnings; use utf8; use experimental 'signatures';

use Exporter 'import';
our @EXPORT_OK = qw(available mldsa87_verify zcap_verify instrument_verify nodecert_verify
                    tlog_leaf_hash tlog_verify_inclusion tlog_verify_consistency ckpt_verify snapshot_verify receipt_verify iot_leaf_verify iot_leaf_key iot_report_build iot_report_check
                    RC_OK RC_FORMAT RC_UNKNOWN_KID RC_BAD_SIG RC_NOT_VALID_AT RC_QUORUM RC_BAD_ARG);

use constant {
    RC_OK          =>  0,
    RC_FORMAT      => -1,
    RC_UNKNOWN_KID => -2,
    RC_BAD_SIG     => -3,
    RC_NOT_VALID_AT => -4,
    RC_QUORUM      => -5,
    RC_BAD_ARG     => -9,
    VK_LEN         => 2592,
    SIG_LEN        => 4627,
};

my ($FFI, $LOADED);

sub _ffi () {
    return $FFI if $LOADED;
    $LOADED = 1;
    $FFI = eval {
        require FFI::Platypus;
        require Amin::ToolPaths;
        my $lib = Amin::ToolPaths::bitcache_lib();
        die "bitcache cdylib not found\n" unless length $lib;
        my $f = FFI::Platypus->new(api => 2);
        $f->lib($lib);
        {
            mldsa87    => $f->function('bitcache_mldsa87_verify'
                => [('string','size_t') x 3] => 'int'),
            zcap       => $f->function('bitcache_zcap_verify'
                => ['string','size_t','string','size_t'] => 'int'),
            instrument => $f->function('bitcache_instrument_verify'
                => [('string','size_t') x 6] => 'int'),
            nodecert   => $f->function('bitcache_nodecert_verify'
                => ['string','size_t','string','size_t','uint64','string','string'] => 'int'),
            leaf       => $f->function('bitcache_tlog_leaf_hash'
                => ['string','size_t','string'] => 'int'),
            incl       => $f->function('bitcache_tlog_verify_inclusion'
                => ['string','uint64','uint64','string','size_t','string'] => 'int'),
            cons       => $f->function('bitcache_tlog_verify_consistency'
                => ['uint64','string','uint64','string','string','size_t'] => 'int'),
            receipt    => $f->function('bitcache_receipt_verify'
                => ['string','size_t','string','size_t','uint64','string','size_t','size_t',
                    'string','string','string','string','string'] => 'int'),
            iotkey     => $f->function('bitcache_iot_leaf_key'
                => ['string','string','size_t','string'] => 'int'),
            iotbuild   => $f->function('bitcache_iot_report_build'
                => ['string','string','size_t','uint64','string','size_t','string','size_t','string'] => 'int'),
            iotcheck   => $f->function('bitcache_iot_report_check'
                => ['string','string','size_t','string'] => 'int'),
            iotleaf    => $f->function('bitcache_iot_leaf_verify'
                => ['string','size_t','string','size_t','uint64','string','size_t','size_t',
                    'string','string','string','string','string','string'] => 'int'),
            snap       => $f->function('bitcache_snapshot_verify'
                => ['string','size_t','string','size_t','uint64','string','size_t','size_t',
                    'string','string','string','string'] => 'int'),
            ckpt       => $f->function('bitcache_ckpt_verify'
                => ['string','size_t','string','size_t','uint64','string','size_t','size_t',
                    'string','string','string','string'] => 'int'),
        };
    };
    return $FFI;
}

# True when the verifier library is loadable.  Callers must treat "false" as
# "reject", never as "skip".
sub available () { return _ffi() ? 1 : 0 }

sub _bytes ($v) {
    return undef unless defined $v && !ref $v;
    utf8::downgrade($v, 1) or return undef;     # wide chars are not byte strings
    return $v;
}

# → 1 iff the signature verifies, else 0.
sub mldsa87_verify ($vk, $sig, $msg) {
    my $f = _ffi() or return 0;
    ($vk, $sig, $msg) = map { _bytes($_) } ($vk, $sig, $msg);
    return 0 unless defined $vk && defined $sig && defined $msg;
    return $f->{mldsa87}->($vk, length $vk, $sig, length $sig, $msg, length $msg) == RC_OK ? 1 : 0;
}

# → RC_OK or a negative RC_*; RC_BAD_ARG when the library is unavailable.
sub zcap_verify ($token_bytes, $anchors) {
    my $f = _ffi() or return RC_BAD_ARG;
    my $tok = _bytes($token_bytes);
    return RC_BAD_ARG unless defined $tok && ref $anchors eq 'ARRAY';
    my @a = grep { defined $_ } map { _bytes($_) } @$anchors;
    return RC_UNKNOWN_KID unless @a;
    # An anchor of the wrong length can never match; drop it rather than
    # let it shift the packing of the others.
    @a = grep { length($_) == VK_LEN } @a;
    return RC_UNKNOWN_KID unless @a;
    my $packed = join '', @a;
    return $f->{zcap}->($tok, length $tok, $packed, scalar @a);
}

# → RC_OK or a negative RC_*.
sub instrument_verify ($maker, $payee, $amount, $kind, $vk, $sig) {
    my $f = _ffi() or return RC_BAD_ARG;
    my @v = map { _bytes($_) } ($maker, $payee, $amount, $kind, $vk, $sig);
    return RC_BAD_ARG if grep { !defined } @v;
    my @args = map { ($_, length $_) } @v;
    return $f->{instrument}->(@args);
}

# Verify a node certificate under the authority VK, valid at authority-log
# position $pos.  → ($rc, $vk_hash_hex, $boot_counter); the last two are only
# meaningful when $rc == RC_OK.
sub nodecert_verify ($cert, $authority_vk, $pos) {
    my $f = _ffi() or return (RC_BAD_ARG);
    my ($c, $vk) = map { _bytes($_) } ($cert, $authority_vk);
    return (RC_BAD_ARG) unless defined $c && defined $vk && defined $pos && $pos =~ /\A[0-9]+\z/;
    my $hash = "\0" x 32;
    my $bc   = "\0" x 8;
    my $rc = $f->{nodecert}->($c, length $c, $vk, length $vk, $pos, $hash, $bc);
    return ($rc) unless $rc == RC_OK;
    return ($rc, unpack('H*', $hash), unpack('Q<', $bc));
}

# ── transparency log ─────────────────────────────────────────────────────────
# Hashes are 32-byte binary strings.

# → 32-byte leaf hash H(0x00 ‖ entry), or undef.
sub tlog_leaf_hash ($entry) {
    my $f = _ffi() or return undef;
    my $e = _bytes($entry);
    return undef unless defined $e;
    my $out = "\0" x 32;
    return $f->{leaf}->($e, length $e, $out) == RC_OK ? $out : undef;
}

sub _hash32 ($h) { my $b = _bytes($h); return (defined $b && length($b) == 32) ? $b : undef }

# → RC_OK iff $leaf is entry $index of the size-$size tree with $root.
sub tlog_verify_inclusion ($leaf, $index, $size, $path, $root) {
    my $f = _ffi() or return RC_BAD_ARG;
    my ($l, $r) = (_hash32($leaf), _hash32($root));
    return RC_BAD_ARG unless defined $l && defined $r && ref $path eq 'ARRAY'
        && ($index // '') =~ /\A[0-9]+\z/ && ($size // '') =~ /\A[0-9]+\z/;
    my @p = map { _hash32($_) } @$path;
    return RC_BAD_ARG if grep { !defined } @p;
    return $f->{incl}->($l, $index, $size, join('', @p), scalar @p, $r);
}

# → RC_OK iff the size-$second tree is an append-only extension of the size-$first one.
sub tlog_verify_consistency ($first, $first_root, $second, $second_root, $proof) {
    my $f = _ffi() or return RC_BAD_ARG;
    my ($a, $b) = (_hash32($first_root), _hash32($second_root));
    return RC_BAD_ARG unless defined $a && defined $b && ref $proof eq 'ARRAY'
        && ($first // '') =~ /\A[0-9]+\z/ && ($second // '') =~ /\A[0-9]+\z/;
    my @p = map { _hash32($_) } @$proof;
    return RC_BAD_ARG if grep { !defined } @p;
    return $f->{cons}->($first, $a, $second, $b, join('', @p), scalar @p);
}

# Verify a signed checkpoint chained to $authority_vk at authority position $pos,
# with $quorum distinct cosignatures from @$roster (ML-DSA-87 keys).
# → ($rc, $size, $root_bin, $origin); the last three only when $rc == RC_OK.
sub ckpt_verify ($wire, $authority_vk, $pos, $roster, $quorum) {
    my $f = _ffi() or return (RC_BAD_ARG);
    my ($w, $avk) = map { _bytes($_) } ($wire, $authority_vk);
    return (RC_BAD_ARG) unless defined $w && defined $avk && ref $roster eq 'ARRAY'
        && ($pos // '') =~ /\A[0-9]+\z/ && ($quorum // '') =~ /\A[0-9]+\z/;
    my @r = map { _bytes($_) } @$roster;
    return (RC_BAD_ARG) if grep { !defined || length($_) != VK_LEN } @r;
    my ($size, $root, $org, $olen) = ("\0" x 8, "\0" x 32, "\0" x 256, "\0" x 4);
    my $rc = $f->{ckpt}->($w, length $w, $avk, length $avk, $pos,
                          join('', @r), scalar @r, $quorum, $size, $root, $org, $olen);
    return ($rc) unless $rc == RC_OK;
    return ($rc, unpack('Q<', $size), $root, substr($org, 0, unpack('V', $olen)));
}

# Verify a join snapshot (a new node adopting the ledger state without its
# history).  → ($rc, $size, $root_bin, $origin); last three only when RC_OK.
sub snapshot_verify ($snap, $authority_vk, $pos, $roster, $quorum) {
    my $f = _ffi() or return (RC_BAD_ARG);
    my ($w, $avk) = map { _bytes($_) } ($snap, $authority_vk);
    return (RC_BAD_ARG) unless defined $w && defined $avk && ref $roster eq 'ARRAY'
        && ($pos // '') =~ /\A[0-9]+\z/ && ($quorum // '') =~ /\A[0-9]+\z/;
    my @r = map { _bytes($_) } @$roster;
    return (RC_BAD_ARG) if grep { !defined || length($_) != VK_LEN } @r;
    my ($size, $root, $org, $olen) = ("\0" x 8, "\0" x 32, "\0" x 256, "\0" x 4);
    my $rc = $f->{snap}->($w, length $w, $avk, length $avk, $pos,
                          join('', @r), scalar @r, $quorum, $size, $root, $org, $olen);
    return ($rc) unless $rc == RC_OK;
    return ($rc, unpack('Q<', $size), $root, substr($org, 0, unpack('V', $olen)));
}

# Verify an offline transfer receipt against any of @$authorities (ML-DSA-87 keys).
# → ($rc, $size, $root_bin, $origin, $entry_id_bin); last four only when RC_OK.
sub receipt_verify ($receipt, $authorities, $pos, $roster = [], $quorum = 0) {
    my $f = _ffi() or return (RC_BAD_ARG);
    my $w = _bytes($receipt);
    return (RC_BAD_ARG) unless defined $w && ref $authorities eq 'ARRAY' && ref $roster eq 'ARRAY'
        && ($pos // '') =~ /\A[0-9]+\z/ && ($quorum // '') =~ /\A[0-9]+\z/;
    my @a = map { _bytes($_) } @$authorities;
    my @r = map { _bytes($_) } @$roster;
    return (RC_BAD_ARG) if grep { !defined || length($_) != VK_LEN } @a, @r;
    my ($size, $root, $org, $olen, $id) = ("\0" x 8, "\0" x 32, "\0" x 256, "\0" x 4, "\0" x 32);
    my $rc = $f->{receipt}->($w, length $w, join('', @a), scalar @a, $pos,
                             join('', @r), scalar @r, $quorum, $size, $root, $org, $olen, $id);
    return ($rc) unless $rc == RC_OK;
    return ($rc, unpack('Q<', $size), $root, substr($org, 0, unpack('V', $olen)), $id);
}

# Verify an IoT leaf receipt: report → batch root → `iot.batch` entry → signed checkpoint.
# → ($rc, $size, $root_bin, $origin, $batch_entry_id_bin, $report_leaf_hash_bin);
# bind the proof to YOUR report with  $leaf_hash eq tlog_leaf_hash($report).
sub iot_leaf_verify ($receipt, $authorities, $pos, $roster = [], $quorum = 0) {
    my $f = _ffi() or return (RC_BAD_ARG);
    my $w = _bytes($receipt);
    return (RC_BAD_ARG) unless defined $w && ref $authorities eq 'ARRAY' && ref $roster eq 'ARRAY'
        && ($pos // '') =~ /\A[0-9]+\z/ && ($quorum // '') =~ /\A[0-9]+\z/;
    my @a = map { _bytes($_) } @$authorities;
    my @r = map { _bytes($_) } @$roster;
    return (RC_BAD_ARG) if grep { !defined || length($_) != VK_LEN } @a, @r;
    my ($size, $root, $org, $olen, $id, $leaf) = ("\0" x 8, "\0" x 32, "\0" x 256, "\0" x 4, "\0" x 32, "\0" x 32);
    my $rc = $f->{iotleaf}->($w, length $w, join('', @a), scalar @a, $pos,
                             join('', @r), scalar @r, $quorum, $size, $root, $org, $olen, $id, $leaf);
    return ($rc) unless $rc == RC_OK;
    return ($rc, unpack('Q<', $size), $root, substr($org, 0, unpack('V', $olen)), $id, $leaf);
}


# Per-leaf key from the gateway master secret (32 bytes) — same function the Rust sensors run.
sub iot_leaf_key ($master, $leaf) {
    my $f = _ffi() or return;
    my ($m, $l) = (_bytes($master), _bytes($leaf));
    return unless defined $m && length($m) == 32 && defined $l && length $l;
    my $key = "\0" x 32;
    return $f->{iotkey}->($m, $l, length $l, $key) == RC_OK ? $key : undef;
}

# Build an authenticated report (wire bytes) — byte-identical to the Rust leaf.
sub iot_report_build ($key, $leaf, $ctr, $payload = '') {
    my $f = _ffi() or return;
    my ($k, $l, $p) = (_bytes($key), _bytes($leaf), _bytes($payload));
    return unless defined $k && length($k) == 32 && defined $l && defined $p && ($ctr // '') =~ /\A[0-9]+\z/;
    my ($out, $n) = ("\0" x 320, pack('Q<', 0));
    my $rc = $f->{iotbuild}->($k, $l, length $l, $ctr, $p, length $p, $out, 320, $n);
    return $rc == RC_OK ? substr($out, 0, unpack('Q<', $n)) : undef;
}

# Check a report's tag under $key → ($rc, $ctr).
sub iot_report_check ($key, $wire) {
    my $f = _ffi() or return (RC_BAD_ARG);
    my ($k, $w) = (_bytes($key), _bytes($wire));
    return (RC_BAD_ARG) unless defined $k && length($k) == 32 && defined $w;
    my $ctr = pack('Q<', 0);
    my $rc = $f->{iotcheck}->($k, $w, length $w, $ctr);
    return $rc == RC_OK ? ($rc, unpack('Q<', $ctr)) : ($rc);
}

1;

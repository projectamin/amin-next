package Amin::Crypto::ML_DSA;

# ═══════════════════════════════════════════════════════════════════════════
# ML-DSA-87 (FIPS 204) verification — thin Perl entry point.
#
# C<verify_87($vk, $sig, $msg)> runs the Rust verifier
# (L<Amin::Crypto::Verify> → rust/crates/bitcache, ml-dsa crate) — the same
# code that signs and verifies everywhere else in Amin.  There is no CPAN
# fallback: a second implementation is a second place for the two languages
# to disagree.  Fail-closed: if the Rust library cannot be loaded, every
# signature is rejected.
#
# Signing lives in the Rust toolchain only (bitcache, ainit).
# ═══════════════════════════════════════════════════════════════════════════

use v5.38; use warnings; use utf8;

use Amin::Crypto::Verify ();

use constant MLDSA87_SIG_LEN => 4627;
use constant MLDSA87_VK_LEN  => 2592;

sub can_verify { return Amin::Crypto::Verify::available() }

sub verify_87 {
    my ($vk, $signature, $message) = @_;
    return 0 unless defined $vk && defined $signature && defined $message;
    return 0 if length($vk)        != MLDSA87_VK_LEN;
    return 0 if length($signature) != MLDSA87_SIG_LEN;
    return Amin::Crypto::Verify::mldsa87_verify($vk, $signature, $message);
}

1;

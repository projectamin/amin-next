package Amin::Crypto::ML_DSA;

# ═══════════════════════════════════════════════════════════════════════════
# ML-DSA-87 (FIPS 204) verification — project shim.
#
# The Amin Perl code calls C<verify_87($vk, $sig, $msg)>.  On CPAN the only
# module providing ML-DSA-87 is L<Crypt::Liboqs::Sign>, whose function is
# C<mldsa87_verify($sig, $msg, $pk)> — same algorithm and wire format, but
# **public key is last** instead of second.
#
# This shim reorders arguments and delegates to Crypt::Liboqs::Sign when it is
# installed (it is listed in cpanfile).  When the XS module is absent,
# verify_87 returns 0 (fail-closed): signature-protected paths reject all
# signatures rather than silently accepting them.
#
# ML-DSA signing in the Rust toolchain lives in
# L<crates/bitcache/src/signer.rs> (ml-dsa crate) and L<crates/ainit>.
# The Perl side is verify-only today.
#
# Once a dedicated Crypt::ML_DSA distribution lands on CPAN, replace this file
# with a thin wrapper that re-exports it, or drop it and update callers.
# ═══════════════════════════════════════════════════════════════════════════

use constant MLDSA87_SIG_LEN => 4627;
use constant MLDSA87_VK_LEN  => 2592;

sub verify_87 {
    my ($vk, $signature, $message) = @_;

    return 0 unless defined $vk && defined $signature && defined $message;
    return 0 if length($vk)       != MLDSA87_VK_LEN;
    return 0 if length($signature) != MLDSA87_SIG_LEN;

    my $ok = eval {
        require Crypt::Liboqs::Sign;
        Crypt::Liboqs::Sign::mldsa87_verify($signature, $message, $vk);
    } || 0;

    return $ok ? 1 : 0;
}

1;

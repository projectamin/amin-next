//! Key derivation for AWP/3.
//!
//! Everything is domain-separated by a fixed ASCII `info` string so a key
//! derived for one purpose can never be confused with a key derived for
//! another (cross-protocol attack defence).  The combiner reuses the PQXDH
//! shape — a 32-byte `0xFF` prefix over the concatenated inputs — so an
//! accidental collision with a bare Diffie-Hellman output is impossible.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::aead::ASCON_KEY_LEN;

/// HKDF-SHA256 extract＋expand into `out`.
///
/// # Panics
/// Panics if `out` exceeds HKDF-SHA256's 255·32-byte output limit; every call
/// site here asks for at most 32 bytes, so this cannot fire.
pub fn expand(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * 32, "HKDF-SHA256 output limit exceeded");
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("output length within HKDF-SHA256 limit");
}

/// The PQXDH-style secret combiner: `SK = HKDF(salt = 0³², ikm = 0xFF³² ‖ parts…)`.
///
/// # Panics
/// Panics if the concatenated parts exceed 224 bytes.  The only caller
/// (`handshake`) passes `3·32 + 32 = 128`, so this cannot fire.
#[must_use]
pub fn combine(parts: &[&[u8]]) -> [u8; 32] {
    let mut ikm = [0u8; 256];
    ikm[..32].fill(0xFF);
    let mut n = 32;
    for p in parts {
        let end = n + p.len();
        assert!(end <= ikm.len(), "AWP/3 combiner input too large");
        ikm[n..end].copy_from_slice(p);
        n = end;
    }
    let mut out = [0u8; 32];
    expand(&[0u8; 32], &ikm[..n], b"Amin3/AWP3/Combiner", &mut out);
    out
}

/// Derive the two directional ASCON-128a keys `(initiator→responder, responder→initiator)`
/// from a handshake shared secret.
#[must_use]
pub fn direction_keys(shared_secret: &[u8; 32]) -> ([u8; ASCON_KEY_LEN], [u8; ASCON_KEY_LEN]) {
    let mut i2r = [0u8; ASCON_KEY_LEN];
    let mut r2i = [0u8; ASCON_KEY_LEN];
    expand(&[0u8; 32], shared_secret, b"Amin3/AWP3/i2r", &mut i2r);
    expand(&[0u8; 32], shared_secret, b"Amin3/AWP3/r2i", &mut r2i);
    (i2r, r2i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_is_order_and_prefix_sensitive() {
        let a = combine(&[&[1u8; 32], &[2u8; 32]]);
        let b = combine(&[&[2u8; 32], &[1u8; 32]]);
        assert_ne!(a, b);
        // The fixed 0xFF prefix must not be reachable by accident from inputs.
        let c = combine(&[&[0xFFu8; 32], &[0xFFu8; 32]]);
        assert_ne!(a, c);
    }

    #[test]
    fn direction_keys_are_distinct_and_deterministic() {
        let ss = [7u8; 32];
        let (a, b) = direction_keys(&ss);
        assert_ne!(a, b);
        assert_eq!(direction_keys(&ss), (a, b));
        assert_ne!(a, ss[..ASCON_KEY_LEN]);
    }
}

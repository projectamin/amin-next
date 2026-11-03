//! Key-derivation functions shared by PQXDH and the Double Ratchet.
//!
//! Every derivation is domain-separated by a fixed ASCII `info` string, so a
//! key derived for one purpose can never be confused with a key derived for
//! another (cross-protocol attack defence, mirroring the
//! `AMIN3-BC-MLD87\n` prefix used by the Bitcache `<bc:signer>` envelope).
//!
//! * `kdf_rk`  — root-key ratchet (`HKDF-SHA256`, 64 bytes out).
//! * `kdf_ck`  — symmetric chain ratchet (`HMAC-SHA256`, the Signal KDF chain).
//! * `mk_to_aead` — message key → XChaCha20-Poly1305 key + nonce.
//! * `kdf_pqxdh` — the PQXDH secret combiner.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric key length in bytes (root key, chain key, message key).
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 24;

type HmacSha256 = Hmac<Sha256>;

/// A 32-byte symmetric secret that is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret([u8; KEY_LEN]);

impl Secret {
    /// The all-zero secret, used as an HKDF salt where the protocol
    /// specifies no salt.
    pub const ZERO: Self = Secret([0u8; KEY_LEN]);

    /// Wrap 32 raw bytes.
    #[inline]
    #[must_use]
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Secret(b)
    }

    /// Borrow the raw bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Copy the raw bytes out.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Constant-time equality.
    #[inline]
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..KEY_LEN {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Root-key ratchet step: `HKDF-SHA256(salt = root, ikm = dh_out) → 64 B → (root', chain)`.
///
/// Passing the current root key as the HKDF *salt* (rather than mixing it into
/// the IKM) is what makes each ratchet step depend on all previous steps.
#[must_use]
pub fn kdf_rk(root: &Secret, dh_out: &[u8]) -> (Secret, Secret) {
    let hk = Hkdf::<Sha256>::new(Some(root.as_bytes()), dh_out);
    let mut okm = [0u8; KEY_LEN * 2];
    // 64 bytes is far below HKDF-SHA256's 255·32-byte limit.
    hk.expand(b"Amin3/PQXDH/RootRatchet", &mut okm)
        .expect("64 <= HKDF-SHA256 output limit");
    let split = split32(&okm);
    okm.zeroize();
    split
}

/// Symmetric chain ratchet step: `CK → (CK', MK)`.
///
/// The `0x01` / `0x02` constants are the Signal KDF-chain convention; they keep
/// the message key and the next chain key computationally independent.
#[must_use]
pub fn kdf_ck(ck: &Secret) -> (Secret, Secret) {
    let next = hmac_sha256(ck.as_bytes(), &[0x02]);
    let mk = hmac_sha256(ck.as_bytes(), &[0x01]);
    (Secret(next), Secret(mk))
}

/// Message key → `(XChaCha20-Poly1305 key, 24-byte nonce)`.
///
/// The nonce is derived deterministically from the message key, so a message
/// key is never reused (the chain ratchet guarantees one key per message).
#[must_use]
pub fn mk_to_aead(mk: &Secret) -> ([u8; KEY_LEN], [u8; NONCE_LEN]) {
    let hk = Hkdf::<Sha256>::new(Some(Secret::ZERO.as_bytes()), mk.as_bytes());
    let mut okm = [0u8; KEY_LEN + NONCE_LEN];
    hk.expand(b"Amin3/PQXDH/MessageKeys", &mut okm)
        .expect("56 <= HKDF-SHA256 output limit");
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    key.copy_from_slice(&okm[..KEY_LEN]);
    nonce.copy_from_slice(&okm[KEY_LEN..]);
    okm.zeroize();
    (key, nonce)
}

/// PQXDH secret combiner.
///
/// `SK = HKDF-SHA256(salt = 0³², ikm = F ‖ DH₁ ‖ … ‖ DHₙ ‖ ss_pq)` where `F`
/// is 32 bytes of `0xFF` — the PQXDH prefix that domain-separates the combiner
/// from a bare Diffie-Hellman output.
///
/// # Panics
/// Panics if the concatenated inputs exceed 224 bytes. The only caller
/// (`pqxdh`) passes at most `32 + 4·32 + 32 = 192`, so this cannot fire.
#[must_use]
pub fn kdf_pqxdh(parts: &[&[u8]]) -> Secret {
    let mut ikm = [0u8; 256];
    ikm[..KEY_LEN].fill(0xFF);
    let mut n = KEY_LEN;
    for p in parts {
        let end = n + p.len();
        assert!(end <= ikm.len(), "PQXDH combiner input too large");
        ikm[n..end].copy_from_slice(p);
        n = end;
    }
    let hk = Hkdf::<Sha256>::new(Some(Secret::ZERO.as_bytes()), &ikm[..n]);
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"Amin3/PQXDH/Combiner", &mut out)
        .expect("32 <= HKDF-SHA256 output limit");
    ikm.zeroize();
    Secret(out)
}

#[inline]
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; KEY_LEN] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[inline]
fn split32(okm: &[u8; KEY_LEN * 2]) -> (Secret, Secret) {
    let mut a = [0u8; KEY_LEN];
    let mut b = [0u8; KEY_LEN];
    a.copy_from_slice(&okm[..KEY_LEN]);
    b.copy_from_slice(&okm[KEY_LEN..]);
    (Secret(a), Secret(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_ck_chain_is_deterministic_and_diverges() {
        let ck = Secret::from_bytes([7u8; KEY_LEN]);
        let (next1, mk1) = kdf_ck(&ck);
        let (next2, mk2) = kdf_ck(&ck);
        assert!(next1.ct_eq(&next2));
        assert!(mk1.ct_eq(&mk2));
        // the chain key and the message key must not be equal to each other
        // nor to the input, or the ratchet would leak the next key.
        assert!(!next1.ct_eq(&mk1));
        assert!(!next1.ct_eq(&ck));
        let (next3, _) = kdf_ck(&next1);
        assert!(!next3.ct_eq(&next1));
    }

    #[test]
    fn kdf_rk_depends_on_both_root_and_dh() {
        let root = Secret::from_bytes([1u8; KEY_LEN]);
        let (rk1, ck1) = kdf_rk(&root, &[2u8; KEY_LEN]);
        let (rk2, ck2) = kdf_rk(&root, &[3u8; KEY_LEN]);
        assert!(!rk1.ct_eq(&rk2));
        assert!(!ck1.ct_eq(&ck2));

        let other_root = Secret::from_bytes([9u8; KEY_LEN]);
        let (rk3, _) = kdf_rk(&other_root, &[2u8; KEY_LEN]);
        assert!(!rk1.ct_eq(&rk3));
    }

    #[test]
    fn mk_to_aead_is_deterministic_and_full_length() {
        let mk = Secret::from_bytes([42u8; KEY_LEN]);
        let (k1, n1) = mk_to_aead(&mk);
        let (k2, n2) = mk_to_aead(&mk);
        assert_eq!(k1, k2);
        assert_eq!(n1, n2);
        assert_eq!(n1.len(), NONCE_LEN);
        assert_ne!(k1[..], mk.to_bytes()[..]);
    }

    #[test]
    fn pqxdh_combiner_is_order_and_prefix_sensitive() {
        let a = kdf_pqxdh(&[&[1u8; 32], &[2u8; 32]]);
        let b = kdf_pqxdh(&[&[2u8; 32], &[1u8; 32]]);
        assert!(!a.ct_eq(&b));
        // the fixed 0xFF prefix must not be reachable by accident from inputs
        let c = kdf_pqxdh(&[&[0xFFu8; 32], &[0xFFu8; 32]]);
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn secret_debug_does_not_leak() {
        let s = Secret::from_bytes([1u8; KEY_LEN]);
        assert_eq!(format!("{s:?}"), "Secret(..)");
    }
}

//! XChaCha20-Poly1305 AEAD (RFC 8439 + the 24-byte extended nonce).
//!
//! XChaCha is used rather than ChaCha20-Poly1305 because the Double Ratchet
//! derives message keys and nonces deterministically; a 192-bit nonce makes
//! accidental reuse across a long-lived session impossible rather than merely
//! improbable.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};

use crate::kdf::{KEY_LEN, NONCE_LEN};
use crate::{RatchetError, Result};

/// Encrypt `pt` under `key`/`nonce`, authenticating `aad` as associated data.
///
/// # Errors
/// Only fails if the AEAD backend rejects the parameters, which cannot happen
/// for the fixed key/nonce sizes used here.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: pt,
                aad,
            },
        )
        .map_err(|_| RatchetError::Aead)
}

/// Decrypt a message produced by [`seal`].
///
/// # Errors
/// Returns [`RatchetError::Aead`] for *any* authentication failure — tampering,
/// wrong key, wrong nonce, or wrong associated data are indistinguishable by
/// design.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad,
            },
        )
        .map_err(|_| RatchetError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x11u8; NONCE_LEN];

    #[test]
    fn round_trips() {
        let ct = seal(&KEY, &NONCE, b"hdr", b"hello amin").unwrap();
        assert_ne!(&ct[..], b"hello amin");
        let pt = open(&KEY, &NONCE, b"hdr", &ct).unwrap();
        assert_eq!(pt, b"hello amin");
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let ct = seal(&KEY, &NONCE, b"", b"").unwrap();
        assert_eq!(ct.len(), 16, "poly1305 tag only");
        assert!(open(&KEY, &NONCE, b"", &ct).unwrap().is_empty());
    }

    #[test]
    fn tampering_fails_closed() {
        let mut ct = seal(&KEY, &NONCE, b"hdr", b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert_eq!(open(&KEY, &NONCE, b"hdr", &ct), Err(RatchetError::Aead));
    }

    #[test]
    fn wrong_aad_fails_closed() {
        let ct = seal(&KEY, &NONCE, b"hdr", b"secret").unwrap();
        assert_eq!(open(&KEY, &NONCE, b"other", &ct), Err(RatchetError::Aead));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let ct = seal(&KEY, &NONCE, b"hdr", b"secret").unwrap();
        let mut k = KEY;
        k[0] ^= 0x01;
        assert_eq!(open(&k, &NONCE, b"hdr", &ct), Err(RatchetError::Aead));
    }
}

//! Per-frame AEAD: ASCON-128a (NIST SP 800-232 lightweight cryptography).
//!
//! ASCON-128a is mandated by the AWP/3 contract (docs/proxy-plan.md §6).  The
//! key is 128 bits and the public nonce is 128 bits; the tag is 128 bits and is
//! appended to the ciphertext by the [`ascon_aead`] crate.
//!
//! Nonce uniqueness is provided by the frame codec ([`crate::framing`]): each
//! direction has its own key and the frame sequence number is the nonce, so a
//! nonce can never repeat under one key.

use ascon_aead::{
    aead::{Aead, NewAead, Payload},
    Ascon128a, Key, Nonce,
};

use crate::{Awp3Error, Result};

/// ASCON-128a key length in bytes.
pub const ASCON_KEY_LEN: usize = 16;
/// ASCON-128a public nonce length in bytes.
pub const ASCON_NONCE_LEN: usize = 16;
/// ASCON-128a authentication tag length in bytes.
pub const ASCON_TAG_LEN: usize = 16;

/// Encrypt `pt` under `key`/`nonce`, authenticating `aad` as associated data.
///
/// # Errors
/// Only fails if the AEAD backend rejects the parameters, which cannot happen
/// for the fixed key/nonce sizes used here.
pub fn seal(
    key: &[u8; ASCON_KEY_LEN],
    nonce: &[u8; ASCON_NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    Ascon128a::new(Key::<Ascon128a>::from_slice(key))
        .encrypt(
            Nonce::<Ascon128a>::from_slice(nonce),
            Payload { msg: pt, aad },
        )
        .map_err(|_| Awp3Error::Aead)
}

/// Decrypt a frame produced by [`seal`].
///
/// # Errors
/// Returns [`Awp3Error::Aead`] for *any* authentication failure — tampering,
/// wrong key, wrong nonce or wrong associated data are indistinguishable by
/// design.
pub fn open(
    key: &[u8; ASCON_KEY_LEN],
    nonce: &[u8; ASCON_NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    Ascon128a::new(Key::<Ascon128a>::from_slice(key))
        .decrypt(
            Nonce::<Ascon128a>::from_slice(nonce),
            Payload { msg: ct, aad },
        )
        .map_err(|_| Awp3Error::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; ASCON_KEY_LEN] = [0x5Au8; ASCON_KEY_LEN];
    const NONCE: [u8; ASCON_NONCE_LEN] = [0x11u8; ASCON_NONCE_LEN];

    #[test]
    fn round_trips() {
        let ct = seal(&KEY, &NONCE, b"hdr", b"hello amin").unwrap();
        assert_ne!(&ct[..], b"hello amin");
        assert_eq!(ct.len(), b"hello amin".len() + ASCON_TAG_LEN);
        assert_eq!(open(&KEY, &NONCE, b"hdr", &ct).unwrap(), b"hello amin");
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let ct = seal(&KEY, &NONCE, b"", b"").unwrap();
        assert_eq!(ct.len(), ASCON_TAG_LEN, "tag only");
        assert!(open(&KEY, &NONCE, b"", &ct).unwrap().is_empty());
    }

    #[test]
    fn tampering_wrong_aad_and_wrong_key_fail_closed() {
        let ct = seal(&KEY, &NONCE, b"hdr", b"secret").unwrap();

        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(open(&KEY, &NONCE, b"hdr", &tampered), Err(Awp3Error::Aead));

        assert_eq!(open(&KEY, &NONCE, b"other", &ct), Err(Awp3Error::Aead));

        let mut k = KEY;
        k[0] ^= 0x01;
        assert_eq!(open(&k, &NONCE, b"hdr", &ct), Err(Awp3Error::Aead));
    }
}

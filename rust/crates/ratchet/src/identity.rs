//! ML-DSA-87 identity signatures (FIPS 204, NIST security level 5).
//!
//! This is the *primitive* used to authenticate a device's published prekeys.
//! It is deliberately kept local to the ratchet crate so the crate stays
//! free of storage dependencies; the `<bc:signer>` envelope that carries an
//! identity on the wire lives in the Bitcache crate and uses the same
//! algorithm and the same raw byte encodings, so the two are interchangeable.
//!
//! The device safety number shown to users is `blake3(verifying_key_bytes)`.

use ml_dsa::{
    EncodedVerifyingKey, KeyExport, KeyInit, Keypair as MlKeypair, MlDsa87, Signature,
    SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey, Seed,
};
use rand::{CryptoRng, RngCore};

use crate::{RatchetError, Result};

/// ML-DSA-87 signing-key length (the FIPS 204 32-byte seed).
pub const MLDSA87_SK_LEN: usize = 32;
/// ML-DSA-87 verifying-key length.
pub const MLDSA87_VK_LEN: usize = 2592;
/// ML-DSA-87 signature length.
pub const MLDSA87_SIG_LEN: usize = 4627;

type Sk87 = SigningKey<MlDsa87>;
type Vk87 = VerifyingKey<MlDsa87>;
type Sig87 = Signature<MlDsa87>;

/// An ML-DSA-87 identity signing key.
pub struct IdentitySigningKey(Sk87);

impl IdentitySigningKey {
    /// Generate a fresh identity key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Seed::default();
        rng.fill_bytes(&mut seed);
        Self(<Sk87 as KeyInit>::new(&seed))
    }

    /// Rebuild an identity key from its 32-byte seed.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let seed: Seed = b.try_into().map_err(|_| RatchetError::KeyMaterial)?;
        Ok(Self(<Sk87 as KeyInit>::new(&seed)))
    }

    /// The 32-byte seed, suitable for on-disk storage (mode 0600).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        <Sk87 as KeyExport>::to_bytes(&self.0).as_slice().to_vec()
    }

    /// The matching public identity.
    #[must_use]
    pub fn verifying_key(&self) -> IdentityVerifyingKey {
        IdentityVerifyingKey(<Sk87 as MlKeypair>::verifying_key(&self.0))
    }

    /// Sign `msg`, returning the raw 4627-byte signature.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sig = Signer::<Sig87>::try_sign(&self.0, msg).map_err(|_| RatchetError::Signature)?;
        Ok(sig.to_bytes().as_slice().to_vec())
    }
}

impl core::fmt::Debug for IdentitySigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentitySigningKey(..)")
    }
}

/// An ML-DSA-87 identity verifying key.
#[derive(Clone, PartialEq)]
pub struct IdentityVerifyingKey(Vk87);

impl IdentityVerifyingKey {
    /// Decode a verifying key from its FIPS 204 encoding.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let enc: EncodedVerifyingKey<MlDsa87> =
            b.try_into().map_err(|_| RatchetError::KeyMaterial)?;
        Ok(Self(Vk87::decode(&enc)))
    }

    /// The FIPS 204 encoding of this verifying key.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().as_slice().to_vec()
    }

    /// Verify `sig` over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let sig = Sig87::try_from(sig).map_err(|_| RatchetError::Signature)?;
        Verifier::<Sig87>::verify(&self.0, msg, &sig).map_err(|_| RatchetError::Signature)
    }

    /// The user-visible safety number: `blake3(vk)` in lowercase hex.
    #[must_use]
    pub fn safety_number(&self) -> String {
        blake3::hash(&self.to_bytes()).to_hex().to_string()
    }
}

impl core::fmt::Debug for IdentityVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IdentityVerifyingKey({})", self.safety_number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn sign_verify_and_reject_tampered() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA11_11);
        let sk = IdentitySigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let sig = sk.sign(b"amin sec prekey").unwrap();
        assert_eq!(sig.len(), MLDSA87_SIG_LEN);
        vk.verify(b"amin sec prekey", &sig).unwrap();

        assert_eq!(
            vk.verify(b"amin sec prekey!", &sig),
            Err(RatchetError::Signature)
        );

        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert_eq!(
            vk.verify(b"amin sec prekey", &bad),
            Err(RatchetError::Signature)
        );
    }

    #[test]
    fn key_encoding_round_trips_and_produces_same_vk() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(12);
        let sk = IdentitySigningKey::generate(&mut rng);
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), MLDSA87_SK_LEN);

        let sk2 = IdentitySigningKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk2.verifying_key().to_bytes(), sk.verifying_key().to_bytes());
        assert_eq!(sk2.verifying_key().to_bytes().len(), MLDSA87_VK_LEN);
    }

    #[test]
    fn safety_number_is_stable_and_distinct() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(13);
        let a = IdentitySigningKey::generate(&mut rng).verifying_key();
        let b = IdentitySigningKey::generate(&mut rng).verifying_key();
        assert_eq!(a.safety_number(), a.safety_number());
        assert_ne!(a.safety_number(), b.safety_number());
        assert_eq!(a.safety_number().len(), 64);
    }

    #[test]
    fn wrong_length_key_material_rejected() {
        assert!(matches!(
            IdentitySigningKey::from_bytes(&[0u8; 31]),
            Err(RatchetError::KeyMaterial)
        ));
        assert!(matches!(
            IdentityVerifyingKey::from_bytes(&[0u8; 31]),
            Err(RatchetError::KeyMaterial)
        ));
    }
}

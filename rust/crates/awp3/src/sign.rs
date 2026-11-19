//! Composite (hybrid) authentication: ML-DSA-65 **and** Ed25519.
//!
//! Every handshake transcript and every `.aminsig` artifact is signed by both
//! algorithms and both signatures must verify — an attacker has to break both
//! a lattice signature and Ed25519 to forge a peer (docs/proxy-plan.md §6).
//!
//! The composite verifying key and signature are simply the two encodings
//! concatenated in a fixed order (ML-DSA-65 first), so the on-wire length is a
//! compile-time constant and parsing is a single split:
//!
//! ```text
//!   verifying key = ML-DSA-65 vk (1952) ‖ Ed25519 vk (32)
//!   signature     = ML-DSA-65 sig (3309) ‖ Ed25519 sig (64)
//! ```

use ed25519_dalek::{
    Signature as EdSignature, Signer as EdSigner, SigningKey as EdSigningKey,
    VerifyingKey as EdVerifyingKey,
};
use ml_dsa::{
    EncodedVerifyingKey, KeyExport, KeyInit, Keypair, MlDsa65, Seed, Signature as MlSignature,
    SignatureEncoding, Signer, SigningKey as MlSigningKey, Verifier, VerifyingKey as MlVerifyingKey,
};
use rand::{CryptoRng, RngCore};

use crate::{Awp3Error, Result};

/// ML-DSA-65 signing-key length (the FIPS 204 32-byte seed).
pub const MLDSA65_SEED_LEN: usize = 32;
/// ML-DSA-65 verifying-key length.
pub const MLDSA65_VK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
pub const MLDSA65_SIG_LEN: usize = 3309;
/// Ed25519 seed (signing key) length.
pub const ED25519_SEED_LEN: usize = 32;
/// Ed25519 verifying-key length.
pub const ED25519_VK_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;

/// A composite verifying key: ML-DSA-65 ‖ Ed25519.
pub const COMPOSITE_VK_LEN: usize = MLDSA65_VK_LEN + ED25519_VK_LEN;
/// A composite signature: ML-DSA-65 ‖ Ed25519.
pub const COMPOSITE_SIG_LEN: usize = MLDSA65_SIG_LEN + ED25519_SIG_LEN;

type MlSk = MlSigningKey<MlDsa65>;
type MlVk = MlVerifyingKey<MlDsa65>;
type MlSig = MlSignature<MlDsa65>;

/// A composite signing key (ML-DSA-65 + Ed25519), cloneable so a finished
/// session can retain it to sign the close receipt.
#[derive(Clone)]
pub struct CompositeSigningKey {
    ml: MlSk,
    ed: EdSigningKey,
}

impl CompositeSigningKey {
    /// Generate a fresh key from the caller's CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut ml_seed = [0u8; MLDSA65_SEED_LEN];
        let mut ed_seed = [0u8; ED25519_SEED_LEN];
        rng.fill_bytes(&mut ml_seed);
        rng.fill_bytes(&mut ed_seed);
        Self::from_seeds(&ml_seed, &ed_seed)
    }

    /// Rebuild from the two 32-byte seeds, for deterministic test vectors and
    /// on-disk storage (mode 0600).
    #[must_use]
    pub fn from_seeds(ml_seed: &[u8; MLDSA65_SEED_LEN], ed_seed: &[u8; ED25519_SEED_LEN]) -> Self {
        let seed = Seed::from(*ml_seed);
        Self {
            ml: <MlSk as KeyInit>::new(&seed),
            ed: EdSigningKey::from_bytes(ed_seed),
        }
    }

    /// The two seeds, in (ML-DSA-65, Ed25519) order.
    #[must_use]
    pub fn to_seeds(&self) -> ([u8; MLDSA65_SEED_LEN], [u8; ED25519_SEED_LEN]) {
        let ml = <MlSk as KeyExport>::to_bytes(&self.ml);
        let mut ml_seed = [0u8; MLDSA65_SEED_LEN];
        ml_seed.copy_from_slice(ml.as_slice());
        (ml_seed, self.ed.to_bytes())
    }

    /// The matching composite verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> CompositeVerifyingKey {
        CompositeVerifyingKey {
            ml: <MlSk as Keypair>::verifying_key(&self.ml).encode().as_slice().to_vec(),
            ed: self.ed.verifying_key().to_bytes(),
        }
    }

    /// Sign `msg` with both algorithms, returning `MLDSA65_SIG_LEN + 64` bytes.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let ml = <MlSk as Signer<MlSig>>::try_sign(&self.ml, msg)
            .map_err(|_| Awp3Error::Signature)?
            .to_bytes();
        let ed = <EdSigningKey as EdSigner<EdSignature>>::sign(&self.ed, msg).to_bytes();
        let mut out = Vec::with_capacity(COMPOSITE_SIG_LEN);
        out.extend_from_slice(ml.as_slice());
        out.extend_from_slice(&ed);
        Ok(out)
    }
}

impl core::fmt::Debug for CompositeSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CompositeSigningKey(..)")
    }
}

/// A composite verifying key (ML-DSA-65 ‖ Ed25519).
#[derive(Clone, PartialEq, Eq)]
pub struct CompositeVerifyingKey {
    ml: Vec<u8>,
    ed: [u8; ED25519_VK_LEN],
}

impl CompositeVerifyingKey {
    /// Decode a verifying key from its 1984-byte composite encoding.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != COMPOSITE_VK_LEN {
            return Err(Awp3Error::KeyMaterial);
        }
        let ml = b[..MLDSA65_VK_LEN].to_vec();
        // Reject an ML-DSA vk that is not a valid FIPS 204 encoding.
        let enc: EncodedVerifyingKey<MlDsa65> =
            ml.as_slice().try_into().map_err(|_| Awp3Error::KeyMaterial)?;
        let _ = MlVk::decode(&enc);
        let mut ed = [0u8; ED25519_VK_LEN];
        ed.copy_from_slice(&b[MLDSA65_VK_LEN..]);
        Ok(Self { ml, ed })
    }

    /// The 1984-byte composite encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COMPOSITE_VK_LEN);
        out.extend_from_slice(&self.ml);
        out.extend_from_slice(&self.ed);
        out
    }

    /// Verify a composite signature.  Both halves must verify.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != COMPOSITE_SIG_LEN {
            return Err(Awp3Error::Signature);
        }
        let enc: EncodedVerifyingKey<MlDsa65> =
            self.ml.as_slice().try_into().map_err(|_| Awp3Error::KeyMaterial)?;
        let vk = MlVk::decode(&enc);
        let ml_sig = MlSig::try_from(&sig[..MLDSA65_SIG_LEN]).map_err(|_| Awp3Error::Signature)?;
        <MlVk as Verifier<MlSig>>::verify(&vk, msg, &ml_sig).map_err(|_| Awp3Error::Signature)?;

        let mut ed_bytes = [0u8; ED25519_SIG_LEN];
        ed_bytes.copy_from_slice(&sig[MLDSA65_SIG_LEN..]);
        let ed_sig = EdSignature::from_bytes(&ed_bytes);
        let ed_vk = EdVerifyingKey::from_bytes(&self.ed).map_err(|_| Awp3Error::KeyMaterial)?;
        ed_vk
            .verify_strict(msg, &ed_sig)
            .map_err(|_| Awp3Error::Signature)
    }
}

impl core::fmt::Debug for CompositeVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CompositeVerifyingKey({})", blake3::hash(&self.to_bytes()).to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn sizes_match_the_contract() {
        assert_eq!(COMPOSITE_VK_LEN, 1984);
        assert_eq!(COMPOSITE_SIG_LEN, 3373);
    }

    #[test]
    fn sign_verify_round_trips_and_rejects_tampering() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let sk = CompositeSigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let sig = sk.sign(b"amin awp3").unwrap();
        assert_eq!(sig.len(), COMPOSITE_SIG_LEN);
        vk.verify(b"amin awp3", &sig).unwrap();

        // Wrong message fails (both halves sign the same message).
        assert_eq!(vk.verify(b"amin awp3!", &sig), Err(Awp3Error::Signature));

        // Tampering with the Ed25519 half alone must still fail closed.
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert_eq!(vk.verify(b"amin awp3", &bad), Err(Awp3Error::Signature));

        // Tampering with the ML-DSA half alone must still fail closed.
        let mut bad2 = sig.clone();
        bad2[0] ^= 0x01;
        assert_eq!(vk.verify(b"amin awp3", &bad2), Err(Awp3Error::Signature));
    }

    #[test]
    fn seeds_round_trip_to_the_same_identity() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let sk = CompositeSigningKey::generate(&mut rng);
        let (ml, ed) = sk.to_seeds();
        let sk2 = CompositeSigningKey::from_seeds(&ml, &ed);
        assert_eq!(sk.verifying_key().to_bytes(), sk2.verifying_key().to_bytes());
    }

    #[test]
    fn verifying_key_encoding_round_trips() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let vk = CompositeSigningKey::generate(&mut rng).verifying_key();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), COMPOSITE_VK_LEN);
        assert_eq!(CompositeVerifyingKey::from_bytes(&bytes).unwrap(), vk);
        assert_eq!(
            CompositeVerifyingKey::from_bytes(&bytes[..10]),
            Err(Awp3Error::KeyMaterial)
        );
    }
}

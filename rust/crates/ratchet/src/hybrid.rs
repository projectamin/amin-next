//! Hybrid key-agreement primitives: X25519 Diffie-Hellman + ML-KEM-768.
//!
//! The pair is what makes PQXDH post-quantum: an attacker must break *both*
//! the elliptic-curve DH and the lattice KEM to recover the shared secret.
//! Wire sizes below are the FIPS 203 ML-KEM-768 values and are asserted
//! against the crate's own type-level sizes in the tests.

use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{RatchetError, Result};

/// X25519 public key / shared secret length in bytes.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation (public) key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 decapsulation (private) key length.
pub const MLKEM768_DK_LEN: usize = 2400;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM-768 shared-secret length.
pub const MLKEM768_SS_LEN: usize = 32;

/// ML-KEM-768 encapsulation key.
pub type MlKem768Ek = <MlKem768 as KemCore>::EncapsulationKey;
/// ML-KEM-768 decapsulation key.
pub type MlKem768Dk = <MlKem768 as KemCore>::DecapsulationKey;

/// An X25519 static key pair.
///
/// Used for identity DH keys, published prekeys, and the Double Ratchet's
/// Diffie-Hellman ratchet keys. `x25519-dalek` does not zeroize `StaticSecret`
/// unless its `zeroize` feature is enabled, which Amin does not pull in; the
/// surrounding [`crate::kdf::Secret`] values *are* zeroized.
#[derive(Clone)]
pub struct X25519Keypair(StaticSecret);

impl X25519Keypair {
    /// Generate a fresh key pair.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }

    /// Rebuild a key pair from its 32 raw secret bytes.
    #[must_use]
    pub fn from_secret_bytes(b: [u8; X25519_LEN]) -> Self {
        Self(StaticSecret::from(b))
    }

    /// The raw secret bytes.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; X25519_LEN] {
        self.0.to_bytes()
    }

    /// The corresponding public key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; X25519_LEN] {
        PublicKey::from(&self.0).to_bytes()
    }

    /// Diffie-Hellman against a peer's public key.
    #[must_use]
    pub fn dh(&self, their_public: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
        self.0
            .diffie_hellman(&PublicKey::from(*their_public))
            .to_bytes()
    }
}

impl core::fmt::Debug for X25519Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519Keypair(..)")
    }
}

/// Derive the X25519 public key for a raw secret without building a key pair.
#[must_use]
pub fn x25519_public(secret: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Generate an ML-KEM-768 (decapsulation, encapsulation) key pair.
pub fn mlkem768_generate<R: RngCore + CryptoRng>(rng: &mut R) -> (MlKem768Dk, MlKem768Ek) {
    MlKem768::generate(rng)
}

/// Encapsulate a fresh shared secret to `ek`: returns `(ciphertext, shared secret)`.
pub fn mlkem768_encaps<R: RngCore + CryptoRng>(
    ek: &MlKem768Ek,
    rng: &mut R,
) -> Result<(Vec<u8>, [u8; MLKEM768_SS_LEN])> {
    let (ct, ss) = ek.encapsulate(rng).map_err(|_| RatchetError::Kem)?;
    let ss = ss.as_slice().try_into().map_err(|_| RatchetError::Kem)?;
    Ok((ct.as_slice().to_vec(), ss))
}

/// Decapsulate the shared secret carried by `ct`.
pub fn mlkem768_decaps(dk: &MlKem768Dk, ct: &[u8]) -> Result<[u8; MLKEM768_SS_LEN]> {
    let ct = ct.try_into().map_err(|_| RatchetError::Kem)?;
    let ss = dk.decapsulate(&ct).map_err(|_| RatchetError::Kem)?;
    ss.as_slice().try_into().map_err(|_| RatchetError::Kem)
}

/// Encode an ML-KEM-768 encapsulation key.
#[must_use]
pub fn mlkem768_ek_to_bytes(ek: &MlKem768Ek) -> Vec<u8> {
    ek.as_bytes().as_slice().to_vec()
}

/// Decode an ML-KEM-768 encapsulation key.
pub fn mlkem768_ek_from_bytes(b: &[u8]) -> Result<MlKem768Ek> {
    let enc: Encoded<MlKem768Ek> = b.try_into().map_err(|_| RatchetError::KeyMaterial)?;
    Ok(MlKem768Ek::from_bytes(&enc))
}

/// Encode an ML-KEM-768 decapsulation key.
#[must_use]
pub fn mlkem768_dk_to_bytes(dk: &MlKem768Dk) -> Vec<u8> {
    dk.as_bytes().as_slice().to_vec()
}

/// Decode an ML-KEM-768 decapsulation key.
pub fn mlkem768_dk_from_bytes(b: &[u8]) -> Result<MlKem768Dk> {
    let enc: Encoded<MlKem768Dk> = b.try_into().map_err(|_| RatchetError::KeyMaterial)?;
    Ok(MlKem768Dk::from_bytes(&enc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn mlkem768_wire_sizes_match_fips203() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let (dk, ek) = mlkem768_generate(&mut rng);
        assert_eq!(mlkem768_ek_to_bytes(&ek).len(), MLKEM768_EK_LEN);
        assert_eq!(mlkem768_dk_to_bytes(&dk).len(), MLKEM768_DK_LEN);
        let (ct, _) = mlkem768_encaps(&ek, &mut rng).unwrap();
        assert_eq!(ct.len(), MLKEM768_CT_LEN);
    }

    #[test]
    fn mlkem768_encaps_decaps_agree() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let (dk, ek) = mlkem768_generate(&mut rng);
        let (ct, sender_ss) = mlkem768_encaps(&ek, &mut rng).unwrap();
        let recv_ss = mlkem768_decaps(&dk, &ct).unwrap();
        assert_eq!(sender_ss, recv_ss);
    }

    #[test]
    fn mlkem768_key_encoding_round_trips() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let (dk, ek) = mlkem768_generate(&mut rng);
        let ek2 = mlkem768_ek_from_bytes(&mlkem768_ek_to_bytes(&ek)).unwrap();
        assert_eq!(mlkem768_ek_to_bytes(&ek2), mlkem768_ek_to_bytes(&ek));
        let dk2 = mlkem768_dk_from_bytes(&mlkem768_dk_to_bytes(&dk)).unwrap();
        let (ct, ss) = mlkem768_encaps(&ek2, &mut rng).unwrap();
        assert_eq!(mlkem768_decaps(&dk2, &ct).unwrap(), ss);
    }

    #[test]
    fn mlkem768_rejects_wrong_length_keys() {
        assert!(matches!(
            mlkem768_ek_from_bytes(&[0u8; 17]),
            Err(RatchetError::KeyMaterial)
        ));
        assert!(matches!(
            mlkem768_dk_from_bytes(&[0u8; 17]),
            Err(RatchetError::KeyMaterial)
        ));
    }

    #[test]
    fn x25519_dh_is_symmetric() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(4);
        let a = X25519Keypair::generate(&mut rng);
        let b = X25519Keypair::generate(&mut rng);
        assert_eq!(a.dh(&b.public_bytes()), b.dh(&a.public_bytes()));
        assert_eq!(x25519_public(&a.secret_bytes()), a.public_bytes());
        assert_eq!(
            X25519Keypair::from_secret_bytes(a.secret_bytes()).public_bytes(),
            a.public_bytes()
        );
    }
}

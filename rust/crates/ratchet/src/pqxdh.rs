//! PQXDH — the X3DH handshake with a post-quantum ML-KEM-768 encapsulation.
//!
//! A publisher (Bob) advertises a [`PrekeyBundle`]. An initiator (Alice)
//! verifies the bundle, mixes four Diffie-Hellman outputs with an ML-KEM
//! shared secret, and sends a [`PqxdhInitialMessage`]. Both sides then hold
//! the identical 32-byte `SK`, which seeds the Double Ratchet in
//! [`crate::session`].
//!
//! ```text
//!   DH1 = DH(IK_A, SPK_B)      DH2 = DH(EK_A, IK_B)
//!   DH3 = DH(EK_A, SPK_B)      DH4 = DH(EK_A, OPK_B)   (optional)
//!   (ct, ss) = ML-KEM-768.Encaps(PQSPK_B)
//!   SK = HKDF(F ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss)
//! ```
//!
//! The responder's signed prekey doubles as the initial Diffie-Hellman ratchet
//! public key, exactly as in the Double Ratchet specification (§3.3).

use rand::{CryptoRng, RngCore};

use crate::hybrid::{
    mlkem768_decaps, mlkem768_ek_from_bytes, mlkem768_ek_to_bytes, mlkem768_encaps,
    mlkem768_generate, MlKem768Dk, X25519Keypair, X25519_LEN,
};
use crate::identity::{IdentitySigningKey, IdentityVerifyingKey};
use crate::kdf::{kdf_pqxdh, Secret};
use crate::{RatchetError, Result};

const SPK_DOMAIN: &[u8] = b"Amin3/PQXDH/SignedPrekey\n";
const PQSPK_DOMAIN: &[u8] = b"Amin3/PQXDH/PQPrekey\n";

/// The exact bytes a publisher signs to authenticate its signed prekey.
///
/// Binding the identity DH key and the prekey id stops an attacker replaying a
/// valid signature onto a substituted key or a different generation.
#[must_use]
pub fn signed_prekey_payload(
    identity_dh: &[u8; X25519_LEN],
    signed_prekey: &[u8; X25519_LEN],
    prekey_id: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(SPK_DOMAIN.len() + 2 * X25519_LEN + 4);
    v.extend_from_slice(SPK_DOMAIN);
    v.extend_from_slice(identity_dh);
    v.extend_from_slice(signed_prekey);
    v.extend_from_slice(&prekey_id.to_le_bytes());
    v
}

/// The exact bytes a publisher signs to authenticate its ML-KEM-768 prekey.
#[must_use]
pub fn pq_prekey_payload(identity_dh: &[u8; X25519_LEN], pq_prekey: &[u8], prekey_id: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(PQSPK_DOMAIN.len() + X25519_LEN + pq_prekey.len() + 4);
    v.extend_from_slice(PQSPK_DOMAIN);
    v.extend_from_slice(identity_dh);
    v.extend_from_slice(pq_prekey);
    v.extend_from_slice(&prekey_id.to_le_bytes());
    v
}

/// A publisher's public prekey bundle.
///
/// `Debug` deliberately redacts nothing here — every field is public.
#[derive(Clone, PartialEq, Eq)]
pub struct PrekeyBundle {
    /// The publisher's ML-DSA-87 identity verifying key.
    pub identity_vk: Vec<u8>,
    /// The publisher's X25519 identity DH public key (`IK_B`).
    pub identity_dh: [u8; X25519_LEN],
    /// The publisher's signed prekey (`SPK_B`), public half.
    pub signed_prekey: [u8; X25519_LEN],
    /// ML-DSA-87 signature over [`signed_prekey_payload`].
    pub signed_prekey_sig: Vec<u8>,
    /// The publisher's ML-KEM-768 encapsulation key.
    pub pq_prekey: Vec<u8>,
    /// ML-DSA-87 signature over [`pq_prekey_payload`].
    pub pq_prekey_sig: Vec<u8>,
    /// An optional one-time prekey, consumed by a single handshake.
    pub one_time_prekey: Option<[u8; X25519_LEN]>,
    /// Opaque generation id, used to select the matching private prekeys.
    pub prekey_id: u32,
}

impl PrekeyBundle {
    /// Verify both prekey signatures against the bundled identity key.
    ///
    /// Callers MUST first establish that `identity_vk` really belongs to the
    /// peer (QR scan, trust anchor, or a verified safety-number upgrade); this
    /// method only proves the prekeys were signed by that identity.
    pub fn verify(&self) -> Result<()> {
        let vk = IdentityVerifyingKey::from_bytes(&self.identity_vk)?;
        vk.verify(
            &signed_prekey_payload(&self.identity_dh, &self.signed_prekey, self.prekey_id),
            &self.signed_prekey_sig,
        )?;
        vk.verify(
            &pq_prekey_payload(&self.identity_dh, &self.pq_prekey, self.prekey_id),
            &self.pq_prekey_sig,
        )
    }

    /// The peer's safety number, for out-of-band comparison.
    pub fn safety_number(&self) -> Result<String> {
        Ok(IdentityVerifyingKey::from_bytes(&self.identity_vk)?.safety_number())
    }
}

impl core::fmt::Debug for PrekeyBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrekeyBundle")
            .field("identity_dh", &hex(&self.identity_dh))
            .field("signed_prekey", &hex(&self.signed_prekey))
            .field("one_time_prekey", &self.one_time_prekey.as_ref().map(hex))
            .field("prekey_id", &self.prekey_id)
            .finish_non_exhaustive()
    }
}

/// A publisher's private half of a [`PrekeyBundle`].
///
/// A one-time prekey must be deleted after a successful [`respond`] so a
/// captured initial message cannot be replayed against it.
pub struct ResponderPrekeys {
    /// The publisher's identity DH key pair.
    pub identity_dh: X25519Keypair,
    /// The signed prekey key pair (also the initial ratchet key).
    pub signed_prekey: X25519Keypair,
    /// The optional one-time prekey key pair.
    pub one_time_prekey: Option<X25519Keypair>,
    /// The ML-KEM-768 decapsulation key.
    pub pq_prekey: MlKem768Dk,
}

impl ResponderPrekeys {
    /// Generate a fresh prekey set and the signed bundle to publish.
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        identity: &IdentitySigningKey,
        prekey_id: u32,
        with_one_time_prekey: bool,
    ) -> Result<(Self, PrekeyBundle)> {
        let identity_dh = X25519Keypair::generate(rng);
        let identity_dh_pub = identity_dh.public_bytes();

        let signed_prekey = X25519Keypair::generate(rng);
        let signed_prekey_pub = signed_prekey.public_bytes();

        let one_time_prekey = with_one_time_prekey.then(|| X25519Keypair::generate(rng));

        let (pq_prekey, pq_ek) = mlkem768_generate(rng);
        let pq_ek_bytes = mlkem768_ek_to_bytes(&pq_ek);

        let spk_sig = identity.sign(&signed_prekey_payload(
            &identity_dh_pub,
            &signed_prekey_pub,
            prekey_id,
        ))?;
        let pq_sig = identity.sign(&pq_prekey_payload(&identity_dh_pub, &pq_ek_bytes, prekey_id))?;

        let bundle = PrekeyBundle {
            identity_vk: identity.verifying_key().to_bytes(),
            identity_dh: identity_dh_pub,
            signed_prekey: signed_prekey_pub,
            signed_prekey_sig: spk_sig,
            pq_prekey: pq_ek_bytes,
            pq_prekey_sig: pq_sig,
            one_time_prekey: one_time_prekey.as_ref().map(X25519Keypair::public_bytes),
            prekey_id,
        };

        Ok((
            Self {
                identity_dh,
                signed_prekey,
                one_time_prekey,
                pq_prekey,
            },
            bundle,
        ))
    }
}

impl core::fmt::Debug for ResponderPrekeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponderPrekeys")
            .field("prekey_id_carrier", &"(secret key material)")
            .finish_non_exhaustive()
    }
}

/// The initiator's initial message: everything the responder needs to derive `SK`.
#[derive(Clone, PartialEq, Eq)]
pub struct PqxdhInitialMessage {
    /// The initiator's identity DH public key (`IK_A`).
    pub identity_dh: [u8; X25519_LEN],
    /// The initiator's ephemeral DH public key (`EK_A`).
    pub ephemeral: [u8; X25519_LEN],
    /// The ML-KEM-768 ciphertext encapsulating `ss`.
    pub pq_ciphertext: Vec<u8>,
    /// Selects which of the responder's private prekeys to use.
    pub prekey_id: u32,
    /// Whether the responder's one-time prekey was consumed.
    pub used_one_time_prekey: bool,
}

impl core::fmt::Debug for PqxdhInitialMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqxdhInitialMessage")
            .field("identity_dh", &hex(&self.identity_dh))
            .field("ephemeral", &hex(&self.ephemeral))
            .field("pq_ciphertext_len", &self.pq_ciphertext.len())
            .field("prekey_id", &self.prekey_id)
            .field("used_one_time_prekey", &self.used_one_time_prekey)
            .finish()
    }
}

/// Run the initiator half of PQXDH.
///
/// Returns the shared secret, the message to send, and the responder's signed
/// prekey — which is the initial Diffie-Hellman ratchet public key for
/// [`crate::Session::init_initiator`].
///
/// # Errors
/// Fails if the bundle's signatures do not verify or the ML-KEM prekey is
/// malformed.
pub fn initiate<R: RngCore + CryptoRng>(
    bundle: &PrekeyBundle,
    initiator_identity_dh: &X25519Keypair,
    rng: &mut R,
) -> Result<(Secret, PqxdhInitialMessage, [u8; X25519_LEN])> {
    bundle.verify()?;

    let ephemeral = X25519Keypair::generate(rng);
    let dh1 = initiator_identity_dh.dh(&bundle.signed_prekey);
    let dh2 = ephemeral.dh(&bundle.identity_dh);
    let dh3 = ephemeral.dh(&bundle.signed_prekey);

    let pq_ek = mlkem768_ek_from_bytes(&bundle.pq_prekey)?;
    let (pq_ciphertext, pq_ss) = mlkem768_encaps(&pq_ek, rng)?;

    let dh4 = bundle.one_time_prekey.map(|opk| ephemeral.dh(&opk));

    let mut parts: Vec<&[u8]> = vec![&dh1[..], &dh2[..], &dh3[..]];
    if let Some(dh4) = &dh4 {
        parts.push(&dh4[..]);
    }
    parts.push(&pq_ss[..]);
    let sk = kdf_pqxdh(&parts);

    let message = PqxdhInitialMessage {
        identity_dh: initiator_identity_dh.public_bytes(),
        ephemeral: ephemeral.public_bytes(),
        pq_ciphertext,
        prekey_id: bundle.prekey_id,
        used_one_time_prekey: dh4.is_some(),
    };
    Ok((sk, message, bundle.signed_prekey))
}

/// Run the responder half of PQXDH.
///
/// Returns the shared secret and the signed prekey public key, i.e. the
/// initial ratchet key for [`crate::Session::init_responder`].
///
/// # Errors
/// Fails if `msg` consumed a one-time prekey that `prekeys` does not have (a
/// replayed initial message), or if the ML-KEM ciphertext is malformed.
pub fn respond(
    msg: &PqxdhInitialMessage,
    prekeys: &ResponderPrekeys,
) -> Result<(Secret, [u8; X25519_LEN])> {
    if msg.used_one_time_prekey != prekeys.one_time_prekey.is_some() {
        // Either a replay after the one-time prekey was consumed, or the
        // initiator referenced a prekey we never published.
        return Err(RatchetError::KeyMaterial);
    }

    let dh1 = prekeys.signed_prekey.dh(&msg.identity_dh);
    let dh2 = prekeys.identity_dh.dh(&msg.ephemeral);
    let dh3 = prekeys.signed_prekey.dh(&msg.ephemeral);
    let dh4 = prekeys
        .one_time_prekey
        .as_ref()
        .map(|opk| opk.dh(&msg.ephemeral));

    let mut parts: Vec<&[u8]> = vec![&dh1[..], &dh2[..], &dh3[..]];
    if let Some(dh4) = &dh4 {
        parts.push(&dh4[..]);
    }
    let pq_ss = mlkem768_decaps(&prekeys.pq_prekey, &msg.pq_ciphertext)?;
    parts.push(&pq_ss[..]);

    Ok((kdf_pqxdh(&parts), prekeys.signed_prekey.public_bytes()))
}

fn hex<const N: usize>(b: &[u8; N]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(N * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    struct Party {
        identity: IdentitySigningKey,
        prekeys: ResponderPrekeys,
        bundle: PrekeyBundle,
    }

    fn publisher(seed: u64, with_otp: bool) -> Party {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let identity = IdentitySigningKey::generate(&mut rng);
        let (prekeys, bundle) =
            ResponderPrekeys::generate(&mut rng, &identity, 1, with_otp).unwrap();
        Party {
            identity,
            prekeys,
            bundle,
        }
    }

    #[test]
    fn handshake_agrees_with_and_without_one_time_prekey() {
        for with_otp in [false, true] {
            let bob = publisher(21 + u64::from(with_otp), with_otp);

            let mut rng = rand::rngs::StdRng::seed_from_u64(77);
            let alice_identity_dh = X25519Keypair::generate(&mut rng);

            let (sk_a, msg, ratchet_pub_a) =
                initiate(&bob.bundle, &alice_identity_dh, &mut rng).unwrap();
            let (sk_b, ratchet_pub_b) = respond(&msg, &bob.prekeys).unwrap();

            assert!(sk_a.ct_eq(&sk_b), "PQXDH shared secrets must agree");
            assert_eq!(ratchet_pub_a, ratchet_pub_b);
            assert_eq!(ratchet_pub_a, bob.bundle.signed_prekey);
            assert_eq!(msg.used_one_time_prekey, with_otp);
        }
    }

    #[test]
    fn bundle_signature_tamper_is_rejected() {
        let bob = publisher(31, true);

        let mut bad_dh = bob.bundle.clone();
        bad_dh.identity_dh[0] ^= 0x01;
        assert_eq!(bad_dh.verify(), Err(RatchetError::Signature));

        let mut bad_spk = bob.bundle.clone();
        bad_spk.signed_prekey[5] ^= 0x01;
        assert!(bad_spk.verify().is_err());

        let mut bad_pq = bob.bundle.clone();
        bad_pq.pq_prekey[100] ^= 0x01;
        assert!(bad_pq.verify().is_err());

        // A bundle re-signed by a different identity must not verify against
        // the original identity key.
        let mallory = publisher(32, true);
        let mut swapped = bob.bundle.clone();
        swapped.identity_vk = mallory.bundle.identity_vk.clone();
        assert!(swapped.verify().is_err());
    }

    #[test]
    fn initiate_refuses_unverified_bundle() {
        let bob = publisher(41, false);
        let mut bundle = bob.bundle.clone();
        bundle.signed_prekey_sig[..8].fill(0);

        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        let alice = X25519Keypair::generate(&mut rng);
        assert_eq!(
            initiate(&bundle, &alice, &mut rng).unwrap_err(),
            RatchetError::Signature
        );
    }

    #[test]
    fn replayed_initial_message_is_rejected_once_otp_is_consumed() {
        let bob = publisher(51, true);
        let mut rng = rand::rngs::StdRng::seed_from_u64(6);
        let alice = X25519Keypair::generate(&mut rng);
        let (_, msg, _) = initiate(&bob.bundle, &alice, &mut rng).unwrap();

        let mut prekeys = bob.prekeys;
        prekeys.one_time_prekey = None; // consumed by the first handshake
        assert_eq!(
            respond(&msg, &prekeys).unwrap_err(),
            RatchetError::KeyMaterial
        );
    }

    #[test]
    fn safety_number_matches_identity() {
        let bob = publisher(61, false);
        assert_eq!(
            bob.bundle.safety_number().unwrap(),
            bob.identity.verifying_key().safety_number()
        );
    }
}

//! The AWP/3 handshake: an XK-shaped, two-flight hybrid post-quantum exchange.
//!
//! ```text
//!   responder bundle (public, self-signed):  version ‖ s_r ‖ pq_ek_r ‖ vk_r ‖ sig_r
//!
//!   msg1 (initiator → responder):
//!     version ‖ e_i ‖ pq_ct ‖ vk_i ‖ ik_i ‖ sig_i
//!     sig_i = Composite(IK_i, "Amin3/AWP3/msg1" ‖ body)
//!
//!   msg2 (responder → initiator):
//!     version ‖ e_r ‖ sig_r
//!     sig_r = Composite(IK_r, "Amin3/AWP3/msg2" ‖ e_r ‖ BLAKE3(msg1))
//!
//!   dh1 = X25519(e_i, s_r)   dh2 = X25519(e_i, e_r)   dh3 = X25519(ik_i, e_r)
//!   pq  = ML-KEM-768.Encaps(pq_ek_r)
//!   ss  = Combiner(dh1 ‖ dh2 ‖ dh3 ‖ pq)      →  Session
//! ```
//!
//! The initiator authenticates the responder against the identity it already
//! trusts (the bundle).  The responder *learns* the initiator's identity from
//! `msg1` and verifies the composite signature over it; it then applies its own
//! authorization policy — being authenticated is not being authorized
//! (docs/proxy-plan.md §5.12).

use blake3::Hasher;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::kdf;
use crate::sign::{CompositeSigningKey, CompositeVerifyingKey, COMPOSITE_VK_LEN};
use crate::{Awp3Error, Result, VERSION};

const BUNDLE_DOMAIN: &[u8] = b"Amin3/AWP3/bundle";
const MSG1_DOMAIN: &[u8] = b"Amin3/AWP3/msg1";
const MSG2_DOMAIN: &[u8] = b"Amin3/AWP3/msg2";

/// X25519 public key / shared secret length.
pub const X25519_LEN: usize = 32;
/// ML-KEM-768 encapsulation key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

/// The public portion of a responder bundle: `version ‖ s_r ‖ pq_ek_r ‖ vk_r`.
pub const BUNDLE_BODY_LEN: usize = 1 + X25519_LEN + MLKEM768_EK_LEN + COMPOSITE_VK_LEN;
/// A complete signed responder bundle.
pub const BUNDLE_LEN: usize = BUNDLE_BODY_LEN + crate::sign::COMPOSITE_SIG_LEN;

/// The `msg1` body: `version ‖ e_i ‖ pq_ct ‖ vk_i ‖ ik_i`.
pub const MSG1_BODY_LEN: usize = 1 + X25519_LEN + MLKEM768_CT_LEN + COMPOSITE_VK_LEN + X25519_LEN;
/// A complete `msg1`.
pub const MSG1_LEN: usize = MSG1_BODY_LEN + crate::sign::COMPOSITE_SIG_LEN;

/// The `msg2` body: `version ‖ e_r`.
pub const MSG2_BODY_LEN: usize = 1 + X25519_LEN;
/// A complete `msg2`.
pub const MSG2_LEN: usize = MSG2_BODY_LEN + crate::sign::COMPOSITE_SIG_LEN;

fn domain_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + body.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(body);
    v
}

/// A responder's static identity: a composite signing key, an X25519 static DH
/// key, and an ML-KEM-768 decapsulation key.  Everything else is derived.
pub struct ResponderIdentity {
    signer: CompositeSigningKey,
    static_dh: StaticSecret,
    pq_dk: Dk,
}

impl ResponderIdentity {
    /// Generate a fresh static identity.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            signer: CompositeSigningKey::generate(rng),
            static_dh: StaticSecret::random_from_rng(&mut *rng),
            pq_dk: MlKem768::generate(rng).0,
        }
    }

    /// The signature (composite) signing key, for reuse across connections.
    #[must_use]
    pub fn signing_key(&self) -> &CompositeSigningKey {
        &self.signer
    }

    /// The self-signed public bundle a peer needs in order to connect.
    pub fn bundle(&self) -> Result<Vec<u8>> {
        let s_r = PublicKey::from(&self.static_dh).to_bytes();
        let ek = self.pq_dk.encapsulation_key().as_bytes();
        let vk = self.signer.verifying_key().to_bytes();

        let mut body = Vec::with_capacity(BUNDLE_BODY_LEN);
        body.push(VERSION);
        body.extend_from_slice(&s_r);
        body.extend_from_slice(ek.as_slice());
        body.extend_from_slice(&vk);
        debug_assert_eq!(body.len(), BUNDLE_BODY_LEN);

        let sig = self.signer.sign(&domain_input(BUNDLE_DOMAIN, &body))?;
        body.extend_from_slice(&sig);
        Ok(body)
    }
}

impl core::fmt::Debug for ResponderIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ResponderIdentity(..)")
    }
}

struct BundleParts {
    static_dh: [u8; X25519_LEN],
    pq_ek: Ek,
    vk: CompositeVerifyingKey,
}

/// Parse and verify a responder bundle.
fn parse_bundle(b: &[u8]) -> Result<BundleParts> {
    if b.len() != BUNDLE_LEN || b[0] != VERSION {
        return Err(Awp3Error::Handshake);
    }
    let vk = CompositeVerifyingKey::from_bytes(&b[1 + X25519_LEN + MLKEM768_EK_LEN..BUNDLE_BODY_LEN])?;
    vk.verify(&domain_input(BUNDLE_DOMAIN, &b[..BUNDLE_BODY_LEN]), &b[BUNDLE_BODY_LEN..])?;

    let mut static_dh = [0u8; X25519_LEN];
    static_dh.copy_from_slice(&b[1..=X25519_LEN]);
    let enc: Encoded<Ek> = b[1 + X25519_LEN..1 + X25519_LEN + MLKEM768_EK_LEN]
        .try_into()
        .map_err(|_| Awp3Error::KeyMaterial)?;
    Ok(BundleParts {
        static_dh,
        pq_ek: Ek::from_bytes(&enc),
        vk,
    })
}

/// An in-progress initiator handshake: the pending `msg1` and the ephemeral
/// state needed to finish once `msg2` arrives.
pub struct Initiator {
    e_i: StaticSecret,
    identity_dh: StaticSecret,
    signer: CompositeSigningKey,
    parts: BundleParts,
    pq_ss: [u8; 32],
    msg1: Vec<u8>,
}

impl Initiator {
    /// The `msg1` flight to send to the responder.
    #[must_use]
    pub fn msg1(&self) -> &[u8] {
        &self.msg1
    }

    /// Consume the responder's `msg2` and produce the live [`crate::Session`].
    ///
    /// # Errors
    /// Fails if `msg2` is malformed or its composite signature does not verify
    /// against the responder identity trusted from the bundle.
    pub fn finish(self, msg2: &[u8]) -> Result<crate::Session> {
        if msg2.len() != MSG2_LEN || msg2[0] != VERSION {
            return Err(Awp3Error::Handshake);
        }
        let e_r_pub: [u8; X25519_LEN] = msg2[1..MSG2_BODY_LEN].try_into().expect("32-byte e_r");

        // Bind msg2 to msg1 by hashing the first flight into the signature.
        let mut input = Vec::with_capacity(MSG2_DOMAIN.len() + 2 * X25519_LEN);
        input.extend_from_slice(MSG2_DOMAIN);
        input.extend_from_slice(&e_r_pub);
        input.extend_from_slice(blake3::hash(&self.msg1).as_bytes());
        self.parts.vk.verify(&input, &msg2[MSG2_BODY_LEN..])?;

        let e_r = PublicKey::from(e_r_pub);
        let dh1 = self
            .e_i
            .diffie_hellman(&PublicKey::from(self.parts.static_dh))
            .to_bytes();
        let dh2 = self.e_i.diffie_hellman(&e_r).to_bytes();
        let dh3 = self.identity_dh.diffie_hellman(&e_r).to_bytes();
        let ss = kdf::combine(&[&dh1, &dh2, &dh3, &self.pq_ss]);
        let (i2r, r2i) = kdf::direction_keys(&ss);

        let mut h = Hasher::new();
        h.update(&self.msg1);
        h.update(msg2);
        let transcript_hash = *h.finalize().as_bytes();

        Ok(crate::Session::new(
            true,
            self.signer,
            self.parts.vk,
            i2r,
            r2i,
            transcript_hash,
        ))
    }
}

impl core::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Initiator(..)")
    }
}

/// Entry point: run the initiator half, producing an [`Initiator`] whose
/// [`Initiator::msg1`] should be sent to the responder.
///
/// `identity` and `identity_dh` are this peer's static composite signing key and
/// X25519 DH key.  `bundle` is the responder's verified public bundle.
pub fn handshake_initiator<R: RngCore + CryptoRng>(
    bundle: &[u8],
    identity: &CompositeSigningKey,
    identity_dh: &StaticSecret,
    rng: &mut R,
) -> Result<Initiator> {
    let parts = parse_bundle(bundle)?;

    let e_i = StaticSecret::random_from_rng(&mut *rng);
    let e_i_pub = PublicKey::from(&e_i).to_bytes();
    let (pq_ct, pq_ss) = parts.pq_ek.encapsulate(rng).map_err(|()| Awp3Error::Kem)?;
    let mut pq_ss_arr = [0u8; 32];
    pq_ss_arr.copy_from_slice(pq_ss.as_slice());
    let ik_i = PublicKey::from(identity_dh).to_bytes();

    let mut body = Vec::with_capacity(MSG1_BODY_LEN);
    body.push(VERSION);
    body.extend_from_slice(&e_i_pub);
    body.extend_from_slice(pq_ct.as_slice());
    body.extend_from_slice(&identity.verifying_key().to_bytes());
    body.extend_from_slice(&ik_i);
    debug_assert_eq!(body.len(), MSG1_BODY_LEN);

    let sig = identity.sign(&domain_input(MSG1_DOMAIN, &body))?;
    body.extend_from_slice(&sig);

    Ok(Initiator {
        e_i,
        identity_dh: identity_dh.clone(),
        signer: identity.clone(),
        parts,
        pq_ss: pq_ss_arr,
        msg1: body,
    })
}

/// Entry point: run the responder half, returning the live [`crate::Session`]
/// and the `msg2` flight to send back to the initiator.
///
/// # Errors
/// Fails if `msg1` is malformed or its composite signature does not verify
/// against the identity it carries.
pub fn handshake_responder<R: RngCore + CryptoRng>(
    identity: &ResponderIdentity,
    msg1: &[u8],
    rng: &mut R,
) -> Result<(crate::Session, Vec<u8>)> {
    if msg1.len() != MSG1_LEN || msg1[0] != VERSION {
        return Err(Awp3Error::Handshake);
    }
    let e_i_pub: [u8; X25519_LEN] = msg1[1..=X25519_LEN].try_into().expect("32-byte e_i");
    let pq_ct = &msg1[1 + X25519_LEN..1 + X25519_LEN + MLKEM768_CT_LEN];
    let vk_at = 1 + X25519_LEN + MLKEM768_CT_LEN;
    let peer_vk = CompositeVerifyingKey::from_bytes(&msg1[vk_at..vk_at + COMPOSITE_VK_LEN])?;
    let ik_i: [u8; X25519_LEN] = msg1[vk_at + COMPOSITE_VK_LEN..MSG1_BODY_LEN]
        .try_into()
        .expect("32-byte ik_i");
    peer_vk.verify(&domain_input(MSG1_DOMAIN, &msg1[..MSG1_BODY_LEN]), &msg1[MSG1_BODY_LEN..])?;

    let e_r = StaticSecret::random_from_rng(rng);
    let e_r_pub = PublicKey::from(&e_r).to_bytes();

    let mut input = Vec::with_capacity(MSG2_DOMAIN.len() + 2 * X25519_LEN);
    input.extend_from_slice(MSG2_DOMAIN);
    input.extend_from_slice(&e_r_pub);
    input.extend_from_slice(blake3::hash(msg1).as_bytes());
    let sig_r = identity.signer.sign(&input)?;

    let mut msg2 = Vec::with_capacity(MSG2_LEN);
    msg2.push(VERSION);
    msg2.extend_from_slice(&e_r_pub);
    msg2.extend_from_slice(&sig_r);
    debug_assert_eq!(msg2.len(), MSG2_LEN);

    let e_i = PublicKey::from(e_i_pub);
    let dh1 = identity.static_dh.diffie_hellman(&e_i).to_bytes();
    let dh2 = e_r.diffie_hellman(&e_i).to_bytes();
    let dh3 = e_r.diffie_hellman(&PublicKey::from(ik_i)).to_bytes();
    let ct = pq_ct.try_into().map_err(|_| Awp3Error::Kem)?;
    let pq_ss_raw = identity.pq_dk.decapsulate(&ct).map_err(|()| Awp3Error::Kem)?;
    let mut pq_ss = [0u8; 32];
    pq_ss.copy_from_slice(pq_ss_raw.as_slice());

    let ss = kdf::combine(&[&dh1, &dh2, &dh3, &pq_ss]);
    let (i2r, r2i) = kdf::direction_keys(&ss);

    let mut h = Hasher::new();
    h.update(msg1);
    h.update(&msg2);
    let transcript_hash = *h.finalize().as_bytes();

    let session = crate::Session::new(
        false,
        identity.signer.clone(),
        peer_vk,
        i2r,
        r2i,
        transcript_hash,
    );
    Ok((session, msg2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn pair(seed: u64) -> (ResponderIdentity, CompositeSigningKey, StaticSecret) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let responder = ResponderIdentity::generate(&mut rng);
        let initiator = CompositeSigningKey::generate(&mut rng);
        let initiator_dh = StaticSecret::random_from_rng(&mut rng);
        (responder, initiator, initiator_dh)
    }

    #[test]
    fn handshake_agrees_on_the_session() {
        let (responder, initiator, initiator_dh) = pair(1);
        let bundle = responder.bundle().unwrap();
        assert_eq!(bundle.len(), BUNDLE_LEN);

        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let hs = handshake_initiator(&bundle, &initiator, &initiator_dh, &mut rng).unwrap();
        assert_eq!(hs.msg1().len(), MSG1_LEN);

        let (mut rs, msg2) = handshake_responder(&responder, hs.msg1(), &mut rng).unwrap();
        assert_eq!(msg2.len(), MSG2_LEN);
        let mut is = hs.finish(&msg2).unwrap();

        assert!(is.is_initiator());
        assert!(!rs.is_initiator());
        assert_eq!(is.transcript_hash(), rs.transcript_hash());
        assert_eq!(is.send_chain(), rs.recv_chain());
        assert_eq!(rs.send_chain(), is.recv_chain());
        assert_eq!(is.peer_verifying_key(), &responder.signing_key().verifying_key());

        // A frame the initiator seals, the responder opens and vice versa.
        let f1 = crate::frame(&mut is, b"hello backend").unwrap();
        assert_eq!(crate::unframe(&mut rs, &f1).unwrap(), b"hello backend");
        let f2 = crate::frame(&mut rs, b"hello front").unwrap();
        assert_eq!(crate::unframe(&mut is, &f2).unwrap(), b"hello front");
    }

    #[test]
    fn tampered_bundle_is_rejected() {
        let (responder, initiator, initiator_dh) = pair(2);
        let mut bundle = responder.bundle().unwrap();
        bundle[10] ^= 0x01;
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        assert!(matches!(
            handshake_initiator(&bundle, &initiator, &initiator_dh, &mut rng),
            Err(Awp3Error::Signature)
        ));
    }

    #[test]
    fn tampered_msg1_signature_is_rejected() {
        let (responder, initiator, initiator_dh) = pair(4);
        let bundle = responder.bundle().unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        let hs = handshake_initiator(&bundle, &initiator, &initiator_dh, &mut rng).unwrap();
        let mut msg1 = hs.msg1().to_vec();
        let last = msg1.len() - 1;
        msg1[last] ^= 0x01;
        assert!(matches!(
            handshake_responder(&responder, &msg1, &mut rng),
            Err(Awp3Error::Signature)
        ));
    }

    #[test]
    fn tampered_msg2_signature_is_rejected() {
        let (responder, initiator, initiator_dh) = pair(6);
        let bundle = responder.bundle().unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let hs = handshake_initiator(&bundle, &initiator, &initiator_dh, &mut rng).unwrap();
        let (_rs, mut msg2) = handshake_responder(&responder, hs.msg1(), &mut rng).unwrap();
        let last = msg2.len() - 1;
        msg2[last] ^= 0x01;
        assert!(matches!(hs.finish(&msg2), Err(Awp3Error::Signature)));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let (responder, initiator, initiator_dh) = pair(8);
        let bundle = responder.bundle().unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let hs = handshake_initiator(&bundle, &initiator, &initiator_dh, &mut rng).unwrap();
        let mut msg1 = hs.msg1().to_vec();
        msg1[0] = 0x02;
        assert!(matches!(
            handshake_responder(&responder, &msg1, &mut rng),
            Err(Awp3Error::Handshake)
        ));
    }
}

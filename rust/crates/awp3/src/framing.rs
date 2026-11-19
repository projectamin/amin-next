//! The AWP/3 frame codec and per-connection [`Session`].
//!
//! A frame is a 54-byte cleartext header — `version ‖ kind ‖ seq ‖ chain`‖
//! `nonce` — followed by an ASCON-128a ciphertext that authenticates the header
//! as associated data.  The `chain` field carries the rolling BLAKE3 hash of
//! the previous frame, and each frame advances the chain by hashing itself in:
//!
//! ```text
//!   chain₀    = BLAKE3("Amin3/AWP3/genesis" ‖ handshake_transcript_hash)
//!   frameₙ    = version ‖ kind ‖ seqₙ ‖ chainₙ ‖ nonceₙ ‖ ASCON(k, nonceₙ, aad=headerₙ‖nonceₙ, ptₙ)
//!   chainₙ₊₁  = BLAKE3("Amin3/AWP3/frame" ‖ frameₙ)
//! ```
//!
//! Because the chain field is authenticated (it is inside the AAD) and each
//! frame depends on the previous one, the frames form an append-only log: a
//! dropped, reordered, or altered frame is detected before its payload is
//! released.  [`close`] seals a final CLOSE frame and signs the resulting chain
//! with the closer's composite identity — the session-close receipt.

use blake3::Hasher;

use crate::aead::{self, ASCON_KEY_LEN, ASCON_NONCE_LEN, ASCON_TAG_LEN};
use crate::sign::{CompositeSigningKey, CompositeVerifyingKey, COMPOSITE_SIG_LEN};
use crate::{Awp3Error, Result, VERSION};

/// Domain separator for the genesis chain value.
pub const GENESIS_DOMAIN: &[u8] = b"Amin3/AWP3/genesis";
/// Domain separator mixed into every frame's chain step.
pub const FRAME_DOMAIN: &[u8] = b"Amin3/AWP3/frame";
/// Domain separator prefixing the bytes a close receipt signs.
pub const RECEIPT_DOMAIN: &[u8] = b"Amin3/AWP3/receipt";

/// Frame kind: an application payload.
pub const KIND_DATA: u8 = 0x00;
/// Frame kind: session close.
pub const KIND_CLOSE: u8 = 0x01;

/// Cleartext header length: `version(1) ‖ kind(1) ‖ seq(4) ‖ chain(32)`.
pub const HEADER_LEN: usize = 1 + 1 + 4 + 32;
/// Bytes authenticated as associated data: the header followed by the nonce.
pub const AAD_LEN: usize = HEADER_LEN + ASCON_NONCE_LEN;
/// Fixed per-frame overhead: AAD plus the AEAD tag.
pub const FRAME_OVERHEAD: usize = AAD_LEN + ASCON_TAG_LEN;

/// The output of [`close`]: the CLOSE frame, the signed receipt, and the final
/// chain value the receipt covers.
#[derive(Clone, PartialEq, Eq)]
pub struct CloseOutcome {
    /// The CLOSE frame to send to the peer.
    pub frame: Vec<u8>,
    /// The composite signature over [`close_receipt_payload`] of `chain`.
    pub receipt: Vec<u8>,
    /// The final rolling chain value both sides agree on.
    pub chain: [u8; 32],
}

/// A live AWP/3 session: the two directional AEAD keys plus the rolling chain
/// state.  Built by [`crate::handshake`] and driven by [`frame`] / [`unframe`] /
/// [`close`].
pub struct Session {
    send_key: [u8; ASCON_KEY_LEN],
    recv_key: [u8; ASCON_KEY_LEN],
    send_seq: u32,
    recv_seq: u32,
    send_chain: [u8; 32],
    recv_chain: [u8; 32],
    transcript_hash: [u8; 32],
    initiator: bool,
    signer: CompositeSigningKey,
    peer_vk: CompositeVerifyingKey,
    closed: bool,
}

impl Session {
    /// Assemble a session from handshake outputs.
    ///
    /// `i2r`/`r2i` are the directional keys from [`crate::kdf::direction_keys`],
    /// keyed by initiator→responder; `initiator` selects which one this side
    /// sends with.
    pub(crate) fn new(
        initiator: bool,
        signer: CompositeSigningKey,
        peer_vk: CompositeVerifyingKey,
        i2r: [u8; ASCON_KEY_LEN],
        r2i: [u8; ASCON_KEY_LEN],
        transcript_hash: [u8; 32],
    ) -> Self {
        let (send_key, recv_key) = if initiator { (i2r, r2i) } else { (r2i, i2r) };
        let mut h = Hasher::new();
        h.update(GENESIS_DOMAIN);
        h.update(&transcript_hash);
        let genesis = *h.finalize().as_bytes();
        Self {
            send_key,
            recv_key,
            send_seq: 0,
            recv_seq: 0,
            send_chain: genesis,
            recv_chain: genesis,
            transcript_hash,
            initiator,
            signer,
            peer_vk,
            closed: false,
        }
    }

    /// Whether this session is the initiator side.
    #[must_use]
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// The BLAKE3 hash of the handshake transcript both sides share.
    #[must_use]
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// The chain value the *next* outgoing frame will carry.
    #[must_use]
    pub fn send_chain(&self) -> &[u8; 32] {
        &self.send_chain
    }

    /// The chain value the *next* incoming frame must carry.
    #[must_use]
    pub fn recv_chain(&self) -> &[u8; 32] {
        &self.recv_chain
    }

    /// The peer's composite verifying key, learned during the handshake.
    #[must_use]
    pub fn peer_verifying_key(&self) -> &CompositeVerifyingKey {
        &self.peer_vk
    }

    /// Seal one frame of `payload` with the given `kind`.
    fn seal(&mut self, kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if self.closed {
            return Err(Awp3Error::Closed);
        }
        let seq = self.send_seq;
        let mut aad = [0u8; AAD_LEN];
        aad[0] = VERSION;
        aad[1] = kind;
        aad[2..6].copy_from_slice(&seq.to_le_bytes());
        aad[6..HEADER_LEN].copy_from_slice(&self.send_chain);
        // The nonce is the sequence number, zero-padded to 128 bits.  The send
        // key is unique per direction, so nonces never repeat under a key.
        aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&u64::from(seq).to_le_bytes());

        let nonce: [u8; ASCON_NONCE_LEN] = aad[HEADER_LEN..].try_into().expect("16-byte nonce");
        let ct = aead::seal(&self.send_key, &nonce, &aad, payload)?;

        let mut frame = Vec::with_capacity(AAD_LEN + ct.len());
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&ct);

        let mut h = Hasher::new();
        h.update(FRAME_DOMAIN);
        h.update(&frame);
        self.send_chain = *h.finalize().as_bytes();
        self.send_seq = self.send_seq.wrapping_add(1);
        if kind == KIND_CLOSE {
            self.closed = true;
        }
        Ok(frame)
    }

    /// Open one frame, returning `(kind, payload)`.
    fn open(&mut self, bytes: &[u8]) -> Result<(u8, Vec<u8>)> {
        if bytes.len() < FRAME_OVERHEAD || bytes[0] != VERSION {
            return Err(Awp3Error::Frame);
        }
        let kind = bytes[1];
        let seq = u32::from_le_bytes(bytes[2..6].try_into().expect("4-byte seq"));
        // Ordering + append-only check, before touching the AEAD.
        if bytes[6..HEADER_LEN] != self.recv_chain || seq != self.recv_seq {
            return Err(Awp3Error::Frame);
        }
        let aad = &bytes[..AAD_LEN];
        let nonce: [u8; ASCON_NONCE_LEN] = bytes[HEADER_LEN..AAD_LEN]
            .try_into()
            .expect("16-byte nonce");
        let pt = aead::open(&self.recv_key, &nonce, aad, &bytes[AAD_LEN..])?;

        let mut h = Hasher::new();
        h.update(FRAME_DOMAIN);
        h.update(bytes);
        self.recv_chain = *h.finalize().as_bytes();
        self.recv_seq = self.recv_seq.wrapping_add(1);
        if kind == KIND_CLOSE {
            self.closed = true;
        }
        Ok((kind, pt))
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("initiator", &self.initiator)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// The bytes a close receipt signs: `"Amin3/AWP3/receipt" ‖ VERSION ‖ chain`.
#[must_use]
pub fn close_receipt_payload(chain: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(RECEIPT_DOMAIN.len() + 1 + 32);
    v.extend_from_slice(RECEIPT_DOMAIN);
    v.push(VERSION);
    v.extend_from_slice(chain);
    v
}

/// Entry point: seal one DATA frame carrying `payload`.
pub fn frame(session: &mut Session, payload: &[u8]) -> Result<Vec<u8>> {
    session.seal(KIND_DATA, payload)
}

/// Entry point: open one DATA frame, returning its payload.
pub fn unframe(session: &mut Session, bytes: &[u8]) -> Result<Vec<u8>> {
    let (kind, pt) = session.open(bytes)?;
    if kind != KIND_DATA {
        return Err(Awp3Error::Frame);
    }
    Ok(pt)
}

/// Entry point: seal a CLOSE frame and sign the resulting chain into a receipt.
///
/// The receipt is an [`CloseOutcome`] attached to the audit log; the peer
/// verifies it with [`verify_receipt`] against this side's verifying key.
pub fn close(session: &mut Session) -> Result<CloseOutcome> {
    let frame = session.seal(KIND_CLOSE, &[])?;
    let chain = session.send_chain;
    let receipt = session.signer.sign(&close_receipt_payload(&chain))?;
    Ok(CloseOutcome {
        frame,
        receipt,
        chain,
    })
}

/// Verify a peer's close receipt under its composite verifying key.
pub fn verify_receipt(
    vk: &CompositeVerifyingKey,
    chain: &[u8; 32],
    receipt: &[u8],
) -> Result<()> {
    if receipt.len() != COMPOSITE_SIG_LEN {
        return Err(Awp3Error::Signature);
    }
    vk.verify(&close_receipt_payload(chain), receipt)
}

/// Entry point: open a CLOSE frame and return the final chain value.
pub fn open_close(session: &mut Session, bytes: &[u8]) -> Result<[u8; 32]> {
    let (kind, _) = session.open(bytes)?;
    if kind != KIND_CLOSE {
        return Err(Awp3Error::Frame);
    }
    Ok(*session.recv_chain())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{handshake_initiator, handshake_responder, ResponderIdentity};
    use crate::sign::CompositeSigningKey;
    use rand::SeedableRng;
    use x25519_dalek::StaticSecret;

    fn session_pair() -> (Session, Session) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA3);
        let responder = ResponderIdentity::generate(&mut rng);
        let initiator = CompositeSigningKey::generate(&mut rng);
        let initiator_dh = StaticSecret::random_from_rng(&mut rng);
        let bundle = responder.bundle().unwrap();

        let hs = handshake_initiator(&bundle, &initiator, &initiator_dh, &mut rng).unwrap();
        let msg1 = hs.msg1().to_vec();
        let (rs, msg2) = handshake_responder(&responder, &msg1, &mut rng).unwrap();
        let is = hs.finish(&msg2).unwrap();
        (is, rs)
    }

    #[test]
    fn frame_overhead_is_fixed() {
        let (mut is, _) = session_pair();
        let f = frame(&mut is, b"abc").unwrap();
        assert_eq!(f.len(), 3 + FRAME_OVERHEAD);
        assert_eq!(FRAME_OVERHEAD, 70);
    }

    #[test]
    fn frames_are_chained_and_out_of_order_is_rejected() {
        let (mut is, mut rs) = session_pair();
        let f0 = frame(&mut is, b"one").unwrap();
        let f1 = frame(&mut is, b"two").unwrap();
        // The second frame carries the chain the first frame produced:
        // chain₁ = BLAKE3("Amin3/AWP3/frame" ‖ frame₀).
        let mut h = Hasher::new();
        h.update(FRAME_DOMAIN);
        h.update(&f0);
        assert_eq!(&f1[6..HEADER_LEN], h.finalize().as_bytes().as_slice());
        // Opening out of order fails closed.
        assert_eq!(unframe(&mut rs, &f1), Err(Awp3Error::Frame));
        assert_eq!(unframe(&mut rs, &f0).unwrap(), b"one");
        assert_eq!(unframe(&mut rs, &f1).unwrap(), b"two");
    }

    #[test]
    fn tampering_a_frame_fails_closed() {
        let (mut is, mut rs) = session_pair();
        let mut f = frame(&mut is, b"payload").unwrap();
        let last = f.len() - 1;
        f[last] ^= 0x01;
        assert_eq!(unframe(&mut rs, &f), Err(Awp3Error::Aead));
    }

    #[test]
    fn close_receipt_binds_the_final_chain() {
        let (mut is, mut rs) = session_pair();
        let body = frame(&mut is, b"body").unwrap();
        assert_eq!(unframe(&mut rs, &body).unwrap(), b"body");

        let out = close(&mut is).unwrap();
        // The responder opens the CLOSE frame and reconstructs the same chain.
        let peer_chain = open_close(&mut rs, &out.frame).unwrap();
        assert_eq!(peer_chain, out.chain);

        // The peer verifies the initiator's receipt against its learned key.
        verify_receipt(rs.peer_verifying_key(), &out.chain, &out.receipt).unwrap();

        // A tampered receipt or a different chain must not verify.
        let mut bad = out.receipt.clone();
        bad[0] ^= 0x01;
        assert_eq!(
            verify_receipt(rs.peer_verifying_key(), &out.chain, &bad),
            Err(Awp3Error::Signature)
        );
        let mut other_chain = out.chain;
        other_chain[0] ^= 0x01;
        assert_eq!(
            verify_receipt(rs.peer_verifying_key(), &other_chain, &out.receipt),
            Err(Awp3Error::Signature)
        );

        // A closed session refuses further frames.
        assert_eq!(frame(&mut is, b"nope"), Err(Awp3Error::Closed));
    }
}

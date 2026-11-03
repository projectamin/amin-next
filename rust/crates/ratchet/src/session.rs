//! The Double Ratchet.
//!
//! Implements the state machine from Marlinspike & Perrin's *The Double
//! Ratchet* (§3.3), seeded by the PQXDH shared secret from [`crate::pqxdh`].
//! Two ratchets run at once:
//!
//! * a **symmetric-key ratchet** (`kdf_ck`) that derives a fresh message key
//!   per message — this gives forward secrecy,
//! * a **Diffie-Hellman ratchet** (`kdf_rk`) that is stepped whenever a new
//!   remote ratchet key appears — this gives post-compromise security.
//!
//! Everything here is serialisation-agnostic: a [`Header`] has a canonical
//! byte form that is used verbatim as AEAD associated data, and
//! [`SessionState`] exposes a plain-data snapshot so a caller (the `sec:` SAX
//! filter) can persist the session through whichever writer it has.

use rand::{rngs::OsRng, CryptoRng, RngCore};

use crate::aead;
use crate::hybrid::{X25519Keypair, X25519_LEN};
use crate::kdf::{kdf_ck, kdf_rk, mk_to_aead, Secret, KEY_LEN};
use crate::{RatchetError, Result};

/// Maximum number of message keys one [`Session::decrypt`] will skip ahead.
///
/// Bounds the memory an attacker can force us to allocate by claiming a huge
/// message index. The Signal default is 1000.
pub const MAX_SKIP: u32 = 1000;

/// The header carried by every ratchet message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Sender's current DH ratchet public key.
    pub dh: [u8; X25519_LEN],
    /// Number of messages in the sender's *previous* sending chain.
    pub pn: u32,
    /// Message number within the sender's current sending chain.
    pub n: u32,
}

impl Header {
    /// Canonical encoded length — also the exact bytes fed to the AEAD as AAD.
    pub const LEN: usize = X25519_LEN + 8;

    /// Canonical encoding, used verbatim as the AEAD associated data so the
    /// header is authenticated and cannot be rewritten in flight.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[..X25519_LEN].copy_from_slice(&self.dh);
        b[X25519_LEN..X25519_LEN + 4].copy_from_slice(&self.pn.to_be_bytes());
        b[X25519_LEN + 4..].copy_from_slice(&self.n.to_be_bytes());
        b
    }

    /// Decode a canonical header.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != Self::LEN {
            return Err(RatchetError::Header);
        }
        let mut dh = [0u8; X25519_LEN];
        dh.copy_from_slice(&b[..X25519_LEN]);
        let mut pn = [0u8; 4];
        pn.copy_from_slice(&b[X25519_LEN..X25519_LEN + 4]);
        let mut n = [0u8; 4];
        n.copy_from_slice(&b[X25519_LEN + 4..]);
        Ok(Self {
            dh,
            pn: u32::from_be_bytes(pn),
            n: u32::from_be_bytes(n),
        })
    }
}

#[derive(Clone)]
struct SkippedKey {
    dh: [u8; X25519_LEN],
    n: u32,
    mk: Secret,
}

/// A live Double Ratchet session between two devices.
pub struct Session {
    dh_self: X25519Keypair,
    dh_remote: Option<[u8; X25519_LEN]>,
    root: Secret,
    ck_send: Option<Secret>,
    ck_recv: Option<Secret>,
    n_send: u32,
    n_recv: u32,
    pn: u32,
    skipped: Vec<SkippedKey>,
}

impl Session {
    /// Initialise the initiator (Alice) side after PQXDH.
    ///
    /// `remote_ratchet` is the responder's signed prekey, which doubles as the
    /// initial Diffie-Hellman ratchet public key.
    pub fn init_initiator<R: RngCore + CryptoRng>(
        sk: Secret,
        remote_ratchet: [u8; X25519_LEN],
        rng: &mut R,
    ) -> Self {
        let dh_self = X25519Keypair::generate(rng);
        let dh_out = dh_self.dh(&remote_ratchet);
        let (root, ck_send) = kdf_rk(&sk, &dh_out);
        Self {
            dh_self,
            dh_remote: Some(remote_ratchet),
            root,
            ck_send: Some(ck_send),
            ck_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    /// Initialise the responder (Bob) side after PQXDH.
    ///
    /// `own_ratchet` must be the key pair whose public half was published as
    /// the signed prekey. The first receiving-chain key is derived when the
    /// initiator's first message arrives.
    #[must_use]
    pub fn init_responder(sk: Secret, own_ratchet: X25519Keypair) -> Self {
        Self {
            dh_self: own_ratchet,
            dh_remote: None,
            root: sk,
            ck_send: None,
            ck_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    /// Encrypt `plaintext`, returning the header to transmit beside the ciphertext.
    ///
    /// `ad` is an application-level associated-data string (the `sec:` filter
    /// passes the conversation/room id); it is authenticated together with the
    /// header.
    ///
    /// # Errors
    /// [`RatchetError::NoSendingChain`] if called before the responder has
    /// received anything, which would be a protocol violation.
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Header, Vec<u8>)> {
        let ck = self.ck_send.as_ref().ok_or(RatchetError::NoSendingChain)?;
        let (next, mk) = kdf_ck(ck);
        self.ck_send = Some(next);

        let header = Header {
            dh: self.dh_self.public_bytes(),
            pn: self.pn,
            n: self.n_send,
        };
        self.n_send += 1;

        let (key, nonce) = mk_to_aead(&mk);
        let ct = aead::seal(&key, &nonce, &aad(ad, &header), plaintext)?;
        Ok((header, ct))
    }

    /// Decrypt a received message, stepping the ratchet as required.
    ///
    /// Out-of-order delivery is supported: message keys for gaps are stored in
    /// the skipped-key cache. Any authentication failure returns
    /// [`RatchetError::Aead`].
    ///
    /// This is not deterministic — a DH ratchet step generates a fresh key
    /// pair from the OS RNG.
    ///
    /// # Errors
    /// * [`RatchetError::Aead`] — tampered, or the wrong session.
    /// * [`RatchetError::DuplicateMessage`] — the message key was already used.
    /// * [`RatchetError::TooManySkipped`] — the claimed index is too far ahead.
    pub fn decrypt(&mut self, header: &Header, ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        let aad = aad(ad, header);

        // 1. A key we stored while skipping ahead earlier?
        if let Some(pos) = self
            .skipped
            .iter()
            .position(|k| k.dh == header.dh && k.n == header.n)
        {
            let k = self.skipped.remove(pos);
            let (key, nonce) = mk_to_aead(&k.mk);
            return aead::open(&key, &nonce, &aad, ciphertext);
        }

        // 2. A new remote ratchet key means catch up, then step the DH ratchet.
        if self.dh_remote != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(&header.dh);
        }

        // 3. Catch up within the current receiving chain.
        if header.n < self.n_recv {
            return Err(RatchetError::DuplicateMessage);
        }
        self.skip_message_keys(header.n)?;

        let ck = self.ck_recv.as_ref().ok_or(RatchetError::Header)?;
        let (next, mk) = kdf_ck(ck);
        self.ck_recv = Some(next);
        self.n_recv += 1;

        let (key, nonce) = mk_to_aead(&mk);
        aead::open(&key, &nonce, &aad, ciphertext)
    }

    /// Advance the receiving chain to `until`, caching the skipped message keys.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.n_recv >= until {
            return Ok(());
        }
        if until - self.n_recv > MAX_SKIP {
            return Err(RatchetError::TooManySkipped);
        }
        let Some(mut ck) = self.ck_recv.clone() else {
            // Nothing to skip: the receiving chain has not been established yet.
            return Err(RatchetError::Header);
        };
        let dh = self.dh_remote.ok_or(RatchetError::Header)?;
        while self.n_recv < until {
            let (next, mk) = kdf_ck(&ck);
            ck = next;
            self.skipped.push(SkippedKey {
                dh,
                n: self.n_recv,
                mk,
            });
            self.n_recv += 1;
        }
        self.ck_recv = Some(ck);
        Ok(())
    }

    /// Perform a Diffie-Hellman ratchet step on receiving `remote`.
    fn dh_ratchet(&mut self, remote: &[u8; X25519_LEN]) {
        self.pn = self.n_send;
        self.n_send = 0;
        self.n_recv = 0;
        self.dh_remote = Some(*remote);

        // Receiving chain against our current key pair.
        let dh_out = self.dh_self.dh(remote);
        let (root, ck_recv) = kdf_rk(&self.root, &dh_out);
        self.root = root;
        self.ck_recv = Some(ck_recv);

        // Fresh key pair for the next sending chain.
        self.dh_self = X25519Keypair::generate(&mut OsRng);
        let dh_out = self.dh_self.dh(remote);
        let (root, ck_send) = kdf_rk(&self.root, &dh_out);
        self.root = root;
        self.ck_send = Some(ck_send);
    }

    /// Snapshot the session for persistence (see [`SessionState`]).
    #[must_use]
    pub fn export_state(&self) -> SessionState {
        SessionState {
            dh_self_secret: self.dh_self.secret_bytes(),
            dh_remote: self.dh_remote,
            root: self.root.to_bytes(),
            ck_send: self.ck_send.as_ref().map(Secret::to_bytes),
            ck_recv: self.ck_recv.as_ref().map(Secret::to_bytes),
            n_send: self.n_send,
            n_recv: self.n_recv,
            pn: self.pn,
            skipped: self
                .skipped
                .iter()
                .map(|k| (k.dh, k.n, k.mk.to_bytes()))
                .collect(),
        }
    }

    /// Restore a session from a [`SessionState`] snapshot.
    #[must_use]
    pub fn import_state(state: SessionState) -> Self {
        Self {
            dh_self: X25519Keypair::from_secret_bytes(state.dh_self_secret),
            dh_remote: state.dh_remote,
            root: Secret::from_bytes(state.root),
            ck_send: state.ck_send.map(Secret::from_bytes),
            ck_recv: state.ck_recv.map(Secret::from_bytes),
            n_send: state.n_send,
            n_recv: state.n_recv,
            pn: state.pn,
            skipped: state
                .skipped
                .into_iter()
                .map(|(dh, n, mk)| SkippedKey {
                    dh,
                    n,
                    mk: Secret::from_bytes(mk),
                })
                .collect(),
        }
    }

    /// Number of cached skipped message keys (diagnostics / sweep tests).
    #[must_use]
    pub fn skipped_key_count(&self) -> usize {
        self.skipped.len()
    }
}

/// Plain-data snapshot of a [`Session`].
///
/// Contains raw secret key material: the caller is responsible for
/// confidentiality of whatever it persists. It exists so the state can be
/// written as a `<sec:session>` element (or any other writer's encoding)
/// without the ratchet crate choosing a wire format.
#[derive(Clone)]
pub struct SessionState {
    /// The local DH ratchet secret.
    pub dh_self_secret: [u8; X25519_LEN],
    /// The current remote DH ratchet public key, if any.
    pub dh_remote: Option<[u8; X25519_LEN]>,
    /// The root key.
    pub root: [u8; KEY_LEN],
    /// The current sending chain key.
    pub ck_send: Option<[u8; KEY_LEN]>,
    /// The current receiving chain key.
    pub ck_recv: Option<[u8; KEY_LEN]>,
    /// Messages sent in the current sending chain.
    pub n_send: u32,
    /// Messages received in the current receiving chain.
    pub n_recv: u32,
    /// Messages sent in the previous sending chain.
    pub pn: u32,
    /// Cached `(remote ratchet key, message number, message key)` triples.
    pub skipped: Vec<([u8; X25519_LEN], u32, [u8; KEY_LEN])>,
}

impl core::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionState")
            .field("n_send", &self.n_send)
            .field("n_recv", &self.n_recv)
            .field("pn", &self.pn)
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

/// AEAD associated data: the application string followed by the canonical header.
fn aad(ad: &[u8], header: &Header) -> Vec<u8> {
    let mut v = Vec::with_capacity(ad.len() + Header::LEN);
    v.extend_from_slice(ad);
    v.extend_from_slice(&header.encode());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    const AD: &[u8] = b"room:ops";

    /// Build both halves of a session from a shared secret, as PQXDH would.
    fn pair(sk_seed: u8) -> (Session, Session) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(100);
        let bob_ratchet = X25519Keypair::generate(&mut rng);
        let sk = Secret::from_bytes([sk_seed; KEY_LEN]);

        let mut rng = rand::rngs::StdRng::seed_from_u64(101);
        let alice = Session::init_initiator(sk.clone(), bob_ratchet.public_bytes(), &mut rng);
        (alice, Session::init_responder(sk, bob_ratchet))
    }

    #[test]
    fn header_round_trips_and_encodes_big_endian() {
        let h = Header {
            dh: [0xAB; X25519_LEN],
            pn: 0x0102_0304,
            n: 0x0506_0708,
        };
        let enc = h.encode();
        assert_eq!(&enc[..X25519_LEN], &[0xAB; X25519_LEN]);
        assert_eq!(&enc[X25519_LEN..X25519_LEN + 4], &[1, 2, 3, 4]);
        assert_eq!(&enc[X25519_LEN + 4..], &[5, 6, 7, 8]);
        assert_eq!(Header::decode(&enc).unwrap(), h);
        assert_eq!(Header::decode(&enc[..39]), Err(RatchetError::Header));
    }

    #[test]
    fn alice_to_bob_round_trip() {
        let (mut alice, mut bob) = pair(0x11);
        let (h, ct) = alice.encrypt(b"first contact", AD).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, AD).unwrap(), b"first contact");
    }

    #[test]
    fn bob_replies_on_a_new_dh_ratchet() {
        let (mut alice, mut bob) = pair(0x22);

        let (h1, ct1) = alice.encrypt(b"ping", AD).unwrap();
        assert_eq!(bob.decrypt(&h1, &ct1, AD).unwrap(), b"ping");

        // Bob has no sending chain until he receives, so his reply forces a
        // DH ratchet step on Alice's side.
        let (h2, ct2) = bob.encrypt(b"pong", AD).unwrap();
        assert_eq!(alice.decrypt(&h2, &ct2, AD).unwrap(), b"pong");

        // ...and Alice can still use her new sending chain.
        let (h3, ct3) = alice.encrypt(b"ping2", AD).unwrap();
        assert_eq!(bob.decrypt(&h3, &ct3, AD).unwrap(), b"ping2");
    }

    #[test]
    fn out_of_order_delivery_uses_skipped_keys() {
        let (mut alice, mut bob) = pair(0x33);

        let m0 = alice.encrypt(b"m0", AD).unwrap();
        let m1 = alice.encrypt(b"m1", AD).unwrap();
        let m2 = alice.encrypt(b"m2", AD).unwrap();

        // Deliver 2, then 0, then 1.
        assert_eq!(bob.decrypt(&m2.0, &m2.1, AD).unwrap(), b"m2");
        assert_eq!(bob.skipped_key_count(), 2);
        assert_eq!(bob.decrypt(&m0.0, &m0.1, AD).unwrap(), b"m0");
        assert_eq!(bob.decrypt(&m1.0, &m1.1, AD).unwrap(), b"m1");
        assert_eq!(bob.skipped_key_count(), 0);
    }

    #[test]
    fn replayed_message_is_rejected() {
        let (mut alice, mut bob) = pair(0x44);
        let (h, ct) = alice.encrypt(b"once", AD).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, AD).unwrap(), b"once");
        assert_eq!(
            bob.decrypt(&h, &ct, AD),
            Err(RatchetError::DuplicateMessage)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let (mut alice, mut bob) = pair(0x55);
        let (h, mut ct) = alice.encrypt(b"secret", AD).unwrap();
        ct[3] ^= 0x01;
        assert_eq!(bob.decrypt(&h, &ct, AD), Err(RatchetError::Aead));
    }

    #[test]
    fn tampered_header_fails_closed() {
        // A forged message index is authenticated as AAD, so the open fails.
        // Note the derived key *is* consumed: a failed AEAD still advances the
        // receiving chain, so the genuine message at that index would later be
        // rejected as a duplicate — hence a fresh session per tamper case.
        let (mut alice, mut bob) = pair(0x55);
        let (h, ct) = alice.encrypt(b"secret", AD).unwrap();
        let mut h_bad = h;
        h_bad.n += 1;
        assert_eq!(bob.decrypt(&h_bad, &ct, AD), Err(RatchetError::Aead));
    }

    #[test]
    fn wrong_associated_data_fails_closed() {
        let (mut alice, mut bob) = pair(0x55);
        let (h, ct) = alice.encrypt(b"secret", AD).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, b"room:other"), Err(RatchetError::Aead));
    }

    #[test]
    fn excessive_skip_is_refused() {
        let (mut alice, mut bob) = pair(0x66);
        let (mut h, ct) = alice.encrypt(b"far", AD).unwrap();
        h.n = MAX_SKIP + 10;
        assert_eq!(bob.decrypt(&h, &ct, AD), Err(RatchetError::TooManySkipped));
    }

    #[test]
    fn responder_cannot_send_before_receiving() {
        let (_, mut bob) = pair(0x77);
        assert_eq!(
            bob.encrypt(b"early", AD).unwrap_err(),
            RatchetError::NoSendingChain
        );
    }

    #[test]
    fn state_export_import_continues_the_conversation() {
        let (mut alice, mut bob) = pair(0x88);

        let (h, ct) = alice.encrypt(b"before", AD).unwrap();
        assert_eq!(bob.decrypt(&h, &ct, AD).unwrap(), b"before");

        // Persist Bob, drop him, restore from the snapshot.
        let snapshot = bob.export_state();
        drop(bob);
        let mut bob = Session::import_state(snapshot);

        let (h2, ct2) = alice.encrypt(b"after", AD).unwrap();
        assert_eq!(bob.decrypt(&h2, &ct2, AD).unwrap(), b"after");

        // And the restored Bob can reply, which ratchets on Alice's side.
        let (h3, ct3) = bob.encrypt(b"rehydrated", AD).unwrap();
        assert_eq!(alice.decrypt(&h3, &ct3, AD).unwrap(), b"rehydrated");
    }

    #[test]
    fn long_conversation_stays_in_sync() {
        let (mut alice, mut bob) = pair(0x99);
        for i in 0..64u32 {
            let (h, ct) = alice.encrypt(&i.to_be_bytes(), AD).unwrap();
            assert_eq!(bob.decrypt(&h, &ct, AD).unwrap(), i.to_be_bytes());
            if i % 7 == 0 {
                let (h2, ct2) = bob.encrypt(&i.to_be_bytes(), AD).unwrap();
                assert_eq!(alice.decrypt(&h2, &ct2, AD).unwrap(), i.to_be_bytes());
            }
        }
    }
}

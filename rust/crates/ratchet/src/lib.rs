//! `ratchet` — Amin 3.0 post-quantum Double Ratchet + PQXDH.
//!
//! A transport- and serialisation-agnostic implementation of the Signal
//! protocol with hybrid post-quantum key agreement:
//!
//! * **PQXDH** ([`pqxdh`]) — the X3DH-style handshake, mixing four X25519
//!   Diffie-Hellman outputs with an ML-KEM-768 encapsulation to produce the
//!   initial shared secret `SK`.
//! * **Double Ratchet** ([`session`]) — the symmetric-key + Diffie-Hellman
//!   ratchet that turns `SK` into a forward-secret, post-compromise-secure
//!   message stream.
//! * **Identity** ([`identity`]) — ML-DSA-87 (FIPS 204) signatures that
//!   authenticate published prekeys; the user-visible safety number is
//!   `blake3(verifying_key)`.
//!
//! The crate deliberately owns no wire format. A [`session::Header`] has a
//! canonical byte encoding used verbatim as AEAD associated data, and
//! [`session::SessionState`] is a plain-data snapshot so the caller — the
//! `sec:` SAX filter in Amin, or the on-device Rust core in the chat app —
//! can persist and frame it through whichever writer it has (XML, BSAX, …).
//!
//! Everything here is `#![forbid(unsafe_code)]`; the underlying primitives
//! are the RustCrypto crates.

#![forbid(unsafe_code)]

pub mod aead;
pub mod hybrid;
pub mod identity;
pub mod kdf;
pub mod pqxdh;
pub mod session;

/// Errors produced by the ratchet crate.
///
/// Variants are deliberately coarse: every authentication failure collapses to
/// [`RatchetError::Aead`] so an attacker cannot distinguish tampering from a
/// wrong key, and every malformed key collapses to [`RatchetError::KeyMaterial`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RatchetError {
    /// AEAD authentication failed — tampered, wrong key, nonce, or AAD.
    #[error("aead authentication failed")]
    Aead,
    /// An ML-KEM-768 encapsulation or decapsulation failed.
    #[error("ml-kem-768 operation failed")]
    Kem,
    /// Key material had the wrong length or an invalid encoding.
    #[error("invalid key material")]
    KeyMaterial,
    /// An ML-DSA-87 signature failed to verify, or signing failed.
    #[error("signature failure")]
    Signature,
    /// A ratchet header was malformed, or the session state is inconsistent.
    #[error("malformed ratchet header or inconsistent session state")]
    Header,
    /// A message key was already consumed (replay).
    #[error("duplicate message")]
    DuplicateMessage,
    /// A message claimed an index more than [`session::MAX_SKIP`] ahead.
    #[error("too many skipped message keys")]
    TooManySkipped,
    /// An attempt to encrypt before a sending chain exists (responder side).
    #[error("no sending chain established")]
    NoSendingChain,
}

/// Convenience alias for `Result<T, RatchetError>`.
pub type Result<T> = core::result::Result<T, RatchetError>;

// ── Re-exports: the crate's public surface in one place. ────────────────────

pub use aead::{open, seal};
pub use hybrid::{
    mlkem768_decaps, mlkem768_dk_from_bytes, mlkem768_dk_to_bytes, mlkem768_ek_from_bytes,
    mlkem768_ek_to_bytes, mlkem768_encaps, mlkem768_generate, x25519_public, MlKem768Dk,
    MlKem768Ek, X25519Keypair, X25519_LEN, MLKEM768_CT_LEN, MLKEM768_DK_LEN, MLKEM768_EK_LEN,
    MLKEM768_SS_LEN,
};
pub use identity::{
    IdentitySigningKey, IdentityVerifyingKey, MLDSA87_SIG_LEN, MLDSA87_SK_LEN, MLDSA87_VK_LEN,
};
pub use kdf::{kdf_ck, kdf_pqxdh, kdf_rk, mk_to_aead, Secret, KEY_LEN, NONCE_LEN};
pub use pqxdh::{
    initiate, pq_prekey_payload, respond, signed_prekey_payload, PqxdhInitialMessage, PrekeyBundle,
    ResponderPrekeys,
};
pub use session::{Header, Session, SessionState, MAX_SKIP};

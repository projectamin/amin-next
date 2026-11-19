//! awp3  — Amin Wire Protocol v3 implementation.
//!
//! # Design contract
//!
//! - **Hybrid post-quantum key exchange** every handshake:
//!   Noise_XKems-shaped, with ML-KEM-768 + X25519 as the KEM tuple.
//! - **Hybrid post-quantum authentication**: ML-DSA-65 + ed25519 composite
//!   signatures on every handshake transcript and every `.aminsig` artifact.
//! - **AEAD per frame**: ASCON-128a on the wire.
//! - **Frame hashes**: BLAKE3 rolling (each frame ID chained into the next,
//!   producing an append-only Merkle log that terminates at the session
//!   close signature — written to the audit log as a receipt).
//! - **Framing only**: no HTTP, no `WebSocket`, no middleware chain.  AWP/3
//!   frames carry raw byte payloads exactly as the SAX pipeline emits them.
//!
//! The three public entry points are [`frame`], [`handshake_initiator`], and
//! [`handshake_responder`] — everything else is internal.
//!
//! ## Wire layout
//!
//! Every multi-byte integer is little-endian and every fixed-size structure is
//! written in field order with no padding, so Perl and Rust driving the same
//! [`ffi`] entry points derive byte-identical output from one transcript
//! (docs/proxy-plan.md §7).
//!
//! ## Handshake (XK-shaped, two flights)
//!
//! The responder publishes a self-signed [`ResponderIdentity::bundle`]. The
//! initiator, which already trusts that identity, sends `msg1`; the responder
//! learns the initiator's identity from `msg1` and replies `msg2`.  Both then
//! hold the same session key:
//!
//! ```text
//!   dh1 = X25519(e_i, s_r)     dh2 = X25519(e_i, e_r)     dh3 = X25519(ik_i, e_r)
//!   pq  = ML-KEM-768.Encaps(pq_ek_r)   →   ss = Combiner(dh1 ‖ dh2 ‖ dh3 ‖ pq)
//! ```
//!
//! `dh2`/`dh3` are ephemeral (forward secrecy), `dh1`/`dh3` bind the static DH
//! keys, and `pq` makes the secret post-quantum.  Both flights carry a
//! composite (ML-DSA-65 **and** Ed25519) signature over their transcript.

#![deny(unsafe_code)]
#![warn(clippy::pedantic, missing_docs)]
// The public surface is documented with prose rather than the `# Errors` /
// `# Panics` sections pedantic asks for, and the handshake uses the
// spec-mandated `e_i`/`e_r`/`ik_i` notation that trips `similar_names`.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::similar_names)]

pub mod aead;
pub mod ffi;
pub mod framing;
pub mod handshake;
pub mod kdf;
pub mod sign;

/// AWP/3 wire protocol version constant.  Bumped for every breaking change to
/// the frame layout / handshake transcript.
pub const VERSION: u8 = 0x03;

/// Default AWP/3 TCP + QUIC listen port (unprivileged so mobile targets can
/// bind without root).
pub const DEFAULT_PORT: u16 = 4514;

/// Errors produced by the AWP/3 core.
///
/// Coarse on purpose: every authentication failure collapses to
/// [`Awp3Error::Aead`] or [`Awp3Error::Signature`] so an attacker cannot
/// distinguish tampering from a wrong key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Awp3Error {
    /// Key material had the wrong length or an invalid encoding.
    #[error("invalid key material")]
    KeyMaterial,
    /// A composite signature failed to verify, or signing failed.
    #[error("signature verification failed")]
    Signature,
    /// AEAD authentication failed — tampered, wrong key, nonce or AAD.
    #[error("aead authentication failed")]
    Aead,
    /// An ML-KEM-768 encapsulation or decapsulation failed.
    #[error("ml-kem-768 operation failed")]
    Kem,
    /// A handshake message was malformed or had the wrong version.
    #[error("malformed handshake message")]
    Handshake,
    /// A frame was malformed, out of order, or its chain did not match.
    #[error("malformed or out-of-order frame")]
    Frame,
    /// An operation was attempted on a session that has already closed.
    #[error("session already closed")]
    Closed,
    /// A caller-supplied output buffer was too small.
    #[error("output buffer too small")]
    BufferTooSmall,
    /// A null or otherwise invalid argument crossed the FFI boundary.
    #[error("invalid argument")]
    BadArgument,
}

/// Convenience alias for `Result<T, Awp3Error>`.
pub type Result<T> = core::result::Result<T, Awp3Error>;

// ── Re-exports: the crate's public surface in one place. ────────────────────

pub use framing::{close, frame, unframe, CloseOutcome, Session};
pub use handshake::{
    handshake_initiator, handshake_responder, Initiator, ResponderIdentity, MSG1_LEN, MSG2_LEN,
};
pub use sign::{CompositeSigningKey, CompositeVerifyingKey};

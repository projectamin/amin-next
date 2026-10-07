//! awp3  — Amin Wire Protocol v3 implementation.
//!
//! # Design contract
//!
//! - **Hybrid post-quantum key exchange** every handshake:
//!   Noise_XKems pattern with ML-KEM-768 + X25519 as the KEM tuple.
//! - **Hybrid post-quantum authentication**: ML-DSA-65 + ed25519 composite
//!   signatures on every handshake transcript and every `.aminsig` artifact.
//! - **AEAD per frame**: ASCON-128a on the wire.
//! - **Frame hashes**: BLAKE3 rolling (each frame ID chained into the next,
//!   producing an append-only Merkle log that terminates at the session
//!   close signature — written to the audit log as a receipt).
//! - **Framing only**: no HTTP, no WebSockets, no middleware chain.  AWP/3
//!   frames carry raw byte payloads exactly as the SAX pipeline emits them.
//!
//! The three public entry points are [`frame`], [`handshake_initiator`], and
//! [`handshake_responder`] — everything else is internal.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic, missing_docs)]

/// AWP/3 wire protocol version constant.  Bumped for every breaking change to
/// the frame layout / handshake transcript.
pub const VERSION: u8 = 0x03;

/// Default AWP/3 TCP + QUIC listen port (unprivileged so mobile targets can
/// bind without root).
pub const DEFAULT_PORT: u16 = 4514;

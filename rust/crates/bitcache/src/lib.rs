//! Bitcache 3.0 slab storage: O_DIRECT append slab + blake3 content-hash dedup
//! + mmapped shmem index.  Carries forward the Bitcache 2014 object identity
//! semantics (http://projectamin.org/ns/bc/) — the wire format and crypto
//! (RSA-2048 + TCP line protocol) have been replaced with BSAX + ML-DSA-87 +
//! AWP3 QUIC, but the slab/object/signer primitive shapes are unchanged.
//!
//! Usage:
//! ```ignore
//! let slab = SlabFile::open_or_create(&path)?;
//! let obj_ref  = slab.put(b"hello world")?;      // 32-byte blake3 hash
//! let same_ref = slab.put(b"hello world")?;      // dedup: 0 new bytes written
//! assert_eq!(obj_ref, same_ref);
//! assert_eq!(slab.get(&obj_ref)?, b"hello world");
//! slab.gc(0.85, Duration::from_secs(7*86400))?;
//! ```

pub mod slab;
pub mod index;
pub mod signer;
pub mod stripe;
pub mod trust_anchor;
mod error;

pub use error::{BitcacheError, Result};
pub use slab::{ObjRef, SlabFile};
pub use index::{IdxEntry, ShmemIndex};
pub use signer::{BcSignature, Keypair, SignedEnvelope, base64_encode, base64_decode, rfc3339_now, MLDSA87_SIG_LEN, MLDSA87_VK_LEN, MLDSA87_SK_LEN, ZcapGrant, zcap_token_bytes, epoch_now};
pub use stripe::{StripeEncoder, StripeDecoder};
pub use trust_anchor::TrustAnchor;

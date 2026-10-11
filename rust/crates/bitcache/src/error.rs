use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, BitcacheError>;

/// Returned from [`crate::SlabFile`] / [`crate::ShmemIndex`].
#[derive(Debug, Error)]
pub enum BitcacheError {
    #[error("i/o on slab file")]
    Io(#[from] std::io::Error),

    #[error("object not present in slab (ref={0:?})")]
    ObjectMissing(Box<[u8]>),

    #[error("slab is full and gc didn't free enough space")]
    SlabFull,

    #[error("read back corrupted at offset {offset} (expected {expected} bytes, saw {saw}")]
    CorruptedRead { offset: u64, expected: usize, saw: usize },

    #[error("object hash mismatch at offset {offset}")]
    HashMismatch { offset: u64 },

    #[error("shmem index keyed under wrong key for ref")]
    IndexMisroute,

    #[error("insufficient reachable peers: have {have} need {need}")]
    InsufficientReachablePeers { have: usize, need: usize },

    #[error("unsupported algorithm: {kind}")]
    UnsupportedAlgorithm { kind: String },

    #[error("trust anchor missing: name={name} path={path:?}")]
    TrustAnchorMissing { name: String, path: PathBuf },

    #[error("wire bc:keyref rejected; use trust-anchor dir")]
    WireKeyrefRejected,
}

//! Node identity — the key a node mints for itself at boot.
//!
//! The identity is an AWP/3 composite key (ML-DSA-65 ‖ Ed25519, the same key
//! family the transport uses).  It is created from OS entropy; the authority
//! then certifies `blake3(composite_vk)` in the BOOT_OFFER
//! (`bitcache::nodecert::NodeCert`).  Authority and mesh-root keys stay
//! ML-DSA-87.
//!
//! No fallback entropy: if the kernel cannot supply 64 random bytes the boot
//! fails.  A predictable node key is worse than no node.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use awp3::CompositeSigningKey;

/// On-disk seed file: ML-DSA-65 seed ‖ Ed25519 seed.
pub const SEED_FILE_LEN: usize = 64;

pub struct NodeIdentity {
    key: CompositeSigningKey,
    vk_bytes: Vec<u8>,
    vk_hash: [u8; 32],
}

impl NodeIdentity {
    /// Rebuild from the two seeds (deterministic vectors, on-disk reload).
    pub fn from_seeds(ml: &[u8; 32], ed: &[u8; 32]) -> Result<Self> {
        if ml.iter().all(|b| *b == 0) || ed.iter().all(|b| *b == 0) {
            bail!("node identity seed is all zero — refusing a degenerate key");
        }
        let key = CompositeSigningKey::from_seeds(ml, ed);
        let vk_bytes = key.verifying_key().to_bytes();
        let vk_hash = *blake3::hash(&vk_bytes).as_bytes();
        Ok(Self { key, vk_bytes, vk_hash })
    }

    /// Mint a fresh identity from OS entropy.  Fails (never degrades) if the
    /// entropy source is unavailable.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; SEED_FILE_LEN];
        getrandom::getrandom(&mut seed).context("node identity: no OS entropy")?;
        let r = Self::from_seed_file_bytes(&seed);
        seed.fill(0);
        r
    }

    fn from_seed_file_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != SEED_FILE_LEN {
            bail!("node identity seed file must be {SEED_FILE_LEN} bytes, got {}", b.len());
        }
        let ml: [u8; 32] = b[..32].try_into().unwrap();
        let ed: [u8; 32] = b[32..].try_into().unwrap();
        Self::from_seeds(&ml, &ed)
    }

    /// Load the identity stored at `path`, or create it (mode 0600, fsynced,
    /// exclusive create) if absent.  Use when the key must outlive a boot.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(mut b) => {
                let r = Self::from_seed_file_bytes(&b);
                b.fill(0);
                r
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut seed = [0u8; SEED_FILE_LEN];
                getrandom::getrandom(&mut seed).context("node identity: no OS entropy")?;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .with_context(|| format!("create {}", path.display()))?;
                f.write_all(&seed)?;
                f.sync_all()?;
                let r = Self::from_seed_file_bytes(&seed);
                seed.fill(0);
                r
            }
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    /// 1984-byte composite verifying key.
    pub fn vk_bytes(&self) -> &[u8] {
        &self.vk_bytes
    }

    /// `blake3(composite_vk)` — what the authority certifies.
    pub fn vk_hash(&self) -> [u8; 32] {
        self.vk_hash
    }

    /// Composite signature (both halves must verify) over `msg`.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.key.sign(msg).map_err(|e| anyhow::anyhow!("node identity sign: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awp3::CompositeVerifyingKey;

    #[test]
    fn signs_and_verifies_and_hash_binds_vk() {
        let id = NodeIdentity::from_seeds(&[1; 32], &[2; 32]).unwrap();
        let sig = id.sign(b"checkpoint").unwrap();
        let vk = CompositeVerifyingKey::from_bytes(id.vk_bytes()).unwrap();
        vk.verify(b"checkpoint", &sig).unwrap();
        assert!(vk.verify(b"other", &sig).is_err());
        assert_eq!(id.vk_hash(), *blake3::hash(id.vk_bytes()).as_bytes());
    }

    #[test]
    fn degenerate_seed_refused() {
        assert!(NodeIdentity::from_seeds(&[0; 32], &[2; 32]).is_err());
        assert!(NodeIdentity::from_seeds(&[1; 32], &[0; 32]).is_err());
    }

    #[test]
    fn generate_is_random_and_file_roundtrips_0600() {
        let a = NodeIdentity::generate().unwrap();
        let b = NodeIdentity::generate().unwrap();
        assert_ne!(a.vk_hash(), b.vk_hash());

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("node.seed");
        let first = NodeIdentity::load_or_create(&p).unwrap();
        let again = NodeIdentity::load_or_create(&p).unwrap();
        assert_eq!(first.vk_hash(), again.vk_hash());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        // a truncated seed file is an error, not a fresh key
        std::fs::write(&p, [7u8; 10]).unwrap();
        assert!(NodeIdentity::load_or_create(&p).is_err());
    }
}

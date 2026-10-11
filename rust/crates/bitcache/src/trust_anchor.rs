use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};

use crate::signer::{SignedEnvelope, MLDSA87_VK_LEN};
use crate::{BitcacheError, Result};

pub struct TrustAnchor {
    base_dir: PathBuf,
}

impl TrustAnchor {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    pub fn load_vk_by_name(&self, signer_name: &str) -> Result<Vec<u8>> {
        let hex = sha256_hex(signer_name.as_bytes());
        let file_name = format!("{}.vk", hex);
        let path = self.base_dir.join(&file_name);

        let bytes = fs::read(&path).map_err(|_| BitcacheError::TrustAnchorMissing {
            name: signer_name.to_string(),
            path: path.clone(),
        })?;

        if bytes.len() > MLDSA87_VK_LEN + 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("VK file too large: {} bytes (max {})",
                        bytes.len(), MLDSA87_VK_LEN + 1024)).into());
        }

        if bytes.len() < MLDSA87_VK_LEN {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("VK file too short: {} bytes (need exactly {})",
                        bytes.len(), MLDSA87_VK_LEN)).into());
        }

        let exact: Vec<u8> = bytes[..MLDSA87_VK_LEN].to_vec();
        Ok(exact)
    }
}

pub fn verify_with_anchor(env: &SignedEnvelope, ta: &TrustAnchor) -> Result<()> {
    let vk_bytes = ta.load_vk_by_name(&env.name)?;
    env.verify(&vk_bytes)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result.iter() {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Keypair;
    use crate::slab::ObjRef;
    use rand::SeedableRng;
    use tempfile::TempDir;

    #[test]
    fn load_vk_by_name_found_and_correct_len() {
        let tmp = TempDir::new().unwrap();
        let ta = TrustAnchor::new(tmp.path());

        let signer_name = "ops@corp.example.test";
        let hex = sha256_hex(signer_name.as_bytes());
        assert_eq!(hex.len(), 64);

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF_u64);
        let kp = Keypair::generate(&mut rng, signer_name.into());
        let vk_bytes = kp.verifying_key_bytes();
        assert_eq!(vk_bytes.len(), MLDSA87_VK_LEN);

        let file_path = tmp.path().join(format!("{}.vk", hex));
        fs::write(&file_path, &vk_bytes).unwrap();

        let loaded = ta.load_vk_by_name(signer_name).unwrap();
        assert_eq!(loaded.len(), MLDSA87_VK_LEN);
        assert_eq!(loaded, vk_bytes);
    }

    #[test]
    fn load_vk_missing_returns_trust_anchor_missing() {
        let tmp = TempDir::new().unwrap();
        let ta = TrustAnchor::new(tmp.path());

        match ta.load_vk_by_name("nobody@nowhere.invalid") {
            Err(BitcacheError::TrustAnchorMissing { name, path }) => {
                assert_eq!(name, "nobody@nowhere.invalid");
                let hex = sha256_hex(b"nobody@nowhere.invalid");
                assert!(path.ends_with(format!("{}.vk", hex)));
            }
            other => panic!("expected TrustAnchorMissing, got {other:?}"),
        }
    }

    #[test]
    fn verify_with_anchor_happy_path() {
        let tmp = TempDir::new().unwrap();
        let ta = TrustAnchor::new(tmp.path());

        let signer_name = "ops@corp.example.test";
        let hex = sha256_hex(signer_name.as_bytes());

        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1234_5678_u64);
        let kp = Keypair::generate(&mut rng, signer_name.into());
        let vk_bytes = kp.verifying_key_bytes();

        let file_path = tmp.path().join(format!("{}.vk", hex));
        fs::write(&file_path, &vk_bytes).unwrap();

        let obj = ObjRef(*blake3::hash(b"trust anchor verify test").as_bytes());
        let env = SignedEnvelope::new(&mut rng, &kp, obj).unwrap();

        verify_with_anchor(&env, &ta).expect("verify_with_anchor should succeed with matching anchor");
    }

    #[test]
    fn verify_with_anchor_name_mismatch_fails_not_wire_keyref_rejected() {
        let tmp = TempDir::new().unwrap();
        let ta = TrustAnchor::new(tmp.path());

        let signer_name = "ops@corp.example.test";
        let hex = sha256_hex(signer_name.as_bytes());

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE_BABE_u64);
        let kp = Keypair::generate(&mut rng, signer_name.into());
        let vk_bytes = kp.verifying_key_bytes();

        let file_path = tmp.path().join(format!("{}.vk", hex));
        fs::write(&file_path, &vk_bytes).unwrap();

        let obj = ObjRef(*blake3::hash(b"mismatch test").as_bytes());
        let env = SignedEnvelope::new(&mut rng, &kp, obj).unwrap();

        let mut mismatched_env = env.clone();
        mismatched_env.name = "attacker@evil.invalid".into();

        match verify_with_anchor(&mismatched_env, &ta) {
            Err(BitcacheError::TrustAnchorMissing { .. }) => {}
            Err(BitcacheError::WireKeyrefRejected) => {
                panic!("WireKeyrefRejected should NOT be triggered for name mismatch; it is a placeholder for future wire keyref enforcement");
            }
            other => panic!("expected TrustAnchorMissing for mismatched name, got {other:?}"),
        }
    }

    #[test]
    fn sha256_hex_is_64_chars() {
        let h = sha256_hex(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

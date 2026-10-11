//! Bitcache CAS fetch over the AWP/3 mesh — *data model + pure-data tests only*.
//!
//! `ainit` fetches every Bitcache blob as an `RS(N=M+K, M)` reed-solomon stripe
//! across N mesh peers.  With M=3 data shards + K=2 recovery we survive the loss of
//! any 2 peers mid-fetch.
//!
//! For ainit's 30 ms bring-up budget we do **minimal** work here:
//!
//! 1. Concatenate the N shard payloads in order.
//! 2. Run reed-solomon-16 to rebuild the original M data shards (if ≤ K
//!    shards were dropped / corrupted in transit).
//! 3. Check blake3(M concatenated data shards) == expected `blake3_ref`.
//! 4. Return the verified payload bytes.
//!
//! The real QUIC pull (`feature = "metal"`) is stubbed in [`fetch_stripe_from_peers`];
//! for CI/test we build stripe byte vectors in-process and exercise the
//! RS-decode + blake3-verify path directly.

use anyhow::{anyhow, bail, Result};
use blake3::Hash;
use reed_solomon_16::{ReedSolomonDecoder, ReedSolomonEncoder};

/// Total shards N = M (data) + K (recovery).  Default: N=5, M=3, K=2 → lose any 2.
pub const DEFAULT_N_SHARDS_TOTAL: usize = 5;
pub const DEFAULT_M_DATA_SHARDS: usize = 3;
pub const DEFAULT_K_RECOVERY_SHARDS: usize = 2;

/// One RS(M + K) stripe across N=M+K mesh peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsStripe {
    /// Data shards count.
    pub m: usize,
    /// Recovery shards count (K).
    pub k: usize,
    /// Shards length N=M+K total, Some=reconstruct from N = M shards data first then K recovery.
    pub shards: Vec<Option<Vec<u8>>>,
    /// Expected blake3 of concatenated M DATA shards concatenated == expected digest: blake3
    pub expected_digest: [u8; 32],
}

/// Reconstructed blob returned by [`RsStripe::reassemble`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedBlob {
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    /// Number of shards reconstructed with None on input.
    pub n_recovered: usize,
}

impl RsStripe {
    /// Build an RS stripe by splitting `payload` into M equal data shards + K recovery
    /// using `reed_solomon_16::ReedSolomonEncoder`.
    pub fn encode_mk(payload: &[u8], m: usize, k: usize) -> Result<Self> {
        if m == 0 || k == 0 || m + k > 256 {
            let t = m + k;
            bail!("invalid RS data={m}+recovery={k} total={t} — need 1 ≤ m,k, m+k ≤ 256");
        }
        let t = m + k;
        // reed-solomon-16: shard_size must be a non-zero multiple of 64 bytes.
        let raw_per_shard = (payload.len() + m - 1) / m.max(1);
        let shard_size = if raw_per_shard == 0 {
            64
        } else {
            let align64 = (64 - (raw_per_shard % 64)) % 64;
            raw_per_shard + align64
        };
        // Pad payload with 0x00 to fill the m data shards evenly.
        let data_shards: Vec<Vec<u8>> = (0..m)
            .map(|i| {
                let start = i * shard_size;
                let end = std::cmp::min(start + shard_size, payload.len());
                let mut v = payload[start..end].to_vec();
                v.resize(shard_size, 0u8);
                v
            })
            .collect();
        let mut encoder = ReedSolomonEncoder::new(m, k, shard_size)
            .map_err(|e| anyhow!("RS encoder init failed: {e}"))?;
        for s in &data_shards {
            encoder.add_original_shard(s)
                .map_err(|e| anyhow!("encoder add_original_shard: {e}"))?;
        }
        let enc = encoder.encode().map_err(|e| anyhow!("RS encode: {e}"))?;

        let all_data: Vec<Vec<u8>> = data_shards.clone();
        let mut all_shards: Vec<Option<Vec<u8>>> = data_shards.into_iter().map(Some).collect();
        for recovery in enc.recovery_iter() {
            all_shards.push(Some(recovery.to_vec()));
        }
        let digest = blake3_concat(&all_data.iter().collect::<Vec<_>>());
        let _ = t;
        Ok(Self {
            m,
            k,
            shards: all_shards,
            expected_digest: *digest.as_bytes(),
        })
    }

    /// Reassemble: RS-reconstruct missing, verify blake3, return bytes.
    pub fn reassemble(self) -> Result<FetchedBlob> {
        let t = self.m + self.k;
        if self.shards.len() != t {
            bail!("stripe shard len {} != m+k={t}", self.shards.len());
        }
        let shard_size = self.shards.iter().flatten().next()
            .map(|s| s.len())
            .ok_or_else(|| anyhow!("all {t} shards are None; need >= M={alive}", alive=self.m))?;
        let have = self.shards.iter().flatten().count();
        if have < self.m {
            bail!("not enough shards: {have}/{t} alive; need m={} to recover stripe", self.m);
        }
        let mut owned: Vec<Vec<u8>> = self.shards.iter()
            .map(|s| s.clone().unwrap_or_else(|| vec![0u8; shard_size]))
            .collect();
        let missing: Vec<usize> = (0..t).filter(|&i| self.shards[i].is_none()).collect();
        let n_recovered = missing.len();

        if n_recovered > 0 {
            let mut decoder = ReedSolomonDecoder::new(self.m, self.k, shard_size)
                .map_err(|e| anyhow!("RS decoder init: {e}"))?;
            for i in 0..t {
                if let Some(bytes) = &self.shards[i] {
                    if i < self.m {
                        decoder.add_original_shard(i, bytes).map_err(|e| anyhow!("add orig {i}: {e}"))?;
                    } else {
                        decoder.add_recovery_shard(i - self.m, bytes).map_err(|e| anyhow!("add rec {i}: {e}"))?;
                    }
                }
            }
            let dec = decoder.decode().map_err(|e| anyhow!("RS decode (corrupt?): {e}"))?;
            for (idx, restored) in dec.restored_original_iter() {
                owned[idx] = restored.to_vec();
            }
        }
        let data_part = &owned[..self.m];
        let digest = blake3_concat(&data_part.iter().collect::<Vec<_>>());
        if digest.as_bytes() != &self.expected_digest {
            bail!(
                "CAS digest mismatch after RS reassemble: expected {} got {}",
                hex_of(&self.expected_digest),
                hex_of(digest.as_bytes())
            );
        }
        let bytes = data_part.iter().flat_map(|s| s.iter().copied()).collect::<Vec<_>>();
        Ok(FetchedBlob { bytes, digest: *digest.as_bytes(), n_recovered })
    }
}

/// Pull shards from peers; for the real QUIC pull.  For CI, the
/// (caller provides a per-peer bytes).
pub fn fetch_stripe_from_peers(
    _peer_fds: &[std::os::unix::io::OwnedFd],
    expected_hash: [u8; 32],
    m: usize,
    k: usize,
    mock_get: impl Fn(usize) -> Option<Vec<u8>>,
) -> Result<RsStripe> {
    let t = m + k;
    let mut shards = Vec::with_capacity(t);
    for peer_idx in 0..t { shards.push(mock_get(peer_idx));
    }
    Ok(RsStripe { m, k, shards, expected_digest: expected_hash })
}

fn blake3_concat(shards: &[&Vec<u8>]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for s in shards { hasher.update(s); }
    hasher.finalize()
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(0x91).wrapping_add(0x23)).collect()
    }

    #[test]
    fn rs_3_2_all_5_present_zero_recovered_digest_ok() {
        let payload = random_payload(2000);
        let stripe = RsStripe::encode_mk(&payload, 3, 2).unwrap();
        let fetched = stripe.reassemble().unwrap();
        assert_eq!(fetched.n_recovered, 0);
        assert_eq!(&fetched.bytes[..2000], &payload[..2000]);
        assert_eq!(fetched.digest.len(), 32);
    }

    #[test]
    fn rs_3_2_kill_data_shard_1_and_recovery_4_dual_recovery_still_verifies() {
        let payload = random_payload(2048);
        let stripe_full = RsStripe::encode_mk(&payload, 3, 2).unwrap();
        let mut damaged = stripe_full;
        damaged.shards[1] = None;
        damaged.shards[4] = None;
        let fetched = damaged.reassemble().unwrap();
        assert_eq!(fetched.n_recovered, 2);
        assert_eq!(&fetched.bytes[..2048], &payload[..2048]);
    }

    #[test]
    fn rs_3_2_all_5_dead_unrecoverable() {
        let payload = random_payload(1024);
        let mut stripe = RsStripe::encode_mk(&payload, 3, 2).unwrap();
        for s in stripe.shards.iter_mut() {
            *s = None;
        }
        let err = stripe.reassemble().unwrap_err().to_string();
        assert!(err.contains("all"));
    }

    #[test]
    fn rs_tamper_parity_digest_matches_parity_not_in_blake3_input() {
        let payload = random_payload(512);
        let mut stripe = RsStripe::encode_mk(&payload, 3, 2).unwrap();
        // Tamper recovery shards 3 & 4 — blake3 is over data only; digest matches.
        for idx in [3, 4] {
            if let Some(shard) = stripe.shards[idx].as_mut() { for b in shard.iter_mut() { *b ^= 0xFF; } }
        }
        let f = stripe.reassemble().unwrap();
        assert_eq!(&f.bytes[..512], &payload);
    }

    #[test]
    fn rs_kill_any_2_of_5_m3_k2() {
        // With m=3,k=2, survive any 2.
        let payload = random_payload(3000);
        let stripe_full = RsStripe::encode_mk(&payload, 3, 2).unwrap();
        let kill_sets = [[0usize,1],[2,4],[0,4],[1,3]];
        for kill in &kill_sets {
            let mut d = stripe_full.clone();
            d.shards[kill[0]] = None;
            d.shards[kill[1]] = None;
            let f = d.reassemble().unwrap_or_else(|e| panic!("kill {kill:?}: {e}"));
            assert_eq!(f.n_recovered, 2);
            assert_eq!(&f.bytes[..3000], &payload);
        }
    }
}

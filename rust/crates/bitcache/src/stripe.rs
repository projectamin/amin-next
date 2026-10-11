use crate::error::{BitcacheError, Result};
use crate::slab::ObjRef;
use reed_solomon_16::{ReedSolomonDecoder, ReedSolomonEncoder};

pub const SHARD_HEADER_LEN: usize = 128;

pub struct StripeEncoder {
    m: u8,
    k: u8,
}

impl StripeEncoder {
    pub fn new(m: u8, k: u8) -> Result<Self> {
        if m < 1 {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!("StripeEncoder M={} must be >= 1", m),
            });
        }
        if k < 1 {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!("StripeEncoder K={} must be >= 1", k),
            });
        }
        if (m as usize) + (k as usize) > 64 {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!(
                    "StripeEncoder M+K={} exceeds cap 64 (reed-solomon-16 allows 65535; Amin 3.0 uses small stripes)",
                    (m as usize) + (k as usize)
                ),
            });
        }
        Ok(Self { m, k })
    }

    pub fn encode(&self, full_payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        let m = self.m as usize;
        let k = self.k as usize;

        let pad_mod_m = (m - (full_payload.len() % m)) % m;
        let partial_padded_len = full_payload.len() + pad_mod_m;
        let raw_chunk_size = partial_padded_len / m;
        let chunk_align_64 = (64 - (raw_chunk_size % 64)) % 64;
        let total_extra_pad = pad_mod_m + chunk_align_64 * m;
        let pad_len = total_extra_pad;

        let mut padded = Vec::with_capacity(full_payload.len() + total_extra_pad);
        padded.extend_from_slice(full_payload);
        padded.resize(full_payload.len() + total_extra_pad, 0u8);

        let chunk_size = padded.len() / m;
        debug_assert_eq!(chunk_size % 64, 0);
        debug_assert_eq!(padded.len(), chunk_size * m);

        let digest = blake3::hash(full_payload);
        let obj_ref = ObjRef(*digest.as_bytes());

        let mut encoder =
            ReedSolomonEncoder::new(m, k, chunk_size).map_err(|e| BitcacheError::UnsupportedAlgorithm {
                kind: format!("reed-solomon-16 encoder init: {}", e),
            })?;

        for i in 0..m {
            let chunk = &padded[i * chunk_size..(i + 1) * chunk_size];
            encoder
                .add_original_shard(chunk)
                .map_err(|e| BitcacheError::UnsupportedAlgorithm {
                    kind: format!("reed-solomon-16 add shard: {}", e),
                })?;
        }

        let enc_result = encoder.encode().map_err(|e| BitcacheError::UnsupportedAlgorithm {
            kind: format!("reed-solomon-16 encode: {}", e),
        })?;

        let recovery_shards: Vec<Vec<u8>> = enc_result.recovery_iter().map(|s| s.to_vec()).collect();

        let mut out = Vec::with_capacity(m + k);

        for i in 0..m {
            let mut shard = Vec::with_capacity(SHARD_HEADER_LEN + chunk_size);
            let mut header = [0u8; SHARD_HEADER_LEN];
            header[0..32].copy_from_slice(obj_ref.as_bytes());
            header[32] = i as u8;
            header[33] = self.m;
            header[34] = self.k;
            header[35..39].copy_from_slice(&(pad_len as u32).to_le_bytes());
            header[39..43].copy_from_slice(&(chunk_size as u32).to_le_bytes());
            shard.extend_from_slice(&header);
            shard.extend_from_slice(&padded[i * chunk_size..(i + 1) * chunk_size]);
            out.push(shard);
        }

        for (ki, recovery) in recovery_shards.into_iter().enumerate() {
            let global_idx = m + ki;
            let mut shard = Vec::with_capacity(SHARD_HEADER_LEN + chunk_size);
            let mut header = [0u8; SHARD_HEADER_LEN];
            header[0..32].copy_from_slice(obj_ref.as_bytes());
            header[32] = global_idx as u8;
            header[33] = self.m;
            header[34] = self.k;
            header[35..39].copy_from_slice(&(pad_len as u32).to_le_bytes());
            header[39..43].copy_from_slice(&(chunk_size as u32).to_le_bytes());
            shard.extend_from_slice(&header);
            shard.extend_from_slice(&recovery);
            out.push(shard);
        }

        Ok(out)
    }
}

pub struct StripeDecoder {
    m: u8,
    k: u8,
}

impl StripeDecoder {
    pub fn new(m: u8, k: u8) -> Result<Self> {
        if m < 1 {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!("StripeDecoder M={} must be >= 1", m),
            });
        }
        if k < 1 {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!("StripeDecoder K={} must be >= 1", k),
            });
        }
        if (m as usize) + (k as usize) > 64 {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!(
                    "StripeDecoder M+K={} exceeds cap 64 (reed-solomon-16 allows 65535; Amin 3.0 uses small stripes)",
                    (m as usize) + (k as usize)
                ),
            });
        }
        Ok(Self { m, k })
    }

    pub fn reconstruct(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>> {
        let m = self.m as usize;
        let k = self.k as usize;
        let total = m + k;

        if shards.len() != total {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!(
                    "StripeDecoder reconstruct: expected shards.len()={}, got {}",
                    total,
                    shards.len()
                ),
            });
        }

        let have = shards.iter().filter(|s| s.is_some()).count();
        if have < m {
            return Err(BitcacheError::InsufficientReachablePeers {
                have,
                need: m,
            });
        }

        let first_avail = shards
            .iter()
            .position(|s| s.is_some())
            .expect("have >=1 checked above");
        let first_bytes = shards[first_avail].as_ref().unwrap();
        if first_bytes.len() < SHARD_HEADER_LEN {
            return Err(BitcacheError::CorruptedRead {
                offset: 0,
                expected: SHARD_HEADER_LEN,
                saw: first_bytes.len(),
            });
        }
        let header = &first_bytes[0..SHARD_HEADER_LEN];
        let header_obj_ref_bytes: [u8; 32] = header[0..32].try_into().map_err(|_| BitcacheError::CorruptedRead {
            offset: 0,
            expected: 32,
            saw: 32,
        })?;
        let m_from_header = header[33];
        let k_from_header = header[34];
        let pad_len = u32::from_le_bytes(header[35..39].try_into().unwrap()) as usize;
        let shard_len = u32::from_le_bytes(header[39..43].try_into().unwrap()) as usize;

        if m_from_header != self.m {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!(
                    "StripeDecoder reconstruct: header M={} != self.M={}",
                    m_from_header, self.m
                ),
            });
        }
        if k_from_header != self.k {
            return Err(BitcacheError::UnsupportedAlgorithm {
                kind: format!(
                    "StripeDecoder reconstruct: header K={} != self.K={}",
                    k_from_header, self.k
                ),
            });
        }

        let mut data_shards: Vec<Option<Vec<u8>>> = vec![None; m];

        for (global_idx, maybe_shard) in shards.iter().enumerate() {
            if let Some(shard_bytes) = maybe_shard {
                if shard_bytes.len() < SHARD_HEADER_LEN + shard_len {
                    return Err(BitcacheError::CorruptedRead {
                        offset: SHARD_HEADER_LEN as u64,
                        expected: shard_len,
                        saw: shard_bytes.len().saturating_sub(SHARD_HEADER_LEN),
                    });
                }
                let payload = &shard_bytes[SHARD_HEADER_LEN..SHARD_HEADER_LEN + shard_len];
                if global_idx < m {
                    data_shards[global_idx] = Some(payload.to_vec());
                }
            }
        }

        let all_data_present = data_shards.iter().all(|s| s.is_some());
        if !all_data_present {
            let mut decoder =
                ReedSolomonDecoder::new(m, k, shard_len).map_err(|e| BitcacheError::UnsupportedAlgorithm {
                    kind: format!("reed-solomon-16 decoder init: {}", e),
                })?;

            for (global_idx, maybe_shard) in shards.iter().enumerate() {
                if let Some(shard_bytes) = maybe_shard {
                    let payload = &shard_bytes[SHARD_HEADER_LEN..SHARD_HEADER_LEN + shard_len];
                    if global_idx < m {
                        decoder
                            .add_original_shard(global_idx, payload)
                            .map_err(|e| BitcacheError::UnsupportedAlgorithm {
                                kind: format!("reed-solomon-16 add original shard {}: {}", global_idx, e),
                            })?;
                    } else {
                        let recovery_idx = global_idx - m;
                        decoder
                            .add_recovery_shard(recovery_idx, payload)
                            .map_err(|e| BitcacheError::UnsupportedAlgorithm {
                                kind: format!(
                                    "reed-solomon-16 add recovery shard {} (global {}): {}",
                                    recovery_idx, global_idx, e
                                ),
                            })?;
                    }
                }
            }

            let dec_result = decoder.decode().map_err(|e| BitcacheError::UnsupportedAlgorithm {
                kind: format!("reed-solomon-16 decode: {}", e),
            })?;

            for (idx, restored) in dec_result.restored_original_iter() {
                data_shards[idx] = Some(restored.to_vec());
            }
        }

        let mut assembled = Vec::with_capacity(m * shard_len);
        for i in 0..m {
            match &data_shards[i] {
                Some(s) => assembled.extend_from_slice(s),
                None => {
                    return Err(BitcacheError::UnsupportedAlgorithm {
                        kind: format!(
                            "StripeDecoder reconstruct: data shard {} still missing after reed-solomon decode",
                            i
                        ),
                    });
                }
            }
        }

        if pad_len > assembled.len() {
            return Err(BitcacheError::CorruptedRead {
                offset: 0,
                expected: pad_len,
                saw: assembled.len(),
            });
        }
        let original_len = assembled.len() - pad_len;
        assembled.truncate(original_len);

        let recomputed = blake3::hash(&assembled);
        if recomputed.as_bytes() != &header_obj_ref_bytes {
            return Err(BitcacheError::HashMismatch { offset: 0 });
        }

        Ok(assembled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_3_2_kill_any_2() {
        const M: u8 = 3;
        const K: u8 = 2;
        const LEN: usize = 1_048_576;

        let enc = StripeEncoder::new(M, K).unwrap();
        let original: Vec<u8> = vec![0x55u8; LEN];
        let original_hash = blake3::hash(&original);

        let shards = enc.encode(&original).unwrap();
        assert_eq!(shards.len(), (M + K) as usize);

        let dec = StripeDecoder::new(M, K).unwrap();

        let kill_sets: [[usize; 2]; 3] = [[0, 1], [0, 4], [3, 4]];

        for kill in &kill_sets {
            let mut damaged: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            for &k in kill {
                damaged[k] = None;
            }
            let restored = dec.reconstruct(&damaged).unwrap();
            assert_eq!(restored.len(), original.len());
            let restored_hash = blake3::hash(&restored);
            assert_eq!(restored_hash, original_hash);
        }
    }

    #[test]
    fn decode_need_more_fails_fast() {
        const M: u8 = 3;
        const K: u8 = 2;
        const LEN: usize = 1_048_576;

        let enc = StripeEncoder::new(M, K).unwrap();
        let original: Vec<u8> = vec![0x55u8; LEN];
        let shards = enc.encode(&original).unwrap();

        let dec = StripeDecoder::new(M, K).unwrap();

        let mut damaged: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        damaged[0] = None;
        damaged[1] = None;
        damaged[2] = None;

        let result = dec.reconstruct(&damaged);
        match result {
            Err(BitcacheError::InsufficientReachablePeers { have, need }) => {
                assert_eq!(have, 2);
                assert_eq!(need, 3);
            }
            other => panic!("expected InsufficientReachablePeers, got {:?}", other),
        }
    }
}

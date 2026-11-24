//! Node certificate — how trust is pushed from the existing ecosystem to a
//! newly booted node.
//!
//! A node mints its own identity key at boot (an AWP/3 composite key,
//! ML-DSA-65 ‖ Ed25519).  The authority (ToR / mesh root, ML-DSA-87) then
//! certifies *the hash of that key* for exactly one boot, inside the signed
//! BOOT_OFFER.  Everything the node later signs — ledger checkpoints, billing
//! entries — chains back to the authority through this certificate.
//!
//! Wire layout (all integers little-endian), then the authority signature:
//!
//! ```text
//!   "AMIN3-NODE-CERT-V1\n"
//!   node_id_len(u32) ‖ node_id
//!   node_vk_hash(32)            blake3 of the 1984-byte composite vk
//!   boot_counter(u64)
//!   scope_hash(32)              hash of the zcap scope granted for this boot
//!   valid_from_pos(u64)         authority-log position, inclusive
//!   valid_to_pos(u64)           authority-log position, inclusive (u64::MAX = open)
//!   signature(4627)             ML-DSA-87 over everything above
//! ```
//!
//! Validity is a position in the authority's own log, not a wall-clock time:
//! a netbooted node has no trustworthy RTC, but it always learns the
//! authority's current position from the signed offer.

use crate::signer::{mldsa87_sign, mldsa87_verify, Keypair, MLDSA87_SIG_LEN};
use crate::trust::Reject;

const MAGIC: &[u8] = b"AMIN3-NODE-CERT-V1\n";
const MAX_NODE_ID: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCert {
    pub node_id: String,
    pub node_vk_hash: [u8; 32],
    pub boot_counter: u64,
    pub scope_hash: [u8; 32],
    pub valid_from_pos: u64,
    pub valid_to_pos: u64,
}

impl NodeCert {
    /// The exact bytes the authority signs.
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(MAGIC.len() + 4 + self.node_id.len() + 32 + 8 + 32 + 16);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&(self.node_id.len() as u32).to_le_bytes());
        b.extend_from_slice(self.node_id.as_bytes());
        b.extend_from_slice(&self.node_vk_hash);
        b.extend_from_slice(&self.boot_counter.to_le_bytes());
        b.extend_from_slice(&self.scope_hash);
        b.extend_from_slice(&self.valid_from_pos.to_le_bytes());
        b.extend_from_slice(&self.valid_to_pos.to_le_bytes());
        b
    }

    /// Issue: `body ‖ ML-DSA-87 signature`.
    pub fn sign(&self, authority: &Keypair) -> crate::Result<Vec<u8>> {
        let mut out = self.body();
        let sig = mldsa87_sign(authority, &out)?;
        out.extend_from_slice(&sig);
        Ok(out)
    }

    /// Whether the certificate covers authority-log position `pos`.
    pub fn valid_at(&self, pos: u64) -> bool {
        self.valid_from_pos <= pos && pos <= self.valid_to_pos
    }

    /// Parse and verify under `authority_vk`.  Fail closed: any structural
    /// problem, trailing bytes, or signature failure is an error.
    pub fn verify(bytes: &[u8], authority_vk: &[u8]) -> Result<Self, Reject> {
        let split = bytes.len().checked_sub(MLDSA87_SIG_LEN).ok_or(Reject::Format)?;
        let (body, sig) = bytes.split_at(split);
        let cert = Self::parse_body(body)?;
        if cert.body() != body {
            return Err(Reject::Format); // non-canonical encoding
        }
        if !mldsa87_verify(authority_vk, body, sig) {
            return Err(Reject::BadSig);
        }
        Ok(cert)
    }

    fn parse_body(b: &[u8]) -> Result<Self, Reject> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Reject> {
            let end = p.checked_add(n).ok_or(Reject::Format)?;
            let s = b.get(p..end).ok_or(Reject::Format)?;
            p = end;
            Ok(s)
        };
        if take(MAGIC.len())? != MAGIC {
            return Err(Reject::Format);
        }
        let n = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if n > MAX_NODE_ID {
            return Err(Reject::Format);
        }
        let node_id = core::str::from_utf8(take(n)?).map_err(|_| Reject::Format)?.to_owned();
        let node_vk_hash: [u8; 32] = take(32)?.try_into().unwrap();
        let boot_counter = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let scope_hash: [u8; 32] = take(32)?.try_into().unwrap();
        let valid_from_pos = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let valid_to_pos = u64::from_le_bytes(take(8)?.try_into().unwrap());
        if p != b.len() {
            return Err(Reject::Format);
        }
        Ok(Self { node_id, node_vk_hash, boot_counter, scope_hash, valid_from_pos, valid_to_pos })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn auth(seed: u8) -> Keypair {
        Keypair::generate(&mut StdRng::from_seed([seed; 32]), "authority".into())
    }
    fn cert() -> NodeCert {
        NodeCert {
            node_id: "metal-abababab".into(),
            node_vk_hash: [7; 32],
            boot_counter: 12,
            scope_hash: [9; 32],
            valid_from_pos: 100,
            valid_to_pos: 200,
        }
    }

    #[test]
    fn issue_and_verify() {
        let a = auth(1);
        let bytes = cert().sign(&a).unwrap();
        let got = NodeCert::verify(&bytes, &a.verifying_key_bytes()).unwrap();
        assert_eq!(got, cert());
        assert!(got.valid_at(100) && got.valid_at(200) && !got.valid_at(99) && !got.valid_at(201));
    }

    #[test]
    fn rejects_forgery_and_malformation() {
        let a = auth(1);
        let vk = a.verifying_key_bytes();
        let bytes = cert().sign(&a).unwrap();
        // wrong authority
        assert_eq!(NodeCert::verify(&bytes, &auth(2).verifying_key_bytes()), Err(Reject::BadSig));
        // any flipped body byte
        for i in [0usize, 25, 40, 60, 90] {
            let mut t = bytes.clone();
            t[i] ^= 1;
            assert!(NodeCert::verify(&t, &vk).is_err(), "byte {i}");
        }
        // trailing byte shifts the signature window
        let mut t = bytes.clone();
        t.push(0);
        assert!(NodeCert::verify(&t, &vk).is_err());
        // truncated / empty
        assert_eq!(NodeCert::verify(&bytes[..50], &vk), Err(Reject::Format));
        assert_eq!(NodeCert::verify(&[], &vk), Err(Reject::Format));
    }
}

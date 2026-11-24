//! Transfer receipts — offline-verifiable proof that an entry is in a log.
//!
//! A receipt is `(entry, inclusion proof, signed checkpoint)`.  Whoever holds it
//! can check, with no network and no history, that the origin's key (chained to
//! an authority) committed to that exact entry at that position.  This is what
//! lets two phones transact while the whole mesh is offline: the payer hands
//! over a receipt for its `transfer.out`; the payee verifies it and records a
//! `transfer.in` that points back at it.
//!
//! Wire (little-endian, canonical, no trailing bytes):
//!
//! ```text
//!   "AMIN3-RECEIPT-V1\n" ‖ u32 len ‖ entry ‖ u64 index ‖ u16 n ‖ n × proof[32]
//!                        ‖ u32 len ‖ signed checkpoint
//! ```

use crate::checkpoint::{self, Checkpoint, CertCache, CkptError};
use crate::entry::Entry;
use crate::tlog::{self, Hash};

const MAGIC: &[u8] = b"AMIN3-RECEIPT-V1\n";
const MAX_ENTRY: usize = 16 * 1024;
const MAX_CKPT: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub entry: Vec<u8>,
    pub index: u64,
    pub proof: Vec<Hash>,
    pub checkpoint: Vec<u8>,
}

impl Receipt {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = MAGIC.to_vec();
        o.extend_from_slice(&(self.entry.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.entry);
        o.extend_from_slice(&self.index.to_le_bytes());
        o.extend_from_slice(&(self.proof.len() as u16).to_le_bytes());
        for p in &self.proof {
            o.extend_from_slice(p);
        }
        o.extend_from_slice(&(self.checkpoint.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.checkpoint);
        o
    }

    pub fn decode(b: &[u8]) -> Result<Self, CkptError> {
        let mut c = b;
        let mut take = |n: usize| -> Result<&[u8], CkptError> {
            if c.len() < n {
                return Err(CkptError::Format);
            }
            let (a, r) = c.split_at(n);
            c = r;
            Ok(a)
        };
        if take(MAGIC.len())? != MAGIC {
            return Err(CkptError::Format);
        }
        let n = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if n > MAX_ENTRY {
            return Err(CkptError::Format);
        }
        let entry = take(n)?.to_vec();
        let index = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let np = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let mut proof = Vec::with_capacity(np);
        for _ in 0..np {
            let mut h = [0u8; 32];
            h.copy_from_slice(take(32)?);
            proof.push(h);
        }
        let n = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if n > MAX_CKPT {
            return Err(CkptError::Format);
        }
        let checkpoint = take(n)?.to_vec();
        if !c.is_empty() {
            return Err(CkptError::Format);
        }
        Ok(Self { entry, index, proof, checkpoint })
    }

    /// Same receipt with the node certificate left out of its checkpoint.
    pub fn slim(&self) -> Result<Self, CkptError> {
        Ok(Self { checkpoint: checkpoint::slim(&self.checkpoint)?, ..self.clone() })
    }

    /// [`Receipt::verify`] against a certificate cache (accepts slim receipts).
    pub fn verify_cached(
        &self, authorities: &[&[u8]], pos: u64, roster: &[&[u8]], quorum: usize, cache: &mut CertCache,
    ) -> Result<(Entry, Hash, Checkpoint), CkptError> {
        let ck = checkpoint::verify_any_cached(&self.checkpoint, authorities, pos, roster, quorum, cache)?;
        self.check_entry(ck)
    }

    fn check_entry(&self, ck: Checkpoint) -> Result<(Entry, Hash, Checkpoint), CkptError> {
        let e = Entry::decode(&self.entry).map_err(|_| CkptError::Format)?;
        let leaf = tlog::leaf_hash(&self.entry);
        if !tlog::verify_inclusion(&leaf, self.index, ck.size, &self.proof, &ck.root) {
            return Err(CkptError::BadSig);
        }
        Ok((e, crate::entry::id_of(&self.entry), ck))
    }

    /// Verify the signed checkpoint (any trusted authority, optional witness
    /// quorum) and that the entry is leaf `index` of exactly that tree.
    /// Returns the decoded entry, its id, and the checkpoint.
    pub fn verify(
        &self,
        authorities: &[&[u8]],
        pos: u64,
        roster: &[&[u8]],
        quorum: usize,
    ) -> Result<(Entry, Hash, Checkpoint), CkptError> {
        let ck = checkpoint::verify_any(&self.checkpoint, authorities, pos, roster, quorum)?;
        self.check_entry(ck)
    }
}

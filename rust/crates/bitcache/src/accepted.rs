//! Bounded replay guard for accepted transfer receipts.
//!
//! A receipt is identified by `(origin, payer actor, seq)`: the payer's actor
//! chain inside its origin ledger is dense and strictly increasing, so the
//! sequence number of its `transfer.out` is a unique, ordered name.  Per
//! `(origin, actor)` the receiver keeps a `floor` and at most [`WINDOW`]
//! accepted sequence numbers at or above it:
//!
//! * `seq < floor` is refused (**stale** — it might have been accepted before
//!   the window moved, and the receiver cannot prove otherwise);
//! * `seq` already in the set is refused (**replay**);
//! * inserting beyond [`WINDOW`] drops the lowest and raises the floor above it.
//!
//! Replay protection is therefore exact for everything it admits, state is
//! O(keys × WINDOW) regardless of history, and it can be committed in a join
//! snapshot ([`root`]) so a node that never saw the old receipts still refuses
//! them.  The cost is that a very old receipt must be re-issued by the payer.

use std::collections::BTreeMap;

use crate::tlog::{self, Hash};

pub const WINDOW: usize = 64;
pub const MAX_KEYS: usize = 1 << 16;
const MAX_NAME: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Replay,
    Stale,
    Full,
    Zero,
}

/// One committed record: `(origin, actor, floor, accepted seqs ascending ≥ floor)`.
pub type Rec = (String, String, u64, Vec<u64>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Accepted {
    map: BTreeMap<(String, String), (u64, Vec<u64>)>,
}

impl Accepted {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn check(&self, origin: &str, actor: &str, seq: u64) -> Result<(), Refusal> {
        if seq == 0 {
            return Err(Refusal::Zero);
        }
        match self.map.get(&(origin.to_string(), actor.to_string())) {
            None if self.map.len() >= MAX_KEYS => Err(Refusal::Full),
            None => Ok(()),
            Some((floor, _)) if seq < *floor => Err(Refusal::Stale),
            Some((_, seqs)) if seqs.binary_search(&seq).is_ok() => Err(Refusal::Replay),
            Some(_) => Ok(()),
        }
    }

    pub fn insert(&mut self, origin: &str, actor: &str, seq: u64) -> Result<(), Refusal> {
        self.check(origin, actor, seq)?;
        let slot = self.map.entry((origin.to_string(), actor.to_string())).or_insert((0, Vec::new()));
        let at = slot.1.binary_search(&seq).unwrap_err();
        slot.1.insert(at, seq);
        if slot.1.len() > WINDOW {
            let lowest = slot.1.remove(0);
            slot.0 = lowest + 1;
        }
        Ok(())
    }

    /// Records in canonical (sorted) order.
    pub fn records(&self) -> Vec<Rec> {
        self.map.iter().map(|((o, a), (f, s))| (o.clone(), a.clone(), *f, s.clone())).collect()
    }

    /// Strict validation: sorted, in-bounds, internally consistent.  `None` ⇒ malformed.
    pub fn from_records(recs: &[Rec]) -> Option<Self> {
        if recs.len() > MAX_KEYS {
            return None;
        }
        let mut map = BTreeMap::new();
        let mut prev: Option<(&str, &str)> = None;
        for (o, a, floor, seqs) in recs {
            if o.len() > MAX_NAME || a.len() > MAX_NAME || seqs.len() > WINDOW {
                return None;
            }
            if let Some((po, pa)) = prev {
                if (po.as_bytes(), pa.as_bytes()) >= (o.as_bytes(), a.as_bytes()) {
                    return None;
                }
            }
            if !seqs.windows(2).all(|w| w[0] < w[1]) || seqs.first().map_or(false, |s| s < floor) || seqs.contains(&0) {
                return None;
            }
            prev = Some((o, a));
            map.insert((o.clone(), a.clone()), (*floor, seqs.clone()));
        }
        Some(Self { map })
    }

    pub fn root(&self) -> Hash {
        root(&self.records())
    }
}

/// Merkle commitment to the records (empty ⇒ the empty-tree root).
pub fn root(recs: &[Rec]) -> Hash {
    let mut t = tlog::Tree::new();
    for (o, a, floor, seqs) in recs {
        let mut b = Vec::with_capacity(8 + o.len() + a.len() + 10 + seqs.len() * 8);
        b.extend_from_slice(&(o.len() as u32).to_le_bytes());
        b.extend_from_slice(o.as_bytes());
        b.extend_from_slice(&(a.len() as u32).to_le_bytes());
        b.extend_from_slice(a.as_bytes());
        b.extend_from_slice(&floor.to_le_bytes());
        b.extend_from_slice(&(seqs.len() as u16).to_le_bytes());
        for s in seqs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        t.append(&b);
    }
    t.root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_stale_and_bounded_window() {
        let mut a = Accepted::new();
        a.insert("o", "alice", 5).unwrap();
        assert_eq!(a.insert("o", "alice", 5), Err(Refusal::Replay));
        a.insert("o", "alice", 3).unwrap(); // out of order is fine inside the window
        a.insert("o", "bob", 5).unwrap(); // different actor, same seq
        a.insert("p", "alice", 5).unwrap(); // different origin
        assert_eq!(a.insert("o", "alice", 0), Err(Refusal::Zero));
        // push the window past WINDOW: the oldest falls out and its floor refuses it forever
        for s in 10..10 + WINDOW as u64 {
            a.insert("o", "alice", s).unwrap();
        }
        let (_, _, floor, seqs) = a.records().into_iter().find(|r| r.0 == "o" && r.1 == "alice").unwrap();
        assert!(seqs.len() <= WINDOW && floor > 3);
        assert_eq!(a.check("o", "alice", 3), Err(Refusal::Stale));
        assert_eq!(a.check("o", "alice", 10 + WINDOW as u64 + 50), Ok(()));
    }

    #[test]
    fn state_is_bounded_and_commitment_round_trips() {
        let mut a = Accepted::new();
        for s in 1..=10_000u64 {
            a.insert("o", "alice", s).unwrap();
        }
        let recs = a.records();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].3.len() <= WINDOW, "10k accepted receipts keep ≤ {WINDOW} seqs");
        let b = Accepted::from_records(&recs).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.root(), b.root());
        // any tamper changes the root or is malformed
        let mut t = recs.clone();
        t[0].2 += 1;
        assert!(Accepted::from_records(&t).map_or(true, |x| x.root() != a.root()));
        let mut unsorted = vec![("b".into(), "x".into(), 0, vec![]), ("a".into(), "x".into(), 0, vec![])];
        assert!(Accepted::from_records(&unsorted).is_none());
        unsorted.swap(0, 1);
        assert!(Accepted::from_records(&unsorted).is_some());
    }

    #[test]
    fn replay_survives_a_snapshot_round_trip() {
        let mut a = Accepted::new();
        for s in [2u64, 4, 6] {
            a.insert("o", "alice", s).unwrap();
        }
        let b = Accepted::from_records(&a.records()).unwrap();
        for s in [2u64, 4, 6] {
            assert_eq!(b.check("o", "alice", s), Err(Refusal::Replay));
        }
        assert_eq!(b.check("o", "alice", 5), Ok(()));
    }
}

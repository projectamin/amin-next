//! Join snapshots: how a new node (or a mesh coming back online) adopts the
//! current ledger state without carrying the history behind it.
//!
//! A snapshot is everything needed to *continue* the log and nothing more:
//!
//! * a signed checkpoint `(origin, size, root)` chained to the authority;
//! * the tree **frontier** — O(log n) hashes that fold to exactly that root;
//! * the **accepted-receipt** replay state (bounded, see [`crate::accepted`]),
//!   committed by the same entry, so a joined node still refuses old receipts;
//! * the per-actor chain **heads**, committed by a `ledger.state` entry that is
//!   itself the last leaf of the checkpointed tree (so the heads are covered by
//!   the signature through an inclusion proof, with no change to the
//!   checkpoint format).
//!
//! Size is O(log n + actors), independent of history length.  History is not
//! lost, only unneeded: any older state can still be audited from the newest
//! checkpoint with an O(log n) consistency proof, and any old entry with an
//! O(log n) inclusion proof, served by whichever archive/witness node kept it.
//!
//! Wire (little-endian, canonical, no trailing bytes):
//!
//! ```text
//!   "AMIN3-SNAPSHOT-V2\n"
//!   u32 len ‖ checkpoint            (empty until the sealed state is signed)
//!   u16 n ‖ n × frontier[32]        (highest subtree first)
//!   u32 n ‖ n × ( u32 len ‖ actor ‖ u64 seq ‖ id[32] )      actors ascending
//!   u32 n ‖ n × ( u32 len ‖ origin ‖ u32 len ‖ actor ‖ u64 floor ‖ u16 m ‖ m × u64 seq )
//!                                                            accepted receipts, ascending
//!   u32 len ‖ state entry           (kind "ledger.state", last leaf)
//!   u16 n ‖ n × proof[32]           (inclusion of that leaf)
//! ```

use crate::accepted::{self, Accepted};
use crate::checkpoint::{self, Checkpoint, CkptError};
use crate::entry::{self, Entry};
use crate::tlog::{self, Hash};

const MAGIC: &[u8] = b"AMIN3-SNAPSHOT-V2\n";
const MAX_HEADS: usize = 1 << 20;
pub const STATE_KIND: &str = "ledger.state";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapError {
    Format,
    Checkpoint(CkptError),
    /// A cross-check between the checkpoint, frontier, heads or state entry failed.
    Mismatch(&'static str),
}

impl SnapError {
    pub const fn code(self) -> i32 {
        match self {
            SnapError::Format => crate::trust::RC_FORMAT,
            SnapError::Checkpoint(e) => e.code(),
            SnapError::Mismatch(_) => crate::trust::RC_BAD_SIG,
        }
    }
}

pub type Head = (String, u64, Hash);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub checkpoint: Vec<u8>,
    pub frontier: Vec<Hash>,
    pub heads: Vec<Head>,
    pub accepted: Vec<accepted::Rec>,
    pub state_entry: Vec<u8>,
    pub proof: Vec<Hash>,
}

/// What a verified snapshot gives the joining node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub checkpoint: Checkpoint,
    /// Actor chain heads *after* the state entry itself.
    pub heads: Vec<Head>,
    pub accepted: Accepted,
}

/// Merkle commitment to the actor heads (sorted by actor).  Empty ⇒ empty root.
pub fn heads_root(heads: &[Head]) -> Hash {
    let mut t = tlog::Tree::new();
    for (actor, seq, id) in heads {
        let mut b = Vec::with_capacity(4 + actor.len() + 8 + 32);
        b.extend_from_slice(&(actor.len() as u32).to_le_bytes());
        b.extend_from_slice(actor.as_bytes());
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(id);
        t.append(&b);
    }
    t.root()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn heads_sorted(h: &[Head]) -> bool {
    h.windows(2).all(|w| w[0].0.as_bytes() < w[1].0.as_bytes())
}

impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = MAGIC.to_vec();
        o.extend_from_slice(&(self.checkpoint.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.checkpoint);
        o.extend_from_slice(&(self.frontier.len() as u16).to_le_bytes());
        for f in &self.frontier {
            o.extend_from_slice(f);
        }
        o.extend_from_slice(&(self.heads.len() as u32).to_le_bytes());
        for (a, s, id) in &self.heads {
            o.extend_from_slice(&(a.len() as u32).to_le_bytes());
            o.extend_from_slice(a.as_bytes());
            o.extend_from_slice(&s.to_le_bytes());
            o.extend_from_slice(id);
        }
        o.extend_from_slice(&(self.accepted.len() as u32).to_le_bytes());
        for (org, a, floor, seqs) in &self.accepted {
            o.extend_from_slice(&(org.len() as u32).to_le_bytes());
            o.extend_from_slice(org.as_bytes());
            o.extend_from_slice(&(a.len() as u32).to_le_bytes());
            o.extend_from_slice(a.as_bytes());
            o.extend_from_slice(&floor.to_le_bytes());
            o.extend_from_slice(&(seqs.len() as u16).to_le_bytes());
            for q in seqs {
                o.extend_from_slice(&q.to_le_bytes());
            }
        }
        o.extend_from_slice(&(self.state_entry.len() as u32).to_le_bytes());
        o.extend_from_slice(&self.state_entry);
        o.extend_from_slice(&(self.proof.len() as u16).to_le_bytes());
        for p in &self.proof {
            o.extend_from_slice(p);
        }
        o
    }

    pub fn decode(b: &[u8]) -> Result<Self, SnapError> {
        struct C<'a>(&'a [u8]);
        impl<'a> C<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8], SnapError> {
                if self.0.len() < n {
                    return Err(SnapError::Format);
                }
                let (a, r) = self.0.split_at(n);
                self.0 = r;
                Ok(a)
            }
            fn u32(&mut self) -> Result<usize, SnapError> {
                Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
            }
            fn h(&mut self) -> Result<Hash, SnapError> {
                let mut h = [0u8; 32];
                h.copy_from_slice(self.take(32)?);
                Ok(h)
            }
        }
        let mut c = C(b);
        if c.take(MAGIC.len())? != MAGIC {
            return Err(SnapError::Format);
        }
        let n = c.u32()?;
        let checkpoint = c.take(n)?.to_vec();
        let n = u16::from_le_bytes(c.take(2)?.try_into().unwrap()) as usize;
        let frontier = (0..n).map(|_| c.h()).collect::<Result<Vec<_>, _>>()?;
        let n = c.u32()?;
        if n > MAX_HEADS {
            return Err(SnapError::Format);
        }
        let mut heads = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let al = c.u32()?;
            if al > 256 {
                return Err(SnapError::Format);
            }
            let a = String::from_utf8(c.take(al)?.to_vec()).map_err(|_| SnapError::Format)?;
            let s = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
            heads.push((a, s, c.h()?));
        }
        let n = c.u32()?;
        if n > accepted::MAX_KEYS {
            return Err(SnapError::Format);
        }
        let mut acc = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let ol = c.u32()?;
            if ol > 256 {
                return Err(SnapError::Format);
            }
            let org = String::from_utf8(c.take(ol)?.to_vec()).map_err(|_| SnapError::Format)?;
            let al = c.u32()?;
            if al > 256 {
                return Err(SnapError::Format);
            }
            let a = String::from_utf8(c.take(al)?.to_vec()).map_err(|_| SnapError::Format)?;
            let floor = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
            let m = u16::from_le_bytes(c.take(2)?.try_into().unwrap()) as usize;
            if m > accepted::WINDOW {
                return Err(SnapError::Format);
            }
            let mut seqs = Vec::with_capacity(m);
            for _ in 0..m {
                seqs.push(u64::from_le_bytes(c.take(8)?.try_into().unwrap()));
            }
            acc.push((org, a, floor, seqs));
        }
        let n = c.u32()?;
        let state_entry = c.take(n)?.to_vec();
        let n = u16::from_le_bytes(c.take(2)?.try_into().unwrap()) as usize;
        let proof = (0..n).map(|_| c.h()).collect::<Result<Vec<_>, _>>()?;
        if !c.0.is_empty() {
            return Err(SnapError::Format);
        }
        Ok(Self { checkpoint, frontier, heads, accepted: acc, state_entry, proof })
    }

    /// Cross-checks that need no signature: frontier ↔ root, heads ↔ state entry,
    /// state entry ↔ last leaf.  `ck` is the (already trusted) checkpoint.
    fn check_against(&self, ck: &Checkpoint) -> Result<Joined, SnapError> {
        if ck.size == 0 {
            return Err(SnapError::Mismatch("empty checkpoint cannot carry a state entry"));
        }
        if tlog::fold_frontier(ck.size, &self.frontier) != Some(ck.root) {
            return Err(SnapError::Mismatch("frontier does not fold to the checkpoint root"));
        }
        let st = Entry::decode(&self.state_entry).map_err(|_| SnapError::Format)?;
        if st.kind != STATE_KIND || st.actor != ck.origin {
            return Err(SnapError::Mismatch("state entry is not this origin's ledger.state"));
        }
        let leaf = tlog::leaf_hash(&self.state_entry);
        if !tlog::verify_inclusion(&leaf, ck.size - 1, ck.size, &self.proof, &ck.root) {
            return Err(SnapError::Mismatch("state entry is not the last leaf of the checkpoint"));
        }
        if !heads_sorted(&self.heads) {
            return Err(SnapError::Format);
        }
        let want = st.attrs.iter().find(|(k, _)| k == "heads_root").map(|(_, v)| v.as_str());
        if want != Some(hex(&heads_root(&self.heads)).as_str()) {
            return Err(SnapError::Mismatch("heads do not match the committed heads_root"));
        }
        let acc = Accepted::from_records(&self.accepted).ok_or(SnapError::Format)?;
        let want = st.attrs.iter().find(|(k, _)| k == "accepted_root").map(|(_, v)| v.as_str());
        if want != Some(hex(&acc.root()).as_str()) {
            return Err(SnapError::Mismatch("accepted receipts do not match the committed accepted_root"));
        }
        // The state entry is itself the next link of its actor's chain.
        let mut heads = self.heads.clone();
        let (seq, prev) = heads.iter().find(|h| h.0 == st.actor).map_or((1, entry::ZERO), |h| (h.1 + 1, h.2));
        if st.seq != seq || st.prev != prev {
            return Err(SnapError::Mismatch("state entry does not continue its actor chain"));
        }
        let id = entry::id_of(&self.state_entry);
        match heads.iter_mut().find(|h| h.0 == st.actor) {
            Some(h) => {
                h.1 = st.seq;
                h.2 = id;
            }
            None => {
                heads.push((st.actor.clone(), st.seq, id));
                heads.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            }
        }
        Ok(Joined { checkpoint: ck.clone(), heads, accepted: acc })
    }

    /// Full verification: signed checkpoint chained to `authority_vk` (and the
    /// witness quorum), then every cross-check.  Fail closed.
    pub fn verify(&self, authority_vk: &[u8], pos: u64, roster: &[&[u8]], quorum: usize) -> Result<Joined, SnapError> {
        let ck = checkpoint::verify(&self.checkpoint, authority_vk, pos, roster, quorum).map_err(SnapError::Checkpoint)?;
        self.check_against(&ck)
    }

    /// Size of the checkpoint this snapshot is anchored at (0 if unparseable).
    pub fn checkpoint_size(&self) -> u64 {
        checkpoint::parse_unverified(&self.checkpoint).map_or(0, |c| c.size)
    }

    /// Re-check a snapshot that was verified when it was admitted (local state).
    pub fn check_stored(&self) -> Result<Joined, SnapError> {
        let ck = checkpoint::parse_unverified(&self.checkpoint).map_err(SnapError::Checkpoint)?;
        self.check_against(&ck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{self, Checkpoint};
    use crate::entry::Draft;
    use crate::ledger::Ledger;
    use crate::nodecert::NodeCert;
    use crate::signer::Keypair;
    use awp3::sign::CompositeSigningKey;
    use rand::{rngs::StdRng, SeedableRng};

    fn draft(actor: &str, n: u32) -> Draft {
        Draft { kind: "billing".into(), actor: actor.into(), subject: format!("s{n}"), auth: None, ts: 1,
                attrs: vec![("n".into(), n.to_string())] }
    }

    struct World {
        _dir: tempfile::TempDir,
        auth: Keypair,
        node: CompositeSigningKey,
        cert: Vec<u8>,
        full: Ledger,
        snap: Snapshot,
        ck: Checkpoint,
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let mut r = StdRng::from_seed([4; 32]);
        let auth = Keypair::generate(&mut r, "auth".into());
        let node = CompositeSigningKey::generate(&mut r);
        let cert = NodeCert {
            node_id: "node-a".into(), node_vk_hash: checkpoint::vk_hash(&node.verifying_key().to_bytes()),
            boot_counter: 1, scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: 100,
        }.sign(&auth).unwrap();
        let mut full = Ledger::open(dir.path().join("full.slab")).unwrap();
        for i in 0..40u32 {
            full.append_drafts(vec![draft(["t1", "t2", "t3"][(i % 3) as usize], i)]).unwrap();
        }
        full.seal("node-a", 9).unwrap();
        let ck = Checkpoint { origin: "node-a".into(), size: full.size(), root: full.root() };
        let wire = checkpoint::sign(&ck, &node, &cert, &[]).unwrap();
        let snap = full.export_snapshot(&wire).unwrap();
        World { _dir: dir, auth, node, cert, full, snap, ck }
    }

    #[test]
    fn new_node_joins_continues_chains_and_proves_back() {
        let mut w = world();
        let avk = w.auth.verifying_key_bytes();
        let bytes = w.snap.encode();
        assert_eq!(Snapshot::decode(&bytes).unwrap(), w.snap);
        // size is O(log n + actors), not O(history)
        assert!(w.snap.frontier.len() <= 6 && w.snap.heads.len() == 3); // t1..t3; the state entry itself is applied on top

        let jd = tempfile::tempdir().unwrap();
        let mut joined = Ledger::join(jd.path().join("j.slab"), &bytes, &avk, 5, &[], 0).unwrap();
        assert_eq!((joined.size(), joined.base(), joined.root()), (w.ck.size, w.ck.size, w.ck.root));
        assert!(joined.entry(0).is_err(), "history is not carried");

        // Both nodes extend the ledger with the same events: identical roots, so a
        // joiner is indistinguishable from a full node going forward.
        for i in 100..130u32 {
            let actor = ["t1", "t2", "t3", "node-a"][(i % 4) as usize];
            let a = w.full.append_drafts(vec![draft(actor, i)]).unwrap().1;
            let b = joined.append_drafts(vec![draft(actor, i)]).unwrap().1;
            assert_eq!(a, b, "chains continue identically (seq/prev from the committed heads)");
        }
        assert_eq!(joined.root(), w.full.root());

        // Backwards, without history: head ⟶ the signed join checkpoint.
        let proof = joined.consistency_proof(w.ck.size, joined.size()).unwrap();
        assert!(crate::tlog::verify_consistency(w.ck.size, &w.ck.root, joined.size(), &joined.root(), &proof));
        assert!(proof.len() <= 2 * 7);

        // Reopening the joined ledger resumes from the stored snapshot.
        let size = joined.size();
        drop(joined);
        let again = Ledger::open(jd.path().join("j.slab")).unwrap();
        assert_eq!((again.size(), again.base(), again.root()), (size, w.ck.size, w.full.root()));
        assert_eq!(again.head_of("t1"), w.full.head_of("t1"));
    }

    #[test]
    fn tampered_or_unauthorised_snapshots_are_rejected() {
        let w = world();
        let avk = w.auth.verifying_key_bytes();
        let ok = |s: &Snapshot| s.verify(&avk, 5, &[], 0);
        assert!(ok(&w.snap).is_ok());

        let mut s = w.snap.clone(); s.frontier[0][0] ^= 1;
        assert!(matches!(ok(&s), Err(SnapError::Mismatch(_))), "frontier");
        let mut s = w.snap.clone(); s.heads[0].1 += 1;
        assert!(matches!(ok(&s), Err(SnapError::Mismatch(_))), "head seq");
        let mut s = w.snap.clone(); s.heads.pop();
        assert!(matches!(ok(&s), Err(SnapError::Mismatch(_))), "dropped actor");
        let mut s = w.snap.clone(); s.proof[0][0] ^= 1;
        assert!(matches!(ok(&s), Err(SnapError::Mismatch(_))), "inclusion proof");
        let mut s = w.snap.clone(); let n = s.state_entry.len(); s.state_entry[n - 1] ^= 1;
        assert!(ok(&s).is_err(), "state entry");
        let mut s = w.snap.clone(); s.checkpoint[30] ^= 1;
        assert!(ok(&s).is_err(), "checkpoint bytes");
        // checkpoint for a different log state than the frontier/heads describe
        let other = Checkpoint { root: [9; 32], ..w.ck.clone() };
        let mut s = w.snap.clone(); s.checkpoint = checkpoint::sign(&other, &w.node, &w.cert, &[]).unwrap();
        assert!(matches!(ok(&s), Err(SnapError::Mismatch(_))), "validly signed but wrong root");

        // authority / certificate window / witness quorum
        let evil = Keypair::generate(&mut StdRng::from_seed([5; 32]), "evil".into());
        assert!(w.snap.verify(&evil.verifying_key_bytes(), 5, &[], 0).is_err(), "wrong authority");
        assert_eq!(w.snap.verify(&avk, 101, &[], 0), Err(SnapError::Checkpoint(checkpoint::CkptError::NotValidAt)));
        assert_eq!(w.snap.verify(&avk, 5, &[], 1), Err(SnapError::Checkpoint(checkpoint::CkptError::Quorum)));

        // a joiner refuses a bad snapshot and a non-empty target, and leaves nothing behind
        let d = tempfile::tempdir().unwrap();
        let mut bad = w.snap.clone(); bad.heads[0].1 += 1;
        assert!(Ledger::join(d.path().join("x.slab"), &bad.encode(), &avk, 5, &[], 0).is_err());
        assert!(!d.path().join("x.slab.base").exists());
        let mut l = Ledger::join(d.path().join("y.slab"), &w.snap.encode(), &avk, 5, &[], 0).unwrap();
        l.append_drafts(vec![draft("t1", 1)]).unwrap();
        drop(l);
        assert!(Ledger::join(d.path().join("y.slab"), &w.snap.encode(), &avk, 5, &[], 0).is_err(), "no re-join over live state");
    }

    #[test]
    fn export_requires_a_checkpoint_of_the_sealed_state() {
        let mut w = world();
        w.full.append_drafts(vec![draft("t1", 999)]).unwrap(); // log moved on past the seal
        let ck = Checkpoint { origin: "node-a".into(), size: w.full.size(), root: w.full.root() };
        let wire = checkpoint::sign(&ck, &w.node, &w.cert, &[]).unwrap();
        assert!(w.full.export_snapshot(&wire).is_err(), "head is not the sealed state");
    }
}

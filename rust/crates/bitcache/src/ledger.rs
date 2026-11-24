//! Durable ledger: a [`tlog::Tree`] whose entries live, pinned, in a Bitcache slab.
//!
//! Storage is two files next to each other:
//! * the slab (`<path>`) holds every entry, content-addressed and `fsync`ed by
//!   `SlabFile::put`, then pinned so `gc` can never evict ledger history;
//! * `<path>.ledger` is the ordered list of entry refs, 32 bytes each.
//!
//! Commit order is entry → pin → ref (fsync).  A crash can strand an
//! unreferenced entry (harmless, unpinned garbage) but never a reference to a
//! missing entry; a torn final ref is truncated on open because it was never
//! acknowledged.  On open the tree is rebuilt from the entries themselves
//! (every `get` re-verifies the BLAKE3 content hash), so a damaged or edited
//! ref file shows up as a different root and fails consistency against any
//! checkpoint that was previously signed or witnessed.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::accepted::Accepted;
use crate::error::{BitcacheError, Result};
use crate::slab::{ObjRef, SlabFile};
use crate::entry::{self, Draft, Entry};
use crate::snapshot::{self, Head, Snapshot};
use crate::tlog::{Hash, Tree};

pub struct Ledger {
    slab: SlabFile,
    refs: File,
    refs_path: PathBuf,
    path: PathBuf,
    /// Entries `< base` were never held here (the ledger was joined from a
    /// snapshot); `list[i]` is entry `base + i`.
    base: u64,
    list: Vec<ObjRef>,
    tree: Tree,
    /// Per-actor chain heads: `(last seq, id of last entry)`.
    pub(crate) heads: HashMap<String, (u64, Hash)>,
    /// Index of each actor's latest *retained* entry (absent for chains whose
    /// last entry predates a snapshot join).
    pub(crate) last_idx: HashMap<String, u64>,
    /// Bounded replay guard for accepted transfer receipts (committed in snapshots).
    pub(crate) accepted: Accepted,
}

impl Ledger {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut slab = SlabFile::open_or_create(path)?;
        let refs_path = sidecar(path, "ledger");
        let mut tree = Tree::new();
        let mut heads: HashMap<String, (u64, Hash)> = HashMap::new();
        let mut base = 0u64;
        let mut last_idx: HashMap<String, u64> = HashMap::new();
        let mut accepted = Accepted::new();
        // Joined (or compacted): resume from the snapshot's frontier, heads and replay state.
        if let Some(snap) = read_snapshot(&sidecar(path, "base"))? {
            let j = snap.check_stored().map_err(|e| BitcacheError::ChainViolation(format!("stored join snapshot: {e:?}")))?;
            tree = Tree::from_frontier(j.checkpoint.size, &snap.frontier)
                .ok_or_else(|| BitcacheError::ChainViolation("stored join snapshot: bad frontier".into()))?;
            heads = j.heads.into_iter().map(|(a, s, h)| (a, (s, h))).collect();
            accepted = j.accepted;
            base = j.checkpoint.size;
        }
        // The ref file starts with a header naming the index of its first ref.  A crash
        // between writing a new snapshot and rewriting the refs leaves refs that begin
        // *before* the snapshot; those leading refs are simply skipped.
        let raw = match std::fs::read(&refs_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let headered = raw.len() >= 32 && raw[..8] == REFS_MAGIC[..];
        let (start, body) = if headered {
            (u64::from_le_bytes(raw[8..16].try_into().unwrap()), &raw[32..])
        } else {
            (base, &raw[..])
        };
        let whole = body.len() - body.len() % 32;
        let all: Vec<ObjRef> = body[..whole].chunks_exact(32).map(|c| { let mut h = [0u8; 32]; h.copy_from_slice(c); ObjRef(h) }).collect();
        if !headered || whole != body.len() {
            write_refs(&refs_path, start, &all)?; // adds the header / drops a never-acknowledged torn tail
        }
        if start > base {
            return Err(BitcacheError::ChainViolation(format!("ref file starts at {start}, after the snapshot base {base}")));
        }
        // refs that hold nothing simply begin at the snapshot (e.g. a crash during join)
        let start = if all.is_empty() && start < base { write_refs(&refs_path, base, &all)?; base } else { start };
        let skip = (base - start) as usize;
        // Finish an interrupted compaction: unpin what the intent file lists, but only if the
        // new base really became durable, and never anything still referenced.
        let intent_path = sidecar(path, "unpin");
        if let Ok(b) = std::fs::read(&intent_path) {
            if b.len() >= 8 && u64::from_le_bytes(b[..8].try_into().unwrap()) <= base {
                let keep: HashSet<[u8; 32]> = all[skip..].iter().map(|r| *r.as_bytes()).collect();
                for c in b[8..].chunks_exact(32) {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(c);
                    if !keep.contains(&h) {
                        let _ = slab.unpin(&ObjRef(h));
                    }
                }
            }
            let _ = std::fs::remove_file(&intent_path);
        }
        if all.len() < skip {
            return Err(BitcacheError::ChainViolation("ref file is shorter than the snapshot it follows".into()));
        }
        let mut list = Vec::with_capacity(all.len() - skip);
        for r in &all[skip..] {
            let data = slab.get(r)?; // verifies the content hash; missing ⇒ error
            // Typed entries must continue their actor's chain; opaque ones are tolerated.
            if let Ok(e) = Entry::decode(&data) {
                check_link(&heads, &e)?;
                heads.insert(e.actor.clone(), (e.seq, entry::id_of(&data)));
                last_idx.insert(e.actor.clone(), base + list.len() as u64);
                if e.kind == "transfer.in" && e.auth != entry::ZERO {
                    let (o, a, q) = transfer_key(&e).ok_or_else(|| BitcacheError::ChainViolation("transfer.in lacks from_origin/from_seq".into()))?;
                    accepted.insert(&o, &a, q).map_err(|x| BitcacheError::ChainViolation(format!("receipt replayed inside the ledger: {x:?}")))?;
                }
            }
            tree.append(&data);
            list.push(r.clone());
        }
        let mut refs = OpenOptions::new().read(true).write(true).open(&refs_path)?;
        refs.seek(SeekFrom::End(0))?;
        Ok(Self { slab, refs, refs_path, path: path.to_path_buf(), base, list, tree, heads, last_idx, accepted })
    }

    pub fn size(&self) -> u64 {
        self.tree.size()
    }
    pub fn root(&self) -> Hash {
        self.tree.root()
    }
    pub fn root_at(&self, size: u64) -> Option<Hash> {
        self.tree.root_at(size)
    }
    pub fn refs_path(&self) -> &Path {
        &self.refs_path
    }

    /// Append a batch durably with a single ref-file fsync.  Returns the index
    /// of the first entry.
    pub fn append_batch(&mut self, entries: &[&[u8]]) -> Result<u64> {
        let first = self.size();
        let mut buf = Vec::with_capacity(entries.len() * 32);
        let mut staged = Vec::with_capacity(entries.len());
        for e in entries {
            let r = self.slab.put(e)?;
            self.slab.pin(&r)?;
            buf.extend_from_slice(r.as_bytes());
            staged.push((r, *e));
        }
        self.refs.write_all(&buf)?;
        self.refs.sync_all()?;
        for (r, e) in staged {
            self.tree.append(e);
            self.list.push(r);
        }
        Ok(first)
    }

    /// Chain head of `actor`: `(last seq, id of last entry)`.
    pub fn head_of(&self, actor: &str) -> Option<(u64, Hash)> {
        self.heads.get(actor).copied()
    }

    /// Append typed events.  `seq` and `prev` are assigned here, per actor, so
    /// callers can neither skip nor fork a chain.  All-or-nothing: if any draft
    /// is invalid nothing is written.  Returns `(first index, entries)`.
    pub fn append_drafts(&mut self, drafts: Vec<Draft>) -> Result<(u64, Vec<Entry>)> {
        let mut heads = self.heads.clone();
        let mut acc: Option<Accepted> = None;
        let mut built = Vec::with_capacity(drafts.len());
        for d in drafts {
            let (seq, prev) = heads.get(&d.actor).map_or((1, entry::ZERO), |(s, h)| (s + 1, *h));
            let e = d.into_entry(seq, prev).map_err(|x| BitcacheError::ChainViolation(format!("bad entry: {x:?}")))?;
            if e.kind == "transfer.in" && e.auth != entry::ZERO {
                let (o, a, q) = transfer_key(&e).ok_or_else(|| BitcacheError::ChainViolation("transfer.in must carry from_origin and from_seq".into()))?;
                acc.get_or_insert_with(|| self.accepted.clone()).insert(&o, &a, q)
                    .map_err(|x| BitcacheError::ChainViolation(format!("receipt refused: {x:?}")))?;
            }
            let enc = e.encode().map_err(|x| BitcacheError::ChainViolation(format!("bad entry: {x:?}")))?;
            heads.insert(e.actor.clone(), (e.seq, entry::id_of(&enc)));
            built.push((e, enc));
        }
        let encs: Vec<&[u8]> = built.iter().map(|(_, b)| b.as_slice()).collect();
        let first = self.append_batch(&encs)?;
        self.heads = heads;
        if let Some(a) = acc {
            self.accepted = a;
        }
        for (i, (e, _)) in built.iter().enumerate() {
            self.last_idx.insert(e.actor.clone(), first + i as u64);
        }
        Ok((first, built.into_iter().map(|(e, _)| e).collect()))
    }

    pub fn append(&mut self, entry: &[u8]) -> Result<u64> {
        self.append_batch(&[entry])
    }

    /// First entry index actually held here (0 unless joined from a snapshot).
    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn entry(&mut self, index: u64) -> Result<Vec<u8>> {
        let local = index.checked_sub(self.base).ok_or_else(|| BitcacheError::ObjectMissing(Box::new([])))?;
        let r = self
            .list
            .get(usize::try_from(local).unwrap_or(usize::MAX))
            .ok_or_else(|| BitcacheError::ObjectMissing(Box::new([])))?
            .clone();
        self.slab.get(&r)
    }

    pub fn leaf(&self, index: u64) -> Option<Hash> {
        self.tree.leaf(index)
    }
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Option<Vec<Hash>> {
        self.tree.inclusion_proof(index, size)
    }
    pub fn consistency_proof(&self, first: u64, second: u64) -> Option<Vec<Hash>> {
        self.tree.consistency_proof(first, second)
    }

    /// Adopt a verified snapshot as the starting point of a brand-new ledger at
    /// `path`: no history is fetched or stored.  Refuses a non-empty target.
    pub fn join<P: AsRef<Path>>(
        path: P, snapshot: &[u8], authority_vk: &[u8], pos: u64, roster: &[&[u8]], quorum: usize,
    ) -> Result<Self> {
        let path = path.as_ref();
        let snap = Snapshot::decode(snapshot).map_err(|e| BitcacheError::ChainViolation(format!("snapshot: {e:?}")))?;
        snap.verify(authority_vk, pos, roster, quorum)
            .map_err(|e| BitcacheError::ChainViolation(format!("snapshot rejected: {e:?}")))?;
        let base = sidecar(path, "base");
        let refs = sidecar(path, "ledger");
        // a bare 32-byte header is an empty ledger; anything more is state
        if base.exists() || std::fs::metadata(&refs).map_or(false, |m| m.len() > 32) {
            return Err(BitcacheError::ChainViolation("refusing to join: ledger already has state".into()));
        }
        write_atomic(&base, snapshot)?;
        write_refs(&refs, snap.checkpoint_size(), &[])?;
        Self::open(path)
    }

    /// Record a `ledger.state` entry committing every actor's chain head, and
    /// remember the material a joiner needs.  Sign a checkpoint immediately
    /// after (head == this seal) and call [`Ledger::export_snapshot`].
    pub fn seal(&mut self, actor: &str, ts: u64) -> Result<(u64, Entry)> {
        let mut hs: Vec<Head> = self.heads.iter().map(|(a, (s, h))| (a.clone(), *s, *h)).collect();
        hs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let recs = self.accepted.records();
        let draft = Draft {
            kind: snapshot::STATE_KIND.into(), actor: actor.into(), subject: "state".into(), auth: None, ts,
            attrs: vec![
                ("accepted".into(), recs.len().to_string()),
                ("accepted_root".into(), snapshot::hex(&crate::accepted::root(&recs))),
                ("heads".into(), hs.len().to_string()),
                ("heads_root".into(), snapshot::hex(&snapshot::heads_root(&hs))),
            ],
        };
        let (idx, mut es) = self.append_drafts(vec![draft])?;
        let e = es.remove(0);
        let size = self.size();
        let proof = self.tree.inclusion_proof(idx, size)
            .ok_or_else(|| BitcacheError::ChainViolation("seal: leaf proof unavailable".into()))?;
        let snap = Snapshot {
            checkpoint: Vec::new(), frontier: self.tree.frontier(), heads: hs, accepted: recs,
            state_entry: e.encode().map_err(|x| BitcacheError::ChainViolation(format!("{x:?}")))?, proof,
        };
        write_atomic(&sidecar(&self.path, "seal"), &snap.encode())?;
        Ok((idx, e))
    }

    /// The latest sealed state combined with `checkpoint_wire` (which must be a
    /// checkpoint of exactly the sealed size and root).  Not signature-verified
    /// here — the joiner does that.
    pub fn export_snapshot(&self, checkpoint_wire: &[u8]) -> Result<Snapshot> {
        let mut snap = read_snapshot(&sidecar(&self.path, "seal"))?
            .ok_or_else(|| BitcacheError::ChainViolation("no sealed state: run seal first".into()))?;
        snap.checkpoint = checkpoint_wire.to_vec();
        snap.check_stored()
            .map_err(|e| BitcacheError::ChainViolation(format!("checkpoint does not match the sealed state: {e:?}")))?;
        Ok(snap)
    }

    /// Bound this ledger's local state: adopt the (own, signed, sealed) state at
    /// `checkpoint_wire` as the new base and drop every entry before it.  What stays is
    /// the O(log n) frontier plus entries after the seal, so a constrained device holds
    /// a rolling window; older history remains provable by whoever archived it (any
    /// consistency/inclusion proof against a later checkpoint still verifies).
    ///
    /// Crash order is snapshot → refs → unpin; every intermediate state reopens correctly.
    /// Returns the reopened ledger and how many entries were dropped.
    pub fn compact(mut self, checkpoint_wire: &[u8]) -> Result<(Self, u64)> {
        let snap = self.export_snapshot(checkpoint_wire)?;
        let j = snap.check_stored().map_err(|e| BitcacheError::ChainViolation(format!("compact: {e:?}")))?;
        let s = j.checkpoint.size;
        if s == self.base {
            return Ok((self, 0));
        }
        if s < self.base || s > self.size() || self.root_at(s) != Some(j.checkpoint.root) {
            return Err(BitcacheError::ChainViolation("compact: checkpoint is not a prefix of this ledger".into()));
        }
        let n_drop = (s - self.base) as usize;
        // Intent first: once the new base is durable, anything in this list is garbage even
        // if we crash before unpinning it.  `open` finishes the job (and ignores the file if
        // the base never advanced).
        let keep: HashSet<[u8; 32]> = self.list[n_drop..].iter().map(|r| *r.as_bytes()).collect();
        let mut intent = s.to_le_bytes().to_vec();
        for r in &self.list[..n_drop] {
            if !keep.contains(r.as_bytes()) {
                intent.extend_from_slice(r.as_bytes());
            }
        }
        write_atomic(&sidecar(&self.path, "unpin"), &intent)?;
        write_atomic(&sidecar(&self.path, "base"), &snap.encode())?;
        write_refs(&self.refs_path, s, &self.list[n_drop..])?;
        for c in intent[8..].chunks_exact(32) {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            let _ = self.slab.unpin(&ObjRef(h));
        }
        let _ = std::fs::remove_file(sidecar(&self.path, "unpin"));
        let path = self.path.clone();
        drop(self);
        Ok((Self::open(path)?, n_drop as u64))
    }

    /// Entries held locally (shrinks after [`Ledger::compact`]).
    pub fn retained(&self) -> usize {
        self.list.len()
    }

    /// Whether every entry is currently pinned (used by tests and audits).
    pub fn all_pinned(&self) -> Result<bool> {
        for r in &self.list {
            if !self.slab.is_pinned(r)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Run slab GC at its most aggressive setting; pinned ledger entries survive.
    pub fn gc_probe(&mut self) -> Result<(usize, u64)> {
        self.slab.gc(0.0, std::time::Duration::from_secs(0))
    }
}

const REFS_MAGIC: &[u8; 8] = b"AMIN3REF";

fn write_refs(path: &Path, start: u64, refs: &[ObjRef]) -> Result<()> {
    let mut b = Vec::with_capacity(32 + refs.len() * 32);
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(REFS_MAGIC);
    h[8..16].copy_from_slice(&start.to_le_bytes());
    b.extend_from_slice(&h);
    for r in refs {
        b.extend_from_slice(r.as_bytes());
    }
    write_atomic(path, &b)
}

/// `(origin, payer actor, seq)` named by an accepted `transfer.in`.
pub(crate) fn transfer_key(e: &Entry) -> Option<(String, String, u64)> {
    let get = |k: &str| e.attrs.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
    Some((get("from_origin")?.to_string(), e.subject.clone(), get("from_seq")?.parse().ok()?))
}

fn sidecar(path: &Path, ext: &str) -> PathBuf {
    PathBuf::from(format!("{}.{ext}", path.display()))
}

fn read_snapshot(p: &Path) -> Result<Option<Snapshot>> {
    match std::fs::read(p) {
        Ok(b) => Ok(Some(Snapshot::decode(&b).map_err(|e| BitcacheError::ChainViolation(format!("{}: {e:?}", p.display())))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Write-then-rename with fsync: a reader sees the old file or the whole new one.
fn write_atomic(p: &Path, data: &[u8]) -> Result<()> {
    let tmp = sidecar(p, "tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, p)?;
    if let Some(d) = p.parent() {
        if let Ok(dir) = File::open(d) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn check_link(heads: &HashMap<String, (u64, Hash)>, e: &Entry) -> Result<()> {
    let (want_seq, want_prev) = heads.get(&e.actor).map_or((1, entry::ZERO), |(s, h)| (s + 1, *h));
    if e.seq != want_seq || e.prev != want_prev {
        return Err(BitcacheError::ChainViolation(format!(
            "actor {} seq {} does not continue chain (expected seq {})", e.actor, e.seq, want_seq)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlog;

    #[test]
    fn append_reopen_prove_and_survive_gc() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ledger.slab");
        let (root7, root12);
        {
            let mut l = Ledger::open(&p).unwrap();
            let first = l.append_batch(&(0..7u8).map(|i| vec![i; 40]).collect::<Vec<_>>().iter().map(|v| v.as_slice()).collect::<Vec<_>>()).unwrap();
            assert_eq!(first, 0);
            root7 = l.root();
            for i in 7..12u8 {
                l.append(&vec![i; 40]).unwrap();
            }
            root12 = l.root();
            assert_eq!(l.size(), 12);
            assert!(l.all_pinned().unwrap());
        }
        let mut l = Ledger::open(&p).unwrap(); // rebuilt from the slab
        assert_eq!((l.size(), l.root()), (12, root12));
        assert_eq!(l.entry(3).unwrap(), vec![3u8; 40]);
        let proof = l.consistency_proof(7, 12).unwrap();
        assert!(tlog::verify_consistency(7, &root7, 12, &root12, &proof));
        let ip = l.inclusion_proof(9, 12).unwrap();
        assert!(tlog::verify_inclusion(&l.leaf(9).unwrap(), 9, 12, &ip, &root12));
        // GC at maximum pressure must not evict ledger history
        l.slab.test_age_all().unwrap();
        let (freed, _) = l.gc_probe().unwrap();
        assert_eq!(freed, 0, "nothing pinned may be evicted");
        for i in 0..12u64 {
            assert_eq!(l.entry(i).unwrap(), vec![i as u8; 40], "entry {i} survived gc");
        }
    }

    #[test]
    fn unpinned_objects_are_still_collectable() {
        let d = tempfile::tempdir().unwrap();
        let mut s = SlabFile::open_or_create(d.path().join("s")).unwrap();
        let a = s.put(b"cache me").unwrap();
        let b = s.put(b"keep me").unwrap();
        s.pin(&b).unwrap();
        s.test_age_all().unwrap();
        s.gc(0.0, std::time::Duration::from_secs(0)).unwrap();
        assert!(s.get(&b).is_ok());
        assert!(s.get(&a).is_err(), "unpinned object is evicted");
        assert!(s.is_pinned(&b).unwrap());
        s.unpin(&b).unwrap();
        assert!(!s.is_pinned(&b).unwrap());
    }

    #[test]
    fn torn_tail_is_dropped_and_reordering_is_detectable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.slab");
        let (r3, r4);
        {
            let mut l = Ledger::open(&p).unwrap();
            for i in 0..3u8 { l.append(&[i; 10]).unwrap(); }
            r3 = l.root();
            l.append(&[3; 10]).unwrap();
            r4 = l.root();
        }
        // torn final write: 17 stray bytes
        let rp = format!("{}.ledger", p.display());
        OpenOptions::new().append(true).open(&rp).unwrap().write_all(&[9; 17]).unwrap();
        assert_eq!(Ledger::open(&p).unwrap().root(), r4);
        // an attacker who swaps two refs yields a different root that cannot be
        // consistent with the root that was previously signed
        let mut raw = std::fs::read(&rp).unwrap();
        let (a, b) = (raw[64..96].to_vec(), raw[96..128].to_vec()); // refs 1 and 2 (after the header)
        raw[64..96].copy_from_slice(&b);
        raw[96..128].copy_from_slice(&a);
        std::fs::write(&rp, &raw).unwrap();
        let l = Ledger::open(&p).unwrap();
        assert_ne!(l.root(), r4);
        let proof = l.consistency_proof(3, 4).unwrap();
        assert!(!tlog::verify_consistency(3, &r3, 4, &l.root(), &proof));
        assert!(!tlog::verify_consistency(4, &r4, 4, &l.root(), &[]));
    }

    fn draft(actor: &str, kind: &str, n: u32) -> Draft {
        Draft { kind: kind.into(), actor: actor.into(), subject: format!("s{n}"), auth: None, ts: 1,
                attrs: vec![("n".into(), n.to_string())] }
    }

    #[test]
    fn per_actor_chains_survive_reopen_and_reject_tampering() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.slab");
        {
            let mut l = Ledger::open(&p).unwrap();
            let (first, es) = l.append_drafts(vec![
                draft("a", "billing", 1), draft("b", "settlement", 2), draft("a", "billing", 3),
            ]).unwrap();
            assert_eq!(first, 0);
            assert_eq!((es[0].seq, es[1].seq, es[2].seq), (1, 1, 2)); // independent per-actor chains
            assert_eq!(es[2].prev, es[0].id().unwrap());
            // an invalid draft in a batch writes nothing
            let before = l.size();
            let mut bad = draft("a", "Bad Kind", 4);
            bad.kind = "Bad Kind".into();
            assert!(l.append_drafts(vec![draft("a", "billing", 5), bad]).is_err());
            assert_eq!(l.size(), before);
            assert_eq!(l.head_of("a").unwrap().0, 2);
        }
        let mut l = Ledger::open(&p).unwrap();
        assert_eq!(l.head_of("a").unwrap().0, 2);
        assert_eq!(l.head_of("b").unwrap().0, 1);
        let (_, es) = l.append_drafts(vec![draft("a", "billing", 6)]).unwrap();
        assert_eq!(es[0].seq, 3);
        // forging a raw entry that skips the chain makes the ledger refuse to open
        let forged = draft("a", "billing", 7).into_entry(9, [7; 32]).unwrap().encode().unwrap();
        l.append(&forged).unwrap();
        drop(l);
        assert!(matches!(Ledger::open(&p), Err(BitcacheError::ChainViolation(_))));
    }

    // ── compaction (IoT rolling window) ────────────────────────────────────────
    use crate::checkpoint::{self, Checkpoint};
    use crate::nodecert::NodeCert;
    use crate::signer::Keypair;
    use awp3::sign::CompositeSigningKey;
    use rand::{rngs::StdRng, SeedableRng};

    fn node(origin: &str) -> (Keypair, CompositeSigningKey, Vec<u8>) {
        let mut r = StdRng::from_seed([21; 32]);
        let auth = Keypair::generate(&mut r, "auth".into());
        let key = CompositeSigningKey::generate(&mut r);
        let cert = NodeCert { node_id: origin.into(), node_vk_hash: checkpoint::vk_hash(&key.verifying_key().to_bytes()),
            boot_counter: 1, scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: 1000 }.sign(&auth).unwrap();
        (auth, key, cert)
    }

    fn seal_and_sign(l: &mut Ledger, origin: &str, key: &CompositeSigningKey, cert: &[u8]) -> Vec<u8> {
        l.seal(origin, 9).unwrap();
        let ck = Checkpoint { origin: origin.into(), size: l.size(), root: l.root() };
        checkpoint::sign(&ck, key, cert, &[]).unwrap()
    }

    #[test]
    fn compaction_bounds_local_state_and_keeps_proofs_and_chains() {
        let (_auth, key, cert) = node("dev-1");
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.slab");
        let mut l = Ledger::open(&p).unwrap();
        for i in 0..300u32 { l.append_drafts(vec![draft(["a", "b"][(i % 2) as usize], "billing", i)]).unwrap(); }
        let wire = seal_and_sign(&mut l, "dev-1", &key, &cert);
        let ck = checkpoint::parse_unverified(&wire).unwrap();
        for i in 300..320u32 { l.append_drafts(vec![draft("a", "billing", i)]).unwrap(); }
        let (size, root) = (l.size(), l.root());
        // the archive role: a proof served from full history, before it is dropped
        let archived = l.consistency_proof(ck.size, size).unwrap();
        let old_leaf0 = l.leaf(0).unwrap();
        let old_inc = l.inclusion_proof(0, ck.size).unwrap();

        let (mut c, dropped) = l.compact(&wire).unwrap();
        assert_eq!(dropped, ck.size);
        assert_eq!((c.base(), c.retained() as u64, c.size(), c.root()), (ck.size, size - ck.size, size, root));
        assert!(c.entry(0).is_err() && c.entry(ck.size).is_ok());
        // history is still provable against the signed checkpoint, without being held
        assert!(tlog::verify_inclusion(&old_leaf0, 0, ck.size, &old_inc, &ck.root));
        assert!(tlog::verify_consistency(ck.size, &ck.root, size, &root, &archived));
        // and also with proofs the compacted node produces itself
        assert!(tlog::verify_consistency(ck.size, &ck.root, size, &root, &c.consistency_proof(ck.size, size).unwrap()));
        // chains continue
        let (_, es) = c.append_drafts(vec![draft("b", "billing", 999)]).unwrap();
        assert_eq!(es[0].seq, 151, "b had 150 entries before compaction");
        // reopen = same state; evicted entries become collectable, retained ones stay pinned
        let size2 = c.size();
        drop(c);
        let mut r = Ledger::open(&p).unwrap();
        assert_eq!((r.base(), r.size()), (ck.size, size2));
        assert!(r.all_pinned().unwrap());
        r.slab.test_age_all().unwrap();
        let (freed, _) = r.gc_probe().unwrap();
        assert!(freed > 0, "dropped history is reclaimable flash");
        for i in ck.size..r.size() { assert!(r.entry(i).is_ok(), "retained entry {i} survived gc"); }
    }

    #[test]
    fn compaction_survives_a_crash_between_snapshot_and_refs() {
        let (_auth, key, cert) = node("dev-1");
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.slab");
        let mut l = Ledger::open(&p).unwrap();
        for i in 0..40u32 { l.append_drafts(vec![draft("a", "billing", i)]).unwrap(); }
        let wire = seal_and_sign(&mut l, "dev-1", &key, &cert);
        for i in 40..50u32 { l.append_drafts(vec![draft("a", "billing", i)]).unwrap(); }
        let (size, root) = (l.size(), l.root());
        // crash after step 1: new base on disk, refs still begin at 0
        let snap = l.export_snapshot(&wire).unwrap();
        write_atomic(&sidecar(&p, "base"), &snap.encode()).unwrap();
        drop(l);
        let l = Ledger::open(&p).unwrap();
        assert_eq!((l.base(), l.size(), l.root()), (41, size, root));
        assert_eq!(l.retained(), 10);
        // compacting again (already at that base) is a no-op
        let (l, dropped) = l.compact(&wire).unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(l.size(), size);
    }

    #[test]
    fn compact_rejects_a_checkpoint_that_is_not_the_sealed_state() {
        let (_auth, key, cert) = node("dev-1");
        let d = tempfile::tempdir().unwrap();
        let mut l = Ledger::open(d.path().join("l.slab")).unwrap();
        for i in 0..10u32 { l.append_drafts(vec![draft("a", "billing", i)]).unwrap(); }
        let ck = Checkpoint { origin: "dev-1".into(), size: l.size(), root: l.root() };
        let unsealed = checkpoint::sign(&ck, &key, &cert, &[]).unwrap();
        assert!(l.compact(&unsealed).is_err(), "no sealed state yet");
    }

    #[test]
    fn an_interrupted_compaction_does_not_leak_pins_or_touch_live_entries() {
        let (_auth, key, cert) = node("dev-1");
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.slab");
        let mut l = Ledger::open(&p).unwrap();
        for i in 0..30u32 { l.append_drafts(vec![draft("a", "billing", i)]).unwrap(); }
        let wire = seal_and_sign(&mut l, "dev-1", &key, &cert);
        for i in 30..35u32 { l.append_drafts(vec![draft("a", "billing", i)]).unwrap(); }
        let dropped: Vec<ObjRef> = l.list[..31].to_vec();
        let kept: Vec<ObjRef> = l.list[31..].to_vec();
        // crash after the new base and the intent are durable, before refs/unpin
        let snap = l.export_snapshot(&wire).unwrap();
        let mut intent = 31u64.to_le_bytes().to_vec();
        for r in &dropped { intent.extend_from_slice(r.as_bytes()); }
        write_atomic(&sidecar(&p, "unpin"), &intent).unwrap();
        write_atomic(&sidecar(&p, "base"), &snap.encode()).unwrap();
        drop(l);
        let r = Ledger::open(&p).unwrap();
        assert!(!sidecar(&p, "unpin").exists(), "intent consumed");
        for x in &dropped { assert!(!r.slab.is_pinned(x).unwrap(), "dropped entry unpinned"); }
        for x in &kept { assert!(r.slab.is_pinned(x).unwrap(), "retained entry still pinned"); }
        drop(r); // the slab is flock'd: one open handle at a time
        // an intent whose base never advanced is ignored, not applied
        let mut bogus = 9_999u64.to_le_bytes().to_vec();
        bogus.extend_from_slice(kept[0].as_bytes());
        write_atomic(&sidecar(&p, "unpin"), &bogus).unwrap();
        let r3 = Ledger::open(&p).unwrap();
        assert!(r3.slab.is_pinned(&kept[0]).unwrap(), "premature intent must not unpin live entries");
    }
}

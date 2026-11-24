//! IoT profile: scale the ledger to devices that cannot afford it.
//!
//! A sensor does not run a ledger, hold a PQ key, or sign anything.  It sends a
//! ~60-byte **report** authenticated with a keyed BLAKE3 tag (128-bit tag, 256-bit
//! key — symmetric, so quantum-safe with no asymmetric work at all).  The leaf's key
//! is derived from one gateway master secret, so the gateway stores a single secret
//! for any number of leaves.
//!
//! A **gateway** (a phone, a hub, a ToR) verifies tags and per-leaf counters, then
//! commits a whole batch of reports with ONE ledger entry (`iot.batch`: count and the
//! Merkle root of the report wires).  That makes the main log grow with batches, not
//! with sensors, keeps the per-actor `heads` list at one entry per gateway, and costs
//! one fsync and one PQ signature per epoch however many reports it holds.
//!
//! A [`LeafReceipt`] proves one report was committed: report → batch root (O(log batch))
//! → the `iot.batch` entry → a signed checkpoint (a normal [`Receipt`]).  It verifies
//! with no network, and through the C ABI from Perl.
//!
//! What this does *not* give: per-leaf non-repudiation.  The tag is symmetric, so only
//! the gateway (key holder) can check it; the signed log says "this gateway committed
//! that it received this report", not "this sensor signed it".  Sensors that need
//! third-party-verifiable signatures should register a hash-based key with their
//! gateway (not built).

use std::collections::BTreeMap;

use crate::checkpoint::{CertCache, Checkpoint, CkptError};
use crate::entry::{Draft, Entry};
use crate::receipt::Receipt;
use crate::snapshot::hex;
use crate::tlog::{self, Hash, Tree};

pub const BATCH_KIND: &str = "iot.batch";
pub const MAX_PAYLOAD: usize = 256;
pub const MAX_LEAF: usize = 32;
pub const TAG_LEN: usize = 16;
const KEY_CONTEXT: &str = "AMIN3-IOT-LEAFKEY-V1";
const MAC_DOMAIN: &[u8] = b"AMIN3-IOT-REPORT-MAC-V1\n";
const LR_MAGIC: &[u8] = b"AMIN3-IOT-LEAF-RECEIPT-V1\n";
const VER: u8 = 1;

pub type LeafKey = [u8; 32];

/// Per-leaf key from the gateway master secret.
pub fn leaf_key(master: &[u8; 32], leaf: &str) -> LeafKey {
    let mut m = Vec::with_capacity(32 + leaf.len());
    m.extend_from_slice(master);
    m.extend_from_slice(leaf.as_bytes());
    blake3::derive_key(KEY_CONTEXT, &m)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub leaf: String,
    pub ctr: u64,
    pub payload: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

fn mac(key: &LeafKey, leaf: &str, ctr: u64, payload: &[u8]) -> [u8; TAG_LEN] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(MAC_DOMAIN);
    h.update(&[leaf.len() as u8]);
    h.update(leaf.as_bytes());
    h.update(&ctr.to_le_bytes());
    h.update(&(payload.len() as u16).to_le_bytes());
    h.update(payload);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&h.finalize().as_bytes()[..TAG_LEN]);
    t
}

impl Report {
    /// What a leaf device computes: one keyed hash over a few dozen bytes.
    pub fn new(key: &LeafKey, leaf: &str, ctr: u64, payload: &[u8]) -> Option<Self> {
        if leaf.is_empty() || leaf.len() > MAX_LEAF || payload.len() > MAX_PAYLOAD {
            return None;
        }
        Some(Self { leaf: leaf.into(), ctr, payload: payload.to_vec(), tag: mac(key, leaf, ctr, payload) })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(12 + self.leaf.len() + self.payload.len() + TAG_LEN);
        o.push(VER);
        o.push(self.leaf.len() as u8);
        o.extend_from_slice(self.leaf.as_bytes());
        o.extend_from_slice(&self.ctr.to_le_bytes());
        o.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        o.extend_from_slice(&self.payload);
        o.extend_from_slice(&self.tag);
        o
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut c = b;
        let mut take = |n: usize| -> Option<&[u8]> {
            if c.len() < n {
                return None;
            }
            let (a, r) = c.split_at(n);
            c = r;
            Some(a)
        };
        if take(1)?[0] != VER {
            return None;
        }
        let ll = take(1)?[0] as usize;
        if ll == 0 || ll > MAX_LEAF {
            return None;
        }
        let leaf = std::str::from_utf8(take(ll)?).ok()?.to_string();
        let ctr = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let pl = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        if pl > MAX_PAYLOAD {
            return None;
        }
        let payload = take(pl)?.to_vec();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(take(TAG_LEN)?);
        if !c.is_empty() {
            return None;
        }
        Some(Self { leaf, ctr, payload, tag })
    }

    /// Constant-time tag check.
    pub fn tag_ok(&self, key: &LeafKey) -> bool {
        let want = mac(key, &self.leaf, self.ctr, &self.payload);
        want.iter().zip(&self.tag).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestError {
    Format,
    BadTag,
    /// Counter not strictly greater than the last accepted for this leaf.
    Replay,
    /// Batch is full: flush first.
    Full,
}

/// One flushed batch: the ledger draft to append, and the report wires it commits.
#[derive(Debug, Clone)]
pub struct Batch {
    pub draft: Draft,
    pub reports: Vec<Vec<u8>>,
}

fn batch_tree(reports: &[Vec<u8>]) -> Tree {
    let mut t = Tree::new();
    for r in reports {
        t.append(r);
    }
    t
}

impl Batch {
    /// Inclusion proof of report `i` within this batch.
    pub fn proof(&self, i: usize) -> Option<Vec<Hash>> {
        batch_tree(&self.reports).inclusion_proof(i as u64, self.reports.len() as u64)
    }

    /// Build the receipt for report `i`, given the ledger [`Receipt`] of this batch's entry.
    pub fn leaf_receipt(&self, i: usize, batch_receipt: Receipt) -> Option<LeafReceipt> {
        Some(LeafReceipt { report: self.reports.get(i)?.clone(), index: i as u32, proof: self.proof(i)?, receipt: batch_receipt })
    }

    /// Flat file form (`u16 len ‖ report`)* for archiving next to the ledger.
    pub fn encode(reports: &[Vec<u8>]) -> Vec<u8> {
        let mut o = Vec::new();
        for r in reports {
            o.extend_from_slice(&(r.len() as u16).to_le_bytes());
            o.extend_from_slice(r);
        }
        o
    }

    pub fn decode(mut b: &[u8]) -> Option<Vec<Vec<u8>>> {
        let mut v = Vec::new();
        while !b.is_empty() {
            if b.len() < 2 {
                return None;
            }
            let n = u16::from_le_bytes([b[0], b[1]]) as usize;
            if b.len() < 2 + n {
                return None;
            }
            v.push(b[2..2 + n].to_vec());
            b = &b[2 + n..];
        }
        Some(v)
    }
}

/// Merkle commitment to the per-leaf counters (sorted by leaf).
pub fn counters_root(c: &BTreeMap<String, u64>) -> Hash {
    let mut t = Tree::new();
    for (leaf, ctr) in c {
        let mut b = Vec::with_capacity(1 + leaf.len() + 8);
        b.push(leaf.len() as u8);
        b.extend_from_slice(leaf.as_bytes());
        b.extend_from_slice(&ctr.to_le_bytes());
        t.append(&b);
    }
    t.root()
}

/// The only stateful piece: per-leaf counters (one u64 per leaf) and the open batch.
pub struct Gateway {
    master: [u8; 32],
    actor: String,
    max_batch: usize,
    last: BTreeMap<String, u64>,
    pending: Vec<Vec<u8>>,
}

impl Gateway {
    pub fn new(master: [u8; 32], actor: &str, max_batch: usize) -> Self {
        Self { master, actor: actor.into(), max_batch: max_batch.max(1), last: BTreeMap::new(), pending: Vec::new() }
    }

    /// Restore counters from a copy (archive, peer, file) and prove it is the one the log
    /// committed: `expected` is the `counters_root` of the latest `iot.batch` entry.  A
    /// stale or doctored copy would reopen replay windows, so it is refused.
    pub fn restore_checked(self, c: BTreeMap<String, u64>, expected: &Hash) -> Option<Self> {
        if counters_root(&c) != *expected {
            return None;
        }
        Some(self.with_counters(c))
    }

    /// Restore leaf counters persisted by [`Gateway::counters`].
    pub fn with_counters(mut self, c: BTreeMap<String, u64>) -> Self {
        self.last = c;
        self
    }

    pub fn counters(&self) -> &BTreeMap<String, u64> {
        &self.last
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    pub fn ingest(&mut self, wire: &[u8]) -> Result<(), IngestError> {
        let r = Report::decode(wire).ok_or(IngestError::Format)?;
        if !r.tag_ok(&leaf_key(&self.master, &r.leaf)) {
            return Err(IngestError::BadTag);
        }
        if self.last.get(&r.leaf).map_or(false, |l| r.ctr <= *l) {
            return Err(IngestError::Replay);
        }
        if self.pending.len() >= self.max_batch {
            return Err(IngestError::Full);
        }
        self.last.insert(r.leaf, r.ctr);
        self.pending.push(wire.to_vec());
        Ok(())
    }

    /// Close the open batch (None if empty).
    pub fn flush(&mut self, ts: u64) -> Option<Batch> {
        if self.pending.is_empty() {
            return None;
        }
        let reports = std::mem::take(&mut self.pending);
        let root = batch_tree(&reports).root();
        let draft = Draft {
            kind: BATCH_KIND.into(), actor: self.actor.clone(), subject: "batch".into(), auth: None, ts,
            attrs: vec![
                ("counters_root".into(), hex(&counters_root(&self.last))),
                ("n".into(), reports.len().to_string()),
                ("reports_root".into(), hex(&root)),
            ],
        };
        Some(Batch { draft, reports })
    }
}

/// Offline-verifiable proof that one leaf report was committed by a gateway's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafReceipt {
    pub report: Vec<u8>,
    pub index: u32,
    pub proof: Vec<Hash>,
    pub receipt: Receipt,
}

fn unhex32(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl LeafReceipt {
    pub fn encode(&self) -> Vec<u8> {
        let r = self.receipt.encode();
        let mut o = LR_MAGIC.to_vec();
        o.extend_from_slice(&(self.report.len() as u16).to_le_bytes());
        o.extend_from_slice(&self.report);
        o.extend_from_slice(&self.index.to_le_bytes());
        o.extend_from_slice(&(self.proof.len() as u16).to_le_bytes());
        for p in &self.proof {
            o.extend_from_slice(p);
        }
        o.extend_from_slice(&(r.len() as u32).to_le_bytes());
        o.extend_from_slice(&r);
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
        if take(LR_MAGIC.len())? != LR_MAGIC {
            return Err(CkptError::Format);
        }
        let n = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let report = take(n)?.to_vec();
        let index = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let np = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        if np > 40 {
            return Err(CkptError::Format);
        }
        let mut proof = Vec::with_capacity(np);
        for _ in 0..np {
            let mut h = [0u8; 32];
            h.copy_from_slice(take(32)?);
            proof.push(h);
        }
        let n = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if n > 128 * 1024 {
            return Err(CkptError::Format);
        }
        let receipt = Receipt::decode(take(n)?)?;
        if !c.is_empty() {
            return Err(CkptError::Format);
        }
        Ok(Self { report, index, proof, receipt })
    }

    /// Same receipt with the node certificate left out (verify with [`LeafReceipt::verify_cached`]).
    pub fn slim(&self) -> Result<Self, CkptError> {
        Ok(Self { receipt: self.receipt.slim()?, ..self.clone() })
    }

    pub fn verify_cached(
        &self, authorities: &[&[u8]], pos: u64, roster: &[&[u8]], quorum: usize, cache: &mut CertCache,
    ) -> Result<(Report, Entry, Checkpoint), CkptError> {
        let r = self.receipt.verify_cached(authorities, pos, roster, quorum, cache)?;
        self.check_leaf(r)
    }

    /// Signed checkpoint ⇒ `iot.batch` entry ⇒ batch root ⇒ this report.
    pub fn verify(
        &self, authorities: &[&[u8]], pos: u64, roster: &[&[u8]], quorum: usize,
    ) -> Result<(Report, Entry, Checkpoint), CkptError> {
        let r = self.receipt.verify(authorities, pos, roster, quorum)?;
        self.check_leaf(r)
    }

    fn check_leaf(&self, r: (Entry, Hash, Checkpoint)) -> Result<(Report, Entry, Checkpoint), CkptError> {
        let (entry, _id, ck) = r;
        if entry.kind != BATCH_KIND {
            return Err(CkptError::Format);
        }
        let get = |k: &str| entry.attrs.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
        let n: u64 = get("n").and_then(|s| s.parse().ok()).ok_or(CkptError::Format)?;
        let root = get("reports_root").and_then(unhex32).ok_or(CkptError::Format)?;
        let report = Report::decode(&self.report).ok_or(CkptError::Format)?;
        if !tlog::verify_inclusion(&tlog::leaf_hash(&self.report), self.index as u64, n, &self.proof, &root) {
            return Err(CkptError::BadSig);
        }
        Ok((report, entry, ck))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint;
    use crate::ledger::Ledger;
    use crate::nodecert::NodeCert;
    use crate::signer::Keypair;
    use awp3::sign::CompositeSigningKey;
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::Instant;

    const MASTER: [u8; 32] = [7; 32];

    #[test]
    fn report_round_trip_tamper_and_replay() {
        let k = leaf_key(&MASTER, "temp-0042");
        let r = Report::new(&k, "temp-0042", 1, b"\x01\x2c").unwrap();
        let w = r.encode();
        assert_eq!(Report::decode(&w).unwrap(), r);
        assert!(r.tag_ok(&k) && !r.tag_ok(&leaf_key(&MASTER, "temp-0043")), "keys are per leaf");
        for i in 0..w.len() {
            let mut t = w.clone();
            t[i] ^= 1;
            let ok = Report::decode(&t).map_or(false, |x| x.tag_ok(&k) && x == r);
            assert!(!ok, "flip at byte {i} accepted unchanged");
        }
        assert!(Report::new(&k, "x", 1, &[0; MAX_PAYLOAD + 1]).is_none());
        let mut g = Gateway::new(MASTER, "gw1", 4);
        g.ingest(&w).unwrap();
        assert_eq!(g.ingest(&w), Err(IngestError::Replay));
        let older = Report::new(&k, "temp-0042", 0, b"x").unwrap().encode();
        assert_eq!(g.ingest(&older), Err(IngestError::Replay), "counter must strictly increase");
        let forged = Report::new(&leaf_key(&MASTER, "other"), "temp-0042", 9, b"x").unwrap().encode();
        assert_eq!(g.ingest(&forged), Err(IngestError::BadTag));
        assert_eq!(g.ingest(&w[..w.len() - 1]), Err(IngestError::Format));
    }

    #[test]
    fn a_replacement_gateway_restores_counters_only_if_they_match_the_log() {
        let mut g = Gateway::new(MASTER, "gw1", 8);
        for (l, c) in [("a", 3u64), ("b", 9), ("c", 1)] {
            g.ingest(&Report::new(&leaf_key(&MASTER, l), l, c, b"x").unwrap().encode()).unwrap();
        }
        let b = g.flush(1).unwrap();
        let committed = b.draft.attrs.iter().find(|(k, _)| k == "counters_root").map(|(_, v)| v.clone()).unwrap();
        let root = unhex32(&committed).unwrap();
        let copy = g.counters().clone();
        let mut g2 = Gateway::new(MASTER, "gw2", 8).restore_checked(copy.clone(), &root).expect("matches the log");
        let old = Report::new(&leaf_key(&MASTER, "b"), "b", 9, b"x").unwrap().encode();
        assert_eq!(g2.ingest(&old), Err(IngestError::Replay), "replay still refused after takeover");
        let mut stale = copy.clone();
        stale.insert("b".into(), 2); // rolled back to reopen a replay window
        assert!(Gateway::new(MASTER, "gw2", 8).restore_checked(stale, &root).is_none());
        let mut dropped = copy;
        dropped.remove("c");
        assert!(Gateway::new(MASTER, "gw2", 8).restore_checked(dropped, &root).is_none());
    }

    fn fixture() -> (Keypair, CompositeSigningKey, Vec<u8>) {
        let mut r = StdRng::from_seed([41; 32]);
        let auth = Keypair::generate(&mut r, "auth".into());
        let key = CompositeSigningKey::generate(&mut r);
        let cert = NodeCert { node_id: "gw1".into(), node_vk_hash: checkpoint::vk_hash(&key.verifying_key().to_bytes()),
            boot_counter: 1, scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: 1000 }.sign(&auth).unwrap();
        (auth, key, cert)
    }

    /// Many sensors, one gateway: the log grows by batches, local state stays bounded,
    /// every report remains provable, and the numbers an IoT designer needs are printed.
    #[test]
    fn many_leaves_few_entries_bounded_state_and_provable_reports() {
        let (auth, key, cert) = fixture();
        let avk = auth.verifying_key_bytes();
        let d = tempfile::tempdir().unwrap();
        let mut led = Ledger::open(d.path().join("gw.slab")).unwrap();
        let mut gw = Gateway::new(MASTER, "gw1", 500);
        let keys: Vec<(String, LeafKey)> = (0..1000).map(|i| { let n = format!("leaf-{i:04}"); let k = leaf_key(&MASTER, &n); (n, k) }).collect();

        let t0 = Instant::now();
        let mut reports = 0u64;
        let mut batches = Vec::new();
        for round in 1..=20u64 {
            for (n, k) in &keys {
                let w = Report::new(k, n, round, &round.to_le_bytes()).unwrap().encode();
                if gw.ingest(&w) == Err(IngestError::Full) {
                    let b = gw.flush(round).unwrap();
                    let (idx, _) = led.append_drafts(vec![b.draft.clone()]).unwrap();
                    batches.push((idx, b));
                    gw.ingest(&w).unwrap();
                }
                reports += 1;
            }
        }
        if let Some(b) = gw.flush(99) {
            let (idx, _) = led.append_drafts(vec![b.draft.clone()]).unwrap();
            batches.push((idx, b));
        }
        let ingest = t0.elapsed();
        assert_eq!(reports, 20_000);
        assert_eq!(led.size(), batches.len() as u64, "log entries = batches, not reports");
        assert_eq!(batches.len(), 40);
        assert_eq!(led.head_of("gw1").unwrap().0, 40, "one actor chain for the whole fleet");

        // sign a checkpoint of the whole thing, and prove one leaf report offline
        let ck = Checkpoint { origin: "gw1".into(), size: led.size(), root: led.root() };
        let t1 = Instant::now();
        let wire = checkpoint::sign(&ck, &key, &cert, &[]).unwrap();
        let sign_t = t1.elapsed();
        let (idx, b) = &batches[17];
        let br = led.make_receipt(*idx, &wire).unwrap();
        let lr = b.leaf_receipt(123, br).unwrap();
        let lr_wire = lr.encode();
        let lr = LeafReceipt::decode(&lr_wire).unwrap();
        let t2 = Instant::now();
        let (rep, entry, got) = lr.verify(&[&avk], 10, &[], 0).unwrap();
        let verify_t = t2.elapsed();
        assert_eq!((got.origin.as_str(), got.size, entry.kind.as_str()), ("gw1", led.size(), BATCH_KIND));
        assert_eq!(rep.encode(), b.reports[123]);
        // slim receipt: ~4.7 KB smaller, verifies only once the gateway's cert is known
        let slim = lr.slim().unwrap();
        let slim_len = slim.encode().len();
        let mut cache = CertCache::new();
        assert!(slim.verify_cached(&[&avk], 10, &[], 0, &mut cache).is_err(), "unknown cert fails closed");
        assert!(slim.verify(&[&avk], 10, &[], 0).is_err(), "plain verify never accepts a slim receipt");
        lr.verify_cached(&[&avk], 10, &[], 0, &mut cache).unwrap(); // full receipt teaches the cache
        let (rep2, _, _) = slim.verify_cached(&[&avk], 10, &[], 0, &mut cache).unwrap();
        assert_eq!(rep2.encode(), b.reports[123]);
        let mut bad_slim = slim.clone();
        bad_slim.report[3] ^= 1;
        assert!(bad_slim.verify_cached(&[&avk], 10, &[], 0, &mut cache).is_err());
        // tamper anywhere in the proof path, the report or the batch index is rejected
        let mut bad = lr.clone();
        bad.report[3] ^= 1;
        assert!(bad.verify(&[&avk], 10, &[], 0).is_err());
        let mut bad = lr.clone();
        bad.index += 1;
        assert!(bad.verify(&[&avk], 10, &[], 0).is_err());
        let mut bad = lr.clone();
        bad.proof[0][0] ^= 1;
        assert!(bad.verify(&[&avk], 10, &[], 0).is_err());
        // a non-batch entry cannot be passed off as a batch
        led.append_drafts(vec![Draft { kind: "billing".into(), actor: "gw1".into(), subject: "x".into(), auth: None, ts: 1, attrs: vec![] }]).unwrap();
        let ck2 = Checkpoint { origin: "gw1".into(), size: led.size(), root: led.root() };
        let w2 = checkpoint::sign(&ck2, &key, &cert, &[]).unwrap();
        let wrong = LeafReceipt { receipt: led.make_receipt(led.size() - 1, &w2).unwrap(), ..lr.clone() };
        assert!(wrong.verify(&[&avk], 10, &[], 0).is_err());

        // bounded local state: seal + sign + compact leaves a frontier, not the history
        led.seal("gw1", 100).unwrap();
        let ck3 = Checkpoint { origin: "gw1".into(), size: led.size(), root: led.root() };
        let w3 = checkpoint::sign(&ck3, &key, &cert, &[]).unwrap();
        let snap = led.export_snapshot(&w3).unwrap();
        let (led, dropped) = led.compact(&w3).unwrap();
        assert_eq!((led.retained(), dropped), (0, 42));

        // MAC throughput on this host (a leaf does exactly this much work per report)
        let k = &keys[0].1;
        let t3 = Instant::now();
        let mut acc = 0u8;
        for i in 0..100_000u64 {
            acc ^= Report::new(k, "leaf-0000", i, &[0u8; 16]).unwrap().tag[0];
        }
        let mac_ns = t3.elapsed().as_nanos() / 100_000;
        let _ = acc;
        eprintln!("iot sizes/costs (host: this machine, not an MCU):\n  report wire (16 B payload): {} B\n  leaf receipt: {} B (report {} + batch proof {} + ledger receipt {})\n  signed checkpoint: {} B   slim leaf receipt: {} B\n  snapshot to join/resume: {} B\n  ingest+verify 20k reports: {:?}  → {:?}/report\n  composite checkpoint sign: {:?}   leaf-receipt verify: {:?}\n  leaf MAC per report: {} ns",
            Report::new(k, "leaf-0000", 1, &[0u8; 16]).unwrap().encode().len(), lr_wire.len(), lr.report.len(), lr.proof.len() * 32,
            lr.receipt.encode().len(), wire.len(), slim_len, snap.encode().len(), ingest, ingest / 20_000, sign_t, verify_t, mac_ns);
        assert!(Report::new(k, "leaf-0000", 1, &[0u8; 16]).unwrap().encode().len() <= 64);
    }
}

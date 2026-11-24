//! Mesh continuity: how independent, intermittently connected ledgers keep a
//! single auditable story.
//!
//! * **Observation** — a ledger records another origin's signed checkpoint
//!   (`ledger.anchor` when reporting up to a parent, `ledger.peer` when two
//!   meshes pass roots to each other).  Each origin gets its own chain, so the
//!   last thing this ledger saw from it is always known (and, for a pruned
//!   ledger, committed by the chain head in its snapshot).  A new checkpoint
//!   must *extend* what was last recorded; otherwise it is not recorded.
//! * **Equivocation** — an origin that signs two different roots for the same
//!   size has produced a self-contained proof of forking.  That alone is
//!   written as a `ledger.fault`; the origin is then refused until resolved.
//!   An unprovable inconsistent extension is *not* recorded as a fault, since a
//!   relay could frame an honest origin with a bad proof; [`Observed::Inconsistent`]
//!   is returned so the caller can challenge the origin (witnesses simply
//!   withhold their cosignature, which is what prevents a fork reaching quorum).
//! * **Receipts** — offline payments: see [`crate::receipt`].
//!
//! Which authority a certificate chains to is the caller's trust set
//! (`authorities`), so meshes under different roots can still verify one another.

use crate::checkpoint::{self, Checkpoint};
use crate::entry::{self, Draft, Entry};
use crate::error::{BitcacheError, Result};
use crate::ledger::Ledger;
use crate::policy::QuorumPolicy;
use crate::receipt::Receipt;
use crate::signer::Keypair;
use crate::snapshot::hex;
use crate::tlog::{self, Hash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveKind {
    /// Reporting a checkpoint up to a parent/global ledger.
    Anchor,
    /// Two meshes (or phones) passing roots to each other.
    Peer,
}

impl ObserveKind {
    pub const fn kind(self) -> &'static str {
        match self {
            ObserveKind::Anchor => "ledger.anchor",
            ObserveKind::Peer => "ledger.peer",
        }
    }
    const fn tag(self) -> &'static str {
        match self {
            ObserveKind::Anchor => "anchor",
            ObserveKind::Peer => "peer",
        }
    }
}

pub struct Observation<'a> {
    pub kind: ObserveKind,
    /// The origin's signed checkpoint.
    pub wire: &'a [u8],
    /// Consistency proof from the origin's last recorded checkpoint to this one.
    pub proof: &'a [Hash],
    /// The previous observation entry of this origin, when this ledger no longer
    /// holds it (pruned / joined).  Must hash to the committed chain head.
    pub prev_entry: Option<&'a [u8]>,
    pub authorities: &'a [&'a [u8]],
    /// Authority position the origin's certificate is checked at (what the
    /// origin last knew — offline origins lag).  Recorded for audit.
    pub claimed_pos: u64,
    /// Authority position this observer currently knows.  Recorded for audit.
    pub observed_pos: u64,
    pub roster: &'a [&'a [u8]],
    pub quorum: usize,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    Recorded(Entry),
    /// Same checkpoint already recorded.
    Duplicate,
    /// Older than what is already recorded; nothing to do.
    Stale,
    /// Does not extend the recorded state and no fork is provable from what was
    /// presented.  Nothing written; challenge the origin for a proof.
    Inconsistent,
    /// Two different roots at the same size: provable equivocation, now recorded.
    Fault(Entry),
}

/// Domain-separated hash of a signed checkpoint, used as an entry's `auth`.
pub fn wire_hash(wire: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(b"AMIN3-CKPT-WIRE-V1\n");
    h.update(wire);
    *h.finalize().as_bytes()
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

fn attr<'a>(e: &'a Entry, k: &str) -> Option<&'a str> {
    e.attrs.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

fn bad(msg: impl Into<String>) -> BitcacheError {
    BitcacheError::ChainViolation(msg.into())
}

impl Ledger {
    pub fn is_faulted(&self, origin: &str) -> bool {
        self.heads.contains_key(&format!("fault:{origin}"))
    }

    /// `(size, root)` of the last checkpoint of `origin` recorded under `kind`.
    pub fn last_observed(&mut self, kind: ObserveKind, origin: &str, supplied: Option<&[u8]>) -> Result<Option<(u64, Hash)>> {
        let actor = format!("{}:{origin}", kind.tag());
        let Some((_, id)) = self.heads.get(&actor).copied() else { return Ok(None) };
        let bytes = match supplied {
            Some(b) => b.to_vec(),
            None => match self.last_idx.get(&actor).copied() {
                Some(i) => self.entry(i)?,
                None => return Err(bad("previous observation entry required (ledger was joined from a snapshot)")),
            },
        };
        if entry::id_of(&bytes) != id {
            return Err(bad("supplied previous entry does not match the committed chain head"));
        }
        let e = Entry::decode(&bytes).map_err(|_| bad("previous observation entry is malformed"))?;
        let size = attr(&e, "size").and_then(|s| s.parse::<u64>().ok()).ok_or_else(|| bad("previous entry lacks size"))?;
        let root = attr(&e, "root").and_then(unhex32).ok_or_else(|| bad("previous entry lacks root"))?;
        Ok(Some((size, root)))
    }

    pub fn observe_checkpoint(&mut self, o: &Observation) -> Result<Observed> {
        let ck = checkpoint::verify_any(o.wire, o.authorities, o.claimed_pos, o.roster, o.quorum)
            .map_err(|e| bad(format!("checkpoint rejected: {e:?}")))?;
        if self.is_faulted(&ck.origin) {
            return Err(bad(format!("origin {} has an open fault", ck.origin)));
        }
        let prev = self.last_observed(o.kind, &ck.origin, o.prev_entry)?;
        let auth = Some(wire_hash(o.wire));
        let mut attrs = vec![
            ("origin".to_string(), ck.origin.clone()),
            ("size".into(), ck.size.to_string()),
            ("root".into(), hex(&ck.root)),
        ];
        if let Some((psize, proot)) = prev {
            if ck.size < psize {
                return Ok(Observed::Stale);
            }
            if ck.size == psize {
                if ck.root == proot {
                    return Ok(Observed::Duplicate);
                }
                // Two signed roots for one size: self-contained proof of a fork.
                let d = Draft {
                    kind: "ledger.fault".into(), actor: format!("fault:{}", ck.origin), subject: ck.origin.clone(),
                    auth, ts: o.ts,
                    attrs: vec![
                        ("reason".into(), "same-size-different-root".into()),
                        ("via".into(), o.kind.tag().into()),
                        ("size".into(), ck.size.to_string()),
                        ("recorded_root".into(), hex(&proot)),
                        ("presented_root".into(), hex(&ck.root)),
                    ],
                };
                let (_, mut es) = self.append_drafts(vec![d])?;
                return Ok(Observed::Fault(es.remove(0)));
            }
            if !tlog::verify_consistency(psize, &proot, ck.size, &ck.root, o.proof) {
                return Ok(Observed::Inconsistent);
            }
        }
        attrs.push(("claimed_pos".into(), o.claimed_pos.to_string()));
        attrs.push(("observed_pos".into(), o.observed_pos.to_string()));
        let d = Draft { kind: o.kind.kind().into(), actor: format!("{}:{}", o.kind.tag(), ck.origin),
                        subject: ck.origin.clone(), auth, ts: o.ts, attrs };
        let (_, mut es) = self.append_drafts(vec![d])?;
        Ok(Observed::Recorded(es.remove(0)))
    }

    /// Receipt for entry `index`, proven against the signed `checkpoint_wire`
    /// (whose size must be ≤ this ledger's and cover `index`).
    pub fn make_receipt(&mut self, index: u64, checkpoint_wire: &[u8]) -> Result<Receipt> {
        let ck: Checkpoint = checkpoint::parse_unverified(checkpoint_wire).map_err(|e| bad(format!("{e:?}")))?;
        if ck.size > self.size() || self.root_at(ck.size) != Some(ck.root) {
            return Err(bad("checkpoint is not a checkpoint of this ledger"));
        }
        let proof = self.inclusion_proof(index, ck.size).ok_or_else(|| bad("entry not provable at that size"))?;
        Ok(Receipt { entry: self.entry(index)?, index, proof, checkpoint: checkpoint_wire.to_vec() })
    }

    /// Witness side of the policy: look at `origin`'s new checkpoint against what this
    /// ledger last recorded for it, and cosign only if it is a consistent extension (or
    /// the very same checkpoint again).  Everything else — older, inconsistent, or a
    /// provable fork — is refused, and a fork is recorded as a fault.  What a witness has
    /// seen is itself ledger entries, so witness behaviour is auditable.
    pub fn witness_review(&mut self, o: &Observation, witness: &Keypair) -> Result<Witnessed> {
        match self.observe_checkpoint(o)? {
            Observed::Recorded(_) | Observed::Duplicate => {
                let ck = checkpoint::parse_unverified(o.wire).map_err(|e| bad(format!("{e:?}")))?;
                let (h, sig) = checkpoint::cosign(&ck, witness)?;
                Ok(Witnessed::Cosigned(h, sig))
            }
            other => Ok(Witnessed::Refused(other)),
        }
    }

    /// Verify a payer's receipt and record the matching `transfer.in` for
    /// `receiver`.  Each receipt is accepted once; the witness quorum demanded
    /// follows `policy` and the payment's amount.
    pub fn accept_receipt(
        &mut self,
        r: &Receipt,
        authorities: &[&[u8]],
        pos: u64,
        roster: &[&[u8]],
        policy: &QuorumPolicy,
        receiver: &str,
        ts: u64,
    ) -> Result<Entry> {
        // The amount only selects the quorum; the entry itself is then proven below.
        let amount = Entry::decode(&r.entry).ok().and_then(|e| attr(&e, "amount").and_then(|a| a.parse::<u64>().ok()));
        let quorum = policy.required(amount);
        let (out, id, ck) = r.verify(authorities, pos, roster, quorum).map_err(|e| bad(format!("receipt rejected: {e:?}")))?;
        if out.kind != "transfer.out" || out.subject != receiver {
            return Err(bad("receipt is not a transfer to this receiver"));
        }
        self.accepted.check(&ck.origin, &out.actor, out.seq).map_err(|x| bad(format!("receipt refused: {x:?}")))?;
        let mut attrs = vec![
            ("from_origin".to_string(), ck.origin.clone()),
            ("from_index".into(), r.index.to_string()),
            ("from_seq".into(), out.seq.to_string()),
            ("from_entry".into(), hex(&id)),
            ("witnesses".into(), quorum.to_string()),
        ];
        for k in ["amount", "currency"] {
            if let Some(v) = attr(&out, k) {
                attrs.push((k.into(), v.into()));
            }
        }
        let d = Draft { kind: "transfer.in".into(), actor: receiver.into(), subject: out.actor.clone(), auth: Some(id), ts, attrs };
        let (_, mut es) = self.append_drafts(vec![d])?;
        Ok(es.remove(0))
    }
}

/// Outcome of a witness review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Witnessed {
    /// `(witness vk hash, ML-DSA-87 cosignature)` to attach with [`checkpoint::attach_cosigs`].
    Cosigned(Hash, Vec<u8>),
    Refused(Observed),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::QuorumPolicy;
    use crate::nodecert::NodeCert;
    use crate::signer::Keypair;
    use awp3::sign::CompositeSigningKey;
    use rand::{rngs::StdRng, SeedableRng};

    struct Phone {
        origin: String,
        key: CompositeSigningKey,
        cert: Vec<u8>,
        led: Ledger,
        _d: tempfile::TempDir,
    }

    fn phone(name: &str, auth: &Keypair, seed: u8) -> Phone {
        let mut r = StdRng::from_seed([seed; 32]);
        let key = CompositeSigningKey::generate(&mut r);
        let cert = NodeCert {
            node_id: name.into(), node_vk_hash: checkpoint::vk_hash(&key.verifying_key().to_bytes()),
            boot_counter: 1, scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: 1000,
        }.sign(auth).unwrap();
        let d = tempfile::tempdir().unwrap();
        let led = Ledger::open(d.path().join("l.slab")).unwrap();
        Phone { origin: name.into(), key, cert, led, _d: d }
    }

    impl Phone {
        fn publish(&self) -> Vec<u8> {
            let ck = Checkpoint { origin: self.origin.clone(), size: self.led.size(), root: self.led.root() };
            checkpoint::sign(&ck, &self.key, &self.cert, &[]).unwrap()
        }
        fn add(&mut self, actor: &str, kind: &str, subject: &str, attrs: &[(&str, &str)]) -> u64 {
            let d = Draft { kind: kind.into(), actor: actor.into(), subject: subject.into(), auth: None, ts: 1,
                attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() };
            self.led.append_drafts(vec![d]).unwrap().0
        }
    }

    fn obs<'a>(kind: ObserveKind, wire: &'a [u8], proof: &'a [Hash], prev: Option<&'a [u8]>, auths: &'a [&'a [u8]]) -> Observation<'a> {
        Observation { kind, wire, proof, prev_entry: prev, authorities: auths, claimed_pos: 10, observed_pos: 500,
                      roster: &[], quorum: 0, ts: 7 }
    }

    #[test]
    fn three_phones_offline_pay_witness_catch_a_fork_and_reconnect() {
        let auth = Keypair::generate(&mut StdRng::from_seed([1; 32]), "auth".into());
        let avk = auth.verifying_key_bytes();
        let auths: [&[u8]; 1] = [&avk];
        let (mut p1, mut p2, mut p3) = (phone("p1", &auth, 11), phone("p2", &auth, 12), phone("p3", &auth, 13));

        // ── offline: alice (p1) pays bob (p2) 5; p2 verifies the receipt with no network ──
        for i in 0..3 { p1.add("alice", "balance.open", &format!("n{i}"), &[("amount", "100")]); }
        let out_idx = p1.add("alice", "transfer.out", "bob", &[("amount", "5"), ("currency", "NZD")]);
        let ck1 = p1.publish();
        let receipt = p1.led.make_receipt(out_idx, &ck1).unwrap();
        let rbytes = receipt.encode();
        let rx = Receipt::decode(&rbytes).unwrap();
        let tin = p2.led.accept_receipt(&rx, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).unwrap();
        assert_eq!((tin.kind.as_str(), tin.subject.as_str()), ("transfer.in", "alice"));
        assert_eq!(tin.auth, entry::id_of(&receipt.entry), "transfer.in points at the exact payer entry");
        assert!(p2.led.accept_receipt(&rx, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).is_err(), "no double acceptance");
        assert!(p2.led.accept_receipt(&rx, &auths, 10, &[], &QuorumPolicy::flat(0), "carol", 8).is_err(), "wrong payee");
        let mut forged = receipt.clone();
        let n = forged.entry.len();
        forged.entry[n - 3] ^= 1;
        assert!(p2.led.accept_receipt(&forged, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).is_err(), "tampered receipt");
        let mut wrong_idx = receipt.clone();
        wrong_idx.index = 0;
        assert!(p3.led.accept_receipt(&wrong_idx, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).is_err(), "wrong position");

        // ── pass roots: p2 and p3 record p1's checkpoint ──
        for p in [&mut p2, &mut p3] {
            assert!(matches!(p.led.observe_checkpoint(&obs(ObserveKind::Peer, &ck1, &[], None, &auths)).unwrap(), Observed::Recorded(_)));
            assert_eq!(p.led.observe_checkpoint(&obs(ObserveKind::Peer, &ck1, &[], None, &auths)).unwrap(), Observed::Duplicate);
        }

        // ── p1 keeps transacting, then both an honest extension and a fork exist at size 6 ──
        let mut fork = phone("p1", &auth, 11); // same key: the attacker IS p1
        for i in 0..3 { fork.add("alice", "balance.open", &format!("n{i}"), &[("amount", "100")]); }
        fork.add("alice", "transfer.out", "bob", &[("amount", "5"), ("currency", "NZD")]);
        assert_eq!(fork.led.root(), p1.led.root(), "fork shares the honest prefix");
        p1.add("alice", "transfer.out", "carol", &[("amount", "50")]);
        p1.add("alice", "transfer.out", "dave", &[("amount", "50")]);
        fork.add("alice", "transfer.out", "carol", &[("amount", "50")]);
        fork.add("alice", "transfer.out", "erin", &[("amount", "50")]); // double-spends the same 50
        let (ck2, ckf) = (p1.publish(), fork.publish());
        assert_ne!(p1.led.root(), fork.led.root());
        let proof = p1.led.consistency_proof(4, 6).unwrap();
        let proof_f = fork.led.consistency_proof(4, 6).unwrap();

        // p2 saw the honest history first
        assert!(matches!(p2.led.observe_checkpoint(&obs(ObserveKind::Peer, &ck2, &proof, None, &auths)).unwrap(), Observed::Recorded(_)));
        match p2.led.observe_checkpoint(&obs(ObserveKind::Peer, &ckf, &proof_f, None, &auths)).unwrap() {
            Observed::Fault(e) => assert_eq!(attr(&e, "reason"), Some("same-size-different-root")),
            o => panic!("expected a fault, got {o:?}"),
        }
        assert!(p2.led.is_faulted("p1"));
        assert!(p2.led.observe_checkpoint(&obs(ObserveKind::Peer, &ck2, &proof, None, &auths)).is_err(), "faulted origin refused");

        // p3 only saw size 4, so the fork extends it validly — until it meets the honest checkpoint
        assert!(matches!(p3.led.observe_checkpoint(&obs(ObserveKind::Peer, &ckf, &proof_f, None, &auths)).unwrap(), Observed::Recorded(_)));
        assert!(matches!(p3.led.observe_checkpoint(&obs(ObserveKind::Peer, &ck2, &proof, None, &auths)).unwrap(), Observed::Fault(_)));

        // a relay cannot frame an honest origin with a bad proof
        let mut p4 = phone("p4", &auth, 14);
        p4.add("x", "k", "s", &[]);
        let c1 = p4.publish();
        p4.add("x", "k", "s2", &[]);
        p4.add("x", "k", "s3", &[]);
        let c3 = p4.publish();
        p2.led.observe_checkpoint(&obs(ObserveKind::Peer, &c1, &[], None, &auths)).unwrap();
        let before = p2.led.size();
        assert_eq!(p2.led.observe_checkpoint(&obs(ObserveKind::Peer, &c3, &[], None, &auths)).unwrap(), Observed::Inconsistent);
        assert_eq!(p2.led.size(), before, "nothing written for an unprovable inconsistency");
        let good = p4.led.consistency_proof(1, 3).unwrap();
        assert!(matches!(p2.led.observe_checkpoint(&obs(ObserveKind::Peer, &c3, &good, None, &auths)).unwrap(), Observed::Recorded(_)));

        // ── reconnect: everyone reports up to the global ledger ──
        let mut g = phone("global", &auth, 20);
        for (ck, pr) in [(&ck1, vec![]), (&ck2, proof.clone())] {
            assert!(matches!(g.led.observe_checkpoint(&obs(ObserveKind::Anchor, ck, &pr, None, &auths)).unwrap(), Observed::Recorded(_)));
        }
        assert!(matches!(g.led.observe_checkpoint(&obs(ObserveKind::Anchor, &ckf, &proof_f, None, &auths)).unwrap(), Observed::Fault(_)));
        assert!(g.led.is_faulted("p1"));
        let p2ck = p2.publish();
        assert!(matches!(g.led.observe_checkpoint(&obs(ObserveKind::Anchor, &p2ck, &[], None, &auths)).unwrap(), Observed::Recorded(_)), "honest phones are unaffected");
    }

    #[test]
    fn a_pruned_joined_ledger_can_keep_observing_with_a_supplied_previous_entry() {
        let auth = Keypair::generate(&mut StdRng::from_seed([2; 32]), "auth".into());
        let avk = auth.verifying_key_bytes();
        let auths: [&[u8]; 1] = [&avk];
        let mut p = phone("p1", &auth, 31);
        for i in 0..5 { p.add("a", "k", &format!("s{i}"), &[]); }
        let c5 = p.publish();
        let mut g = phone("global", &auth, 32);
        g.led.observe_checkpoint(&obs(ObserveKind::Anchor, &c5, &[], None, &auths)).unwrap();
        let prev_idx = g.led.last_idx["anchor:p1"];
        let prev_bytes = g.led.entry(prev_idx).unwrap();

        // global seals; a new phone joins from its snapshot and holds no history
        g.led.seal("global", 9).unwrap();
        let gck = g.publish();
        let snap = g.led.export_snapshot(&gck).unwrap().encode();
        let jd = tempfile::tempdir().unwrap();
        let mut j = Ledger::join(jd.path().join("j.slab"), &snap, &avk, 10, &[], 0).unwrap();

        for i in 5..9 { p.add("a", "k", &format!("s{i}"), &[]); }
        let c9 = p.publish();
        let proof = p.led.consistency_proof(5, 9).unwrap();
        let need = j.observe_checkpoint(&obs(ObserveKind::Anchor, &c9, &proof, None, &auths));
        assert!(need.is_err(), "pruned ledger must be given the previous entry");
        let mut wrong = prev_bytes.clone();
        let n = wrong.len(); wrong[n - 1] ^= 1;
        assert!(j.observe_checkpoint(&obs(ObserveKind::Anchor, &c9, &proof, Some(&wrong), &auths)).is_err());
        assert!(matches!(j.observe_checkpoint(&obs(ObserveKind::Anchor, &c9, &proof, Some(&prev_bytes), &auths)).unwrap(), Observed::Recorded(_)));
        assert_eq!(j.last_observed(ObserveKind::Anchor, "p1", None).unwrap().unwrap().0, 9);
    }

    #[test]
    fn independent_meshes_under_different_authorities_pass_roots_and_pay() {
        let (auth_a, auth_b) = (Keypair::generate(&mut StdRng::from_seed([3; 32]), "A".into()), Keypair::generate(&mut StdRng::from_seed([4; 32]), "B".into()));
        let (va, vb) = (auth_a.verifying_key_bytes(), auth_b.verifying_key_bytes());
        let (mut a1, mut b1) = (phone("a1", &auth_a, 41), phone("b1", &auth_b, 42));
        a1.add("ann", "k", "s", &[]);
        b1.add("ben", "transfer.out", "ann", &[("amount", "9")]);
        let (ca, cb) = (a1.publish(), b1.publish());

        // each trusts only its own authority → refuses the other mesh
        assert!(a1.led.observe_checkpoint(&obs(ObserveKind::Peer, &cb, &[], None, &[&va])).is_err());
        // after the meshes agree to trust both roots, they pass roots
        let both: [&[u8]; 2] = [&va, &vb];
        assert!(matches!(a1.led.observe_checkpoint(&obs(ObserveKind::Peer, &cb, &[], None, &both)).unwrap(), Observed::Recorded(_)));
        assert!(matches!(b1.led.observe_checkpoint(&obs(ObserveKind::Peer, &ca, &[], None, &both)).unwrap(), Observed::Recorded(_)));

        // …and ben's offline payment verifies in mesh A
        let r = b1.led.make_receipt(0, &cb).unwrap();
        assert!(a1.led.accept_receipt(&r, &[&va], 10, &[], &QuorumPolicy::flat(0), "ann", 3).is_err(), "unknown authority");
        assert!(a1.led.accept_receipt(&r, &both, 10, &[], &QuorumPolicy::flat(0), "ann", 3).is_ok());

        // both go offline and carry on; on the next meeting each proves it only extended
        for i in 0..4 { a1.add("ann", "k", &format!("o{i}"), &[]); b1.add("ben", "k", &format!("o{i}"), &[]); }
        let (ca2, cb2) = (a1.publish(), b1.publish());
        let (pa, pb) = (a1.led.consistency_proof(1, a1.led.size()).unwrap(), b1.led.consistency_proof(1, b1.led.size()).unwrap());
        assert!(matches!(b1.led.observe_checkpoint(&obs(ObserveKind::Peer, &ca2, &pa, None, &both)).unwrap(), Observed::Recorded(_)));
        assert!(matches!(a1.led.observe_checkpoint(&obs(ObserveKind::Peer, &cb2, &pb, None, &both)).unwrap(), Observed::Recorded(_)));
    }

    #[test]
    fn a_snapshot_joined_node_still_refuses_receipts_accepted_before_it_joined() {
        let auth = Keypair::generate(&mut StdRng::from_seed([1; 32]), "auth".into());
        let avk = auth.verifying_key_bytes();
        let auths: [&[u8]; 1] = [&avk];
        let (mut p1, mut p2) = (phone("p1", &auth, 11), phone("p2", &auth, 12));
        p1.add("alice", "balance.open", "n0", &[("amount", "100")]);
        let out = p1.add("alice", "transfer.out", "bob", &[("amount", "5")]);
        let rx = p1.led.make_receipt(out, &p1.publish()).unwrap();
        p2.led.accept_receipt(&rx, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).unwrap();

        // p2 seals and a fresh node joins from the signed snapshot — no history carried
        p2.led.seal("p2", 9).unwrap();
        let snap = p2.led.export_snapshot(&p2.publish()).unwrap();
        let jd = tempfile::tempdir().unwrap();
        let mut joined = Ledger::join(jd.path().join("j.slab"), &snap.encode(), &avk, 10, &[], 0).unwrap();
        assert!(joined.entry(0).is_err());
        assert!(joined.accept_receipt(&rx, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).is_err(),
                "replay state travelled in the snapshot");
        // control: without the snapshot's committed state the same receipt is accepted
        let mut naive = phone("p3", &auth, 13);
        assert!(naive.led.accept_receipt(&rx, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).is_ok());
        // and the protection survives a reopen of the joined ledger
        let p = jd.path().join("j.slab");
        drop(joined);
        let mut again = Ledger::open(&p).unwrap();
        assert!(again.accept_receipt(&rx, &auths, 10, &[], &QuorumPolicy::flat(0), "bob", 8).is_err());
        // a snapshot whose accepted set was edited no longer matches the committed root
        let mut forged = snap.clone();
        forged.accepted.clear();
        assert!(forged.check_stored().is_err());
    }

    #[test]
    fn witnesses_gate_large_payments_and_never_cosign_a_fork() {
        let auth = Keypair::generate(&mut StdRng::from_seed([1; 32]), "auth".into());
        let avk = auth.verifying_key_bytes();
        let auths: [&[u8]; 1] = [&avk];
        let w1k = Keypair::generate(&mut StdRng::from_seed([31; 32]), "w1".into());
        let w2k = Keypair::generate(&mut StdRng::from_seed([32; 32]), "w2".into());
        let (w1vk, w2vk) = (w1k.verifying_key_bytes(), w2k.verifying_key_bytes());
        let roster: [&[u8]; 2] = [&w1vk, &w2vk];
        let (mut payer, mut bob, mut carol) = (phone("p1", &auth, 11), phone("p2", &auth, 12), phone("p3", &auth, 13));
        let (mut w1, mut w2) = (phone("w1", &auth, 14), phone("w2", &auth, 15));
        let policy = QuorumPolicy::with_tiers(0, &["100:2".into()]).unwrap();

        payer.add("alice", "balance.open", "n0", &[("amount", "1000")]);
        let small = payer.add("alice", "transfer.out", "bob", &[("amount", "5")]);
        let big = payer.add("alice", "transfer.out", "bob", &[("amount", "500")]);
        let ck = payer.publish();
        let review = |w: &mut Phone, k: &Keypair, wire: &[u8]| {
            w.led.witness_review(&obs(ObserveKind::Peer, wire, &[], None, &auths), k).unwrap()
        };
        // both witnesses see the checkpoint first and cosign it
        let mut cos = Vec::new();
        for (w, k) in [(&mut w1, &w1k), (&mut w2, &w2k)] {
            match review(w, k, &ck) { Witnessed::Cosigned(h, s) => cos.push((h, s)), x => panic!("expected cosign, got {x:?}") }
        }
        let ckw = checkpoint::attach_cosigs(&ck, &cos).unwrap();

        // a small payment needs only the payer's signature; a large one needs both witnesses
        let r_small = payer.led.make_receipt(small, &ck).unwrap();
        assert!(bob.led.accept_receipt(&r_small, &auths, 10, &roster, &policy, "bob", 8).is_ok());
        let r_big_bare = payer.led.make_receipt(big, &ck).unwrap();
        assert!(bob.led.accept_receipt(&r_big_bare, &auths, 10, &roster, &policy, "bob", 8).is_err(), "no witnesses ⇒ refused");
        let r_big = payer.led.make_receipt(big, &ckw).unwrap();
        let tin = bob.led.accept_receipt(&r_big, &auths, 10, &roster, &policy, "bob", 8).unwrap();
        assert!(tin.attrs.contains(&("witnesses".to_string(), "2".to_string())), "the quorum applied is on the record");
        // one witness is not enough
        let one = checkpoint::attach_cosigs(&ck, &cos[..1]).unwrap();
        let r_one = payer.led.make_receipt(big, &one).unwrap();
        assert!(carol.led.accept_receipt(&r_one, &auths, 10, &roster, &policy, "bob", 8).is_err());

        // ── the payer forks: same size, different root (pays carol instead of bob) ──
        let mut fork = phone("p1", &auth, 11);
        fork.add("alice", "balance.open", "n0", &[("amount", "1000")]);
        fork.add("alice", "transfer.out", "bob", &[("amount", "5")]);
        let big2 = fork.add("alice", "transfer.out", "carol", &[("amount", "500")]);
        let ck_fork = fork.publish();
        assert_eq!(checkpoint::parse_unverified(&ck_fork).unwrap().size, checkpoint::parse_unverified(&ck).unwrap().size);
        for (w, k) in [(&mut w1, &w1k), (&mut w2, &w2k)] {
            assert!(matches!(review(w, k, &ck_fork), Witnessed::Refused(Observed::Fault(_))), "fork is refused and recorded");
            assert!(w.led.is_faulted("p1"));
        }
        // the forked history can never reach a quorum, so carol refuses the big payment
        let r_fork = fork.led.make_receipt(big2, &ck_fork).unwrap();
        assert!(carol.led.accept_receipt(&r_fork, &auths, 10, &roster, &policy, "carol", 8).is_err());
        // a witness that has seen later state will not cosign an older checkpoint
        let mut late = phone("w3", &auth, 16);
        let k3 = Keypair::generate(&mut StdRng::from_seed([33; 32]), "w3".into());
        payer.add("alice", "transfer.out", "bob", &[("amount", "1")]);
        let newer = payer.publish();
        assert!(matches!(late.led.witness_review(&obs(ObserveKind::Peer, &newer, &[], None, &auths), &k3).unwrap(), Witnessed::Cosigned(..)));
        assert!(matches!(late.led.witness_review(&obs(ObserveKind::Peer, &ck, &[], None, &auths), &k3).unwrap(),
                         Witnessed::Refused(Observed::Stale)));
    }
}

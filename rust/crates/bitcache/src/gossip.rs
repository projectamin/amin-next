//! Checkpoint gossip over the existing mesh discovery record.
//!
//! A node advertises its latest signed checkpoint as a content-addressed object
//! in `hot_refs[CKPT_SLOT]` of its peer record (the slab ref is the BLAKE3 of
//! the wire, so nothing new is needed on the discovery wire).  A peer that sees
//! a ref it has not recorded fetches it from the replicated slab and offers it
//! to its ledger as an observation.  The fetched bytes are untrusted: the hash
//! must match the ref, and `Ledger::observe_checkpoint` verifies the signature
//! chain before anything is written.
//!
//! Gossip carries no consistency proof, so it can only *start* tracking an
//! origin or confirm a checkpoint already recorded.  A newer checkpoint that
//! does not extend the recorded one comes back as [`Gossiped::NeedProof`]: the
//! caller challenges that origin for a proof (as `ckpt-observe` does), which is
//! the only place a fork can be established.

use anyhow::Result;

use crate::ledger::Ledger;
use crate::mesh::{Observation, ObserveKind, Observed};
use crate::slab::{ObjRef, SlabFile};

/// Which of the four `hot_refs` slots carries the checkpoint ref.
pub const CKPT_SLOT: usize = 3;

/// Store `wire` in `slab` and return the ref to put in the peer record.
pub fn publish(slab: &mut SlabFile, wire: &[u8]) -> Result<[u8; 32]> {
    Ok(*slab.put(wire)?.as_bytes())
}

/// The checkpoint ref a peer record advertises, if it has one.
pub fn advertised(hot_refs: &[[u8; 32]; 4]) -> Option<[u8; 32]> {
    let r = hot_refs[CKPT_SLOT];
    (r != [0u8; 32]).then_some(r)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Gossiped {
    /// Fetched, verified and recorded (or already recorded).
    Applied(Observed),
    /// Fetched but not provable from here — challenge the origin for a proof.
    NeedProof { wire_ref: [u8; 32] },
    /// Fetched bytes did not hash to the advertised ref, or did not verify.
    Rejected { wire_ref: [u8; 32], why: String },
    /// The ref is not in the local slab yet; try again after replication.
    Missing { wire_ref: [u8; 32] },
}

/// What the observer knows when judging gossiped checkpoints.
pub struct Context<'a> {
    pub authorities: &'a [&'a [u8]],
    pub claimed_pos: u64,
    pub observed_pos: u64,
    pub ts: u64,
}

/// Offer each advertised ref to the ledger.  `fetch` returns the bytes for a ref,
/// or `None` if the replica does not hold it yet.
pub fn apply<F>(ledger: &mut Ledger, refs: &[[u8; 32]], ctx: &Context, mut fetch: F) -> Vec<Gossiped>
where
    F: FnMut(&[u8; 32]) -> Option<Vec<u8>>,
{
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for r in refs.iter().filter(|r| **r != [0u8; 32] && seen.insert(**r)) {
        let Some(wire) = fetch(r) else { out.push(Gossiped::Missing { wire_ref: *r }); continue };
        if blake3::hash(&wire).as_bytes() != r {
            out.push(Gossiped::Rejected { wire_ref: *r, why: "bytes do not match the advertised ref".into() });
            continue;
        }
        let o = Observation {
            kind: ObserveKind::Peer, wire: &wire, proof: &[], prev_entry: None,
            authorities: ctx.authorities, claimed_pos: ctx.claimed_pos, observed_pos: ctx.observed_pos,
            roster: &[], quorum: 0, ts: ctx.ts,
        };
        out.push(match ledger.observe_checkpoint(&o) {
            Ok(Observed::Inconsistent) => Gossiped::NeedProof { wire_ref: *r },
            Ok(v) => Gossiped::Applied(v),
            Err(e) => Gossiped::Rejected { wire_ref: *r, why: e.to_string() },
        });
    }
    out
}

/// Fetch from a local slab (what a replica of the mesh slab looks like).
pub fn slab_fetch(slab: &mut SlabFile) -> impl FnMut(&[u8; 32]) -> Option<Vec<u8>> + '_ {
    move |r| slab.get(&ObjRef(*r)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{self, Checkpoint};
    use crate::entry::Draft;
    use crate::nodecert::NodeCert;
    use crate::signer::Keypair;
    use awp3::sign::CompositeSigningKey;
    use rand::{rngs::StdRng, SeedableRng};

    struct Node { name: String, key: CompositeSigningKey, cert: Vec<u8>, led: Ledger, _d: tempfile::TempDir }
    fn node(name: &str, auth: &Keypair, seed: u8) -> Node {
        let key = CompositeSigningKey::generate(&mut StdRng::from_seed([seed; 32]));
        let cert = NodeCert { node_id: name.into(), node_vk_hash: checkpoint::vk_hash(&key.verifying_key().to_bytes()),
            boot_counter: 1, scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: 1000 }.sign(auth).unwrap();
        let d = tempfile::tempdir().unwrap();
        Node { name: name.into(), key, cert, led: Ledger::open(d.path().join("l.slab")).unwrap(), _d: d }
    }
    impl Node {
        fn add(&mut self, n: usize) {
            for i in 0..n {
                let d = Draft { kind: "tick".into(), actor: "a".into(), subject: format!("s{i}"), auth: None, ts: 1, attrs: vec![] };
                self.led.append_drafts(vec![d]).unwrap();
            }
        }
        fn wire(&self) -> Vec<u8> {
            let ck = Checkpoint { origin: self.name.clone(), size: self.led.size(), root: self.led.root() };
            checkpoint::sign(&ck, &self.key, &self.cert, &[]).unwrap()
        }
    }

    #[test]
    fn peers_learn_each_others_checkpoints_through_advertised_refs() {
        let auth = Keypair::generate(&mut StdRng::from_seed([1; 32]), "auth".into());
        let avk = auth.verifying_key_bytes();
        let auths: [&[u8]; 1] = [&avk];
        let (mut a, mut b) = (node("a", &auth, 21), node("b", &auth, 22));
        a.add(3);
        let d = tempfile::tempdir().unwrap();
        let mut shared = SlabFile::open_or_create(d.path().join("mesh.slab")).unwrap();
        let ctx = Context { authorities: &auths, claimed_pos: 10, observed_pos: 500, ts: 9 };

        // a advertises; b has never seen a → recorded
        let w1 = a.wire();
        let r1 = publish(&mut shared, &w1).unwrap();
        let mut hot = [[0u8; 32]; 4]; hot[CKPT_SLOT] = r1;
        assert_eq!(advertised(&hot), Some(r1));
        assert_eq!(advertised(&[[0u8; 32]; 4]), None);
        let got = apply(&mut b.led, &[r1, r1, [0u8; 32]], &ctx, slab_fetch(&mut shared));
        assert_eq!(got.len(), 1, "duplicates and empty slots are skipped");
        assert!(matches!(got[0], Gossiped::Applied(Observed::Recorded(_))), "{:?}", got[0]);
        // same advert again → duplicate
        let got = apply(&mut b.led, &[r1], &ctx, slab_fetch(&mut shared));
        assert_eq!(got[0], Gossiped::Applied(Observed::Duplicate));

        // a grows; its next checkpoint needs a proof, gossip cannot supply one
        a.add(2);
        let r2 = publish(&mut shared, &a.wire()).unwrap();
        let got = apply(&mut b.led, &[r2], &ctx, slab_fetch(&mut shared));
        assert_eq!(got[0], Gossiped::NeedProof { wire_ref: r2 });

        // a ref nobody has replicated yet, and bytes that do not match their ref
        let got = apply(&mut b.led, &[[7u8; 32]], &ctx, |_| None);
        assert_eq!(got[0], Gossiped::Missing { wire_ref: [7u8; 32] });
        let got = apply(&mut b.led, &[r1], &ctx, |_| Some(b"forged".to_vec()));
        assert!(matches!(got[0], Gossiped::Rejected { .. }));
        // genuine hash, but not a checkpoint any authority signed
        let junk = b"not a checkpoint".to_vec();
        let jr = *blake3::hash(&junk).as_bytes();
        let got = apply(&mut b.led, &[jr], &ctx, |_| Some(junk.clone()));
        assert!(matches!(got[0], Gossiped::Rejected { .. }), "{:?}", got[0]);
    }

}

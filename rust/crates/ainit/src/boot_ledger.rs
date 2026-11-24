//! Boot ledger entry — the first link of a node's audit chain.
//!
//! Once a BOOT_OFFER has been fully verified (authority signature, node
//! certificate, key binding) the node records a `boot` event under its own
//! `node_id`.  `auth` is the digest the authority actually signed, so the entry
//! points at the exact capability that admitted this boot.  Everything the node
//! later does can chain off this entry, and the chain is rooted in the same
//! authority trust that admitted the node.

use anyhow::{bail, Context, Result};
use std::path::Path;
use bitcache::entry::{Draft, Entry};
use bitcache::ledger::Ledger;

use crate::boot_offer::{BootOffer, MeshHello};

/// `bitcache:blake3:<64 hex>` → the 32-byte hash.
pub fn parse_blake3_ref(r: &str) -> Option<[u8; 32]> {
    let h = r.strip_prefix("bitcache:blake3:")?;
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Open this node's ledger at boot, adopting the offer's snapshot when there is one.
///
/// * no snapshot ref in the offer → open (or create) normally;
/// * ledger already has state (a reboot) → keep it: the node continues its own chain and
///   never swaps history underneath itself;
/// * empty ledger + snapshot ref → `fetch` the bytes, require their BLAKE3 to equal the
///   (offer-signed) ref, then verify the snapshot against the authority key at the
///   offer's authority position and join from it.  Any failure aborts the boot — the
///   closed-world rule — rather than falling back to an unanchored empty ledger.
pub fn open_for_boot<F>(path: &Path, offer: &BootOffer, authority_vk: Option<&[u8]>, fetch: F) -> Result<Ledger>
where
    F: FnOnce(&str) -> Result<Vec<u8>>,
{
    let ledger = Ledger::open(path).context("opening the boot ledger")?;
    if offer.ledger_snapshot_ref.is_empty() || ledger.size() > 0 {
        return Ok(ledger);
    }
    drop(ledger);
    let want = parse_blake3_ref(&offer.ledger_snapshot_ref)
        .with_context(|| format!("malformed ledger_snapshot_ref {:?}", offer.ledger_snapshot_ref))?;
    let Some(vk) = authority_vk else { bail!("a ledger snapshot needs a real trust anchor to verify against") };
    let bytes = fetch(&offer.ledger_snapshot_ref).context("fetching the ledger snapshot")?;
    if *blake3::hash(&bytes).as_bytes() != want {
        bail!("ledger snapshot does not match its ref");
    }
    Ledger::join(path, &bytes, vk, offer.authority_pos, &[], 0).context("joining from the offer's ledger snapshot")
}

/// Build the `boot` draft for a verified offer.  Call only after `BootOffer::verify`.
pub fn boot_draft(offer: &BootOffer, hello: &MeshHello, ts: u64) -> Draft {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Draft {
        kind: "boot".into(),
        actor: offer.node_id.clone(),
        subject: "boot".into(),
        auth: Some(*BootOffer::compute_digest(hello, offer).as_bytes()),
        ts,
        attrs: vec![
            ("authority_pos".into(), offer.authority_pos.to_string()),
            ("boot_counter".into(), hello.boot_counter.to_string()),
            ("init_profile_ref".into(), offer.init_profile_ref.clone()),
            ("node_fingerprint".into(), hex(&hello.node_fingerprint)),
            ("node_vk_hash".into(), hex(&hello.node_vk_hash)),
            ("rootfs_ref".into(), offer.aminexec_rootfs_ref.clone()),
        ],
    }
}

/// Record the boot in `ledger`; returns `(index, entry)`.
pub fn record_boot(ledger: &mut Ledger, offer: &BootOffer, hello: &MeshHello, ts: u64) -> Result<(u64, Entry)> {
    let (first, mut es) = ledger
        .append_drafts(vec![boot_draft(offer, hello, ts)])
        .context("recording boot in the ledger")?;
    Ok((first, es.remove(0)))
}

/// Fetch a ledger snapshot by its `bitcache:blake3:<hex>` ref from a local
/// bitcache slab — the slab a mesh replica (or an installer) has populated.
/// The bytes are untrusted here: `open_for_boot` re-checks the hash against the
/// signed ref and the snapshot signature against the authority before use.
pub fn slab_fetcher(slab: &Path) -> impl FnOnce(&str) -> Result<Vec<u8>> + '_ {
    move |r: &str| {
        let h = parse_blake3_ref(r).with_context(|| format!("malformed snapshot ref {r:?}"))?;
        let mut s = bitcache::slab::SlabFile::open_or_create(slab)
            .with_context(|| format!("opening snapshot slab {}", slab.display()))?;
        s.get(&bitcache::slab::ObjRef(h)).with_context(|| format!("snapshot {r} is not in {}", slab.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_offer::TrustedAnchor;
    use crate::node_identity::NodeIdentity;
    use bitcache::nodecert::NodeCert;
    use std::path::PathBuf;

    fn verified_offer(counter: u64) -> (BootOffer, MeshHello) {
        let authority = bitcache::Keypair::generate_os("t".into());
        let node = NodeIdentity::generate().unwrap();
        let hello = MeshHello::new([0x22; 32], counter, node.vk_hash());
        let cert = NodeCert {
            node_id: "node-x".into(), node_vk_hash: node.vk_hash(), boot_counter: counter,
            scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: u64::MAX,
        };
        let mut o = BootOffer {
            node_id: "node-x".into(), init_profile_ref: "bitcache:blake3:aa".into(),
            aminexec_rootfs_ref: "bitcache:blake3:bb".into(), slab_dev: PathBuf::from("/dev/null"),
            zcap_token_b64: "z".into(), offer_ts_sec: 1_700_000_000, authority_pos: 5,
            ledger_snapshot_ref: String::new(), node_cert: cert.sign(&authority).unwrap(), offer_signature_bytes: Vec::new(),
        };
        o.sign(&hello, &authority).unwrap();
        o.verify(&hello, &TrustedAnchor::MLDsa87(authority.verifying_key_bytes()), 1_700_000_050).unwrap();
        (o, hello)
    }

    #[test]
    fn reboots_extend_one_chain_rooted_in_the_offer() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.slab");
        let (o1, h1) = verified_offer(1);
        let (o2, h2) = verified_offer(2);
        let mut l = Ledger::open(&p).unwrap();
        let (_, e1) = record_boot(&mut l, &o1, &h1, 10).unwrap();
        assert_eq!((e1.seq, e1.prev), (1, bitcache::entry::ZERO));
        assert_eq!(e1.auth, *BootOffer::compute_digest(&h1, &o1).as_bytes());
        drop(l);
        let mut l = Ledger::open(&p).unwrap(); // reboot: same ledger
        let (_, e2) = record_boot(&mut l, &o2, &h2, 20).unwrap();
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev, e1.id().unwrap());
        assert!(e2.attrs.iter().any(|(k, v)| k == "boot_counter" && v == "2"));
    }

    // ── joining from the offer's snapshot ─────────────────────────────────────
    use bitcache::checkpoint::{self, Checkpoint};
    use bitcache::entry::Draft;
    use rand::{rngs::StdRng, SeedableRng};

    struct Mesh {
        authority: bitcache::Keypair,
        snap: Vec<u8>,
        ck: Checkpoint,
    }

    /// An existing mesh node "gw" with some history, sealed and signed under the authority.
    fn mesh() -> Mesh {
        let mut r = StdRng::from_seed([61; 32]);
        let authority = bitcache::Keypair::generate(&mut r, "tor".into());
        let key = awp3::sign::CompositeSigningKey::generate(&mut r);
        let cert = NodeCert { node_id: "gw".into(), node_vk_hash: checkpoint::vk_hash(&key.verifying_key().to_bytes()),
            boot_counter: 1, scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: u64::MAX }.sign(&authority).unwrap();
        let d = tempfile::tempdir().unwrap();
        let mut l = Ledger::open(d.path().join("gw.slab")).unwrap();
        for i in 0..50u32 {
            l.append_drafts(vec![Draft { kind: "billing".into(), actor: format!("t{}", i % 4), subject: format!("s{i}"),
                auth: None, ts: 1, attrs: vec![] }]).unwrap();
        }
        l.seal("gw", 2).unwrap();
        let ck = Checkpoint { origin: "gw".into(), size: l.size(), root: l.root() };
        let wire = checkpoint::sign(&ck, &key, &cert, &[]).unwrap();
        Mesh { authority, snap: l.export_snapshot(&wire).unwrap().encode(), ck }
    }

    fn offer_with(m: &Mesh, snap_ref: String, counter: u64) -> (BootOffer, MeshHello) {
        let node = NodeIdentity::generate().unwrap();
        let hello = MeshHello::new([0x33; 32], counter, node.vk_hash());
        let cert = NodeCert { node_id: "new-node".into(), node_vk_hash: node.vk_hash(), boot_counter: counter,
            scope_hash: [0; 32], valid_from_pos: 0, valid_to_pos: u64::MAX };
        let mut o = BootOffer {
            node_id: "new-node".into(), init_profile_ref: "bitcache:blake3:aa".into(),
            aminexec_rootfs_ref: "bitcache:blake3:bb".into(), slab_dev: PathBuf::from("/dev/null"),
            zcap_token_b64: "z".into(), offer_ts_sec: 1_700_000_000, authority_pos: 5, ledger_snapshot_ref: snap_ref,
            node_cert: cert.sign(&m.authority).unwrap(), offer_signature_bytes: Vec::new(),
        };
        o.sign(&hello, &m.authority).unwrap();
        (o, hello)
    }

    fn snap_ref(b: &[u8]) -> String {
        format!("bitcache:blake3:{}", blake3::hash(b).to_hex())
    }

    #[test]
    fn a_new_node_boots_into_the_mesh_ledger_without_its_history() {
        let m = mesh();
        let avk = m.authority.verifying_key_bytes();
        let (offer, hello) = offer_with(&m, snap_ref(&m.snap), 1);
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("n.slab");
        let mut l = open_for_boot(&p, &offer, Some(&avk), |r| { assert_eq!(r, offer.ledger_snapshot_ref); Ok(m.snap.clone()) }).unwrap();
        assert_eq!((l.size(), l.base(), l.root()), (m.ck.size, m.ck.size, m.ck.root));
        assert!(l.entry(0).is_err(), "history is not carried");
        let (idx, boot) = record_boot(&mut l, &offer, &hello, 10).unwrap();
        assert_eq!(idx, m.ck.size, "the boot event is the next leaf after the mesh's signed state");
        assert_eq!(boot.actor, "new-node");
        // reboot: the existing chain is kept and the snapshot is not fetched again
        drop(l);
        let (offer2, hello2) = offer_with(&m, snap_ref(&m.snap), 2);
        let mut l = open_for_boot(&p, &offer2, Some(&avk), |_| panic!("must not refetch on reboot")).unwrap();
        let (_, b2) = record_boot(&mut l, &offer2, &hello2, 11).unwrap();
        assert_eq!((b2.seq, b2.prev), (2, boot.id().unwrap()));
        // and the signed join checkpoint is still provable from the new head
        let proof = l.consistency_proof(m.ck.size, l.size()).unwrap();
        assert!(bitcache::tlog::verify_consistency(m.ck.size, &m.ck.root, l.size(), &l.root(), &proof));
    }

    #[test]
    fn a_node_joins_from_a_snapshot_held_in_a_local_slab_and_refuses_a_missing_one() {
        let m = mesh();
        let avk = m.authority.verifying_key_bytes();
        let d = tempfile::tempdir().unwrap();
        let sp = d.path().join("snaps.slab");
        let r = {
            let mut s = bitcache::slab::SlabFile::open_or_create(&sp).unwrap();
            s.put(&m.snap).unwrap();
            format!("bitcache:blake3:{}", blake3::hash(&m.snap).to_hex())
        };
        let (offer, _) = offer_with(&m, r, 1);
        let l = open_for_boot(&d.path().join("n.slab"), &offer, Some(&avk), slab_fetcher(&sp)).unwrap();
        assert_eq!((l.size(), l.base()), (m.ck.size, m.ck.size));
        drop(l);
        // a ref the slab doesn't hold aborts the join
        let (offer2, _) = offer_with(&m, format!("bitcache:blake3:{}", "ab".repeat(32)), 2);
        assert!(open_for_boot(&d.path().join("n2.slab"), &offer2, Some(&avk), slab_fetcher(&sp)).is_err());
    }

    #[test]
    fn a_bad_snapshot_aborts_the_boot_instead_of_starting_unanchored() {
        let m = mesh();
        let avk = m.authority.verifying_key_bytes();
        let try_boot = |offer: &BootOffer, vk: Option<&[u8]>, bytes: Vec<u8>| {
            let d = tempfile::tempdir().unwrap();
            open_for_boot(&d.path().join("n.slab"), offer, vk, |_| Ok(bytes)).map(|l| l.size())
        };
        let (good, _) = offer_with(&m, snap_ref(&m.snap), 1);
        assert!(try_boot(&good, Some(&avk), m.snap.clone()).is_ok());
        // content does not match the signed ref
        let mut t = m.snap.clone();
        let n = t.len();
        t[n / 2] ^= 1;
        assert!(try_boot(&good, Some(&avk), t.clone()).is_err());
        // right ref for tampered bytes still fails: the snapshot's own signature chain catches it
        let (forged_ref, _) = offer_with(&m, snap_ref(&t), 1);
        assert!(try_boot(&forged_ref, Some(&avk), t).is_err());
        // wrong authority, no anchor, malformed ref, failing fetch
        let other = bitcache::Keypair::generate(&mut StdRng::from_seed([62; 32]), "x".into());
        assert!(try_boot(&good, Some(&other.verifying_key_bytes()), m.snap.clone()).is_err());
        assert!(try_boot(&good, None, m.snap.clone()).is_err());
        let (bad_ref, _) = offer_with(&m, "bitcache:blake3:zz".into(), 1);
        assert!(try_boot(&bad_ref, Some(&avk), m.snap.clone()).is_err());
        let d = tempfile::tempdir().unwrap();
        assert!(open_for_boot(&d.path().join("n.slab"), &good, Some(&avk), |_| bail!("offline")).is_err());
        // the ref is covered by the offer signature
        let mut swapped = good.clone();
        swapped.ledger_snapshot_ref = snap_ref(b"something else");
        assert_ne!(BootOffer::compute_digest(&offer_with(&m, snap_ref(&m.snap), 1).1, &good),
                   BootOffer::compute_digest(&offer_with(&m, snap_ref(&m.snap), 1).1, &swapped));
    }
}

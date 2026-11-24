//! Golden trust vectors — shared byte-for-byte with the Perl suite.
//!
//! `t/data/trust-golden-v1.tsv` is the contract between the two languages:
//! this test drives every vector through the **C ABI** (`bitcache::ffi`), the
//! same entry points `Amin::Crypto::Verify` binds, and `t/73-trust-golden.t`
//! drives the same file through Perl.  Both must reach the same verdict for
//! every row, so any drift between the languages fails a test on one side.
//!
//! Regenerate (deterministic: seeded keys, deterministic ML-DSA-87 signing):
//!   AMIN_REGEN_GOLDEN=1 cargo test -p bitcache --test golden

use bitcache::ffi::*;
use bitcache::checkpoint::{self, Checkpoint};
use bitcache::nodecert::NodeCert;
use bitcache::tlog::{self, Tree};
use awp3::sign::CompositeSigningKey;
use bitcache::{base64_decode, base64_encode, mldsa87_sign, zcap_token_bytes, Keypair, ZcapGrant};
use rand::{rngs::StdRng, SeedableRng};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../t/data/trust-golden-v1.tsv");

fn kp(seed: u8, name: &str) -> Keypair {
    Keypair::generate(&mut StdRng::from_seed([seed; 32]), name.into())
}
fn b64(b: &[u8]) -> String { base64_encode(b) }
fn flip(b: &[u8], i: usize) -> Vec<u8> { let mut v = b.to_vec(); v[i] ^= 1; v }

fn generate() -> String {
    let mut rows: Vec<String> = vec![
        "# kind\tname\texpect\tfields…   (base64 fields; see t/73-trust-golden.t and bitcache/tests/golden.rs)".into(),
        "# expect: 0 accepted | -1 format | -2 unknown_kid | -3 bad_sig | -4 not_valid_at | -5 quorum | -9 bad_arg".into(),
    ];
    let auth = kp(1, "authority");
    let other = kp(2, "other");
    let avk = auth.verifying_key_bytes();
    let ovk = other.verifying_key_bytes();

    // ── mldsa87 ────────────────────────────────────────────────────────────
    let msg = b"amin golden message";
    let sig = mldsa87_sign(&auth, msg).unwrap();
    let m = |name: &str, exp: i32, vk: &[u8], sg: &[u8], ms: &[u8]| {
        format!("mldsa87\t{name}\t{exp}\t{}\t{}\t{}", b64(vk), b64(sg), b64(ms))
    };
    rows.push(m("valid", 0, &avk, &sig, msg));
    rows.push(m("wrong-key", -3, &ovk, &sig, msg));
    rows.push(m("flipped-sig", -3, &avk, &flip(&sig, 17), msg));
    rows.push(m("other-message", -3, &avk, &sig, b"amin golden messagf"));
    rows.push(m("short-sig", -3, &avk, &sig[..100], msg));
    rows.push(m("short-vk", -3, &avk[..100], &sig, msg));

    // ── zcap ───────────────────────────────────────────────────────────────
    let grant = ZcapGrant {
        tiers: vec!["metal-32c".into(), "shared".into()], zones: vec!["us-east-1".into()],
        netpolicies: vec!["vpc-a".into(), "vpc-b".into()], max_redundancy: 3, vpc_quota: 4,
        memory_tier: 1, tenant_id: "t-tenant-0123456789abc".into(), ts: 1_735_689_600,
    };
    let tok = zcap_token_bytes(&auth, &grant).unwrap();
    let z = |name: &str, exp: i32, t: &[u8], anchors: &[&[u8]]| {
        let a: Vec<String> = anchors.iter().map(|x| b64(x)).collect();
        format!("zcap\t{name}\t{exp}\t{}\t{}", b64(t), a.join(","))
    };
    let tenant_off = 4627 + 2592 + 32 + 8 + 2 + 2 + 2 + 1 + 4 + 1 + 2;
    rows.push(z("valid", 0, &tok, &[&avk]));
    rows.push(z("valid-among-several-anchors", 0, &tok, &[&ovk, &avk]));
    rows.push(z("no-anchors", -2, &tok, &[]));
    rows.push(z("foreign-anchor", -2, &tok, &[&ovk]));
    rows.push(z("flipped-sig", -3, &flip(&tok, 300), &[&avk]));
    rows.push(z("tampered-tenant", -3, &flip(&tok, tenant_off), &[&avk]));
    let mut bad_utf8 = tok.clone();
    bad_utf8[tenant_off] = 0xFF;
    rows.push(z("invalid-utf8-tenant", -1, &bad_utf8, &[&avk]));
    rows.push(z("truncated", -1, &tok[..200], &[&avk]));
    rows.push(z("empty", -1, &[], &[&avk]));
    // placeholder token of the legacy "structural" mode: zero VK, 0xAA signature
    let mut structural = vec![0xAAu8; 4627];
    structural.extend_from_slice(&[0u8; 2592]);
    structural.extend_from_slice(&tok[4627 + 2592..]);
    rows.push(z("structural-placeholder", -2, &structural, &[&avk]));
    rows.push(z("structural-placeholder-zero-anchor", -3, &structural, &[&[0u8; 2592]]));

    // ── instrument ─────────────────────────────────────────────────────────
    let imsg = bitcache::trust::instrument_message("buyer-co", "seller-co", "1500.00", "draft", 41);
    let isig = mldsa87_sign(&auth, &imsg).unwrap();
    let i = |name: &str, exp: i32, mk: &str, py: &str, am: &str, kd: &str, sq: u64, vk: &[u8], sg: &[u8]| {
        format!("instrument\t{name}\t{exp}\t{mk}\t{py}\t{am}\t{kd}\t{sq}\t{}\t{}", b64(vk), b64(sg))
    };
    rows.push(i("valid", 0, "buyer-co", "seller-co", "1500.00", "draft", 41, &avk, &isig));
    rows.push(i("amount-tampered", -3, "buyer-co", "seller-co", "15000.00", "draft", 41, &avk, &isig));
    rows.push(i("payee-tampered", -3, "buyer-co", "mallory", "1500.00", "draft", 41, &avk, &isig));
    rows.push(i("kind-tampered", -3, "buyer-co", "seller-co", "1500.00", "check", 41, &avk, &isig));
    rows.push(i("wrong-key", -3, "buyer-co", "seller-co", "1500.00", "draft", 41, &ovk, &isig));
    rows.push(i("short-sig", -1, "buyer-co", "seller-co", "1500.00", "draft", 41, &avk, &isig[..50]));
    rows.push(i("seq-tampered", -3, "buyer-co", "seller-co", "1500.00", "draft", 42, &avk, &isig));

    // ── nodecert ───────────────────────────────────────────────────────────
    let cert = NodeCert {
        node_id: "metal-blake3-abababab".into(), node_vk_hash: *blake3::hash(b"node-key").as_bytes(),
        boot_counter: 12, scope_hash: [3; 32], valid_from_pos: 100, valid_to_pos: 200,
    };
    let cb = cert.sign(&auth).unwrap();
    let n = |name: &str, exp: i32, c: &[u8], vk: &[u8], pos: u64| {
        format!("nodecert\t{name}\t{exp}\t{}\t{}\t{pos}\t{}\t{}", b64(c), b64(vk),
                hex(&cert.node_vk_hash), cert.boot_counter)
    };
    rows.push(n("valid", 0, &cb, &avk, 150));
    rows.push(n("valid-at-lower-bound", 0, &cb, &avk, 100));
    rows.push(n("valid-at-upper-bound", 0, &cb, &avk, 200));
    rows.push(n("expired", -4, &cb, &avk, 201));
    rows.push(n("not-yet-valid", -4, &cb, &avk, 99));
    rows.push(n("wrong-authority", -3, &cb, &ovk, 150));
    rows.push(n("flipped-body", -3, &flip(&cb, 40), &avk, 150));
    rows.push(n("truncated", -1, &cb[..40], &avk, 150));

    // ── transparency log: inclusion / consistency ──────────────────────────
    let mut tree = Tree::new();
    for i in 0..13u8 { tree.append(format!("golden-entry-{i}").as_bytes()); }
    let hs = |v: &[tlog::Hash]| v.iter().map(|h| b64(h)).collect::<Vec<_>>().join(",");
    let inc = |name: &str, exp: i32, leaf: &tlog::Hash, idx: u64, size: u64, path: &[tlog::Hash], root: &tlog::Hash| {
        format!("tlog-incl\t{name}\t{exp}\t{}\t{idx}\t{size}\t{}\t{}", b64(leaf), hs(path), b64(root))
    };
    let r13 = tree.root();
    for idx in [0u64, 6, 12] {
        let p = tree.inclusion_proof(idx, 13).unwrap();
        rows.push(inc(&format!("valid-{idx}"), 0, &tree.leaf(idx).unwrap(), idx, 13, &p, &r13));
    }
    let p5 = tree.inclusion_proof(5, 13).unwrap();
    rows.push(inc("wrong-index", -3, &tree.leaf(5).unwrap(), 4, 13, &p5, &r13));
    rows.push(inc("wrong-leaf", -3, &tlog::leaf_hash(b"nope"), 5, 13, &p5, &r13));
    rows.push(inc("wrong-root", -3, &tree.leaf(5).unwrap(), 5, 13, &p5, &tree.root_at(12).unwrap()));
    rows.push(inc("short-path", -3, &tree.leaf(5).unwrap(), 5, 13, &p5[1..], &r13));
    rows.push(inc("index-out-of-range", -3, &tree.leaf(5).unwrap(), 13, 13, &p5, &r13));
    let con = |name: &str, exp: i32, a: u64, ar: &tlog::Hash, b: u64, br: &tlog::Hash, p: &[tlog::Hash]| {
        format!("tlog-cons\t{name}\t{exp}\t{a}\t{}\t{b}\t{}\t{}", b64(ar), b64(br), hs(p))
    };
    for (a, b) in [(1u64, 13u64), (4, 13), (7, 13), (13, 13), (0, 13)] {
        let p = tree.consistency_proof(a, b).unwrap();
        rows.push(con(&format!("valid-{a}-{b}"), 0, a, &tree.root_at(a).unwrap(), b, &tree.root_at(b).unwrap(), &p));
    }
    let pc = tree.consistency_proof(7, 13).unwrap();
    rows.push(con("forked-first-root", -3, 7, &tlog::leaf_hash(b"fork"), 13, &r13, &pc));
    rows.push(con("forked-second-root", -3, 7, &tree.root_at(7).unwrap(), 13, &tlog::leaf_hash(b"fork"), &pc));
    rows.push(con("shrinking", -3, 13, &r13, 7, &tree.root_at(7).unwrap(), &[]));

    // ── signed checkpoints (composite node key + ML-DSA-87 witnesses) ───────
    let node = CompositeSigningKey::from_seeds(&[11; 32], &[12; 32]);
    let ncert = NodeCert {
        node_id: "node-golden".into(),
        node_vk_hash: checkpoint::vk_hash(&node.verifying_key().to_bytes()),
        boot_counter: 3, scope_hash: [0; 32], valid_from_pos: 50, valid_to_pos: 60,
    }.sign(&auth).unwrap();
    let ck = Checkpoint { origin: "node-golden".into(), size: 13, root: r13 };
    let (w1, w2, w3) = (kp(21, "w1"), kp(22, "w2"), kp(23, "w3"));
    let (v1, v2, v3) = (w1.verifying_key_bytes(), w2.verifying_key_bytes(), w3.verifying_key_bytes());
    let cs1 = checkpoint::cosign(&ck, &w1).unwrap();
    let cs2 = checkpoint::cosign(&ck, &w2).unwrap();
    let plain = checkpoint::sign(&ck, &node, &ncert, &[]).unwrap();
    let two = checkpoint::sign(&ck, &node, &ncert, &[cs1.clone(), cs2.clone()]).unwrap();
    let dup = checkpoint::sign(&ck, &node, &ncert, &[cs1.clone(), cs1.clone()]).unwrap();
    let other_origin = checkpoint::sign(&Checkpoint { origin: "node-evil".into(), ..ck.clone() }, &node, &ncert, &[]).unwrap();
    let rogue = CompositeSigningKey::from_seeds(&[13; 32], &[14; 32]);
    let rogue_w = checkpoint::sign(&ck, &rogue, &ncert, &[]).unwrap();
    let c = |name: &str, exp: i32, wire: &[u8], avk: &[u8], pos: u64, roster: &[&[u8]], q: usize| {
        let r: Vec<String> = roster.iter().map(|x| b64(x)).collect();
        format!("ckpt\t{name}\t{exp}\t{}\t{}\t{pos}\t{}\t{q}\t{}\t{}\t{}",
                b64(wire), b64(avk), r.join(","), ck.size, hex(&ck.root), ck.origin)
    };
    let roster: [&[u8]; 3] = [&v1, &v2, &v3];
    rows.push(c("valid", 0, &plain, &avk, 55, &[], 0));
    rows.push(c("valid-2-of-3", 0, &two, &avk, 55, &roster, 2));
    rows.push(c("quorum-short", -5, &two, &avk, 55, &roster, 3));
    rows.push(c("quorum-duplicate-cosigner", -5, &dup, &avk, 55, &roster, 2));
    rows.push(c("quorum-without-cosigs", -5, &plain, &avk, 55, &roster, 1));
    rows.push(c("expired-cert", -4, &plain, &avk, 61, &[], 0));
    rows.push(c("not-yet-valid-cert", -4, &plain, &avk, 49, &[], 0));
    rows.push(c("wrong-authority", -3, &plain, &ovk, 55, &[], 0));
    rows.push(c("origin-not-cert-node", -2, &other_origin, &avk, 55, &[], 0));
    rows.push(c("node-key-not-in-cert", -2, &rogue_w, &avk, 55, &[], 0));
    let root_off = 19 + 4 + ck.origin.len() + 8;
    rows.push(c("tampered-root", -3, &flip(&plain, root_off), &avk, 55, &[], 0));
    let sig_off = 19 + 4 + ck.origin.len() + 8 + 32 + 1984 + 40;
    rows.push(c("flipped-node-sig", -3, &flip(&plain, sig_off), &avk, 55, &[], 0));
    let mut trailing = plain.clone();
    trailing.push(0);
    rows.push(c("trailing-byte", -1, &trailing, &avk, 55, &[], 0));
    rows.push(c("truncated", -1, &plain[..100], &avk, 55, &[], 0));
    // slim (cert-less) checkpoints are only for a verifier holding a cert cache; the C ABI has none
    rows.push(c("slim-without-cache", -2, &checkpoint::slim(&plain).unwrap(), &avk, 55, &[], 0));

    // ── join snapshots ──────────────────────────────────────────────────────
    {
        use bitcache::entry::Draft;
        use bitcache::ledger::Ledger;
        use bitcache::snapshot::Snapshot;
        let dir = tempfile::tempdir().unwrap();
        let mut led = Ledger::open(dir.path().join("g.slab")).unwrap();
        for i in 0..21u32 {
            led.append_drafts(vec![Draft { kind: "billing".into(), actor: format!("tenant-{}", i % 3),
                subject: format!("pid:{i}"), auth: None, ts: 1, attrs: vec![("cpu_ms".into(), (i * 7).to_string())] }]).unwrap();
        }
        led.seal("node-golden", 2).unwrap();
        let sck = Checkpoint { origin: "node-golden".into(), size: led.size(), root: led.root() };
        let swire = checkpoint::sign(&sck, &node, &ncert, &[]).unwrap();
        let snap = led.export_snapshot(&swire).unwrap();
        let enc = snap.encode();
        let sn = |name: &str, exp: i32, bytes: &[u8], vk: &[u8], pos: u64, q: usize| {
            format!("snapshot\t{name}\t{exp}\t{}\t{}\t{pos}\t\t{q}\t{}\t{}\t{}", b64(bytes), b64(vk),
                    sck.size, hex(&sck.root), sck.origin)
        };
        rows.push(sn("valid", 0, &enc, &avk, 55, 0));
        rows.push(sn("expired-cert", -4, &enc, &avk, 61, 0));
        rows.push(sn("wrong-authority", -3, &enc, &ovk, 55, 0));
        rows.push(sn("quorum-short", -5, &enc, &avk, 55, 1));
        let mut s1 = snap.clone(); s1.frontier[0][0] ^= 1;
        rows.push(sn("frontier-tampered", -3, &s1.encode(), &avk, 55, 0));
        let mut s2: Snapshot = snap.clone(); s2.heads[0].1 += 1;
        rows.push(sn("head-tampered", -3, &s2.encode(), &avk, 55, 0));
        let mut s3 = snap.clone(); s3.proof[0][0] ^= 1;
        rows.push(sn("state-proof-tampered", -3, &s3.encode(), &avk, 55, 0));
        let mut s4 = snap.clone(); s4.accepted.push(("evil".into(), "x".into(), 0, vec![1]));
        rows.push(sn("accepted-state-tampered", -3, &s4.encode(), &avk, 55, 0));
        rows.push(sn("truncated", -1, &enc[..enc.len() - 5], &avk, 55, 0));
        let mut t = enc.clone(); t.push(0);
        rows.push(sn("trailing-byte", -1, &t, &avk, 55, 0));
    }

    // ── offline receipts ────────────────────────────────────────────────────
    {
        use bitcache::entry::Draft;
        use bitcache::ledger::Ledger;
        use bitcache::receipt::Receipt;
        let dir = tempfile::tempdir().unwrap();
        let mut led = Ledger::open(dir.path().join("r.slab")).unwrap();
        let mk = |kind: &str, subject: &str, n: u32| Draft { kind: kind.into(), actor: "alice".into(), subject: subject.into(),
            auth: None, ts: 3, attrs: vec![("amount".into(), n.to_string()), ("currency".into(), "NZD".into())] };
        for i in 0..5 { led.append_drafts(vec![mk("balance.open", &format!("n{i}"), 100 + i)]).unwrap(); }
        let (out_idx, _) = led.append_drafts(vec![mk("transfer.out", "bob", 5)]).unwrap();
        let rck = Checkpoint { origin: "node-golden".into(), size: led.size(), root: led.root() };
        let rwire = checkpoint::sign(&rck, &node, &ncert, &[]).unwrap();
        let rc = led.make_receipt(out_idx, &rwire).unwrap();
        let renc = rc.encode();
        let id = bitcache::entry::id_of(&rc.entry);
        let rr = |name: &str, exp: i32, bytes: &[u8], auths: &[&[u8]], pos: u64| {
            let a: Vec<String> = auths.iter().map(|x| b64(x)).collect();
            format!("receipt\t{name}\t{exp}\t{}\t{}\t{pos}\t{}\t{}\t{}\t{}", b64(bytes), a.join(","),
                    rck.size, hex(&rck.root), rck.origin, hex(&id))
        };
        rows.push(rr("valid", 0, &renc, &[&avk], 55));
        rows.push(rr("valid-second-authority", 0, &renc, &[&ovk, &avk], 55));
        rows.push(rr("unknown-authority", -3, &renc, &[&ovk], 55));
        rows.push(rr("expired-cert", -4, &renc, &[&avk], 61));
        let ent_last = 17 + 4 + rc.entry.len() - 1;
        rows.push(rr("entry-tampered", -3, &flip(&renc, ent_last), &[&avk], 55));
        let mut wrong_idx = Receipt::decode(&renc).unwrap(); wrong_idx.index = 0;
        rows.push(rr("wrong-index", -3, &wrong_idx.encode(), &[&avk], 55));
        let mut bad_proof = Receipt::decode(&renc).unwrap(); bad_proof.proof[0][0] ^= 1;
        rows.push(rr("proof-tampered", -3, &bad_proof.encode(), &[&avk], 55));
        rows.push(rr("slim-without-cache", -2, &rc.slim().unwrap().encode(), &[&avk], 55));
        rows.push(rr("truncated", -1, &renc[..renc.len() - 4], &[&avk], 55));
        let mut t = renc.clone(); t.push(0);
        rows.push(rr("trailing-byte", -1, &t, &[&avk], 55));
    }

    // ── IoT leaf receipts ───────────────────────────────────────────────────
    {
        use bitcache::entry::Draft;
        use bitcache::iot::{leaf_key, Gateway, LeafReceipt, Report};
        use bitcache::ledger::Ledger;
        let dir = tempfile::tempdir().unwrap();
        let mut led = Ledger::open(dir.path().join("i.slab")).unwrap();
        let mut gw = Gateway::new([9; 32], "node-golden", 64);
        for ctr in 1..=3u64 {
            for leaf in ["leaf-a", "leaf-b", "leaf-c", "leaf-d", "leaf-e"] {
                let k = leaf_key(&[9; 32], leaf);
                gw.ingest(&Report::new(&k, leaf, ctr, &[ctr as u8; 4]).unwrap().encode()).unwrap();
            }
        }
        let batch = gw.flush(5).unwrap();
        led.append_drafts(vec![Draft { kind: "billing".into(), actor: "tenant-x".into(), subject: "s".into(), auth: None, ts: 1, attrs: vec![] }]).unwrap();
        let (bidx, _) = led.append_drafts(vec![batch.draft.clone()]).unwrap();
        let ick = Checkpoint { origin: "node-golden".into(), size: led.size(), root: led.root() };
        let iwire = checkpoint::sign(&ick, &node, &ncert, &[]).unwrap();
        let lr = batch.leaf_receipt(7, led.make_receipt(bidx, &iwire).unwrap()).unwrap();
        let enc = lr.encode();
        let bid = led.make_receipt(bidx, &iwire).unwrap();
        let eid = bitcache::entry::id_of(&bid.entry);
        let lh = bitcache::tlog::leaf_hash(&lr.report);
        let il = |name: &str, exp: i32, bytes: &[u8], auths: &[&[u8]], pos: u64| {
            let a: Vec<String> = auths.iter().map(|x| b64(x)).collect();
            format!("iotleaf\t{name}\t{exp}\t{}\t{}\t{pos}\t{}\t{}\t{}\t{}\t{}", b64(bytes), a.join(","),
                    ick.size, hex(&ick.root), ick.origin, hex(&eid), hex(&lh))
        };
        rows.push(il("valid", 0, &enc, &[&avk], 55));
        rows.push(il("unknown-authority", -3, &enc, &[&ovk], 55));
        rows.push(il("expired-cert", -4, &enc, &[&avk], 61));
        let mut r1 = LeafReceipt::decode(&enc).unwrap(); r1.report[3] ^= 1;
        rows.push(il("report-tampered", -3, &r1.encode(), &[&avk], 55));
        let mut r2 = LeafReceipt::decode(&enc).unwrap(); r2.index += 1;
        rows.push(il("wrong-batch-index", -3, &r2.encode(), &[&avk], 55));
        let mut r3 = LeafReceipt::decode(&enc).unwrap(); r3.proof[0][0] ^= 1;
        rows.push(il("batch-proof-tampered", -3, &r3.encode(), &[&avk], 55));
        let mut r4 = LeafReceipt::decode(&enc).unwrap(); r4.receipt = led.make_receipt(0, &iwire).unwrap();
        rows.push(il("not-a-batch-entry", -1, &r4.encode(), &[&avk], 55));
        rows.push(il("slim-without-cache", -2, &lr.slim().unwrap().encode(), &[&avk], 55));
        rows.push(il("truncated", -1, &enc[..enc.len() - 4], &[&avk], 55));
        let mut t = enc.clone(); t.push(0);
        rows.push(il("trailing-byte", -1, &t, &[&avk], 55));
    }

    // ── IoT reports (leaf key derivation + tag) ─────────────────────────────
    {
        use bitcache::iot::{leaf_key, Report};
        let master = [9u8; 32];
        let key = leaf_key(&master, "leaf-a");
        let wire = Report::new(&key, "leaf-a", 42, &[1, 2, 3, 4]).unwrap().encode();
        rows.push(format!("iotkey\tderive\t0\t{}\tleaf-a\t{}", b64(&master), b64(&key)));
        rows.push(format!("iotkey\tderive-other-leaf\t0\t{}\tleaf-b\t{}", b64(&master), b64(&leaf_key(&master, "leaf-b"))));
        let rr = |name: &str, exp: i32, k: &[u8], w: &[u8]| {
            format!("iotreport\t{name}\t{exp}\t{}\t{}\tleaf-a\t42\t{}", b64(k), b64(w), b64(&[1, 2, 3, 4]))
        };
        rows.push(rr("valid", 0, &key, &wire));
        rows.push(rr("wrong-leaf-key", -3, &leaf_key(&master, "leaf-b"), &wire));
        rows.push(rr("tag-flipped", -3, &key, &flip(&wire, wire.len() - 1)));
        rows.push(rr("payload-flipped", -3, &key, &flip(&wire, 14)));
        rows.push(rr("counter-flipped", -3, &key, &flip(&wire, 8)));
        rows.push(rr("bad-version", -1, &key, &flip(&wire, 0)));
        rows.push(rr("truncated", -1, &key, &wire[..wire.len() - 1]));
        let mut t = wire.clone(); t.push(0);
        rows.push(rr("trailing-byte", -1, &key, &t));
        rows.push(rr("empty-leaf-name", -1, &key, &[1, 0]));
    }
    rows.join("\n") + "\n"
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn dec(s: &str) -> Vec<u8> { if s.is_empty() { vec![] } else { base64_decode(s).unwrap() } }

#[test]
fn vectors_match_the_c_abi() {
    if std::env::var_os("AMIN_REGEN_GOLDEN").is_some() {
        std::fs::write(PATH, generate()).unwrap();
    }
    let text = std::fs::read_to_string(PATH).expect("golden vectors (run with AMIN_REGEN_GOLDEN=1 once)");
    assert_eq!(text, generate(), "golden file is stale: regenerate with AMIN_REGEN_GOLDEN=1");
    let mut n = 0;
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        let (kind, name, want) = (f[0], f[1], f[2].parse::<i32>().unwrap());
        let got = unsafe {
            match kind {
                "mldsa87" => {
                    let (vk, sg, ms) = (dec(f[3]), dec(f[4]), dec(f[5]));
                    // the ABI answers 0 / -3 (and -9 for unusable pointers)
                    bitcache_mldsa87_verify(vk.as_ptr(), vk.len(), sg.as_ptr(), sg.len(), ms.as_ptr(), ms.len())
                }
                "zcap" => {
                    let t = dec(f[3]);
                    let anchors: Vec<Vec<u8>> = f[4].split(',').filter(|x| !x.is_empty()).map(dec).collect();
                    let packed: Vec<u8> = anchors.concat();
                    bitcache_zcap_verify(t.as_ptr(), t.len(), packed.as_ptr(), anchors.len())
                }
                "instrument" => {
                    let (vk, sg) = (dec(f[8]), dec(f[9]));
                    let sq: u64 = f[7].parse().unwrap();
                    bitcache_instrument_verify(
                        f[3].as_ptr(), f[3].len(), f[4].as_ptr(), f[4].len(), f[5].as_ptr(), f[5].len(),
                        f[6].as_ptr(), f[6].len(), sq, vk.as_ptr(), vk.len(), sg.as_ptr(), sg.len())
                }
                "nodecert" => {
                    let (c, vk) = (dec(f[3]), dec(f[4]));
                    let pos: u64 = f[5].parse().unwrap();
                    let mut h = [0u8; 32];
                    let mut bc = 0u64;
                    let rc = bitcache_nodecert_verify(c.as_ptr(), c.len(), vk.as_ptr(), vk.len(), pos, h.as_mut_ptr(), &mut bc);
                    if rc == 0 {
                        assert_eq!(hex(&h), f[6], "{name}: certified key hash");
                        assert_eq!(bc.to_string(), f[7], "{name}: boot counter");
                    }
                    rc
                }
                "tlog-incl" => {
                    let (leaf, root) = (dec(f[3]), dec(f[7]));
                    let path: Vec<u8> = f[6].split(',').filter(|x| !x.is_empty()).flat_map(dec).collect();
                    let np = path.len() / 32;
                    bitcache_tlog_verify_inclusion(leaf.as_ptr(), f[4].parse().unwrap(), f[5].parse().unwrap(),
                        path.as_ptr(), np, root.as_ptr())
                }
                "tlog-cons" => {
                    let (ar, br) = (dec(f[4]), dec(f[6]));
                    let p: Vec<u8> = f[7].split(',').filter(|x| !x.is_empty()).flat_map(dec).collect();
                    bitcache_tlog_verify_consistency(f[3].parse().unwrap(), ar.as_ptr(), f[5].parse().unwrap(),
                        br.as_ptr(), p.as_ptr(), p.len() / 32)
                }
                "ckpt" => {
                    let (w, avk) = (dec(f[3]), dec(f[4]));
                    let roster: Vec<u8> = f[6].split(',').filter(|x| !x.is_empty()).flat_map(dec).collect();
                    let (mut size, mut root, mut org, mut olen) = (0u64, [0u8; 32], [0u8; 256], 0u32);
                    let rc = bitcache_ckpt_verify(w.as_ptr(), w.len(), avk.as_ptr(), avk.len(), f[5].parse().unwrap(),
                        roster.as_ptr(), roster.len() / 2592, f[7].parse().unwrap(),
                        &mut size, root.as_mut_ptr(), org.as_mut_ptr(), &mut olen);
                    if rc == 0 {
                        assert_eq!(size.to_string(), f[8], "{name}: size");
                        assert_eq!(hex(&root), f[9], "{name}: root");
                        assert_eq!(std::str::from_utf8(&org[..olen as usize]).unwrap(), f[10], "{name}: origin");
                    }
                    rc
                }
                "snapshot" => {
                    let (w, avk) = (dec(f[3]), dec(f[4]));
                    let (mut size, mut root, mut org, mut olen) = (0u64, [0u8; 32], [0u8; 256], 0u32);
                    let rc = bitcache_snapshot_verify(w.as_ptr(), w.len(), avk.as_ptr(), avk.len(), f[5].parse().unwrap(),
                        std::ptr::null(), 0, f[7].parse().unwrap(),
                        &mut size, root.as_mut_ptr(), org.as_mut_ptr(), &mut olen);
                    if rc == 0 {
                        assert_eq!(size.to_string(), f[8], "{name}: size");
                        assert_eq!(hex(&root), f[9], "{name}: root");
                        assert_eq!(std::str::from_utf8(&org[..olen as usize]).unwrap(), f[10], "{name}: origin");
                    }
                    rc
                }
                "receipt" => {
                    let w = dec(f[3]);
                    let auths: Vec<u8> = f[4].split(',').filter(|x| !x.is_empty()).flat_map(dec).collect();
                    let (mut size, mut root, mut org, mut olen, mut id) = (0u64, [0u8; 32], [0u8; 256], 0u32, [0u8; 32]);
                    let rc = bitcache_receipt_verify(w.as_ptr(), w.len(), auths.as_ptr(), auths.len() / 2592,
                        f[5].parse().unwrap(), std::ptr::null(), 0, 0,
                        &mut size, root.as_mut_ptr(), org.as_mut_ptr(), &mut olen, id.as_mut_ptr());
                    if rc == 0 {
                        assert_eq!(size.to_string(), f[6], "{name}: size");
                        assert_eq!(hex(&root), f[7], "{name}: root");
                        assert_eq!(std::str::from_utf8(&org[..olen as usize]).unwrap(), f[8], "{name}: origin");
                        assert_eq!(hex(&id), f[9], "{name}: entry id");
                    }
                    rc
                }
                "iotkey" => {
                    let (m, leaf, want_key) = (dec(f[3]), f[4], dec(f[5]));
                    let mut k = [0u8; 32];
                    let rc = bitcache_iot_leaf_key(m.as_ptr(), leaf.as_ptr(), leaf.len(), k.as_mut_ptr());
                    if rc == 0 { assert_eq!(&k[..], &want_key[..], "{name}: key"); }
                    rc
                }
                "iotreport" => {
                    let (k, w, leaf, ctr, payload) = (dec(f[3]), dec(f[4]), f[5], f[6].parse::<u64>().unwrap(), dec(f[7]));
                    let mut got = 0u64;
                    let rc = bitcache_iot_report_check(k.as_ptr(), w.as_ptr(), w.len(), &mut got);
                    if rc == 0 {
                        assert_eq!(got, ctr, "{name}: ctr");
                        let (mut out, mut n) = ([0u8; 320], 0usize);
                        let b = bitcache_iot_report_build(k.as_ptr(), leaf.as_ptr(), leaf.len(), ctr, payload.as_ptr(), payload.len(),
                            out.as_mut_ptr(), out.len(), &mut n);
                        assert_eq!(b, 0);
                        assert_eq!(&out[..n], &w[..], "{name}: build reproduces the wire bytes");
                    }
                    rc
                }
                "iotleaf" => {
                    let w = dec(f[3]);
                    let auths: Vec<u8> = f[4].split(',').filter(|x| !x.is_empty()).flat_map(dec).collect();
                    let (mut size, mut root, mut org, mut olen, mut id, mut leaf) = (0u64, [0u8; 32], [0u8; 256], 0u32, [0u8; 32], [0u8; 32]);
                    let rc = bitcache_iot_leaf_verify(w.as_ptr(), w.len(), auths.as_ptr(), auths.len() / 2592,
                        f[5].parse().unwrap(), std::ptr::null(), 0, 0,
                        &mut size, root.as_mut_ptr(), org.as_mut_ptr(), &mut olen, id.as_mut_ptr(), leaf.as_mut_ptr());
                    if rc == 0 {
                        assert_eq!(size.to_string(), f[6], "{name}: size");
                        assert_eq!(hex(&root), f[7], "{name}: root");
                        assert_eq!(std::str::from_utf8(&org[..olen as usize]).unwrap(), f[8], "{name}: origin");
                        assert_eq!(hex(&id), f[9], "{name}: entry id");
                        assert_eq!(hex(&leaf), f[10], "{name}: report leaf hash");
                    }
                    rc
                }
                other => panic!("unknown vector kind {other}"),
            }
        };
        // an mldsa87 length mismatch is a plain "not valid" at this layer
        assert_eq!(got, want, "{kind}/{name}");
        n += 1;
    }
    assert!(n >= 99, "expected the full vector set, ran {n}");
}

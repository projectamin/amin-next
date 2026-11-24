//! bctool — CLI bridge between Perl `Amin::Storage::Bitcache` filter and the
//! Rust slab/crypto layer.  IPC via simple TSV stdout (easy `split /\t/` in
//! Perl).  This design avoids FFI / libloading in Phase 1 (landlock'd metal
//! mode disallows `dlopen()` anyway; the PID 1 landlock profile will grant
//! `aminexec` `FILE__EXECUTE` on `/srv/amin/bin/bctool` only).
//!
//! Commands:
//!   bctool put    --slab PATH                  # read stdin → put → `hash\tHEX32\nsize\t...`
//!   bctool get    --slab PATH --hash HEX32      # print raw object bytes on stdout
//!   bctool genkey --name N --sk PATH            # write ML-DSA-87 SK to PATH (chmod 0600)
//!   bctool sign   --slab PATH --hash HEX32 --name N --sk PATH
//!   bctool verify --slab PATH --hash HEX32 --name N --ts TS --vk TOKEN --sig TOKEN
//!                TOKEN = filepath OR inline base64
//!
//! Exit codes (stable — Perl `$? >> 8` matches them):
//!   0 OK | 2 usage | 7 sig invalid | 8 bad hash | 10..=49 tool errors
use clap::{Parser, Subcommand};
use std::io::Read;

use bitcache::{ObjRef, SlabFile, Keypair, SignedEnvelope, base64_encode, base64_decode,
               MLDSA87_SIG_LEN, MLDSA87_VK_LEN};

#[derive(Parser)]
#[command(name = "bctool", version, about = "Amin 3 Bitcache slab helper")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    Put    { #[arg(long)] slab: String },
    Get    { #[arg(long)] slab: String, #[arg(long)] hash: String },
    Genkey { #[arg(long)] name: String, #[arg(long)] sk: String },
    Sign   { #[arg(long)] slab: String, #[arg(long)] hash: String,
             #[arg(long)] name: String, #[arg(long)] sk: String },
    Verify { #[arg(long)] slab: String, #[arg(long)] hash: String,
             #[arg(long)] name: String, #[arg(long)] ts: u64,
             #[arg(long)] vk: String,
             #[arg(long)] sig: String },
    /// Issue a signed zcap.v1 boot-authority token (Amin::Auth::ZCap
    /// wire format).  Signs with the ML-DSA-87 key from `--sk` (32-byte
    /// Seed as written by `genkey`) and prints the standard-base64 token.
    ZcapToken { #[arg(long)] sk: String,
                #[arg(long)] tenant: String,
                #[arg(long)] ts: Option<u64>,
                #[arg(long = "tier")]    tiers:   Vec<String>,
                #[arg(long = "zone")]    zones:   Vec<String>,
                #[arg(long = "netpol")]  netpols: Vec<String>,
                #[arg(long)] max_redundancy: u8,
                #[arg(long)] vpc_quota: u32,
                #[arg(long)] memory_tier: u8 },
    /// Sign a UCC Art.3 instrument (prints `sig` and `vk`, standard base64).
    InstrumentSign { #[arg(long)] sk: String, #[arg(long)] maker: String,
                     #[arg(long)] payee: String, #[arg(long)] amount: String,
                     #[arg(long)] kind: String },
    /// Verify a zcap.v1 token (base64) against one or more anchor VKs
    /// (`--anchor` = filepath or inline base64).  Exit 0 OK; 7 rejected.
    ZcapVerify { #[arg(long)] token: String,
                 #[arg(long = "anchor")] anchors: Vec<String> },
    /// Issue a node certificate (ML-DSA-87 authority signs; node key from a
    /// 64-byte seed file = ML-DSA-65 seed ‖ Ed25519 seed).  Prints base64.
    NodecertIssue { #[arg(long)] sk: String, #[arg(long)] node_seeds: String,
                    #[arg(long)] node_id: String, #[arg(long)] boot_counter: u64,
                    #[arg(long)] from_pos: u64, #[arg(long)] to_pos: u64 },
    /// Append entries to the ledger (`--entry` repeated, or one entry on stdin).
    TlogAppend { #[arg(long)] slab: String, #[arg(long = "entry")] entries: Vec<String> },
    /// Append typed audited events.  Reads TSV from stdin, one event per line:
    /// `kind \t actor \t subject \t auth(64 hex | -) \t key=value …`
    /// with %XX escapes in every text field.  The ledger assigns per-actor
    /// `seq`/`prev`; the whole batch is one fsync, all-or-nothing.
    LedgerAppend { #[arg(long)] slab: String },
    /// Print one entry (decoded) by index.
    LedgerShow { #[arg(long)] slab: String, #[arg(long)] index: u64 },
    /// Open the ledger, re-verifying content hashes and every actor chain.
    /// Exit 0 OK; 7 on a chain violation.
    LedgerVerify { #[arg(long)] slab: String },

    /// Commit every actor's chain head in a `ledger.state` entry (as ACTOR, the
    /// node's origin) — the point a joining node can start from.  Sign a
    /// checkpoint immediately after, then `snapshot-export`.
    LedgerSeal { #[arg(long)] slab: String, #[arg(long)] actor: String },
    /// Bundle the latest seal with its signed checkpoint into a join snapshot
    /// (O(log n + actors) bytes, independent of history length).
    SnapshotExport { #[arg(long)] slab: String, #[arg(long)] checkpoint: String, #[arg(long)] out: String },
    /// Verify a join snapshot offline.  Exit 0 OK; 7 rejected.
    SnapshotVerify { #[arg(long)] snapshot: String, #[arg(long)] authority_vk: String, #[arg(long)] pos: u64,
                     #[arg(long = "witness-vk")] witness_vks: Vec<String>,
                     #[arg(long, default_value_t = 0)] quorum: usize },
    /// Start a brand-new ledger from a verified snapshot (no history needed).
    LedgerJoin { #[arg(long)] slab: String, #[arg(long)] snapshot: String, #[arg(long)] authority_vk: String,
                 #[arg(long)] pos: u64,
                 #[arg(long = "witness-vk")] witness_vks: Vec<String>,
                 #[arg(long, default_value_t = 0)] quorum: usize },

    /// Record another origin's signed checkpoint (`--kind anchor` to report up to
    /// a parent, `--kind peer` when meshes pass roots).  It must extend what this
    /// ledger last recorded for that origin; `--proof` is the consistency proof
    /// (comma-separated base64).  Exit 0 recorded/duplicate/stale; 7 inconsistent
    /// or fault.  With `--cosign-sk`, a witness cosignature is printed when the
    /// checkpoint was accepted.
    CkptObserve { #[arg(long)] slab: String, #[arg(long)] kind: String, #[arg(long)] checkpoint: String,
                  #[arg(long = "authority-vk")] authority_vks: Vec<String>,
                  #[arg(long)] claimed_pos: u64, #[arg(long)] observed_pos: u64,
                  #[arg(long, default_value = "")] proof: String,
                  #[arg(long)] prev_entry: Option<String>,
                  #[arg(long = "witness-vk")] witness_vks: Vec<String>,
                  #[arg(long, default_value_t = 0)] quorum: usize,
                  #[arg(long)] cosign_sk: Option<String> },
    /// Print the latest recorded observation of ORIGIN (index, size, root, raw entry).
    CkptLast { #[arg(long)] slab: String, #[arg(long)] kind: String, #[arg(long)] origin: String },
    /// Build an offline-verifiable receipt for entry INDEX against a signed checkpoint.
    ReceiptMake { #[arg(long)] slab: String, #[arg(long)] index: u64, #[arg(long)] checkpoint: String },
    /// Verify a receipt offline.  Exit 0 OK; 7 rejected.
    ReceiptVerify { #[arg(long)] receipt: String, #[arg(long = "authority-vk")] authority_vks: Vec<String>,
                    #[arg(long)] pos: u64,
                    #[arg(long = "witness-vk")] witness_vks: Vec<String>,
                    #[arg(long, default_value_t = 0)] quorum: usize,
                    /// File of known node certificates (one base64 per line, re-verified on load);
                    /// lets slim receipts verify, and is extended by every full receipt that does.
                    #[arg(long)] cert_cache: Option<String> },
    /// Drop the node certificate from a receipt (verify with --cert-cache).
    ReceiptSlim { #[arg(long)] receipt: String },
    /// Drop the node certificate from an IoT leaf receipt.
    IotSlim { #[arg(long)] receipt: String },
    /// Verify a receipt and record the matching `transfer.in` for ACTOR (once).
    ReceiptAccept { #[arg(long)] slab: String, #[arg(long)] receipt: String, #[arg(long)] actor: String,
                    #[arg(long = "authority-vk")] authority_vks: Vec<String>,
                    #[arg(long)] pos: u64,
                    #[arg(long = "witness-vk")] witness_vks: Vec<String>,
                    /// Witnesses always required (default 0).
                    #[arg(long, default_value_t = 0)] quorum: usize,
                    /// `AMOUNT:WITNESSES` — payments of at least AMOUNT need that many cosignatures.
                    #[arg(long = "quorum-tier")] quorum_tiers: Vec<String> },
    /// Attach witness cosignatures (`HASH_B64:SIG_B64`, as printed by ckpt-observe
    /// --cosign-sk) to a signed checkpoint; prints the new wire.
    CkptAttach { #[arg(long)] checkpoint: String, #[arg(long = "cosig")] cosigs: Vec<String> },
    /// Drop local history before a sealed, signed checkpoint of this ledger (IoT rolling
    /// window).  The checkpoint must match the last `ledger-seal`.
    LedgerCompact { #[arg(long)] slab: String, #[arg(long)] checkpoint: String },
    /// Leaf side of the IoT profile: one authenticated report (base64 on stdout).
    IotReport { #[arg(long)] master: String, #[arg(long)] leaf: String, #[arg(long)] ctr: u64,
                #[arg(long, default_value = "")] payload_hex: String },
    /// Gateway side: read base64 reports (one per line) from stdin, drop bad/replayed ones,
    /// commit the rest as `iot.batch` ledger entries, archive each batch to
    /// `<batch-out>.<ledger index>`, and persist per-leaf counters in `--state`.
    IotIngest { #[arg(long)] slab: String, #[arg(long)] master: String, #[arg(long)] actor: String,
                #[arg(long)] state: String, #[arg(long)] batch_out: String,
                #[arg(long, default_value_t = 4096)] max_batch: usize,
                /// Refuse to start unless the counters in --state match this `counters_root`
                /// (hex, from the latest `iot.batch` entry).
                #[arg(long)] counters_root: Option<String> },
    /// Leaf receipt for one report of an archived batch, against a signed checkpoint.
    IotReceipt { #[arg(long)] slab: String, #[arg(long)] batch: String, #[arg(long)] report_index: usize,
                 #[arg(long)] entry_index: u64, #[arg(long)] checkpoint: String },
    /// Verify a leaf receipt offline.  Exit 0 OK; 7 rejected.
    IotVerify { #[arg(long)] receipt: String, #[arg(long = "authority-vk")] authority_vks: Vec<String>,
                #[arg(long)] pos: u64,
                #[arg(long = "witness-vk")] witness_vks: Vec<String>,
                #[arg(long, default_value_t = 0)] quorum: usize,
                #[arg(long)] cert_cache: Option<String> },
    /// Print ledger size and root.
    TlogHead { #[arg(long)] slab: String },
    /// Inclusion proof for entry INDEX in the tree of SIZE leaves (default: current).
    TlogProve { #[arg(long)] slab: String, #[arg(long)] index: u64, #[arg(long)] size: Option<u64> },
    /// Consistency proof FIRST → SECOND (default: current).
    TlogConsistency { #[arg(long)] slab: String, #[arg(long)] first: u64, #[arg(long)] second: Option<u64> },
    /// Verify an inclusion proof offline.  Exit 0 OK; 7 rejected.
    TlogVerifyInclusion { #[arg(long)] leaf: String, #[arg(long)] index: u64, #[arg(long)] size: u64,
                          #[arg(long)] path: String, #[arg(long)] root: String },
    /// Verify a consistency proof offline.  Exit 0 OK; 7 rejected.
    TlogVerifyConsistency { #[arg(long)] first: u64, #[arg(long)] first_root: String,
                            #[arg(long)] second: u64, #[arg(long)] second_root: String,
                            #[arg(long)] proof: String },
    /// Sign a checkpoint of the current head (composite node key, optional
    /// local witness cosignatures).  Prints the base64 wire form.
    TlogCheckpoint { #[arg(long)] slab: String, #[arg(long)] node_seeds: String,
                     #[arg(long)] cert: String, #[arg(long)] origin: String,
                     #[arg(long = "witness-sk")] witness_sks: Vec<String> },
    /// Verify a signed checkpoint.  Exit 0 OK; 7 rejected (code on stderr).
    TlogVerifyCheckpoint { #[arg(long)] wire: String, #[arg(long)] authority_vk: String,
                           #[arg(long)] pos: u64,
                           #[arg(long = "witness-vk")] witness_vks: Vec<String>,
                           #[arg(long, default_value_t = 0)] quorum: usize },
}

fn die(code: i32, s: impl std::fmt::Display) -> ! {
    eprintln!("bctool: {s}");
    std::process::exit(code);
}

fn hex32_decode(s: &str) -> [u8; 32] {
    if s.len() != 64 { die(8, format!("hash hex must be 64 chars, got {}", s.len())) }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2*i..2*i+2], 16)
            .unwrap_or_else(|_| die(8, format!("bad hex at pos {i}")));
    }
    out
}
fn hex32_encode(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    use std::fmt::Write;
    for byte in b { let _ = write!(s, "{:02x}", byte); }
    s
}

fn read_file_or_b64(token: &str, label: &str) -> Vec<u8> {
    if std::path::Path::new(token).exists() {
        return std::fs::read(token).unwrap_or_else(|e|
            die(5, format!("read {label} file {token}: {e}")));
    }
    base64_decode(token).unwrap_or_else(|e|
        die(5, format!("decode {label} b64: {e}")))
}

fn hash_arg(s: &str, label: &str) -> bitcache::tlog::Hash {
    let b = read_file_or_b64(s, label);
    <[u8; 32]>::try_from(b.as_slice()).unwrap_or_else(|_| die(5, format!("{label}: need 32 bytes")))
}
fn hashes_arg(s: &str) -> Vec<bitcache::tlog::Hash> {
    s.split(',').filter(|x| !x.is_empty()).map(|x| hash_arg(x, "path element")).collect()
}
fn path_b64(p: &[bitcache::tlog::Hash]) -> String {
    p.iter().map(|h| base64_encode(h)).collect::<Vec<_>>().join(",")
}
fn node_key(path: &str) -> awp3::sign::CompositeSigningKey {
    let b = std::fs::read(path).unwrap_or_else(|e| die(40, format!("read node seeds {path}: {e}")));
    if b.len() != 64 { die(41, "node seed file must be 64 bytes") }
    let (mut ml, mut ed) = ([0u8; 32], [0u8; 32]);
    ml.copy_from_slice(&b[..32]);
    ed.copy_from_slice(&b[32..]);
    awp3::sign::CompositeSigningKey::from_seeds(&ml, &ed)
}
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() { die(5, "truncated %-escape") }
            let h = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|x| u8::from_str_radix(x, 16).ok());
            match h { Some(v) => { o.push(v); i += 3; continue } None => die(5, "bad %-escape") }
        }
        o.push(b[i]);
        i += 1;
    }
    String::from_utf8(o).unwrap_or_else(|_| die(5, "field is not valid UTF-8"))
}

/// Certificates are re-verified under every trusted authority as they are loaded, so the
/// cache file carries no trust of its own.
fn load_cert_cache(path: &Option<String>, auths: &[&[u8]]) -> bitcache::checkpoint::CertCache {
    let mut c = bitcache::checkpoint::CertCache::new();
    if let Some(p) = path {
        for line in std::fs::read_to_string(p).unwrap_or_default().lines() {
            if let Ok(cert) = base64_decode(line.trim()) {
                for a in auths { c.admit(&cert, a); }
            }
        }
    }
    c
}

fn save_cert(path: &Option<String>, checkpoint_wire: &[u8]) {
    use std::io::Write;
    let (Some(p), Some(cert)) = (path, bitcache::checkpoint::embedded_cert(checkpoint_wire)) else { return };
    let line = base64_encode(&cert);
    if std::fs::read_to_string(p).unwrap_or_default().lines().any(|l| l.trim() == line) { return; }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) { let _ = writeln!(f, "{line}"); }
}

fn master32(tok: &str) -> [u8; 32] {
    let b = read_file_or_b64(tok, "master key");
    <[u8; 32]>::try_from(b.as_slice()).unwrap_or_else(|_| die(2, "master key must be exactly 32 bytes"))
}

fn open_ledger(slab: &str) -> bitcache::ledger::Ledger {
    bitcache::ledger::Ledger::open(slab).unwrap_or_else(|e| die(11, format!("open ledger {slab}: {e}")))
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Put { slab } => {
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)
                .unwrap_or_else(|e| die(10, format!("read stdin: {e}")));
            let mut sf = SlabFile::open_or_create(&slab)
                .unwrap_or_else(|e| die(11, format!("open slab {slab}: {e}")));
            let r = sf.put(&data).unwrap_or_else(|e| die(12, format!("slab put: {e}")));
            println!("hash\t{}\nsize\t{}", hex32_encode(r.as_bytes()), data.len());
        }

        Cmd::Get { slab, hash } => {
            let r = ObjRef(hex32_decode(&hash));
            let mut sf = SlabFile::open_or_create(&slab)
                .unwrap_or_else(|e| die(11, format!("open slab {slab}: {e}")));
            let got = sf.get(&r).unwrap_or_else(|e| die(13, format!("slab get: {e}")));
            use std::io::Write;
            std::io::stdout().write_all(&got)
                .unwrap_or_else(|e| die(14, format!("write stdout: {e}")));
        }

        Cmd::Genkey { name, sk } => {
            use rand::rngs::OsRng;
            let mut rng = OsRng;
            let kp: Keypair = Keypair::generate(&mut rng, name);
            let sk_bytes = kp.signing_key_bytes();
            use std::fs::OpenOptions;
            use std::io::Write as _;
            let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&sk)
                .unwrap_or_else(|e| die(20, format!("open sk {sk}: {e}")));
            f.write_all(&sk_bytes).unwrap_or_else(|e| die(21, format!("write sk: {e}")));
            drop(f);
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&sk, std::fs::Permissions::from_mode(0o600))
                    .unwrap_or_else(|e| die(22, format!("chmod 600 sk: {e}")));
            }
            println!("vk\t{}", base64_encode(&kp.verifying_key_bytes()));
        }

        Cmd::Sign { slab, hash, name, sk } => {
            let sk_bytes = std::fs::read(&sk)
                .unwrap_or_else(|e| die(30, format!("open sk {sk}: {e}")));
            let mut kp = Keypair::from_sk_bytes(&sk_bytes)
                .unwrap_or_else(|e| die(31, format!("parse sk: {e}")));
            kp.name = name.clone();
            let obj_ref = ObjRef(hex32_decode(&hash));
            // Fail closed: don't sign objects that have never been landed in
            // the slab (prevents "signature on phantom content" attacks).
            {
                let mut sf = SlabFile::open_or_create(&slab)
                    .unwrap_or_else(|e| die(11, format!("open slab {slab}: {e}")));
                sf.get(&obj_ref).unwrap_or_else(|e|
                    die(33, format!("ref {hash} not in slab: {e}")));
            }
            use rand::rngs::OsRng;
            let mut rng = OsRng;
            let env = SignedEnvelope::new(&mut rng, &kp, obj_ref)
                .unwrap_or_else(|e| die(34, format!("sign: {e}")));
            println!("sig\t{}",        base64_encode(&env.signature.0));
            println!("name\t{}",       env.name);
            println!("date\t{}",       env.date);
            println!("timestamp\t{}",  env.timestamp);
            println!("keyref_pem\t{}", env.keyref_pem.replace('\n', "\\n"));
        }

        Cmd::Verify { slab: _, hash, name, ts, vk, sig } => {
            let vk_bytes  = read_file_or_b64(&vk, "vk");
            let sig_bytes = read_file_or_b64(&sig, "sig");
            if sig_bytes.len() != MLDSA87_SIG_LEN {
                die(43, format!("bad ML-DSA-87 sig len {} expected {}",
                                sig_bytes.len(), MLDSA87_SIG_LEN));
            }
            if vk_bytes.len() != MLDSA87_VK_LEN {
                die(44, format!("bad ML-DSA-87 vk len {} expected {}",
                                vk_bytes.len(), MLDSA87_VK_LEN));
            }
            let mut sig_arr = [0u8; MLDSA87_SIG_LEN];
            sig_arr.copy_from_slice(&sig_bytes);
            let obj_ref = ObjRef(hex32_decode(&hash));
            let env = SignedEnvelope {
                name, date: String::new(), keyref_pem: String::new(),
                obj_ref, timestamp: ts,
                signature: bitcache::BcSignature(sig_arr),
            };
            match env.verify(&vk_bytes) {
                Ok(())  => { println!("verify\tOK"); std::process::exit(0) }
                Err(e)  => { eprintln!("verify FAIL: {e}"); std::process::exit(7) }
            }
        }

        Cmd::ZcapToken { sk, tenant, ts, tiers, zones, netpols,
                         max_redundancy, vpc_quota, memory_tier } => {
            let sk_bytes = std::fs::read(&sk)
                .unwrap_or_else(|e| die(30, format!("open sk {sk}: {e}")));
            let kp = Keypair::from_sk_bytes(&sk_bytes)
                .unwrap_or_else(|e| die(31, format!("parse sk: {e}")));
            let grant = bitcache::ZcapGrant {
                tiers,
                zones,
                netpolicies: netpols,
                max_redundancy,
                vpc_quota,
                memory_tier,
                tenant_id: tenant,
                ts: ts.unwrap_or_else(bitcache::epoch_now),
            };
            let token = bitcache::zcap_token_bytes(&kp, &grant)
                .unwrap_or_else(|e| die(34, format!("zcap-token: {e}")));
            println!("token\t{}", base64_encode(&token));
            println!("vk\t{}",    base64_encode(&kp.verifying_key_bytes()));
            println!("ts\t{}",    grant.ts);
            println!("sighex\t{}", grant.scope_hash_hex());
        }

        Cmd::InstrumentSign { sk, maker, payee, amount, kind } => {
            let sk_bytes = std::fs::read(&sk)
                .unwrap_or_else(|e| die(30, format!("open sk {sk}: {e}")));
            let kp = Keypair::from_sk_bytes(&sk_bytes)
                .unwrap_or_else(|e| die(31, format!("parse sk: {e}")));
            let msg = bitcache::trust::instrument_message(&maker, &payee, &amount, &kind);
            let sig = bitcache::mldsa87_sign(&kp, &msg)
                .unwrap_or_else(|e| die(34, format!("instrument-sign: {e}")));
            println!("sig\t{}", base64_encode(&sig));
            println!("vk\t{}",  base64_encode(&kp.verifying_key_bytes()));
        }

        Cmd::ZcapVerify { token, anchors } => {
            let tok = read_file_or_b64(&token, "token");
            let a: Vec<Vec<u8>> = anchors.iter().map(|x| read_file_or_b64(x, "anchor")).collect();
            let refs: Vec<&[u8]> = a.iter().map(Vec::as_slice).collect();
            match bitcache::trust::zcap_verify(&tok, &refs) {
                Ok(_)  => { println!("zcap-verify\tOK"); std::process::exit(0) }
                Err(r) => { eprintln!("zcap-verify FAIL: {r:?}"); std::process::exit(7) }
            }
        }

        Cmd::NodecertIssue { sk, node_seeds, node_id, boot_counter, from_pos, to_pos } => {
            let kp = Keypair::from_sk_bytes(&std::fs::read(&sk).unwrap_or_else(|e| die(30, format!("open sk {sk}: {e}"))))
                .unwrap_or_else(|e| die(31, format!("parse sk: {e}")));
            let nk = node_key(&node_seeds);
            let cert = bitcache::nodecert::NodeCert {
                node_id, boot_counter, scope_hash: [0; 32], valid_from_pos: from_pos, valid_to_pos: to_pos,
                node_vk_hash: bitcache::checkpoint::vk_hash(&nk.verifying_key().to_bytes()),
            }.sign(&kp).unwrap_or_else(|e| die(32, format!("sign cert: {e}")));
            println!("cert\t{}", base64_encode(&cert));
        }

        Cmd::TlogAppend { slab, entries } => {
            let mut l = open_ledger(&slab);
            let data: Vec<Vec<u8>> = if entries.is_empty() {
                let mut b = Vec::new();
                std::io::stdin().read_to_end(&mut b).unwrap_or_else(|e| die(10, format!("read stdin: {e}")));
                vec![b]
            } else { entries.into_iter().map(String::into_bytes).collect() };
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let first = l.append_batch(&refs).unwrap_or_else(|e| die(12, format!("ledger append: {e}")));
            println!("first\t{first}\nsize\t{}\nroot\t{}", l.size(), hex32_encode(&l.root()));
        }

        Cmd::LedgerAppend { slab } => {
            let mut txt = String::new();
            std::io::stdin().read_to_string(&mut txt).unwrap_or_else(|e| die(10, format!("read stdin: {e}")));
            let ts = bitcache::epoch_now();
            let mut drafts = Vec::new();
            for (n, line) in txt.lines().filter(|l| !l.is_empty()).enumerate() {
                let f: Vec<&str> = line.split('\t').collect();
                if f.len() < 4 { die(5, format!("line {}: need kind, actor, subject, auth", n + 1)) }
                let auth = if f[3] == "-" { None } else { Some(hex32_decode(f[3])) };
                let attrs = f[4..].iter().map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or_else(|| die(5, format!("line {}: attr needs key=value", n + 1)));
                    (pct_decode(k), pct_decode(v))
                }).collect();
                drafts.push(bitcache::entry::Draft { kind: pct_decode(f[0]), actor: pct_decode(f[1]),
                    subject: pct_decode(f[2]), auth, ts, attrs });
            }
            if drafts.is_empty() { die(5, "no events on stdin") }
            let mut l = open_ledger(&slab);
            let (first, es) = l.append_drafts(drafts).unwrap_or_else(|e| die(12, format!("ledger append: {e}")));
            for (i, e) in es.iter().enumerate() {
                println!("entry\t{}\t{}\t{}\t{}", first + i as u64, e.actor, e.seq, hex32_encode(&e.id().unwrap()));
            }
            println!("size\t{}\nroot\t{}", l.size(), hex32_encode(&l.root()));
        }

        Cmd::LedgerShow { slab, index } => {
            let mut l = open_ledger(&slab);
            let raw = l.entry(index).unwrap_or_else(|e| die(13, format!("ledger entry: {e}")));
            match bitcache::entry::Entry::decode(&raw) {
                Ok(e) => {
                    println!("kind\t{}\nactor\t{}\nsubject\t{}\nseq\t{}\nprev\t{}\nauth\t{}\nts\t{}\nid\t{}",
                        e.kind, e.actor, e.subject, e.seq, hex32_encode(&e.prev), hex32_encode(&e.auth), e.ts,
                        hex32_encode(&bitcache::entry::id_of(&raw)));
                    for (k, v) in &e.attrs { println!("attr\t{k}\t{v}"); }
                }
                Err(_) => println!("opaque\t{}", base64_encode(&raw)),
            }
        }

        Cmd::LedgerVerify { slab } => {
            match bitcache::ledger::Ledger::open(&slab) {
                Ok(l) => { println!("ledger-verify\tOK\nsize\t{}\nroot\t{}", l.size(), hex32_encode(&l.root())); }
                Err(e @ bitcache::BitcacheError::ChainViolation(_)) => { eprintln!("ledger-verify FAIL: {e}"); std::process::exit(7) }
                Err(e) => die(11, format!("open ledger {slab}: {e}")),
            }
        }

        Cmd::LedgerSeal { slab, actor } => {
            let mut l = open_ledger(&slab);
            let (idx, e) = l.seal(&actor, bitcache::epoch_now()).unwrap_or_else(|e| die(12, format!("ledger seal: {e}")));
            println!("index\t{idx}\nactor\t{}\nseq\t{}\nsize\t{}\nroot\t{}", e.actor, e.seq, l.size(), hex32_encode(&l.root()));
        }

        Cmd::SnapshotExport { slab, checkpoint, out } => {
            let l = open_ledger(&slab);
            let snap = l.export_snapshot(&read_file_or_b64(&checkpoint, "checkpoint"))
                .unwrap_or_else(|e| die(14, format!("snapshot export: {e}")));
            let b = snap.encode();
            std::fs::write(&out, &b).unwrap_or_else(|e| die(14, format!("write {out}: {e}")));
            println!("snapshot\t{out}\nbytes\t{}\nframe\t{}\nheads\t{}", b.len(), snap.frontier.len(), snap.heads.len());
        }

        Cmd::SnapshotVerify { snapshot, authority_vk, pos, witness_vks, quorum } => {
            let snap = bitcache::snapshot::Snapshot::decode(&read_file_or_b64(&snapshot, "snapshot"))
                .unwrap_or_else(|e| { eprintln!("snapshot-verify FAIL: {e:?}"); std::process::exit(7) });
            let avk = read_file_or_b64(&authority_vk, "authority vk");
            let roster: Vec<Vec<u8>> = witness_vks.iter().map(|x| read_file_or_b64(x, "witness vk")).collect();
            let r: Vec<&[u8]> = roster.iter().map(Vec::as_slice).collect();
            match snap.verify(&avk, pos, &r, quorum) {
                Ok(j) => println!("origin\t{}\nsize\t{}\nroot\t{}\nactors\t{}", j.checkpoint.origin, j.checkpoint.size,
                                   hex32_encode(&j.checkpoint.root), j.heads.len()),
                Err(e) => { eprintln!("snapshot-verify FAIL: {e:?} ({})", e.code()); std::process::exit(7) }
            }
        }

        Cmd::LedgerJoin { slab, snapshot, authority_vk, pos, witness_vks, quorum } => {
            let avk = read_file_or_b64(&authority_vk, "authority vk");
            let roster: Vec<Vec<u8>> = witness_vks.iter().map(|x| read_file_or_b64(x, "witness vk")).collect();
            let r: Vec<&[u8]> = roster.iter().map(Vec::as_slice).collect();
            match bitcache::ledger::Ledger::join(&slab, &read_file_or_b64(&snapshot, "snapshot"), &avk, pos, &r, quorum) {
                Ok(l) => println!("joined\t{slab}\nsize\t{}\nbase\t{}\nroot\t{}", l.size(), l.base(), hex32_encode(&l.root())),
                Err(e) => { eprintln!("ledger-join FAIL: {e}"); std::process::exit(7) }
            }
        }

        Cmd::CkptObserve { slab, kind, checkpoint, authority_vks, claimed_pos, observed_pos, proof, prev_entry,
                           witness_vks, quorum, cosign_sk } => {
            use bitcache::mesh::{ObserveKind, Observation, Observed};
            let kind = match kind.as_str() { "anchor" => ObserveKind::Anchor, "peer" => ObserveKind::Peer,
                _ => die(2, "--kind must be anchor or peer") };
            let wire = read_file_or_b64(&checkpoint, "checkpoint");
            let auths: Vec<Vec<u8>> = authority_vks.iter().map(|x| read_file_or_b64(x, "authority vk")).collect();
            let roster: Vec<Vec<u8>> = witness_vks.iter().map(|x| read_file_or_b64(x, "witness vk")).collect();
            let (ar, rr): (Vec<&[u8]>, Vec<&[u8]>) = (auths.iter().map(Vec::as_slice).collect(), roster.iter().map(Vec::as_slice).collect());
            let prev = prev_entry.as_deref().map(|p| read_file_or_b64(p, "prev entry"));
            let proof = hashes_arg(&proof);
            let mut l = open_ledger(&slab);
            let out = l.observe_checkpoint(&Observation { kind, wire: &wire, proof: &proof, prev_entry: prev.as_deref(),
                authorities: &ar, claimed_pos, observed_pos, roster: &rr, quorum, ts: bitcache::epoch_now() })
                .unwrap_or_else(|e| die(12, format!("observe: {e}")));
            let (name, code) = match &out {
                Observed::Recorded(e) => { println!("entry\t{}\t{}\t{}", e.kind, e.actor, e.seq); ("recorded", 0) }
                Observed::Duplicate => ("duplicate", 0),
                Observed::Stale => ("stale", 0),
                Observed::Inconsistent => ("inconsistent", 7),
                Observed::Fault(e) => { println!("entry\t{}\t{}\t{}", e.kind, e.actor, e.seq); ("fault", 7) }
            };
            println!("outcome\t{name}");
            // A witness vouches only for a consistent extension (or the same checkpoint again).
            if code == 0 && matches!(name, "recorded" | "duplicate") {
                if let Some(sk) = cosign_sk {
                    let w = Keypair::from_sk_bytes(&std::fs::read(&sk).unwrap_or_else(|e| die(30, format!("open {sk}: {e}"))))
                        .unwrap_or_else(|e| die(31, format!("parse sk: {e}")));
                    let ck = bitcache::checkpoint::parse_unverified(&wire).unwrap_or_else(|e| die(32, format!("{e:?}")));
                    let (h, sg) = bitcache::checkpoint::cosign(&ck, &w).unwrap_or_else(|e| die(32, format!("cosign: {e}")));
                    println!("cosig\t{}\t{}", base64_encode(&h), base64_encode(&sg));
                }
            }
            std::process::exit(code);
        }

        Cmd::CkptLast { slab, kind, origin } => {
            use bitcache::mesh::ObserveKind;
            let kind = match kind.as_str() { "anchor" => ObserveKind::Anchor, "peer" => ObserveKind::Peer,
                _ => die(2, "--kind must be anchor or peer") };
            let mut l = open_ledger(&slab);
            match l.last_observed(kind, &origin, None).unwrap_or_else(|e| die(12, format!("{e}"))) {
                None => { println!("none"); }
                Some((size, root)) => println!("size\t{size}\nroot\t{}", hex32_encode(&root)),
            }
        }

        Cmd::ReceiptMake { slab, index, checkpoint } => {
            let mut l = open_ledger(&slab);
            let r = l.make_receipt(index, &read_file_or_b64(&checkpoint, "checkpoint"))
                .unwrap_or_else(|e| die(14, format!("receipt: {e}")));
            println!("receipt\t{}", base64_encode(&r.encode()));
        }

        Cmd::ReceiptSlim { receipt } => {
            let r = bitcache::receipt::Receipt::decode(&read_file_or_b64(&receipt, "receipt")).unwrap_or_else(|e| die(7, format!("{e:?}")));
            println!("receipt\t{}", base64_encode(&r.slim().unwrap_or_else(|e| die(7, format!("{e:?}"))).encode()));
        }

        Cmd::IotSlim { receipt } => {
            let r = bitcache::iot::LeafReceipt::decode(&read_file_or_b64(&receipt, "leaf receipt")).unwrap_or_else(|e| die(7, format!("{e:?}")));
            println!("leaf_receipt\t{}", base64_encode(&r.slim().unwrap_or_else(|e| die(7, format!("{e:?}"))).encode()));
        }

        Cmd::ReceiptVerify { receipt, authority_vks, pos, witness_vks, quorum, cert_cache } => {
            let r = bitcache::receipt::Receipt::decode(&read_file_or_b64(&receipt, "receipt"))
                .unwrap_or_else(|e| { eprintln!("receipt-verify FAIL: {e:?}"); std::process::exit(7) });
            let auths: Vec<Vec<u8>> = authority_vks.iter().map(|x| read_file_or_b64(x, "authority vk")).collect();
            let roster: Vec<Vec<u8>> = witness_vks.iter().map(|x| read_file_or_b64(x, "witness vk")).collect();
            let (ar, rr): (Vec<&[u8]>, Vec<&[u8]>) = (auths.iter().map(Vec::as_slice).collect(), roster.iter().map(Vec::as_slice).collect());
            let mut cache = load_cert_cache(&cert_cache, &ar);
            match r.verify_cached(&ar, pos, &rr, quorum, &mut cache) {
                Ok((e, id, ck)) => { save_cert(&cert_cache, &r.checkpoint); println!("kind\t{}\nactor\t{}\nsubject\t{}\norigin\t{}\nsize\t{}\nid\t{}",
                    e.kind, e.actor, e.subject, ck.origin, ck.size, hex32_encode(&id)) },
                Err(e) => { eprintln!("receipt-verify FAIL: {e:?} ({})", e.code()); std::process::exit(7) }
            }
        }

        Cmd::IotReport { master, leaf, ctr, payload_hex } => {
            let m = master32(&master);
            let payload: Vec<u8> = (0..payload_hex.len() / 2)
                .map(|i| u8::from_str_radix(&payload_hex[2 * i..2 * i + 2], 16).unwrap_or_else(|_| die(2, "bad --payload-hex"))).collect();
            let r = bitcache::iot::Report::new(&bitcache::iot::leaf_key(&m, &leaf), &leaf, ctr, &payload)
                .unwrap_or_else(|| die(2, "leaf must be 1..=32 bytes, payload ≤ 256"));
            println!("report\t{}", base64_encode(&r.encode()));
        }

        Cmd::IotIngest { slab, master, actor, state, batch_out, max_batch, counters_root } => {
            use bitcache::iot::{Batch, Gateway, IngestError};
            let counters: std::collections::BTreeMap<String, u64> = std::fs::read_to_string(&state).unwrap_or_default()
                .lines().filter_map(|l| l.split_once('\t').and_then(|(k, v)| Some((k.to_string(), v.parse().ok()?)))).collect();
            if let Some(want) = counters_root {
                if bitcache::iot::counters_root(&counters) != hex32_decode(&want) {
                    eprintln!("iot-ingest: counters in {state} do not match the committed counters_root");
                    std::process::exit(7);
                }
            }
            let mut gw = Gateway::new(master32(&master), &actor, max_batch).with_counters(counters);
            let mut l = open_ledger(&slab);
            let commit = |gw: &mut Gateway, l: &mut bitcache::ledger::Ledger| {
                if let Some(b) = gw.flush(bitcache::epoch_now()) {
                    let (idx, _) = l.append_drafts(vec![b.draft.clone()]).unwrap_or_else(|e| die(12, format!("append: {e}")));
                    let path = format!("{batch_out}.{idx}");
                    std::fs::write(&path, Batch::encode(&b.reports)).unwrap_or_else(|e| die(30, format!("write {path}: {e}")));
                    println!("batch\t{idx}\t{}\t{path}", b.reports.len());
                }
            };
            let (mut ok, mut bad) = (0u64, 0u64);
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input).unwrap_or_else(|e| die(30, format!("stdin: {e}")));
            for (i, line) in input.lines().filter(|x| !x.trim().is_empty()).enumerate() {
                let wire = base64_decode(line.trim()).unwrap_or_default();
                let mut res = gw.ingest(&wire);
                if res == Err(IngestError::Full) {
                    commit(&mut gw, &mut l);
                    res = gw.ingest(&wire);
                }
                match res { Ok(()) => ok += 1, Err(e) => { bad += 1; println!("reject\t{i}\t{e:?}"); } }
            }
            commit(&mut gw, &mut l);
            let st: String = gw.counters().iter().map(|(k, v)| format!("{k}\t{v}\n")).collect();
            std::fs::write(&state, st).unwrap_or_else(|e| die(30, format!("write {state}: {e}")));
            println!("accepted\t{ok}\nrejected\t{bad}");
        }

        Cmd::IotReceipt { slab, batch, report_index, entry_index, checkpoint } => {
            let reports = bitcache::iot::Batch::decode(&std::fs::read(&batch).unwrap_or_else(|e| die(30, format!("read {batch}: {e}"))))
                .unwrap_or_else(|| die(8, "malformed batch file"));
            let mut l = open_ledger(&slab);
            let br = l.make_receipt(entry_index, &read_file_or_b64(&checkpoint, "checkpoint"))
                .unwrap_or_else(|e| die(14, format!("receipt: {e}")));
            let b = bitcache::iot::Batch { draft: bitcache::entry::Draft { kind: String::new(), actor: String::new(), subject: String::new(),
                auth: None, ts: 0, attrs: vec![] }, reports };
            let lr = b.leaf_receipt(report_index, br).unwrap_or_else(|| die(8, "report index out of range"));
            println!("leaf_receipt\t{}", base64_encode(&lr.encode()));
        }

        Cmd::IotVerify { receipt, authority_vks, pos, witness_vks, quorum, cert_cache } => {
            let r = bitcache::iot::LeafReceipt::decode(&read_file_or_b64(&receipt, "leaf receipt"))
                .unwrap_or_else(|e| { eprintln!("iot-verify FAIL: {e:?}"); std::process::exit(7) });
            let auths: Vec<Vec<u8>> = authority_vks.iter().map(|x| read_file_or_b64(x, "authority vk")).collect();
            let roster: Vec<Vec<u8>> = witness_vks.iter().map(|x| read_file_or_b64(x, "witness vk")).collect();
            let (ar, rr): (Vec<&[u8]>, Vec<&[u8]>) = (auths.iter().map(Vec::as_slice).collect(), roster.iter().map(Vec::as_slice).collect());
            let mut cache = load_cert_cache(&cert_cache, &ar);
            match r.verify_cached(&ar, pos, &rr, quorum, &mut cache) {
                Ok((rep, _e, ck)) => { save_cert(&cert_cache, &r.receipt.checkpoint); println!("leaf\t{}\nctr\t{}\npayload\t{}\norigin\t{}\nsize\t{}",
                    rep.leaf, rep.ctr, rep.payload.iter().map(|b| format!("{b:02x}")).collect::<String>(), ck.origin, ck.size) },
                Err(e) => { eprintln!("iot-verify FAIL: {e:?} ({})", e.code()); std::process::exit(7) }
            }
        }

        Cmd::CkptAttach { checkpoint, cosigs } => {
            let wire = read_file_or_b64(&checkpoint, "checkpoint");
            let parsed: Vec<(bitcache::tlog::Hash, Vec<u8>)> = cosigs.iter().map(|c| {
                let (h, sg) = c.split_once(':').unwrap_or_else(|| die(2, "--cosig wants HASH_B64:SIG_B64"));
                (hash_arg(h, "cosig hash"), base64_decode(sg).unwrap_or_else(|e| die(2, format!("cosig sig: {e}"))))
            }).collect();
            let out = bitcache::checkpoint::attach_cosigs(&wire, &parsed).unwrap_or_else(|e| die(7, format!("attach: {e:?}")));
            println!("checkpoint\t{}", base64_encode(&out));
        }

        Cmd::LedgerCompact { slab, checkpoint } => {
            let l = open_ledger(&slab);
            match l.compact(&read_file_or_b64(&checkpoint, "checkpoint")) {
                Ok((l, dropped)) => println!("dropped\t{dropped}\nbase\t{}\nretained\t{}\nsize\t{}\nroot\t{}",
                                           l.base(), l.retained(), l.size(), hex32_encode(&l.root())),
                Err(e) => { eprintln!("ledger-compact FAIL: {e}"); std::process::exit(7) }
            }
        }

        Cmd::ReceiptAccept { slab, receipt, actor, authority_vks, pos, witness_vks, quorum, quorum_tiers } => {
            let r = bitcache::receipt::Receipt::decode(&read_file_or_b64(&receipt, "receipt"))
                .unwrap_or_else(|e| { eprintln!("receipt-accept FAIL: {e:?}"); std::process::exit(7) });
            let auths: Vec<Vec<u8>> = authority_vks.iter().map(|x| read_file_or_b64(x, "authority vk")).collect();
            let roster: Vec<Vec<u8>> = witness_vks.iter().map(|x| read_file_or_b64(x, "witness vk")).collect();
            let (ar, rr): (Vec<&[u8]>, Vec<&[u8]>) = (auths.iter().map(Vec::as_slice).collect(), roster.iter().map(Vec::as_slice).collect());
            let mut l = open_ledger(&slab);
            let policy = bitcache::policy::QuorumPolicy::with_tiers(quorum, &quorum_tiers).unwrap_or_else(|e| die(2, e));
            match l.accept_receipt(&r, &ar, pos, &rr, &policy, &actor, bitcache::epoch_now()) {
                Ok(e) => println!("entry\t{}\t{}\t{}\t{}", e.kind, e.actor, e.seq, hex32_encode(&e.id().unwrap())),
                Err(e) => { eprintln!("receipt-accept FAIL: {e}"); std::process::exit(7) }
            }
        }

        Cmd::TlogHead { slab } => {
            let l = open_ledger(&slab);
            println!("size\t{}\nroot\t{}", l.size(), hex32_encode(&l.root()));
        }

        Cmd::TlogProve { slab, index, size } => {
            let l = open_ledger(&slab);
            let size = size.unwrap_or_else(|| l.size());
            let (Some(path), Some(root), Some(leaf)) = (l.inclusion_proof(index, size), l.root_at(size), l.leaf(index))
                else { die(8, "index/size out of range") };
            println!("leaf\t{}\nindex\t{index}\nsize\t{size}\npath\t{}\nroot\t{}",
                     base64_encode(&leaf), path_b64(&path), base64_encode(&root));
        }

        Cmd::TlogConsistency { slab, first, second } => {
            let l = open_ledger(&slab);
            let second = second.unwrap_or_else(|| l.size());
            let (Some(p), Some(a), Some(b)) = (l.consistency_proof(first, second), l.root_at(first), l.root_at(second))
                else { die(8, "sizes out of range") };
            println!("first\t{first}\nfirst_root\t{}\nsecond\t{second}\nsecond_root\t{}\nproof\t{}",
                     base64_encode(&a), base64_encode(&b), path_b64(&p));
        }

        Cmd::TlogVerifyInclusion { leaf, index, size, path, root } => {
            let ok = bitcache::tlog::verify_inclusion(&hash_arg(&leaf, "leaf"), index, size, &hashes_arg(&path), &hash_arg(&root, "root"));
            if ok { println!("tlog-verify-inclusion\tOK") } else { eprintln!("tlog-verify-inclusion FAIL"); std::process::exit(7) }
        }

        Cmd::TlogVerifyConsistency { first, first_root, second, second_root, proof } => {
            let ok = bitcache::tlog::verify_consistency(first, &hash_arg(&first_root, "first_root"),
                second, &hash_arg(&second_root, "second_root"), &hashes_arg(&proof));
            if ok { println!("tlog-verify-consistency\tOK") } else { eprintln!("tlog-verify-consistency FAIL"); std::process::exit(7) }
        }

        Cmd::TlogCheckpoint { slab, node_seeds, cert, origin, witness_sks } => {
            let l = open_ledger(&slab);
            let ck = bitcache::checkpoint::Checkpoint { origin, size: l.size(), root: l.root() };
            let mut cos = Vec::new();
            for w in &witness_sks {
                let kp = Keypair::from_sk_bytes(&std::fs::read(w).unwrap_or_else(|e| die(30, format!("open witness sk {w}: {e}"))))
                    .unwrap_or_else(|e| die(31, format!("parse witness sk: {e}")));
                cos.push(bitcache::checkpoint::cosign(&ck, &kp).unwrap_or_else(|e| die(32, format!("cosign: {e}"))));
            }
            let wire = bitcache::checkpoint::sign(&ck, &node_key(&node_seeds), &read_file_or_b64(&cert, "cert"), &cos)
                .unwrap_or_else(|e| die(33, format!("checkpoint sign: {e:?}")));
            println!("size\t{}\nroot\t{}\ncheckpoint\t{}", ck.size, hex32_encode(&ck.root), base64_encode(&wire));
        }

        Cmd::TlogVerifyCheckpoint { wire, authority_vk, pos, witness_vks, quorum } => {
            let w = read_file_or_b64(&wire, "checkpoint");
            let avk = read_file_or_b64(&authority_vk, "authority vk");
            let roster: Vec<Vec<u8>> = witness_vks.iter().map(|x| read_file_or_b64(x, "witness vk")).collect();
            let r: Vec<&[u8]> = roster.iter().map(Vec::as_slice).collect();
            match bitcache::checkpoint::verify(&w, &avk, pos, &r, quorum) {
                Ok(ck) => { println!("origin\t{}\nsize\t{}\nroot\t{}", ck.origin, ck.size, hex32_encode(&ck.root)); std::process::exit(0) }
                Err(e) => { eprintln!("tlog-verify-checkpoint FAIL: {e:?} ({})", e.code()); std::process::exit(7) }
            }
        }
    }
}

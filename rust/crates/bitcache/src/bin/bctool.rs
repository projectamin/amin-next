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
    }
}

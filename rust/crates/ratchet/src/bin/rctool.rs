//! rctool — CLI bridge between the Perl `sec:` SAX filters and the Rust
//! [`ratchet`] crate (post-quantum Double Ratchet + PQXDH).
//!
//! Same shape as `bctool`: TSV on stdout so the Perl side can `split /\t/`,
//! and stable exit codes matched by `$? >> 8`.  No FFI — the landlocked metal
//! profile grants `aminexec` `FILE__EXECUTE` on the tool binary only.
//!
//! Every binary blob on the wire is **lowercase hex** (`hex`), so `rctool`
//! needs no base64 codec; the `sec:` SAX elements carry the same hex in their
//! attributes and element text.
//!
//! ## Commands
//! ```text
//!   rctool genkey        --sk PATH
//!       # write a 32-byte ML-DSA-87 seed (chmod 0600);
//!       # print `vk\tHEX` and `safety\tHEX`
//!   rctool safety        --vk HEX
//!   rctool dh-gen        --path PATH
//!       # write a 32-byte X25519 secret (chmod 0600); print `pub\tHEX`
//!   rctool prekey-gen    --sk PATH --prekeys PATH --id N [--otp]
//!       # write the private prekey set (chmod 0600); print the signed
//!       # public bundle as TSV on stdout
//!   rctool prekey-verify --bundle PATH|-
//!   rctool prekey-safety --bundle PATH|-
//!   rctool init          --bundle PATH|- --id-dh PATH --state PATH
//!       # PQXDH initiator; write session state; print the initial message
//!   rctool respond       --msg PATH|- --prekeys PATH --state PATH
//!       # PQXDH responder; write session state
//!   rctool seal          --state PATH [--ad STR]         # stdin = plaintext
//!       # print `dh\tHEX\npn\tDEC\nn\tDEC\nct\tHEX`; rewrite --state
//!   rctool open          --state PATH --dh HEX --pn N --n N [--ad STR]
//!       # stdin = hex ciphertext; plaintext to stdout; rewrite --state
//!   rctool state         --state PATH
//! ```
//!
//! Exit codes (stable — Perl `$? >> 8` matches them):
//!   0 OK | 2 usage | 7 auth failed | 8 bad key/hex input |
//!   9 replay or protocol violation | 10..=49 tool errors

use clap::{Parser, Subcommand};
use std::io::{Read, Write};

use rand::rngs::OsRng;

use ratchet::{
    mlkem768_dk_from_bytes, mlkem768_dk_to_bytes, Header, IdentitySigningKey,
    IdentityVerifyingKey, PqxdhInitialMessage, PrekeyBundle, RatchetError, ResponderPrekeys,
    Session, SessionState, X25519Keypair,
};

#[derive(Parser)]
#[command(name = "rctool", version, about = "Amin 3 sec: ratchet helper")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an ML-DSA-87 identity signing key (32-byte seed) at --sk.
    Genkey {
        #[arg(long)]
        sk: String,
    },
    /// Print the safety number (blake3 hex) for an ML-DSA-87 verifying key.
    Safety {
        #[arg(long)]
        vk: String,
    },
    /// Generate an X25519 key pair; write the 32-byte secret to --path.
    DhGen {
        #[arg(long)]
        path: String,
    },
    /// Generate responder prekeys and the signed public bundle.
    PrekeyGen {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        prekeys: String,
        #[arg(long)]
        id: u32,
        /// Include a one-time prekey (consumed by the first handshake).
        #[arg(long)]
        otp: bool,
    },
    /// Verify a public bundle's ML-DSA-87 signatures.
    PrekeyVerify {
        #[arg(long)]
        bundle: String,
    },
    /// Print a bundle's safety number.
    PrekeySafety {
        #[arg(long)]
        bundle: String,
    },
    /// PQXDH initiator: write session state, print the initial message.
    Init {
        #[arg(long)]
        bundle: String,
        #[arg(long = "id-dh")]
        id_dh: String,
        #[arg(long)]
        state: String,
    },
    /// PQXDH responder: write session state.
    Respond {
        #[arg(long)]
        msg: String,
        #[arg(long)]
        prekeys: String,
        #[arg(long)]
        state: String,
    },
    /// Encrypt stdin, rewrite --state, print header + ciphertext (TSV).
    Seal {
        #[arg(long)]
        state: String,
        #[arg(long, default_value = "")]
        ad: String,
    },
    /// Decrypt a hex ciphertext, rewrite --state, print the plaintext.
    Open {
        #[arg(long)]
        state: String,
        #[arg(long)]
        dh: String,
        #[arg(long)]
        pn: u32,
        #[arg(long)]
        n: u32,
        #[arg(long, default_value = "")]
        ad: String,
    },
    /// Print session diagnostics.
    State {
        #[arg(long)]
        state: String,
    },
}

fn die(code: i32, s: impl std::fmt::Display) -> ! {
    eprintln!("rctool: {s}");
    std::process::exit(code);
}

/// Map a ratchet error onto a stable exit code.
fn err_code(e: &RatchetError) -> i32 {
    match e {
        RatchetError::Aead => 7,
        RatchetError::DuplicateMessage | RatchetError::TooManySkipped | RatchetError::NoSendingChain => 9,
        RatchetError::KeyMaterial | RatchetError::Signature | RatchetError::Header => 8,
        RatchetError::Kem => 10,
    }
}

fn rct<T>(r: ratchet::Result<T>) -> T {
    r.unwrap_or_else(|e| die(err_code(&e), e))
}

// ── hex codec ───────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex ({} chars)", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        out.push(
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| format!("bad hex at byte {i}"))?,
        );
    }
    Ok(out)
}

fn arr32(s: &str) -> Result<[u8; 32], String> {
    let v = hex_decode(s)?;
    let n = v.len();
    v.try_into().map_err(|_| format!("expected 32-byte hex, got {n}"))
}

fn opt32(s: &str) -> Result<Option<[u8; 32]>, String> {
    let t = s.trim();
    if t.is_empty() || t == "-" {
        return Ok(None);
    }
    Ok(Some(arr32(t)?))
}

// ── input helpers ───────────────────────────────────────────────────────────

/// Read a text argument: `-` means stdin, anything else is a file path.
fn read_text(token: &str, label: &str) -> String {
    if token == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .unwrap_or_else(|e| die(10, format!("read stdin ({label}): {e}")));
        s
    } else {
        std::fs::read_to_string(token)
            .unwrap_or_else(|e| die(10, format!("read {label} {token}: {e}")))
    }
}

fn read_bytes(token: &str, label: &str) -> Vec<u8> {
    std::fs::read(token).unwrap_or_else(|e| die(10, format!("read {label} {token}: {e}")))
}

/// Write a secret-bearing file with mode 0600.
fn write_secret(path: &str, bytes: &[u8]) {
    use std::fs::OpenOptions;
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap_or_else(|e| die(20, format!("open {path}: {e}")));
    f.write_all(bytes)
        .unwrap_or_else(|e| die(21, format!("write {path}: {e}")));
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| die(22, format!("chmod 600 {path}: {e}")));
    }
}

// ── TSV records ─────────────────────────────────────────────────────────────

/// First component of every `key\tvalue…` line, plus the remaining columns.
fn rows(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter_map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() {
                return None;
            }
            Some(line.split('\t').map(str::to_string).collect())
        })
        .collect()
}

fn field<'a>(r: &'a [Vec<String>], key: &str) -> Option<&'a str> {
    r.iter().find(|c| c[0] == key).and_then(|c| c.get(1)).map(String::as_str)
}

fn need<'a>(r: &'a [Vec<String>], key: &str, label: &str) -> &'a str {
    field(r, key).unwrap_or_else(|| die(8, format!("{label}: missing `{key}` field")))
}

// ── session state ───────────────────────────────────────────────────────────

fn state_to_text(s: &SessionState) -> String {
    let mut o = String::new();
    o.push_str(&format!("dh_self_secret\t{}\n", hex_encode(&s.dh_self_secret)));
    o.push_str(&format!(
        "dh_remote\t{}\n",
        s.dh_remote.map_or_else(|| "-".into(), |k| hex_encode(&k))
    ));
    o.push_str(&format!("root\t{}\n", hex_encode(&s.root)));
    o.push_str(&format!(
        "ck_send\t{}\n",
        s.ck_send.map_or_else(|| "-".into(), |k| hex_encode(&k))
    ));
    o.push_str(&format!(
        "ck_recv\t{}\n",
        s.ck_recv.map_or_else(|| "-".into(), |k| hex_encode(&k))
    ));
    o.push_str(&format!("n_send\t{}\n", s.n_send));
    o.push_str(&format!("n_recv\t{}\n", s.n_recv));
    o.push_str(&format!("pn\t{}\n", s.pn));
    for (dh, n, mk) in &s.skipped {
        o.push_str(&format!("skipped\t{}\t{n}\t{}\n", hex_encode(dh), hex_encode(mk)));
    }
    o
}

fn state_from_text(text: &str) -> Result<SessionState, String> {
    let r = rows(text);
    let dh_self_secret = arr32(need(&r, "dh_self_secret", "state"))?;
    let root = arr32(need(&r, "root", "state"))?;
    let dh_remote = opt32(field(&r, "dh_remote").unwrap_or("-"))?;
    let ck_send = opt32(field(&r, "ck_send").unwrap_or("-"))?;
    let ck_recv = opt32(field(&r, "ck_recv").unwrap_or("-"))?;
    let num = |k: &str| -> Result<u32, String> {
        field(&r, k).unwrap_or("0").parse::<u32>().map_err(|_| format!("state: bad {k}"))
    };
    let mut skipped = Vec::new();
    for c in r.iter().filter(|c| c[0] == "skipped") {
        if c.len() != 4 {
            return Err("state: malformed skipped row".into());
        }
        skipped.push((arr32(&c[1])?, c[2].parse::<u32>().map_err(|_| "state: bad skipped n")?, arr32(&c[3])?));
    }
    Ok(SessionState {
        dh_self_secret,
        dh_remote,
        root,
        ck_send,
        ck_recv,
        n_send: num("n_send")?,
        n_recv: num("n_recv")?,
        pn: num("pn")?,
        skipped,
    })
}

fn load_state(path: &str) -> SessionState {
    let text = read_bytes(path, "state");
    let text = String::from_utf8(text).unwrap_or_else(|_| die(8, format!("state {path}: not UTF-8")));
    state_from_text(&text).unwrap_or_else(|e| die(8, format!("state {path}: {e}")))
}

fn save_state(path: &str, s: &Session) {
    write_secret(path, state_to_text(&s.export_state()).as_bytes());
}

// ── prekey bundle ───────────────────────────────────────────────────────────

fn bundle_to_text(b: &PrekeyBundle) -> String {
    let mut o = String::new();
    o.push_str(&format!("identity_vk\t{}\n", hex_encode(&b.identity_vk)));
    o.push_str(&format!("identity_dh\t{}\n", hex_encode(&b.identity_dh)));
    o.push_str(&format!("signed_prekey\t{}\n", hex_encode(&b.signed_prekey)));
    o.push_str(&format!("signed_prekey_sig\t{}\n", hex_encode(&b.signed_prekey_sig)));
    o.push_str(&format!("pq_prekey\t{}\n", hex_encode(&b.pq_prekey)));
    o.push_str(&format!("pq_prekey_sig\t{}\n", hex_encode(&b.pq_prekey_sig)));
    if let Some(o_) = b.one_time_prekey {
        o.push_str(&format!("one_time_prekey\t{}\n", hex_encode(&o_)));
    }
    o.push_str(&format!("prekey_id\t{}\n", b.prekey_id));
    o
}

fn bundle_from_text(text: &str) -> Result<PrekeyBundle, String> {
    let r = rows(text);
    Ok(PrekeyBundle {
        identity_vk: hex_decode(need(&r, "identity_vk", "bundle"))?,
        identity_dh: arr32(need(&r, "identity_dh", "bundle"))?,
        signed_prekey: arr32(need(&r, "signed_prekey", "bundle"))?,
        signed_prekey_sig: hex_decode(need(&r, "signed_prekey_sig", "bundle"))?,
        pq_prekey: hex_decode(need(&r, "pq_prekey", "bundle"))?,
        pq_prekey_sig: hex_decode(need(&r, "pq_prekey_sig", "bundle"))?,
        one_time_prekey: opt32(field(&r, "one_time_prekey").unwrap_or("-"))?,
        prekey_id: need(&r, "prekey_id", "bundle").parse::<u32>().map_err(|_| "bundle: bad prekey_id")?,
    })
}

fn load_bundle(token: &str) -> PrekeyBundle {
    let text = read_text(token, "bundle");
    bundle_from_text(&text).unwrap_or_else(|e| die(8, e))
}

// ── responder prekeys ───────────────────────────────────────────────────────

fn prekeys_to_text(p: &ResponderPrekeys) -> String {
    let mut o = String::new();
    o.push_str(&format!("identity_dh\t{}\n", hex_encode(&p.identity_dh.secret_bytes())));
    o.push_str(&format!("signed_prekey\t{}\n", hex_encode(&p.signed_prekey.secret_bytes())));
    o.push_str(&format!(
        "one_time_prekey\t{}\n",
        p.one_time_prekey.as_ref().map_or_else(|| "-".into(), |k| hex_encode(&k.secret_bytes()))
    ));
    o.push_str(&format!("pq_prekey\t{}\n", hex_encode(&mlkem768_dk_to_bytes(&p.pq_prekey))));
    o
}

fn prekeys_from_text(text: &str) -> Result<ResponderPrekeys, String> {
    let r = rows(text);
    let one_time_prekey = match opt32(field(&r, "one_time_prekey").unwrap_or("-"))? {
        Some(b) => Some(X25519Keypair::from_secret_bytes(b)),
        None => None,
    };
    Ok(ResponderPrekeys {
        identity_dh: X25519Keypair::from_secret_bytes(arr32(need(&r, "identity_dh", "prekeys"))?),
        signed_prekey: X25519Keypair::from_secret_bytes(arr32(need(&r, "signed_prekey", "prekeys"))?),
        one_time_prekey,
        pq_prekey: mlkem768_dk_from_bytes(&hex_decode(need(&r, "pq_prekey", "prekeys"))?)
            .unwrap_or_else(|e| die(8, format!("prekeys: {e}"))),
    })
}

// ── PQXDH initial message ───────────────────────────────────────────────────

fn msg_to_text(m: &PqxdhInitialMessage) -> String {
    let mut o = String::new();
    o.push_str(&format!("identity_dh\t{}\n", hex_encode(&m.identity_dh)));
    o.push_str(&format!("ephemeral\t{}\n", hex_encode(&m.ephemeral)));
    o.push_str(&format!("pq_ciphertext\t{}\n", hex_encode(&m.pq_ciphertext)));
    o.push_str(&format!("prekey_id\t{}\n", m.prekey_id));
    o.push_str(&format!("used_one_time_prekey\t{}\n", u8::from(m.used_one_time_prekey)));
    o
}

fn msg_from_text(text: &str) -> Result<PqxdhInitialMessage, String> {
    let r = rows(text);
    Ok(PqxdhInitialMessage {
        identity_dh: arr32(need(&r, "identity_dh", "msg"))?,
        ephemeral: arr32(need(&r, "ephemeral", "msg"))?,
        pq_ciphertext: hex_decode(need(&r, "pq_ciphertext", "msg"))?,
        prekey_id: need(&r, "prekey_id", "msg").parse::<u32>().map_err(|_| "msg: bad prekey_id")?,
        used_one_time_prekey: need(&r, "used_one_time_prekey", "msg") == "1",
    })
}

// ── dispatch ────────────────────────────────────────────────────────────────

fn main() {
    match Cli::parse().cmd {
        Cmd::Genkey { sk } => {
            let key = IdentitySigningKey::generate(&mut OsRng);
            write_secret(&sk, &key.to_bytes());
            let vk = key.verifying_key();
            println!("vk\t{}", hex_encode(&vk.to_bytes()));
            println!("safety\t{}", vk.safety_number());
        }

        Cmd::Safety { vk } => {
            let vk = IdentityVerifyingKey::from_bytes(&hex_decode(&vk).unwrap_or_else(|e| die(8, e)))
                .unwrap_or_else(|e| die(8, e));
            println!("safety\t{}", vk.safety_number());
        }

        Cmd::DhGen { path } => {
            let kp = X25519Keypair::generate(&mut OsRng);
            write_secret(&path, &kp.secret_bytes());
            println!("pub\t{}", hex_encode(&kp.public_bytes()));
        }

        Cmd::PrekeyGen { sk, prekeys, id, otp } => {
            let identity = IdentitySigningKey::from_bytes(&read_bytes(&sk, "sk"))
                .unwrap_or_else(|e| die(8, format!("sk {sk}: {e}")));
            let (privs, bundle) =
                rct(ResponderPrekeys::generate(&mut OsRng, &identity, id, otp));
            write_secret(&prekeys, prekeys_to_text(&privs).as_bytes());
            print!("{}", bundle_to_text(&bundle));
        }

        Cmd::PrekeyVerify { bundle } => {
            let b = load_bundle(&bundle);
            match b.verify() {
                Ok(()) => println!("verify\tOK"),
                Err(e) => die(7, format!("prekey verify failed: {e}")),
            }
        }

        Cmd::PrekeySafety { bundle } => {
            let b = load_bundle(&bundle);
            println!("safety\t{}", rct(b.safety_number()));
        }

        Cmd::Init { bundle, id_dh, state } => {
            let b = load_bundle(&bundle);
            let dh_bytes = read_bytes(&id_dh, "id-dh");
            let arr: [u8; 32] = dh_bytes
                .as_slice()
                .try_into()
                .unwrap_or_else(|_| die(8, format!("id-dh {id_dh}: expected 32 bytes")));
            let initiator = X25519Keypair::from_secret_bytes(arr);
            let (sk, msg, ratchet_pub) =
                rct(ratchet::initiate(&b, &initiator, &mut OsRng));
            let session = Session::init_initiator(sk, ratchet_pub, &mut OsRng);
            save_state(&state, &session);
            print!("{}", msg_to_text(&msg));
        }

        Cmd::Respond { msg, prekeys, state } => {
            let m = msg_from_text(&read_text(&msg, "msg")).unwrap_or_else(|e| die(8, e));
            let privs = prekeys_from_text(&read_text(&prekeys, "prekeys"))
                .unwrap_or_else(|e| die(8, e));
            let (sk, _ratchet_pub) = rct(ratchet::respond(&m, &privs));
            let session = Session::init_responder(sk, privs.signed_prekey);
            save_state(&state, &session);
        }

        Cmd::Seal { state, ad } => {
            let mut session = Session::import_state(load_state(&state));
            let mut pt = Vec::new();
            std::io::stdin()
                .read_to_end(&mut pt)
                .unwrap_or_else(|e| die(10, format!("read stdin: {e}")));
            let (header, ct) = rct(session.encrypt(&pt, ad.as_bytes()));
            save_state(&state, &session);
            println!("dh\t{}", hex_encode(&header.dh));
            println!("pn\t{}", header.pn);
            println!("n\t{}", header.n);
            println!("ct\t{}", hex_encode(&ct));
        }

        Cmd::Open { state, dh, pn, n, ad } => {
            let mut session = Session::import_state(load_state(&state));
            let header = Header { dh: arr32(&dh).unwrap_or_else(|e| die(8, e)), pn, n };
            let ct = hex_decode(&read_text("-", "ciphertext")).unwrap_or_else(|e| die(8, e));
            let pt = rct(session.decrypt(&header, &ct, ad.as_bytes()));
            save_state(&state, &session);
            std::io::stdout()
                .write_all(&pt)
                .unwrap_or_else(|e| die(14, format!("write stdout: {e}")));
        }

        Cmd::State { state } => {
            let s = load_state(&state);
            println!("n_send\t{}", s.n_send);
            println!("n_recv\t{}", s.n_recv);
            println!("pn\t{}", s.pn);
            println!("skipped\t{}", s.skipped.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("rctool-test-{tag}-{}", std::process::id()));
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_encode(&bytes), "0001abff");
        assert_eq!(hex_decode("0001abff").unwrap(), bytes);
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn bundle_record_round_trips() {
        let identity = IdentitySigningKey::generate(&mut OsRng);
        let (_, bundle) = ResponderPrekeys::generate(&mut OsRng, &identity, 7, true).unwrap();
        let text = bundle_to_text(&bundle);
        let back = bundle_from_text(&text).unwrap();
        assert_eq!(back, bundle);
        back.verify().unwrap();
    }

    #[test]
    fn prekeys_record_round_trips() {
        let identity = IdentitySigningKey::generate(&mut OsRng);
        let (privs, _) = ResponderPrekeys::generate(&mut OsRng, &identity, 1, true).unwrap();
        let text = prekeys_to_text(&privs);
        let back = prekeys_from_text(&text).unwrap();
        assert_eq!(back.identity_dh.public_bytes(), privs.identity_dh.public_bytes());
        assert_eq!(back.signed_prekey.public_bytes(), privs.signed_prekey.public_bytes());
        assert_eq!(mlkem768_dk_to_bytes(&back.pq_prekey), mlkem768_dk_to_bytes(&privs.pq_prekey));
    }

    #[test]
    fn state_record_round_trips_for_a_live_session() {
        let bob_ratchet = X25519Keypair::generate(&mut OsRng);
        let sk = ratchet::Secret::from_bytes([9u8; 32]);
        let mut alice = Session::init_initiator(sk.clone(), bob_ratchet.public_bytes(), &mut OsRng);
        let mut bob = Session::init_responder(sk, bob_ratchet);

        let (h, ct) = alice.encrypt(b"hi", b"ad").unwrap();
        bob.decrypt(&h, &ct, b"ad").unwrap();
        let (h2, ct2) = bob.encrypt(b"reply", b"ad").unwrap();
        alice.decrypt(&h2, &ct2, b"ad").unwrap();

        let snapshot = alice.export_state();
        let back = state_from_text(&state_to_text(&snapshot)).unwrap();
        assert_eq!(back.n_send, snapshot.n_send);
        assert_eq!(back.n_recv, snapshot.n_recv);
        assert_eq!(back.root, snapshot.root);
        assert_eq!(back.skipped.len(), snapshot.skipped.len());

        // A restored session keeps talking to the same peer.
        let mut alice2 = Session::import_state(back);
        let (h3, ct3) = alice2.encrypt(b"more", b"ad").unwrap();
        assert_eq!(bob.decrypt(&h3, &ct3, b"ad").unwrap(), b"more");
    }

    #[test]
    fn msg_record_round_trips() {
        let identity = IdentitySigningKey::generate(&mut OsRng);
        let (_, bundle) = ResponderPrekeys::generate(&mut OsRng, &identity, 3, false).unwrap();
        let initiator = X25519Keypair::generate(&mut OsRng);
        let (_, msg, _) = ratchet::initiate(&bundle, &initiator, &mut OsRng).unwrap();
        let back = msg_from_text(&msg_to_text(&msg)).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn seal_open_files_round_trip() {
        // Drive the full handshake then a seal/open through the files.
        let sk_path = tmp("sk");
        let prekeys_path = tmp("prekeys");
        let bundle_path = tmp("bundle");
        let dh_path = tmp("dh");
        let alice_state = tmp("alice.state");
        let bob_state = tmp("bob.state");

        let identity = IdentitySigningKey::generate(&mut OsRng);
        write_secret(&sk_path, &identity.to_bytes());
        let (privs, bundle) = ResponderPrekeys::generate(&mut OsRng, &identity, 1, true).unwrap();
        write_secret(&prekeys_path, prekeys_to_text(&privs).as_bytes());
        std::fs::write(&bundle_path, bundle_to_text(&bundle)).unwrap();

        let b = load_bundle(&bundle_path);
        let initiator = X25519Keypair::generate(&mut OsRng);
        write_secret(&dh_path, &initiator.secret_bytes());
        let (sk, msg, ratchet_pub) = ratchet::initiate(&b, &initiator, &mut OsRng).unwrap();
        let mut alice = Session::init_initiator(sk, ratchet_pub, &mut OsRng);

        let privs2 = prekeys_from_text(&read_text(&prekeys_path, "prekeys")).unwrap();
        let msg2 = msg_from_text(&msg_to_text(&msg)).unwrap();
        let (sk2, _) = ratchet::respond(&msg2, &privs2).unwrap();
        let bob0 = Session::init_responder(sk2, privs2.signed_prekey);
        write_secret(&bob_state, state_to_text(&bob0.export_state()).as_bytes());

        // Alice seals; her advanced state is persisted.
        let (header, ct) = alice.encrypt(b"over the wire", b"room:1").unwrap();
        write_secret(&alice_state, state_to_text(&alice.export_state()).as_bytes());

        // Bob opens from his persisted state.
        let mut bob = Session::import_state(load_state(&bob_state));
        let pt = bob.decrypt(&header, &ct, b"room:1").unwrap();
        assert_eq!(pt, b"over the wire");

        for p in [sk_path, prekeys_path, bundle_path, dh_path, alice_state, bob_state] {
            let _ = std::fs::remove_file(p);
        }
    }
}

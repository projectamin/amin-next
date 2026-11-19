//! Adapter-side session plumbing — the Rust form of `Amin::AXA::Session`.
//!
//! An opaque cookie id and a CSRF token (axa-plan §4.7/§5.6).  Transport
//! hygiene only: a session is never a principal; it selects which store record
//! to attach to.  First pass has no ZCap binding over HTTP (anonymous
//! browsing), so the CSRF token is what the cookie must present on mutations.

use rand::Rng;
use sha2::{Digest, Sha256};

/// The session cookie name.
pub const COOKIE: &str = "axa_sid";

/// Session id and CSRF helpers (≈ the `Amin::AXA::Session` class methods).
#[derive(Debug)]
pub struct Session;

impl Session {
    /// Mint a fresh `(sid, csrf)` pair.
    ///
    /// Both are SHA-256 hex of a `/`-joined random/process/time tuple, the CSRF
    /// folding in the freshly minted sid — the same shape as the Perl `mint`.
    /// The values are opaque and never compared across implementations.
    #[must_use]
    pub fn mint() -> (String, String) {
        let mut rng = rand::thread_rng();
        let sid = sha256_hex(&join(&[
            rand_part(&mut rng),
            rand_part(&mut rng),
            rand_part(&mut rng),
            rand_part(&mut rng),
            std::process::id().to_string(),
            now_secs().to_string(),
            rand_part(&mut rng),
        ]));
        let csrf = sha256_hex(&join(&[
            rand_part(&mut rng),
            rand_part(&mut rng),
            rand_part(&mut rng),
            rand_part(&mut rng),
            sid.clone(),
            rand_part(&mut rng),
        ]));
        (sid, csrf)
    }

    /// The `axa_sid` value in a `Cookie:` header, when it is a 64-char hex id.
    #[must_use]
    pub fn cookie_sid(cookie_header: Option<&str>) -> Option<String> {
        for pair in cookie_header.unwrap_or("").split(';') {
            let pair = pair.trim_start();
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            if k == COOKIE && is_sid(v) {
                return Some(v.to_string());
            }
        }
        None
    }

    /// The `Set-Cookie` header value for `sid`.
    #[must_use]
    pub fn set_cookie(sid: &str) -> String {
        format!("{COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax")
    }
}

/// `^[0-9a-f]{64}$`.
fn is_sid(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A `/`-joined random part (Perl uses a bare `rand` interpolation).
fn rand_part<R: Rng>(rng: &mut R) -> String {
    rng.gen::<f64>().to_string()
}

/// Seconds since the Unix epoch (Perl `time()`).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn join(parts: &[String]) -> String {
    parts.join("/")
}

/// Lowercase hex SHA-256 (≈ `Digest::SHA::sha256_hex`).
#[must_use]
pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

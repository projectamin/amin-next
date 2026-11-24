//! URI/bitcache resolution for machine specs and related documents.
//!
//! Parity target: `Amin::Machine::MachineSpec::_load_uri_static` and
//! `Amin::Bitcache::Reference`. Resolution is fail-closed: errors return None/Err,
//! callers degrade or refuse as appropriate.

use std::path::{Path, PathBuf};

/// A resolved document source.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// Document bytes (UTF-8 text expected by spec/profile parsers).
    pub bytes: Vec<u8>,
    /// Canonical source label for diagnostics.
    pub source: String,
}

/// Resolve a spec/profile/document reference to bytes.
///
/// Supported: local path, `file://`, `http://`, `https://`, `bitcache://`, `bc://`.
/// Bitcache references require signer metadata in URI query or environment/trust anchor;
/// unresolved/unverified references fail closed.
pub fn resolve(uri_or_path: &str) -> Result<Resolved, String> {
    resolve_with(uri_or_path, &ResolveOptions::default())
}

/// Options influencing bitcache/HTTP resolution.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    pub slab_path: Option<PathBuf>,
    pub trust_anchor_dir: Option<PathBuf>,
    pub bctool_path: Option<PathBuf>,
    pub signer_name: Option<String>,
    pub signer_ts: Option<String>,
    pub signer_vk: Option<String>,
    pub signer_sig: Option<String>,
}

pub fn resolve_with(uri_or_path: &str, opts: &ResolveOptions) -> Result<Resolved, String> {
    let s = uri_or_path.trim();
    if s.is_empty() {
        return Err("empty URI/path".to_string());
    }

    if is_bitcache_uri(s) {
        return resolve_bitcache(s, opts);
    }
    if let Some(path) = parse_file_uri(s) {
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        return Ok(Resolved { bytes, source: path.display().to_string() });
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return resolve_http(s);
    }
    // Plain local path
    let p = PathBuf::from(s);
    let bytes = std::fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
    Ok(Resolved { bytes, source: p.display().to_string() })
}

pub fn is_uri(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("file://")
        || s.starts_with("http://")
        || s.starts_with("https://")
        || is_bitcache_uri(s)
}

pub fn is_bitcache_uri(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("bitcache://") || s.starts_with("bc://")
}

fn parse_file_uri(s: &str) -> Option<PathBuf> {
    let rest = s.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') {
        return None;
    }
    Some(PathBuf::from(percent_decode(rest)))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn resolve_http(url: &str) -> Result<Resolved, String> {
    // Minimal HTTP(S) fetch via curl to avoid adding heavy deps; fail-closed.
    // This keeps runtime behavior deterministic in environments where curl is present.
    // If curl is unavailable, return an explicit error.
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "20", "--proto", "=http,https", url])
        .output()
        .map_err(|e| format!("http fetch {url}: curl unavailable: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "http fetch {url}: curl failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if out.stdout.is_empty() {
        return Err(format!("http fetch {url}: empty response"));
    }
    Ok(Resolved { bytes: out.stdout, source: url.to_string() })
}

#[derive(Debug, Clone)]
struct BitcacheRef {
    hash_hex: String,
    signer_name: Option<String>,
    signer_ts: Option<String>,
    signer_vk: Option<String>,
    signer_sig: Option<String>,
}

fn parse_bitcache_ref(uri: &str) -> Result<BitcacheRef, String> {
    let norm = if let Some(rest) = uri.strip_prefix("bc://") {
        format!("bitcache://{rest}")
    } else {
        uri.to_string()
    };
    let rest = norm
        .strip_prefix("bitcache://")
        .ok_or_else(|| "not a bitcache URI".to_string())?;
    let (authority_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (authority, path) = authority_path
        .split_once('/')
        .ok_or_else(|| "bitcache URI missing hash path".to_string())?;
    if authority != "blake3" {
        return Err(format!("unsupported bitcache authority: {authority}"));
    }
    let hash_hex = path.trim_start_matches('/').to_string();
    if hash_hex.len() != 64 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bitcache hash must be 64 hex chars".to_string());
    }
    let mut r = BitcacheRef {
        hash_hex: hash_hex.to_ascii_lowercase(),
        signer_name: None,
        signer_ts: None,
        signer_vk: None,
        signer_sig: None,
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k {
            "signer" => r.signer_name = Some(v),
            "ts" => r.signer_ts = Some(v),
            "vk" => r.signer_vk = Some(v),
            "sig" => r.signer_sig = Some(v),
            _ => {}
        }
    }
    Ok(r)
}

fn resolve_bitcache(uri: &str, opts: &ResolveOptions) -> Result<Resolved, String> {
    let mut r = parse_bitcache_ref(uri)?;
    // Fill from options if URI omitted them.
    r.signer_name = r.signer_name.or_else(|| opts.signer_name.clone());
    r.signer_ts = r.signer_ts.or_else(|| opts.signer_ts.clone());
    r.signer_vk = r.signer_vk.or_else(|| opts.signer_vk.clone());
    r.signer_sig = r.signer_sig.or_else(|| opts.signer_sig.clone());

    let signer_name = r.signer_name.as_deref().ok_or("bitcache ref missing signer")?;
    let signer_ts = r.signer_ts.as_deref().ok_or("bitcache ref missing ts")?;
    let signer_sig = r.signer_sig.as_deref().ok_or("bitcache ref missing sig")?;

    let slab_path = opts
        .slab_path
        .clone()
        .or_else(|| std::env::var_os("AMIN_SLAB_PATH").map(PathBuf::from))
        .unwrap_or_else(default_slab_path);
    let trust_anchor_dir = opts
        .trust_anchor_dir
        .clone()
        .or_else(|| std::env::var_os("AMIN_TRUST_ANCHOR_DIR").map(PathBuf::from));

    let hash_bytes = hex_to_32(&r.hash_hex).ok_or("invalid bitcache hash")?;
    let obj = bitcache::ObjRef(hash_bytes);

    // Read object from slab.
    let mut slab = bitcache::SlabFile::open_or_create(&slab_path)
        .map_err(|e| format!("open slab {}: {e}", slab_path.display()))?;
    let bytes = slab
        .get(&obj)
        .map_err(|e| format!("bitcache get {}: {e}", r.hash_hex))?;

    // Resolve VK: inline vk, trust anchor dir, or env/default trust anchor.
    let vk_bytes = resolve_vk(&r, signer_name, trust_anchor_dir.as_deref())?;

    // Verify signature over the object hash using SignedEnvelope-compatible payload.
    let ts = signer_ts
        .parse::<u64>()
        .map_err(|_| "bitcache ts must be unix seconds".to_string())?;
    let sig_bytes = bitcache::base64_decode(signer_sig)
        .map_err(|e| format!("bitcache sig is not valid base64: {e}"))?;
    if sig_bytes.len() != bitcache::MLDSA87_SIG_LEN {
        return Err(format!(
            "bitcache sig length {}, expected {}",
            sig_bytes.len(),
            bitcache::MLDSA87_SIG_LEN
        ));
    }
    let mut sig_arr = [0u8; bitcache::MLDSA87_SIG_LEN];
    sig_arr.copy_from_slice(&sig_bytes);

    let env = bitcache::SignedEnvelope {
        name: signer_name.to_string(),
        date: bitcache::rfc3339_now(),
        keyref_pem: String::new(),
        obj_ref: obj,
        timestamp: ts,
        signature: bitcache::BcSignature(sig_arr),
    };
    env.verify(&vk_bytes)
        .map_err(|e| format!("bitcache verify {}: {e}", r.hash_hex))?;

    Ok(Resolved { bytes, source: uri.to_string() })
}

fn resolve_vk(r: &BitcacheRef, signer_name: &str, trust_anchor_dir: Option<&Path>) -> Result<Vec<u8>, String> {
    if let Some(vk) = &r.signer_vk {
        // vk may be base64 or path
        if let Ok(bytes) = bitcache::base64_decode(vk) {
            if bytes.len() == bitcache::MLDSA87_VK_LEN {
                return Ok(bytes);
            }
        }
        let p = PathBuf::from(vk);
        if p.is_file() {
            let bytes = std::fs::read(&p).map_err(|e| format!("read vk {}: {e}", p.display()))?;
            if bytes.len() == bitcache::MLDSA87_VK_LEN {
                return Ok(bytes);
            }
            if let Ok(dec) = bitcache::base64_decode(String::from_utf8_lossy(&bytes).trim()) {
                if dec.len() == bitcache::MLDSA87_VK_LEN {
                    return Ok(dec);
                }
            }
            return Err(format!("vk file {} has invalid length", p.display()));
        }
        return Err("bitcache vk is neither valid base64 nor file path".to_string());
    }

    if let Some(dir) = trust_anchor_dir {
        let ta = bitcache::TrustAnchor::new(dir);
        return ta
            .load_vk_by_name(signer_name)
            .map_err(|e| format!("trust anchor vk for {signer_name}: {e}"));
    }

    if let Some(dir) = std::env::var_os("AMIN_TRUST_ANCHOR_DIR") {
        let ta = bitcache::TrustAnchor::new(dir);
        return ta
            .load_vk_by_name(signer_name)
            .map_err(|e| format!("trust anchor vk for {signer_name}: {e}"));
    }

    Err("bitcache ref missing vk and no trust anchor dir".to_string())
}

fn hex_to_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 { return None; }
    let mut out = [0u8; 32];
    let b = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(b[i * 2])?;
        let lo = hex_nibble(b[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn default_slab_path() -> PathBuf {
    if let Some(p) = std::env::var_os("HOME") {
        return PathBuf::from(p).join(".amin/bitcache/default.slab");
    }
    PathBuf::from("/tmp/amin-bitcache-default.slab")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bc_alias() {
        let uri = "bc://blake3/".to_string() + &"a".repeat(64) + "?signer=s&ts=1&sig=x";
        let r = parse_bitcache_ref(&uri).unwrap();
        assert_eq!(r.hash_hex, "a".repeat(64));
        assert_eq!(r.signer_name.as_deref(), Some("s"));
    }

    #[test]
    fn file_uri_decode() {
        let p = parse_file_uri("file://localhost/tmp/a%20b.xml").unwrap();
        assert_eq!(p, PathBuf::from("/tmp/a b.xml"));
    }
}

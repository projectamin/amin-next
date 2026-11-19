//! The ACME account key and its openssl bridge — the Rust peer of
//! `Amin::Acme::Key` (proxy-plan §7: Perl ↔ Rust byte-identical decisions).
//!
//! RFC 8555 is a JWS protocol, and the HTTP-01 key authorization a CA fetches
//! is `token "." base64url(SHA-256(canonical JWK))` — the *thumbprint* of the
//! account key (RFC 7638).  This module derives that JWK + thumbprint from an
//! EC P-256 key and signs a JWS (ES256), exactly as the Perl module does, so
//! the two fronts answer a challenge with identical bytes.
//!
//! Every primitive shells out to the `openssl` CLI — the same choice the Perl
//! side makes, and the one the ACME workstream locked in.  ES256 is served:
//! `openssl ec -pubout -outform DER` yields a SubjectPublicKeyInfo whose final
//! 65 bytes are the uncompressed point `04 || X(32) || Y(32)`, and the JWK
//! `x`/`y` are those halves base64url.  `openssl dgst -sha256 -sign` yields an
//! *ASN.1 DER* ECDSA signature `SEQUENCE( INTEGER r, INTEGER s )`, which JWS
//! does NOT want: the raw 64-byte `R || S` is transcoded out of it before it is
//! base64url.
//!
//! The RFC 7638 JWK text is built by hand in the one canonical order EC keys
//! fix (`crv`, `kty`, `x`, `y`) — the Perl module builds the identical bytes,
//! so both derive byte-identical thumbprints.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

/// A failure deriving or using the account key.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// A filesystem or process I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The `openssl` invocation failed (spawn, non-zero exit, or empty output).
    #[error("openssl: {0}")]
    Openssl(String),
    /// The key or signature was not in the shape ES256 requires.
    #[error("{0}")]
    Bad(String),
}

/// An EC P-256 account key, with its JWK coordinates and RFC 7638 thumbprint
/// derived once at load (≈ `Amin::Acme::Key`).
#[derive(Debug, Clone)]
pub struct AcmeKey {
    path: PathBuf,
    x: String,
    y: String,
    thumbprint: String,
}

impl AcmeKey {
    /// Load the key at `path`, deriving its JWK coordinates and thumbprint.
    ///
    /// Fail-fast: a missing or malformed key (or a missing `openssl`) errors
    /// here rather than at the first request.
    ///
    /// # Errors
    /// [`AcmeError::Openssl`] when `openssl` cannot read the key, and
    /// [`AcmeError::Bad`] when the public key is not an uncompressed EC point.
    pub fn load(path: &Path) -> Result<Self, AcmeError> {
        let der = openssl(&["ec", "-in", &path.to_string_lossy(), "-pubout", "-outform", "DER"], None)?;
        if der.len() < 65 {
            return Err(AcmeError::Bad(format!(
                "acme: cannot read public key from {}",
                path.display()
            )));
        }
        let pt = &der[der.len() - 65..];
        if pt[0] != 0x04 {
            return Err(AcmeError::Bad(format!(
                "acme: key {} is not an uncompressed EC point",
                path.display()
            )));
        }
        let x = b64url(&pt[1..33]);
        let y = b64url(&pt[33..65]);
        let canon = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let thumbprint = b64url(&Sha256::digest(canon.as_bytes()));
        Ok(Self {
            path: path.to_path_buf(),
            x,
            y,
            thumbprint,
        })
    }

    /// The RFC 7638 thumbprint (base64url SHA-256 of the canonical JWK).
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// The canonical JWK text (RFC 7638 member order, no whitespace).
    #[must_use]
    pub fn jwk_json(&self) -> String {
        format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            self.x, self.y
        )
    }

    /// The HTTP-01 key authorization for `token`: `token "." thumbprint`
    /// (RFC 8555 §8.1).
    #[must_use]
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint)
    }

    /// The raw 64-byte ES256 signature (`R || S`) over `SHA-256(input)`.
    ///
    /// # Errors
    /// [`AcmeError::Openssl`] when `openssl` cannot sign, and
    /// [`AcmeError::Bad`] when the DER signature is malformed.
    pub fn sign(&self, input: &str) -> Result<Vec<u8>, AcmeError> {
        let der = openssl(
            &[
                "dgst",
                "-sha256",
                "-sign",
                &self.path.to_string_lossy(),
            ],
            Some(input.as_bytes()),
        )?;
        der_es_to_raw(&der)
    }

    /// The flattened JSON JWS (RFC 7515) for `protected_json` and `payload`,
    /// POSTed as `application/jose+json`; a `POST-as-GET` (RFC 8555 §6.3) is
    /// the empty payload.  The JSON member order is the canonical one the Perl
    /// module produces (`payload`, `protected`, `signature`).
    ///
    /// # Errors
    /// As [`AcmeKey::sign`].
    pub fn jws(&self, protected_json: &str, payload: &str) -> Result<String, AcmeError> {
        let ph = b64url(protected_json.as_bytes());
        let pl = if payload.is_empty() {
            String::new()
        } else {
            b64url(payload.as_bytes())
        };
        let raw = self.sign(&format!("{ph}.{pl}"))?;
        Ok(format!(
            r#"{{"payload":"{pl}","protected":"{ph}","signature":"{}"}}"#,
            b64url(&raw)
        ))
    }
}

/// Run `openssl` with `args`, feeding `stdin` (if any), returning stdout.
fn openssl(args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, AcmeError> {
    let mut cmd = Command::new("openssl");
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| AcmeError::Openssl(format!("spawn openssl: {e}")))?;
    if let Some(bytes) = stdin {
        if let Some(mut fh) = child.stdin.take() {
            fh.write_all(bytes)?;
        }
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(AcmeError::Openssl(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(out.stdout)
}

/// base64url, unpadded (RFC 7515 §2).
fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        }
    }
    out
}

/// One DER tag byte, advancing `i`.
fn der_tag(der: &[u8], i: &mut usize) -> Result<u8, AcmeError> {
    let b = *der
        .get(*i)
        .ok_or_else(|| AcmeError::Bad("acme: DER underrun".to_string()))?;
    *i += 1;
    Ok(b)
}

/// A DER length: a single byte < 0x80, else the low 7 bits count the following
/// big-endian length bytes.
fn der_len(der: &[u8], i: &mut usize) -> Result<usize, AcmeError> {
    let b = der_tag(der, i)?;
    if b < 0x80 {
        return Ok(usize::from(b));
    }
    let n = b & 0x7F;
    let mut len = 0usize;
    for _ in 0..n {
        len = len * 256 + usize::from(der_tag(der, i)?);
    }
    Ok(len)
}

/// openssl's `SEQUENCE(r, s)` → the raw `R || S` JWS wants (each integer
/// left-padded to 32 bytes, its DER sign byte stripped).
fn der_es_to_raw(der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let mut i = 0usize;
    if der_tag(der, &mut i)? != 0x30 {
        return Err(AcmeError::Bad("acme: bad DER signature".to_string()));
    }
    der_len(der, &mut i)?;
    if der_tag(der, &mut i)? != 0x02 {
        return Err(AcmeError::Bad("acme: bad DER signature (r)".to_string()));
    }
    let rl = der_len(der, &mut i)?;
    let r = der
        .get(i..i + rl)
        .ok_or_else(|| AcmeError::Bad("acme: DER underrun".to_string()))?
        .to_vec();
    i += rl;
    if der_tag(der, &mut i)? != 0x02 {
        return Err(AcmeError::Bad("acme: bad DER signature (s)".to_string()));
    }
    let sl = der_len(der, &mut i)?;
    let s = der
        .get(i..i + sl)
        .ok_or_else(|| AcmeError::Bad("acme: DER underrun".to_string()))?
        .to_vec();
    let mut out = pad32(&r)?;
    out.extend(pad32(&s)?);
    Ok(out)
}

/// A big-endian DER INTEGER to exactly 32 bytes: strip leading zeros (the DER
/// sign byte on a high-bit value), then left-pad.
fn pad32(int: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let stripped = int
        .iter()
        .position(|&b| b != 0)
        .map_or(&int[int.len()..], |p| &int[p..]);
    if stripped.len() > 32 {
        return Err(AcmeError::Bad("acme: ECDSA integer too large".to_string()));
    }
    let mut out = vec![0u8; 32 - stripped.len()];
    out.extend_from_slice(stripped);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{der_es_to_raw, AcmeKey};
    use std::process::Command;

    fn have_openssl() -> bool {
        Command::new("openssl")
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn der_es_to_raw_pads_both_integers() {
        // SEQUENCE( INTEGER 01, INTEGER 02 ) → 32 bytes || 01 || 32 bytes || 02.
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let raw = der_es_to_raw(&der).expect("decode");
        assert_eq!(raw.len(), 64);
        assert_eq!(raw[31], 1);
        assert_eq!(raw[63], 2);
    }

    #[test]
    fn key_authorization_is_token_dot_thumbprint() {
        if !have_openssl() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("amin-acme-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let key = dir.join("acct.key");
        let gen = Command::new("openssl")
            .args(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out"])
            .arg(&key)
            .status()
            .expect("gen key");
        assert!(gen.success());

        let k = AcmeKey::load(&key).expect("load");
        // The canonical RFC 7638 JWK: member order crv, kty, x, y; no spaces.
        let jwk = k.jwk_json();
        assert!(jwk.starts_with(r#"{"crv":"P-256","kty":"EC","x":""#));
        assert!(jwk.contains(r#"","y":""#));
        assert!(jwk.ends_with(r#""}"#));
        // x and y are 32-byte base64url (43 chars, unpadded).
        assert_eq!(k.thumbprint().len(), 43);
        let ka = k.key_authorization("tokABC");
        assert_eq!(ka, format!("tokABC.{}", k.thumbprint()));

        std::fs::remove_dir_all(&dir).ok();
    }
}

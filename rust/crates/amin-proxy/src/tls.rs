//! TLS termination for the front (proxy-plan §5.5).
//!
//! The accepted socket is wrapped by rustls and the profile's PEM cert/key
//! (§4.1) become the server certificate; ALPN advertises `h2` ahead of
//! `http/1.1`, so an H2 client negotiates H2 and an H1.1 client falls through.
//! From there the plaintext drivers run unchanged — the hop is the same L7 code
//! behind a different [`AsyncRead`](tokio::io::AsyncRead) handle.
//!
//! The crypto provider is named explicitly (`ring`) rather than left to the
//! process default, so a workspace that also enables another provider can never
//! silently change which one terminates TLS here.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::ServerConfig;

/// Build a rustls server config from PEM `cert`/`key` files, with ALPN set to
/// prefer `h2` and fall back to `http/1.1`.
///
/// # Errors
/// The files cannot be read, contain no usable certificate or key, or form a
/// certificate/key pair rustls rejects.
pub(crate) fn server_config(cert: &Path, key: &Path) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(invalid)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(invalid)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Read every `CERTIFICATE` block from `path`.
fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path)?;
    let mut rd = io::BufReader::new(&pem[..]);
    let certs = rustls_pemfile::certs(&mut rd)?;
    if certs.is_empty() {
        return Err(invalid("no certificate in PEM file"));
    }
    Ok(certs.into_iter().map(CertificateDer::from).collect())
}

/// Read the first private key from `path`, accepting PKCS#8, PKCS#1 (RSA), or
/// SEC1 (EC) encoding — the encodings `openssl` emits for each key type.
fn load_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read(path)?;
    let mut rd = io::BufReader::new(&pem[..]);
    if let Some(k) = rustls_pemfile::pkcs8_private_keys(&mut rd)?.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k)));
    }
    let mut rd = io::BufReader::new(&pem[..]);
    if let Some(k) = rustls_pemfile::rsa_private_keys(&mut rd)?.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(k)));
    }
    let mut rd = io::BufReader::new(&pem[..]);
    if let Some(k) = rustls_pemfile::ec_private_keys(&mut rd)?.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(k)));
    }
    Err(invalid("no private key in PEM file"))
}

/// Wrap a rendering error as an `InvalidData` I/O error.
fn invalid<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

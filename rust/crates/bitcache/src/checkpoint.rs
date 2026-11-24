//! Signed log checkpoints — the unit of trust for the Amin ledger.
//!
//! A checkpoint commits to `(origin, size, root)`.  Entries are never signed
//! individually; one signature per batch is what keeps the ledger cheap.
//!
//! Chain of trust (every link post-quantum):
//!
//! ```text
//!   authority ML-DSA-87 ──signs──▶ NodeCert(node_id, H(node_vk), pos window)
//!   node composite (ML-DSA-65 ‖ Ed25519, both must verify) ──signs──▶ body
//!   optional witnesses ML-DSA-87 ──cosign──▶ body   (explicit roster, quorum)
//! ```
//!
//! `origin` must equal the certificate's `node_id`, so a node can only sign
//! checkpoints for its own log.  The node signature and the witness cosignature
//! use distinct domain tags so one can never be replayed as the other.
//!
//! Wire format (all integers little-endian, canonical, no trailing bytes):
//!
//! ```text
//!   body  = "AMIN3-TLOG-CKPT-V1\n" ‖ u32 len ‖ origin ‖ u64 size ‖ root[32]
//!   wire  = body ‖ node_vk[1984] ‖ node_sig[3373] ‖ u32 cert_len ‖ cert
//!                ‖ u16 n ‖ n × ( witness_vk_hash[32] ‖ sig[4627] )
//! ```

use awp3::sign::{CompositeSigningKey, CompositeVerifyingKey, COMPOSITE_SIG_LEN, COMPOSITE_VK_LEN};

use crate::nodecert::NodeCert;
use crate::signer::{mldsa87_sign, mldsa87_verify, Keypair, MLDSA87_SIG_LEN};
use crate::tlog::Hash;
use crate::trust::Reject;

const BODY_MAGIC: &[u8] = b"AMIN3-TLOG-CKPT-V1\n";
const COSIG_MAGIC: &[u8] = b"AMIN3-TLOG-COSIG-V1\n";
const MAX_ORIGIN: usize = 256;
const MAX_CERT: usize = 8192;
const MAX_COSIGS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CkptError {
    Format,
    UnknownKid,
    BadSig,
    /// Node certificate not valid at the supplied authority-log position.
    NotValidAt,
    /// Fewer distinct valid roster cosignatures than required.
    Quorum,
}

impl CkptError {
    pub const fn code(self) -> i32 {
        use crate::trust::*;
        match self {
            CkptError::Format => RC_FORMAT,
            CkptError::UnknownKid => RC_UNKNOWN_KID,
            CkptError::BadSig => RC_BAD_SIG,
            CkptError::NotValidAt => RC_NOT_VALID_AT,
            CkptError::Quorum => RC_QUORUM,
        }
    }
}

impl From<Reject> for CkptError {
    fn from(r: Reject) -> Self {
        match r {
            Reject::Format => CkptError::Format,
            Reject::UnknownKid => CkptError::UnknownKid,
            Reject::BadSig => CkptError::BadSig,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

pub fn vk_hash(vk: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(b"AMIN3-VK-HASH-V1\n");
    h.update(vk);
    *h.finalize().as_bytes()
}

impl Checkpoint {
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(BODY_MAGIC.len() + 4 + self.origin.len() + 8 + 32);
        b.extend_from_slice(BODY_MAGIC);
        b.extend_from_slice(&(self.origin.len() as u32).to_le_bytes());
        b.extend_from_slice(self.origin.as_bytes());
        b.extend_from_slice(&self.size.to_le_bytes());
        b.extend_from_slice(&self.root);
        b
    }

    fn cosig_message(&self) -> Vec<u8> {
        let mut m = COSIG_MAGIC.to_vec();
        m.extend_from_slice(&self.body());
        m
    }
}

/// A witness cosignature over a checkpoint body.
pub fn cosign(ck: &Checkpoint, witness: &Keypair) -> crate::Result<(Hash, Vec<u8>)> {
    Ok((vk_hash(&witness.verifying_key_bytes()), mldsa87_sign(witness, &ck.cosig_message())?))
}

/// Re-assemble a signed checkpoint with a (merged, de-duplicated) set of witness
/// cosignatures.  The node signature covers only the body, so witnesses can be
/// collected after the node signed and attached by anyone holding the wire.
/// Nothing is verified here — [`verify`] checks it all.
pub fn attach_cosigs(wire: &[u8], add: &[(Hash, Vec<u8>)]) -> Result<Vec<u8>, CkptError> {
    let ck = parse_unverified(wire)?;
    let body_len = ck.body().len();
    let mut c = Cur(&wire[body_len.min(wire.len())..]);
    c.take(COMPOSITE_VK_LEN)?;
    c.take(COMPOSITE_SIG_LEN)?;
    let cert_len = c.u32()? as usize;
    if cert_len > MAX_CERT {
        return Err(CkptError::Format);
    }
    c.take(cert_len)?;
    let head_len = wire.len() - c.0.len();
    let n = c.u16()? as usize;
    let mut all: Vec<(Hash, Vec<u8>)> = Vec::new();
    for _ in 0..n {
        let mut h = [0u8; 32];
        h.copy_from_slice(c.take(32)?);
        all.push((h, c.take(MLDSA87_SIG_LEN)?.to_vec()));
    }
    if !c.0.is_empty() {
        return Err(CkptError::Format);
    }
    for (h, s) in add {
        if s.len() != MLDSA87_SIG_LEN {
            return Err(CkptError::Format);
        }
        if !all.iter().any(|(x, _)| x == h) {
            all.push((*h, s.clone()));
        }
    }
    if all.len() > MAX_COSIGS {
        return Err(CkptError::Format);
    }
    let mut out = wire[..head_len].to_vec();
    out.extend_from_slice(&(all.len() as u16).to_le_bytes());
    for (h, s) in &all {
        out.extend_from_slice(h);
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// Produce the full wire form.  `cert` is the authority-issued node certificate.
pub fn sign(
    ck: &Checkpoint,
    node: &CompositeSigningKey,
    cert: &[u8],
    cosigs: &[(Hash, Vec<u8>)],
) -> Result<Vec<u8>, CkptError> {
    if cert.len() > MAX_CERT || cosigs.len() > MAX_COSIGS || ck.origin.len() > MAX_ORIGIN {
        return Err(CkptError::Format);
    }
    let body = ck.body();
    let sig = node.sign(&body).map_err(|_| CkptError::BadSig)?;
    let mut out = body;
    out.extend_from_slice(&node.verifying_key().to_bytes());
    out.extend_from_slice(&sig);
    out.extend_from_slice(&(cert.len() as u32).to_le_bytes());
    out.extend_from_slice(cert);
    out.extend_from_slice(&(cosigs.len() as u16).to_le_bytes());
    for (h, s) in cosigs {
        if s.len() != MLDSA87_SIG_LEN {
            return Err(CkptError::Format);
        }
        out.extend_from_slice(h);
        out.extend_from_slice(s);
    }
    Ok(out)
}

struct Cur<'a>(&'a [u8]);
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CkptError> {
        if self.0.len() < n {
            return Err(CkptError::Format);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32, CkptError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, CkptError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u16(&mut self) -> Result<u16, CkptError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
}

/// Parse a checkpoint's body WITHOUT verifying any signature.  Only for data
/// that was verified when it was admitted (e.g. a stored join snapshot).
pub fn parse_unverified(wire: &[u8]) -> Result<Checkpoint, CkptError> {
    let mut c = Cur(wire);
    if c.take(BODY_MAGIC.len())? != BODY_MAGIC {
        return Err(CkptError::Format);
    }
    let olen = c.u32()? as usize;
    if olen > MAX_ORIGIN {
        return Err(CkptError::Format);
    }
    let origin = String::from_utf8(c.take(olen)?.to_vec()).map_err(|_| CkptError::Format)?;
    let size = c.u64()?;
    let mut root = [0u8; 32];
    root.copy_from_slice(c.take(32)?);
    Ok(Checkpoint { origin, size, root })
}

/// Verify a checkpoint end to end.  Fail closed.
///
/// * `authority_vk` — ML-DSA-87 key the node certificate must chain to;
/// * `pos` — current authority-log position (certificate validity window);
/// * `roster` / `quorum` — explicit ML-DSA-87 witness keys and how many
///   *distinct* roster members must have validly cosigned.  `quorum == 0`
///   means witnesses are not required.
pub fn verify(
    wire: &[u8],
    authority_vk: &[u8],
    pos: u64,
    roster: &[&[u8]],
    quorum: usize,
) -> Result<Checkpoint, CkptError> {
    verify_inner(wire, authority_vk, pos, roster, quorum, None)
}

/// Bounded cache of authority-verified node certificates, keyed by
/// `(authority key hash, node key hash)`.  It lets a verifier that has already seen a
/// node's certificate accept that node's *slim* checkpoints (certificate omitted,
/// ~4.7 KB smaller) and skip the ML-DSA-87 certificate check.
///
/// Belts and braces: entries are admitted only after the certificate itself verifies
/// under that authority key (never from a checkpoint's say-so); a hit still re-checks
/// validity at `pos`, `node_id == origin`, the key hash, and the node's own signature;
/// a miss fails closed (`UnknownKid`).  Nothing here is persisted as trust — persisted
/// certificate bytes are re-verified on load via [`CertCache::admit`].
#[derive(Debug, Default)]
pub struct CertCache {
    map: std::collections::HashMap<(Hash, Hash), NodeCert>,
}

const CERT_CACHE_MAX: usize = 4096;

impl CertCache {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    /// Verify `cert_bytes` under `authority_vk` and remember it.  `false` ⇒ not admitted.
    pub fn admit(&mut self, cert_bytes: &[u8], authority_vk: &[u8]) -> bool {
        let Ok(cert) = NodeCert::verify(cert_bytes, authority_vk) else { return false };
        if self.map.len() >= CERT_CACHE_MAX {
            self.map.clear(); // bounded; a refill only costs full-cert checkpoints
        }
        self.map.insert((vk_hash(authority_vk), cert.node_vk_hash), cert);
        true
    }
    fn get(&self, authority_vk: &[u8], node_vk_hash: &Hash) -> Option<&NodeCert> {
        self.map.get(&(vk_hash(authority_vk), *node_vk_hash))
    }
}

/// The certificate embedded in a checkpoint wire (empty ⇒ a slim checkpoint).
pub fn embedded_cert(wire: &[u8]) -> Option<Vec<u8>> {
    let (_, cert_len, _) = split_cert(wire).ok()?;
    if cert_len == 0 {
        return None;
    }
    let ck = parse_unverified(wire).ok()?;
    let start = ck.body().len() + COMPOSITE_VK_LEN + COMPOSITE_SIG_LEN + 4;
    Some(wire[start..start + cert_len].to_vec())
}

/// Offsets: `(index just after the cert-length field, cert length, index after the cert)`.
fn split_cert(wire: &[u8]) -> Result<(usize, usize, usize), CkptError> {
    let ck = parse_unverified(wire)?;
    let len_at = ck.body().len() + COMPOSITE_VK_LEN + COMPOSITE_SIG_LEN;
    let mut c = Cur(wire.get(len_at..).ok_or(CkptError::Format)?);
    let n = c.u32()? as usize;
    if n > MAX_CERT || wire.len() < len_at + 4 + n {
        return Err(CkptError::Format);
    }
    Ok((len_at + 4, n, len_at + 4 + n))
}

/// Drop the certificate from a checkpoint wire.  The result verifies only against a
/// [`CertCache`] that already holds that node's certificate.
pub fn slim(wire: &[u8]) -> Result<Vec<u8>, CkptError> {
    let (after_len, _, end) = split_cert(wire)?;
    let mut out = wire[..after_len - 4].to_vec();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&wire[end..]);
    Ok(out)
}

/// [`verify`] that also accepts slim checkpoints known to `cache`, and teaches the
/// cache the certificate of every full checkpoint that verifies.
pub fn verify_cached(
    wire: &[u8], authority_vk: &[u8], pos: u64, roster: &[&[u8]], quorum: usize, cache: &mut CertCache,
) -> Result<Checkpoint, CkptError> {
    let ck = verify_inner(wire, authority_vk, pos, roster, quorum, Some(cache))?;
    if let Some(c) = embedded_cert(wire) {
        cache.admit(&c, authority_vk); // already verified above; this just records it
    }
    Ok(ck)
}

pub fn verify_any_cached(
    wire: &[u8], authorities: &[&[u8]], pos: u64, roster: &[&[u8]], quorum: usize, cache: &mut CertCache,
) -> Result<Checkpoint, CkptError> {
    let mut last = CkptError::UnknownKid;
    for a in authorities {
        match verify_cached(wire, a, pos, roster, quorum, cache) {
            Ok(c) => return Ok(c),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn verify_inner(
    wire: &[u8],
    authority_vk: &[u8],
    pos: u64,
    roster: &[&[u8]],
    quorum: usize,
    cache: Option<&CertCache>,
) -> Result<Checkpoint, CkptError> {
    if quorum > roster.len() {
        return Err(CkptError::Quorum);
    }
    let mut c = Cur(wire);
    if c.take(BODY_MAGIC.len())? != BODY_MAGIC {
        return Err(CkptError::Format);
    }
    let olen = c.u32()? as usize;
    if olen > MAX_ORIGIN {
        return Err(CkptError::Format);
    }
    let origin = String::from_utf8(c.take(olen)?.to_vec()).map_err(|_| CkptError::Format)?;
    let size = c.u64()?;
    let mut root = [0u8; 32];
    root.copy_from_slice(c.take(32)?);
    let ck = Checkpoint { origin, size, root };
    let body = ck.body();
    if wire[..body.len()] != body[..] {
        return Err(CkptError::Format);
    }
    let node_vk = c.take(COMPOSITE_VK_LEN)?;
    let node_sig = c.take(COMPOSITE_SIG_LEN)?;
    let cert_len = c.u32()? as usize;
    if cert_len > MAX_CERT {
        return Err(CkptError::Format);
    }
    let cert_bytes = c.take(cert_len)?;
    let n = c.u16()? as usize;
    if n > MAX_COSIGS {
        return Err(CkptError::Format);
    }
    let mut cos: Vec<(&[u8], &[u8])> = Vec::with_capacity(n);
    for _ in 0..n {
        cos.push((c.take(32)?, c.take(MLDSA87_SIG_LEN)?));
    }
    if !c.0.is_empty() {
        return Err(CkptError::Format); // trailing bytes
    }

    // 1. authority → node certificate (embedded, or already verified and cached)
    let cert = if cert_bytes.is_empty() {
        cache.and_then(|c| c.get(authority_vk, &vk_hash(node_vk))).cloned().ok_or(CkptError::UnknownKid)?
    } else {
        NodeCert::verify(cert_bytes, authority_vk)?
    };
    if !cert.valid_at(pos) {
        return Err(CkptError::NotValidAt);
    }
    // 2. certificate → node key, and the node may only sign its own log
    if cert.node_vk_hash != vk_hash(node_vk) || cert.node_id != ck.origin {
        return Err(CkptError::UnknownKid);
    }
    // 3. node composite signature (both PQ and classical halves must verify)
    let vk = CompositeVerifyingKey::from_bytes(node_vk).map_err(|_| CkptError::Format)?;
    vk.verify(&body, node_sig).map_err(|_| CkptError::BadSig)?;

    // 4. witness quorum: distinct roster members, each must verify
    if quorum > 0 {
        let msg = ck.cosig_message();
        let mut seen = vec![false; roster.len()];
        let mut ok = 0usize;
        for (h, s) in cos {
            if let Some(i) = roster.iter().position(|r| vk_hash(r)[..] == *h) {
                if !seen[i] && mldsa87_verify(roster[i], &msg, s) {
                    seen[i] = true;
                    ok += 1;
                }
            }
        }
        if ok < quorum {
            return Err(CkptError::Quorum);
        }
    }
    Ok(ck)
}

/// Verify against any of several trusted authority keys (independent meshes may
/// answer to different roots of trust).  Returns the last error if none accept.
pub fn verify_any(
    wire: &[u8],
    authorities: &[&[u8]],
    pos: u64,
    roster: &[&[u8]],
    quorum: usize,
) -> Result<Checkpoint, CkptError> {
    let mut last = CkptError::UnknownKid;
    for a in authorities {
        match verify(wire, a, pos, roster, quorum) {
            Ok(c) => return Ok(c),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    struct Fx {
        auth: Keypair,
        node: CompositeSigningKey,
        cert: Vec<u8>,
        ck: Checkpoint,
    }

    fn fx() -> Fx {
        let mut r = StdRng::from_seed([7; 32]);
        let auth = Keypair::generate(&mut r, "auth".into());
        let node = CompositeSigningKey::generate(&mut r);
        let cert = NodeCert {
            node_id: "node-a".into(),
            node_vk_hash: vk_hash(&node.verifying_key().to_bytes()),
            boot_counter: 1,
            scope_hash: [0; 32],
            valid_from_pos: 10,
            valid_to_pos: 20,
        }
        .sign(&auth)
        .unwrap();
        let mut t = crate::tlog::Tree::new();
        for i in 0..5 {
            t.append(&[i]);
        }
        Fx { auth, node, cert, ck: Checkpoint { origin: "node-a".into(), size: 5, root: t.root() } }
    }

    #[test]
    fn roundtrip_and_chain_checks() {
        let f = fx();
        let avk = f.auth.verifying_key_bytes();
        let w = sign(&f.ck, &f.node, &f.cert, &[]).unwrap();
        assert_eq!(verify(&w, &avk, 15, &[], 0).unwrap(), f.ck);
        // outside certificate window
        assert_eq!(verify(&w, &avk, 21, &[], 0), Err(CkptError::NotValidAt));
        assert_eq!(verify(&w, &avk, 9, &[], 0), Err(CkptError::NotValidAt));
        // wrong authority
        let other = Keypair::generate(&mut StdRng::from_seed([8; 32]), "x".into());
        assert!(verify(&w, &other.verifying_key_bytes(), 15, &[], 0).is_err());
        // trailing byte, truncation, every single-byte flip in the body/sig region
        let mut t = w.clone();
        t.push(0);
        assert_eq!(verify(&t, &avk, 15, &[], 0), Err(CkptError::Format));
        assert!(verify(&w[..w.len() - 1], &avk, 15, &[], 0).is_err());
        for i in (0..w.len()).step_by(97) {
            let mut b = w.clone();
            b[i] ^= 1;
            assert!(verify(&b, &avk, 15, &[], 0).is_err(), "flip at {i}");
        }
    }

    #[test]
    fn node_cannot_sign_another_origin_or_use_unbound_key() {
        let f = fx();
        let avk = f.auth.verifying_key_bytes();
        let mut ck = f.ck.clone();
        ck.origin = "node-b".into();
        let w = sign(&ck, &f.node, &f.cert, &[]).unwrap();
        assert_eq!(verify(&w, &avk, 15, &[], 0), Err(CkptError::UnknownKid));
        // a different node key under the same certificate
        let rogue = CompositeSigningKey::generate(&mut StdRng::from_seed([3; 32]));
        let w = sign(&f.ck, &rogue, &f.cert, &[]).unwrap();
        assert_eq!(verify(&w, &avk, 15, &[], 0), Err(CkptError::UnknownKid));
    }

    #[test]
    fn witness_quorum() {
        let f = fx();
        let avk = f.auth.verifying_key_bytes();
        let mut r = StdRng::from_seed([5; 32]);
        let w1 = Keypair::generate(&mut r, "w1".into());
        let w2 = Keypair::generate(&mut r, "w2".into());
        let w3 = Keypair::generate(&mut r, "w3".into());
        let (v1, v2, v3) = (w1.verifying_key_bytes(), w2.verifying_key_bytes(), w3.verifying_key_bytes());
        let roster: Vec<&[u8]> = vec![&v1, &v2, &v3];
        let c1 = cosign(&f.ck, &w1).unwrap();
        let c2 = cosign(&f.ck, &w2).unwrap();
        // 2-of-3 satisfied
        let w = sign(&f.ck, &f.node, &f.cert, &[c1.clone(), c2.clone()]).unwrap();
        assert!(verify(&w, &avk, 15, &roster, 2).is_ok());
        assert_eq!(verify(&w, &avk, 15, &roster, 3), Err(CkptError::Quorum));
        // duplicates do not count twice
        let w = sign(&f.ck, &f.node, &f.cert, &[c1.clone(), c1.clone()]).unwrap();
        assert_eq!(verify(&w, &avk, 15, &roster, 2), Err(CkptError::Quorum));
        // a cosignature over a different checkpoint does not count
        let mut other = f.ck.clone();
        other.size = 6;
        let bad = cosign(&other, &w2).unwrap();
        let w = sign(&f.ck, &f.node, &f.cert, &[c1.clone(), bad]).unwrap();
        assert_eq!(verify(&w, &avk, 15, &roster, 2), Err(CkptError::Quorum));
        // a non-roster witness does not count
        let outsider = Keypair::generate(&mut r, "o".into());
        let w = sign(&f.ck, &f.node, &f.cert, &[c1, cosign(&f.ck, &outsider).unwrap()]).unwrap();
        assert_eq!(verify(&w, &avk, 15, &roster, 2), Err(CkptError::Quorum));
        // quorum larger than roster is refused outright
        assert_eq!(verify(&w, &avk, 15, &roster, 4), Err(CkptError::Quorum));
    }

    #[test]
    fn cosig_is_not_a_node_signature_domain() {
        // A witness signature must never validate as the checkpoint body signature.
        let f = fx();
        let w = Keypair::generate(&mut StdRng::from_seed([6; 32]), "w".into());
        let (_, s) = cosign(&f.ck, &w).unwrap();
        assert!(!mldsa87_verify(&w.verifying_key_bytes(), &f.ck.body(), &s));
    }

    // ── slim checkpoints / certificate cache ──────────────────────────────────
    #[test]
    fn slim_checkpoints_verify_only_against_a_cache_that_already_holds_the_cert() {
        let f = fx();
        let avk = f.auth.verifying_key_bytes();
        let full = sign(&f.ck, &f.node, &f.cert, &[]).unwrap();
        let slim = slim(&full).unwrap();
        assert_eq!(slim.len() + f.cert.len(), full.len(), "exactly the certificate is dropped");
        assert_eq!(embedded_cert(&full).unwrap(), f.cert);
        assert!(embedded_cert(&slim).is_none());
        // plain verify and an empty cache both fail closed
        assert_eq!(verify(&slim, &avk, 15, &[], 0), Err(CkptError::UnknownKid));
        let mut cache = CertCache::new();
        assert_eq!(verify_cached(&slim, &avk, 15, &[], 0, &mut cache), Err(CkptError::UnknownKid));
        // a full checkpoint teaches the cache; then the slim one verifies
        assert_eq!(verify_cached(&full, &avk, 15, &[], 0, &mut cache).unwrap(), f.ck);
        assert_eq!(cache.len(), 1);
        assert_eq!(verify_cached(&slim, &avk, 15, &[], 0, &mut cache).unwrap(), f.ck);
        // the cache does not weaken the other checks
        assert_eq!(verify_cached(&slim, &avk, 21, &[], 0, &mut cache), Err(CkptError::NotValidAt), "expiry still applies");
        let other = Keypair::generate(&mut StdRng::from_seed([9; 32]), "other".into());
        assert!(verify_cached(&slim, &other.verifying_key_bytes(), 15, &[], 0, &mut cache).is_err(), "cache is per authority");
        let n = slim.len();
        let mut bad = slim.clone();
        bad[n - 5] ^= 1;
        assert!(verify_cached(&bad, &avk, 15, &[], 0, &mut cache).is_err(), "tampering is still caught");
        // another node key cannot ride on this node's cached certificate
        let rogue = CompositeSigningKey::from_seeds(&[13; 32], &[14; 32]);
        let rogue_slim = super::slim(&sign(&f.ck, &rogue, &f.cert, &[]).unwrap()).unwrap();
        assert_eq!(verify_cached(&rogue_slim, &avk, 15, &[], 0, &mut cache), Err(CkptError::UnknownKid));
        // a failed full verification teaches nothing
        let mut fresh = CertCache::new();
        let forged = sign(&f.ck, &rogue, &f.cert, &[]).unwrap();
        assert!(verify_cached(&forged, &avk, 15, &[], 0, &mut fresh).is_err());
        assert!(fresh.is_empty());
        // only genuine certificates are admitted
        assert!(!fresh.admit(b"garbage", &avk));
        assert!(!fresh.admit(&f.cert, &other.verifying_key_bytes()));
        assert!(fresh.admit(&f.cert, &avk));
    }

    #[test]
    fn slimming_keeps_witness_cosignatures() {
        let f = fx();
        let avk = f.auth.verifying_key_bytes();
        let w = Keypair::generate(&mut StdRng::from_seed([5; 32]), "w".into());
        let wvk = w.verifying_key_bytes();
        let cs = cosign(&f.ck, &w).unwrap();
        let full = sign(&f.ck, &f.node, &f.cert, &[cs]).unwrap();
        let mut cache = CertCache::new();
        verify_cached(&full, &avk, 15, &[&wvk], 1, &mut cache).unwrap();
        let s = slim(&full).unwrap();
        assert!(verify_cached(&s, &avk, 15, &[&wvk], 1, &mut cache).is_ok());
        let no_cos = attach_cosigs(&slim(&sign(&f.ck, &f.node, &f.cert, &[]).unwrap()).unwrap(), &[]).unwrap();
        assert_eq!(verify_cached(&no_cos, &avk, 15, &[&wvk], 1, &mut cache), Err(CkptError::Quorum));
    }
}

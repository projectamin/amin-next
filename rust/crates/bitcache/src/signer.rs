//! `<bc:signer>` envelope carried forward from legacy Bitcache 2014.
//!
//! Legacy 2014 Bitcache used RSA-2048 for `<bc:signer>` envelopes.  Amin 3.0
//! replaces the crypto with ML-DSA-87 (FIPS 204, NIST security level 5)
//! while keeping the *envelope shape* identical to the 2014 `<bc:signer>`
//! element carried in the `<bc:networkmap>` document:
//!
//! ```xml
//! <bc:signer xmlns:bc="http://projectamin.org/ns/bc/"
//!            bc:name="ops@corp.example.test"
//!            bc:date="2026-10-09T14:30:22Z"
//!            bc:keyref="-----BEGIN PUBLIC KEY-----…">
//!   <bc:signature> … base64(ML-DSA-87 sig, 4627 bytes) … </bc:signature>
//!   <bc:object bc:hash="…"/>
//! </bc:signer>
//! ```
//!
//! NAME_ID allocation: `bc/signature` = 90, `bc/date` = 73, `bc/name` = 75,
//! `bc/keyref` = 76 (all single LEB, < 127 guard from §AC-2).

use ml_dsa::{self, MlDsa87, Signature, SigningKey, VerifyingKey, Seed};
use ml_dsa::{KeyExport, KeyInit, Keypair as MlKeypair, SignatureEncoding, Signer, Verifier};

pub use crate::slab::ObjRef;
use crate::Result;

/// RFC-3339 / ISO-8601 UTC timestamp for the `<bc:date>` attribute.
pub type Rfc3339Time = String;

pub fn rfc3339_now() -> Rfc3339Time {
    let secs = now_epoch_secs();
    let (y, mo, d, h, mi, s) = secs_to_ymdhms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}
fn now_epoch_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
/// Minimal Gregorian date math (no libc, no deps).  Correct for every date
/// >= UNIX epoch, which covers the entire Amin 3.0 operational lifetime.
fn secs_to_ymdhms(mut total: u64) -> (i32, u32, u32, u32, u32, u32) {
    let s = (total % 60) as u32; total /= 60;
    let mi = (total % 60) as u32; total /= 60;
    let h = (total % 24) as u32;
    let mut days = (total / 24) as i64;
    let mut y = 1970i32;
    loop {
        let yd = if is_leap(y) { 366 } else { 365 };
        if days < yd { break }
        days -= yd; y += 1;
    }
    let md = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let (mut mo, mut dd) = (1u32, days as u64);
    for (i, &mlen) in md.iter().enumerate() {
        let mlen = if i == 1 && is_leap(y) { mlen + 1 } else { mlen };
        if dd < mlen { mo = (i + 1) as u32; break }
        dd -= mlen; mo = (i + 2) as u32;
    }
    (y, mo, (dd + 1) as u32, h, mi, s)
}
fn is_leap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}
fn ts_to_rfc3339(secs: u64) -> Rfc3339Time {
    let (y, mo, d, h, mi, s) = secs_to_ymdhms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

// Fixed ML-DSA-87 sizes (NIST FIPS 204 values).  We hardcode these rather
// than pulling from the associated type consts so callers (Perl) never have
// to trust the Rust type system for memory-layout assertions.
pub const MLDSA87_SIG_LEN: usize = 4627;
pub const MLDSA87_VK_LEN:  usize = 2592;   // ml-dsa-0.1.1: EncodedVerifyingKey<MlDsa87> = 32 + T1Size
pub const MLDSA87_SK_LEN:  usize = 32;     // Seed (B32) per ml-dsa-0.1.1 signing key convention

// Concrete ML-DSA-87 key/sig types (single location, one name).
type Sk87 = SigningKey<MlDsa87>;
type Vk87 = VerifyingKey<MlDsa87>;
type Sig87 = Signature<MlDsa87>;
type EncVk87 = ml_dsa::EncodedVerifyingKey<MlDsa87>;

fn enc_vk_from_slice(bytes: &[u8]) -> &EncVk87 {
    assert_eq!(bytes.len(), MLDSA87_VK_LEN);
    unsafe { &*(bytes.as_ptr() as *const EncVk87) }
}

/// Generic helper: read exactly 32 bytes of key material from any RNG that
/// implements `rand 0.8`'s `RngCore`.  We deliberately avoid depending on
/// `rand_core 0.10`'s `TryCryptoRng` here — the caller's side of the dep
/// diamond lives on rand 0.8 while ml-dsa uses 0.10; 32 raw bytes bridge
/// both sides without trait conflicts.
fn seed_from_rng_08<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Seed {
    let mut seed = Seed::default();
    rng.fill_bytes(&mut seed);
    seed
}
/// Same idea but from a raw byte slice (for `from_sk_bytes`).
fn seed_from_bytes(bytes: &[u8]) -> Result<Seed> {
    if bytes.len() != MLDSA87_SK_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            format!("bad ML-DSA-87 SK len {} expected {} (Seed = 32 B)",
                    bytes.len(), MLDSA87_SK_LEN)).into());
    }
    let mut seed = Seed::default();
    seed.copy_from_slice(bytes);
    Ok(seed)
}

/// ML-DSA-87 keypair.  `sk` bytes are written to disk by aminexec PID 1
/// (chmod 0600, landlock rw on `/srv/amin/keys/bc-signer-<name>.sk`); `vk`
/// bytes are distributed via the trust-anchor directory (the `<bc:signer
/// bc:keyref="…">` attribute is informational only — it never substitutes
/// for trust anchor lookup, that's the seal-chain trust proof from spec
/// DI-2).
pub struct Keypair {
    pub name:    String,
    pub created: Rfc3339Time,
    pub sk:      Sk87,
    pub vk:      Vk87,
}
impl Keypair {
    /// Randomly generate a fresh ML-DSA-87 keypair.  Keyname is a human
    /// string (email / X500-ish) and is embedded into the signed payload so
    /// tampering with bc:name invalidates the signature.
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R, name: String,
    ) -> Self {
        // Bypass `Generate`/`TryCryptoRng` (rand_core 0.10) entirely: draw
        // 32 seed bytes using the caller's rand 0.8 RngCore, then init.
        let seed = seed_from_rng_08(rng);
        let sk: Sk87 = <Sk87 as KeyInit>::new(&seed);
        let vk: Vk87 = <Sk87 as MlKeypair>::verifying_key(&sk);
        Self { name, created: rfc3339_now(), sk, vk }
    }
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.vk.to_bytes().as_slice().to_vec()
    }
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        <Sk87 as KeyExport>::to_bytes(&self.sk).as_slice().to_vec()
    }
    /// Reconstruct a keypair from on-disk ML-DSA-87 signing-key bytes
    /// (Seed = 32 B).
    pub fn from_sk_bytes(bytes: &[u8]) -> Result<Self> {
        let seed = seed_from_bytes(bytes)?;
        let sk: Sk87 = <Sk87 as KeyInit>::new(&seed);
        let vk: Vk87 = <Sk87 as MlKeypair>::verifying_key(&sk);
        Ok(Self { name: String::new(), created: rfc3339_now(), sk, vk })
    }
}

/// ML-DSA-87 signature bytes — fixed 4627 B.  Serialized as standard base64
/// characters inside `<bc:signature>`'s SAX text() node.
#[derive(Clone, Debug)]
pub struct BcSignature(pub [u8; MLDSA87_SIG_LEN]);
impl BcSignature {
    pub fn as_bytes(&self) -> &[u8; MLDSA87_SIG_LEN] { &self.0 }
}

/// 1:1 shape of the XML `<bc:signer>` element.  All fields map directly to
/// SAX attributes / child elements; this struct is the bridge between the
/// Rust cryptographic layer and the Perl Storage filter.
#[derive(Clone, Debug)]
pub struct SignedEnvelope {
    pub name:       String,     // bc:name attr
    pub date:       String,     // bc:date attr
    pub keyref_pem: String,     // bc:keyref attr (informational; not source of trust)
    pub obj_ref:    ObjRef,     // bc:hash attr of the object being signed
    pub timestamp:  u64,        // epoch seconds embedded in signed payload
    pub signature:  BcSignature, // <bc:signature> text (raw 4627 B — XML carries b64)
}

/// Deterministic signed payload.  Magic prefix prevents cross-protocol
/// attacks (e.g. an ML-DSA signature produced by AWP3 QUIC can't be replayed
/// against the Bitcache envelope).
fn signing_payload(name: &str, ts: u64, obj: &ObjRef) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + name.len());
    v.extend_from_slice(b"AMIN3-BC-MLD87\n");
    v.extend_from_slice(&(name.len() as u32).to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(obj.as_bytes());
    v
}

impl SignedEnvelope {
    /// Produce a signed envelope for the object at `obj`.  ML-DSA-87 signing
    /// is fully deterministic (uses SHAKE256 internally); the `_rng` param
    /// is a placeholder retained for future Dilithium-randomized variants.
    pub fn new<R: rand::RngCore + rand::CryptoRng>(
        _rng: &mut R, kp: &Keypair, obj: ObjRef,
    ) -> Result<Self> {
        let ts = now_epoch_secs();
        let payload = signing_payload(&kp.name, ts, &obj);
        let sig_obj: Sig87 = Signer::<Sig87>::try_sign(&kp.sk, &payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData,
                                             format!("mldsa87 sign: {e}")))?;
        let enc = sig_obj.to_bytes();
        let sig_slice: &[u8] = enc.as_ref();
        if sig_slice.len() != MLDSA87_SIG_LEN {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("unexpected ML-DSA-87 sig len {} expected {}",
                        sig_slice.len(), MLDSA87_SIG_LEN)).into());
        }
        let mut sig_arr = [0u8; MLDSA87_SIG_LEN];
        sig_arr.copy_from_slice(sig_slice);

        let vk_bytes: Vec<u8> = kp.verifying_key_bytes();
        let keyref = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            wrap_b64(&b64enc(&vk_bytes)));

        Ok(Self {
            name:       kp.name.clone(),
            date:       ts_to_rfc3339(ts),
            keyref_pem: keyref,
            obj_ref:    obj,
            timestamp:  ts,
            signature:  BcSignature(sig_arr),
        })
    }

    /// Verify envelope.  Fail closed: any mismatch (sig bytes, name, ts,
    /// obj_ref) returns an error.  Callers MUST ensure `vk_bytes` comes
    /// from the trust-anchor directory, not from the wire keyref.
    pub fn verify(&self, vk_bytes: &[u8]) -> Result<()> {
        if vk_bytes.len() != MLDSA87_VK_LEN {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("bad VK length: got {} want {}",
                        vk_bytes.len(), MLDSA87_VK_LEN)).into());
        }
        let vk: Vk87 = Vk87::decode(enc_vk_from_slice(vk_bytes));
        let payload = signing_payload(&self.name, self.timestamp, &self.obj_ref);
        let sig = Sig87::try_from(&self.signature.0[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData,
                                             format!("parse signature: {e:?}")))?;
        Verifier::<Sig87>::verify(&vk, &payload, &sig).map_err(|e|
            std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                                format!("bc:signer mldsa87 verify: {e}")))?;
        Ok(())
    }
}

// ── zcap.v1 boot-authority token (Amin::Auth::ZCap wire format 1:1) ─────
//
// The Perl trust layer (perl-lib/Amin/Auth/ZCap.pm) is **verify-only** by
// design; issuance lives here (rust toolchain).  Wire layout (FIPS-204 LE
// encodings, 1:1 with `_parse_token_fields` / `_compute_scope_hash`):
//
//   token = sig(4627) ‖ vk(2592) ‖ scope_hash(32) ‖ ts(le64)
//         ‖ tier_cnt(le16) ‖ zone_cnt(le16) ‖ netp_cnt(le16)
//         ‖ max_redundancy(u8) ‖ vpc_quota(le32) ‖ memory_tier(u8)
//         ‖ tenant_len(le16) ‖ tenant ‖ tier_data ‖ zone_data ‖ netp_data
//   tier/zone/netp_data = repeated (le16 len ‖ bytes)
//
// The embedded `scope_hash` field is informational; the signature binds the
// receiver-computed BLAKE3 **hexdigest string** (see `smsg`), matching
// `_verify_token` exactly:

/// One zcap.v1 grant — the scope fields a signer authorizes.
pub struct ZcapGrant {
    pub tiers:          Vec<String>,
    pub zones:          Vec<String>,
    pub netpolicies:    Vec<String>,
    pub max_redundancy: u8,
    pub vpc_quota:      u32,
    pub memory_tier:    u8,
    pub tenant_id:      String,
    pub ts:             u64,
}

fn len_prefix16(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

impl ZcapGrant {
    /// Exact byte composition of the Perl `_compute_scope_hash` scope buf.
    pub fn scope_buf(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for t in &self.tiers       { len_prefix16(&mut b, t) }
        for z in &self.zones       { len_prefix16(&mut b, z) }
        for n in &self.netpolicies { len_prefix16(&mut b, n) }
        b.push(self.max_redundancy);
        b.extend_from_slice(&self.vpc_quota.to_le_bytes());
        b.push(self.memory_tier);
        b.extend_from_slice(b"amin.zcap.v1");
        b
    }

    /// BLAKE3 hexdigest string (64 lowercase ASCII hex chars).  Perl's
    /// `_compute_scope_hash` returns `hexdigest()` (a 64-char string) and
    /// concatenates it into the signed message — so we sign the hex **text**,
    /// not the raw digest bytes.
    pub fn scope_hash_hex(&self) -> String {
        blake3::hash(&self.scope_buf()).to_hex().to_string()
    }

    /// Exact signed message from Perl `_verify_token`:
    ///   local_hash_hex ‖ vk(2592) ‖ ts(le64) ‖ tenant ‖ "amin.zcap.v1"
    pub fn smsg(&self, vk_bytes: &[u8]) -> Vec<u8> {
        assert_eq!(vk_bytes.len(), MLDSA87_VK_LEN,"vk bytes must be FIPS-204 encoded VK");
        let mut m = Vec::with_capacity(64 + MLDSA87_VK_LEN + 8 + self.tenant_id.len() + 12);
        m.extend_from_slice(self.scope_hash_hex().as_bytes());
        m.extend_from_slice(vk_bytes);
        m.extend_from_slice(&self.ts.to_le_bytes());
        m.extend_from_slice(self.tenant_id.as_bytes());
        m.extend_from_slice(b"amin.zcap.v1");
        m
    }

    /// Assemble (unsigned) token wire bytes for this grant using the given
    /// VK bytes: `vk ‖ scope_hash(32) ‖ ts ‖ counts ‖ fields…` (the caller
    /// prepends the 4627-byte ML-DSA-87 signature).  The embedded
    /// `scope_hash` field carries the raw 32-byte BLAKE3 digest of
    /// `scope_buf` (informational — receivers recompute from parsed fields).
    fn token_bytes_with_vk(&self, vk_bytes: &[u8]) -> Result<Vec<u8>> {
        if vk_bytes.len() != MLDSA87_VK_LEN {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                format!("bad VK length: got {} want {}",
                        vk_bytes.len(), MLDSA87_VK_LEN)).into());
        }
        let mut t = Vec::new();
        t.extend_from_slice(vk_bytes);
        t.extend_from_slice(blake3::hash(&self.scope_buf()).as_bytes());
        t.extend_from_slice(&self.ts.to_le_bytes());
        t.extend_from_slice(&(self.tiers.len() as u16).to_le_bytes());
        t.extend_from_slice(&(self.zones.len() as u16).to_le_bytes());
        t.extend_from_slice(&(self.netpolicies.len() as u16).to_le_bytes());
        t.push(self.max_redundancy);
        t.extend_from_slice(&self.vpc_quota.to_le_bytes());
        t.push(self.memory_tier);
        len_prefix16(&mut t, &self.tenant_id);
        for t2 in &self.tiers      { len_prefix16(&mut t, t2) }
        for z  in &self.zones      { len_prefix16(&mut t, z) }
        for n  in &self.netpolicies{ len_prefix16(&mut t, n) }
        Ok(t)
    }
}

/// Issue a signed zcap.v1 token from the given keypair and grant:
/// ML-DSA-87 signature over `smsg` prepended to the grant wire bytes.
/// Base64 encoding is the caller's choice.
pub fn zcap_token_bytes(kp: &Keypair, g: &ZcapGrant) -> Result<Vec<u8>> {
    use ml_dsa::SignatureEncoding;
    let vk_bytes = kp.verifying_key_bytes();
    let smsg = g.smsg(&vk_bytes);
    let sig: Sig87 = Signer::<Sig87>::try_sign(&kp.sk, &smsg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData,
                                         format!("mldsa87 zcap sign: {e}")))?;
    let enc = sig.to_bytes();
    let sig_slice: &[u8] = enc.as_ref();
    if sig_slice.len() != MLDSA87_SIG_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            format!("unexpected ML-DSA-87 sig len {} expected {}",
                    sig_slice.len(), MLDSA87_SIG_LEN)).into());
    }
    let mut out = Vec::with_capacity(MLDSA87_SIG_LEN + MLDSA87_VK_LEN + g.tenant_id.len());
    out.extend_from_slice(sig_slice);
    out.extend_from_slice(&g.token_bytes_with_vk(&vk_bytes)?);
    Ok(out)
}

/// Deterministic now-epoch helper for tooling (bctool zcap-token).
pub fn epoch_now() -> u64 { now_epoch_secs() }

// ── Small standard base64 encoder / decoder (no extra dep) ─────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub fn b64enc(b: &[u8]) -> String {
    let mut out = String::with_capacity((b.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= b.len() {
        let n = ((b[i] as u32) << 16) | ((b[i+1] as u32) << 8) | (b[i+2] as u32);
        out.push(B64[((n>>18)&63) as usize] as char);
        out.push(B64[((n>>12)&63) as usize] as char);
        out.push(B64[((n>>6 )&63) as usize] as char);
        out.push(B64[( n     &63) as usize] as char);
        i += 3;
    }
    let rem = b.len() - i;
    if rem == 1 {
        let n = (b[i] as u32) << 16;
        out.push(B64[((n>>18)&63) as usize] as char);
        out.push(B64[((n>>12)&63) as usize] as char);
        out.push('='); out.push('=');
    } else if rem == 2 {
        let n = ((b[i] as u32) << 16) | ((b[i+1] as u32) << 8);
        out.push(B64[((n>>18)&63) as usize] as char);
        out.push(B64[((n>>12)&63) as usize] as char);
        out.push(B64[((n>>6 )&63) as usize] as char);
        out.push('=');
    }
    out
}
pub fn b64dec(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if s.len() % 4 != 0 { return Err("base64 bad len".into()) }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut i = 0;
    while i < s.len() {
        let mut bits: u32 = 0;
        let mut pad = 0u32;
        for j in 0..4 {
            let c = s[i + j];
            let v = if c == b'=' { pad += 1; 0 } else
                    if c.is_ascii_uppercase() { (c - b'A') as u32 } else
                    if c.is_ascii_lowercase() { (c - b'a' + 26) as u32 } else
                    if c.is_ascii_digit()      { (c - b'0' + 52) as u32 } else
                    if c == b'+'               { 62 } else
                    if c == b'/'               { 63 } else
                    { return Err(format!("bad base64 char {c}")) };
            bits = (bits << 6) | v;
        }
        out.push(((bits >> 16) & 0xff) as u8);
        if pad < 2 { out.push(((bits >> 8) & 0xff) as u8) }
        if pad < 1 { out.push((bits & 0xff) as u8) }
        i += 4;
    }
    Ok(out)
}
fn wrap_b64(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 64);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && i % 64 == 0 { out.push('\n') }
        out.push(c);
    }
    out
}

pub use self::b64enc as base64_encode;
pub use self::b64dec as base64_decode;

use crate::BitcacheError;

pub fn detect_legacy_algorithm(envelope_xml_or_sig_bytes: &[u8]) -> Result<()> {
    let haystack = envelope_xml_or_sig_bytes;
    let contains_rsa = haystack.windows(3).any(|w| w == b"RSA" || w == b"rsa");
    if contains_rsa {
        return Err(BitcacheError::UnsupportedAlgorithm {
            kind: "RSA-2048".into(),
        });
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn sign_ok_and_tamper_fail_closed() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE_0DDBA11u64);
        let kp = Keypair::generate(&mut rng, "ops@corp.example.test".into());
        let obj = ObjRef(*blake3::hash(b"hello Amin3 BC envelope").as_bytes());
        let env = SignedEnvelope::new(&mut rng, &kp, obj).unwrap();
        env.verify(&kp.verifying_key_bytes()).expect("expected good sig");
        // tamper object
        let mut bad = env.clone();
        bad.obj_ref = ObjRef(*blake3::hash(b"attacker object").as_bytes());
        assert!(bad.verify(&kp.verifying_key_bytes()).is_err());
        // 1-bit sig flip
        let mut bad2 = env.clone();
        bad2.signature.0[4_626] ^= 0x01;
        assert!(bad2.verify(&kp.verifying_key_bytes()).is_err());
        // different verifying key
        let kp2 = Keypair::generate(&mut rng, "attacker".into());
        assert!(env.verify(&kp2.verifying_key_bytes()).is_err());
        // name tamper
        let mut bad5 = env.clone();
        bad5.name = "not-ops@corp".into();
        assert!(bad5.verify(&kp.verifying_key_bytes()).is_err());
        // size consts
        assert_eq!(kp.signing_key_bytes().len(),   MLDSA87_SK_LEN);
        assert_eq!(kp.verifying_key_bytes().len(), MLDSA87_VK_LEN);
        assert_eq!(env.signature.0.len(),          MLDSA87_SIG_LEN);
    }

    #[test]
    fn b64_roundtrip_and_sk_reconstruction() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let kp = Keypair::generate(&mut rng, "ops".into());
        let obj = ObjRef(*blake3::hash(b"t").as_bytes());
        let env = SignedEnvelope::new(&mut rng, &kp, obj).unwrap();
        let sb = b64enc(&env.signature.0);
        assert_eq!(sb.len(), (4627 + 2) / 3 * 4);
        let dec = b64dec(&sb).unwrap();
        assert_eq!(dec.len(), MLDSA87_SIG_LEN);
        assert_eq!(&dec[..], &env.signature.0[..]);
        // SK reconstruction
        let sk_bytes = kp.signing_key_bytes();
        let kp2 = Keypair::from_sk_bytes(&sk_bytes).unwrap();
        assert_eq!(kp2.verifying_key_bytes(), kp.verifying_key_bytes());
        let env2 = SignedEnvelope::new(&mut rng, &kp2, obj).unwrap();
        env2.verify(&kp.verifying_key_bytes()).expect("reconstructed SK valid");
    }

    #[test]
    fn legacy_rsa_detected_and_rejected() {
        match detect_legacy_algorithm(b"<RSAKeyValue>...</RSAKeyValue>") {
            Err(BitcacheError::UnsupportedAlgorithm { kind }) => {
                assert_eq!(kind, "RSA-2048");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
        match detect_legacy_algorithm(b"rsa") {
            Err(BitcacheError::UnsupportedAlgorithm { kind }) => {
                assert_eq!(kind, "RSA-2048");
            }
            other => panic!("expected UnsupportedAlgorithm for lowercase rsa, got {other:?}"),
        }
        let mldsa87_vk = [0xABu8; MLDSA87_VK_LEN];
        assert!(detect_legacy_algorithm(&mldsa87_vk).is_ok());
    }
}

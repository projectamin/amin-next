//! Amin trust-layer verifiers — the single implementation.
//!
//! Perl (`Amin::Auth::ZCap`, `Amin::UCC::Instruments`) never re-implements a
//! check in this module: it binds the C ABI in [`crate::ffi`] and maps the
//! return code.  Rust callers (`ainit`, `bctool`) call these functions
//! directly, so both languages run byte-identical code.
//!
//! Every verifier is fail-closed: malformed, truncated, unanchored or
//! unverifiable input is an error, never a pass.

use crate::signer::{mldsa87_verify, MLDSA87_SIG_LEN, MLDSA87_VK_LEN};

/// Return codes shared with the C ABI (negative = rejected).
pub const RC_OK: i32 = 0;
pub const RC_FORMAT: i32 = -1;
pub const RC_UNKNOWN_KID: i32 = -2;
pub const RC_BAD_SIG: i32 = -3;
pub const RC_NOT_VALID_AT: i32 = -4;
pub const RC_QUORUM: i32 = -5;
pub const RC_BAD_ARG: i32 = -9;

/// Why a trust object was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Format,
    UnknownKid,
    BadSig,
}

impl Reject {
    pub const fn code(self) -> i32 {
        match self {
            Reject::Format => RC_FORMAT,
            Reject::UnknownKid => RC_UNKNOWN_KID,
            Reject::BadSig => RC_BAD_SIG,
        }
    }
}

// ── zcap.v1 ─────────────────────────────────────────────────────────────────

/// A parsed zcap.v1 token (layout documented on [`crate::ZcapGrant`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZcapParsed {
    pub vk: Vec<u8>,
    pub ts: u64,
    pub max_redundancy: u8,
    pub vpc_quota: u32,
    pub memory_tier: u8,
    pub tenant_id: String,
    pub tiers: Vec<String>,
    pub zones: Vec<String>,
    pub netpolicies: Vec<String>,
}

const ZCAP_FIXED: usize = MLDSA87_SIG_LEN + MLDSA87_VK_LEN + 32 + 8 + 2 + 2 + 2 + 1 + 4 + 1 + 2;

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        let s = self.b.get(self.p..end)?;
        self.p = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }
    /// Strict UTF-8: a lossy decode would let two different byte strings map
    /// to the same signed text (signature malleability across languages).
    fn str16(&mut self) -> Option<String> {
        let n = self.u16()? as usize;
        let s = self.take(n)?;
        core::str::from_utf8(s).ok().map(str::to_owned)
    }
}

/// Parse (structure only — no trust decision) a zcap.v1 token.
pub fn zcap_parse(bytes: &[u8]) -> Result<(Vec<u8>, ZcapParsed), Reject> {
    if bytes.len() < ZCAP_FIXED {
        return Err(Reject::Format);
    }
    let mut c = Cur { b: bytes, p: 0 };
    let sig = c.take(MLDSA87_SIG_LEN).ok_or(Reject::Format)?.to_vec();
    let vk = c.take(MLDSA87_VK_LEN).ok_or(Reject::Format)?.to_vec();
    let _scope_hash = c.take(32).ok_or(Reject::Format)?; // informational
    let ts = c.u64().ok_or(Reject::Format)?;
    let tc = c.u16().ok_or(Reject::Format)?;
    let zc = c.u16().ok_or(Reject::Format)?;
    let nc = c.u16().ok_or(Reject::Format)?;
    let max_redundancy = c.u8().ok_or(Reject::Format)?;
    let vpc_quota = c.u32().ok_or(Reject::Format)?;
    let memory_tier = c.u8().ok_or(Reject::Format)?;
    let tenant_id = c.str16().ok_or(Reject::Format)?;
    let mut tiers = Vec::new();
    let mut zones = Vec::new();
    let mut netpolicies = Vec::new();
    for _ in 0..tc { tiers.push(c.str16().ok_or(Reject::Format)?); }
    for _ in 0..zc { zones.push(c.str16().ok_or(Reject::Format)?); }
    for _ in 0..nc { netpolicies.push(c.str16().ok_or(Reject::Format)?); }
    Ok((sig, ZcapParsed { vk, ts, max_redundancy, vpc_quota, memory_tier, tenant_id, tiers, zones, netpolicies }))
}

/// Verify a zcap.v1 token against the registered mesh trust anchors (raw
/// 2592-byte ML-DSA-87 VKs).  Order of checks (and so of error codes) is the
/// one `Amin::Auth::ZCap` has always had: format → anchor → signature.  An
/// empty anchor list rejects everything.
pub fn zcap_verify(token: &[u8], anchors: &[&[u8]]) -> Result<ZcapParsed, Reject> {
    let (sig, p) = zcap_parse(token)?;
    if !anchors.iter().any(|a| *a == p.vk.as_slice()) {
        return Err(Reject::UnknownKid);
    }
    let grant = crate::ZcapGrant {
        tiers: p.tiers.clone(),
        zones: p.zones.clone(),
        netpolicies: p.netpolicies.clone(),
        max_redundancy: p.max_redundancy,
        vpc_quota: p.vpc_quota,
        memory_tier: p.memory_tier,
        tenant_id: p.tenant_id.clone(),
        ts: p.ts,
    };
    let smsg = grant.smsg(&p.vk);
    if mldsa87_verify(&p.vk, &smsg, &sig) {
        Ok(p)
    } else {
        Err(Reject::BadSig)
    }
}

// ── UCC Art.3 instruments ───────────────────────────────────────────────────

/// Exact message a maker signs: `maker \0 payee \0 amount \0 kind ‖ "amin.ucc.art3.v1"`.
pub fn instrument_message(maker: &str, payee: &str, amount: &str, kind: &str) -> Vec<u8> {
    let mut m = Vec::new();
    for (i, f) in [maker, payee, amount, kind].iter().enumerate() {
        if i > 0 { m.push(0); }
        m.extend_from_slice(f.as_bytes());
    }
    m.extend_from_slice(b"amin.ucc.art3.v1");
    m
}

/// Verify an instrument signature (raw VK / signature bytes).
pub fn instrument_verify(maker: &str, payee: &str, amount: &str, kind: &str, vk: &[u8], sig: &[u8]) -> Result<(), Reject> {
    if vk.len() != MLDSA87_VK_LEN || sig.len() != MLDSA87_SIG_LEN {
        return Err(Reject::Format);
    }
    if mldsa87_verify(vk, &instrument_message(maker, payee, amount, kind), sig) {
        Ok(())
    } else {
        Err(Reject::BadSig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{zcap_token_bytes, Keypair, ZcapGrant};
    use rand::{rngs::StdRng, SeedableRng};

    fn kp(seed: u8) -> Keypair {
        Keypair::generate(&mut StdRng::from_seed([seed; 32]), "t".into())
    }
    fn grant() -> ZcapGrant {
        ZcapGrant {
            tiers: vec!["metal-32c".into()], zones: vec!["us-east-1".into()],
            netpolicies: vec!["vpc-a".into()], max_redundancy: 3, vpc_quota: 4,
            memory_tier: 1, tenant_id: "t-tenant".into(), ts: 1_735_689_600,
        }
    }

    #[test]
    fn zcap_roundtrip_and_fail_closed() {
        let k = kp(1);
        let tok = zcap_token_bytes(&k, &grant()).unwrap();
        let vk = k.verifying_key_bytes();
        assert!(zcap_verify(&tok, &[vk.as_slice()]).is_ok());
        // no anchors → reject (the old Perl code substituted an all-zero anchor)
        assert_eq!(zcap_verify(&tok, &[]), Err(Reject::UnknownKid));
        // foreign anchor
        let other = kp(2).verifying_key_bytes();
        assert_eq!(zcap_verify(&tok, &[other.as_slice()]), Err(Reject::UnknownKid));
        // flipped signature byte
        let mut bad = tok.clone();
        bad[300] ^= 1;
        assert_eq!(zcap_verify(&bad, &[vk.as_slice()]), Err(Reject::BadSig));
        // tampered scope (tenant) breaks the signature
        let mut t2 = tok.clone();
        let tenant_off = ZCAP_FIXED; // first tenant byte
        t2[tenant_off] ^= 1;
        assert_eq!(zcap_verify(&t2, &[vk.as_slice()]), Err(Reject::BadSig));
        // invalid UTF-8 in a signed text field must be a format error, never
        // a lossy match for the original
        let mut t3 = tok.clone();
        t3[ZCAP_FIXED] = 0xFF;
        assert_eq!(zcap_verify(&t3, &[vk.as_slice()]), Err(Reject::Format));
        // truncated
        assert_eq!(zcap_verify(&tok[..100], &[vk.as_slice()]), Err(Reject::Format));
        assert_eq!(zcap_verify(&[], &[vk.as_slice()]), Err(Reject::Format));
    }

    #[test]
    fn instrument_roundtrip() {
        let k = kp(3);
        let msg = instrument_message("a", "b", "42.50", "check");
        let sig = crate::signer::mldsa87_sign(&k, &msg).unwrap();
        let vk = k.verifying_key_bytes();
        assert!(instrument_verify("a", "b", "42.50", "check", &vk, &sig).is_ok());
        assert_eq!(instrument_verify("a", "b", "42.51", "check", &vk, &sig), Err(Reject::BadSig));
        assert_eq!(instrument_verify("a", "b", "42.50", "check", &vk, &sig[..10]), Err(Reject::Format));
    }
}

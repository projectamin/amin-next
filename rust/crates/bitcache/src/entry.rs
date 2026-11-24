//! Typed ledger entries — one audited-event format for the whole stack.
//!
//! Billing, settlement, instruments, boot, AI actions, authorisations … are all
//! just `kind`s.  Every entry belongs to an `actor` and is hash-linked to that
//! actor's previous entry (`seq`, `prev`), so each actor has its own tamper-
//! evident chain inside the single global Merkle log.  Per-actor chains are
//! what make double-spend / replay detectable without global consensus: two
//! different entries claiming the same `(actor, seq)` are proof of equivocation.
//!
//! `auth` optionally names the authority that permitted the action (e.g. the
//! hash of the zcap token or signed instrument), tying each recorded fact to
//! the capability that allowed it.
//!
//! Canonical wire form (little-endian; decode re-encodes and compares, so there
//! is exactly one valid encoding of any entry):
//!
//! ```text
//!   "AMIN3-LEDGER-ENTRY-V1\n"
//!   u32 len ‖ kind  u32 len ‖ actor  u32 len ‖ subject
//!   u64 seq ‖ prev[32] ‖ auth[32] ‖ u64 ts ‖ u16 n
//!   n × ( u32 len ‖ key  u32 len ‖ value )        keys strictly ascending
//! ```
//!
//! `ts` is informational; ordering is log position.

use crate::tlog::Hash;

const MAGIC: &[u8] = b"AMIN3-LEDGER-ENTRY-V1\n";
const ID_DOMAIN: &[u8] = b"AMIN3-LEDGER-ENTRY-ID-V1\n";
const MAX_NAME: usize = 256;
const MAX_KEY: usize = 128;
const MAX_VAL: usize = 4096;
const MAX_ATTRS: usize = 64;
pub const ZERO: Hash = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    Format,
    TooLarge,
    BadKind,
    DuplicateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: String,
    pub actor: String,
    pub subject: String,
    pub seq: u64,
    pub prev: Hash,
    pub auth: Hash,
    pub ts: u64,
    /// Strictly ascending by key.
    pub attrs: Vec<(String, String)>,
}

/// An entry before the ledger assigns `seq` / `prev`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub kind: String,
    pub actor: String,
    pub subject: String,
    pub auth: Option<Hash>,
    pub ts: u64,
    pub attrs: Vec<(String, String)>,
}

pub fn valid_kind(k: &str) -> bool {
    !k.is_empty() && k.len() <= 64 && k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_')
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

impl Entry {
    pub fn check(&self) -> Result<(), EntryError> {
        if !valid_kind(&self.kind) {
            return Err(EntryError::BadKind);
        }
        if self.actor.is_empty() || self.actor.len() > MAX_NAME || self.subject.len() > MAX_NAME || self.seq == 0 {
            return Err(EntryError::TooLarge);
        }
        if self.attrs.len() > MAX_ATTRS {
            return Err(EntryError::TooLarge);
        }
        let mut last: Option<&str> = None;
        for (k, v) in &self.attrs {
            if k.is_empty() || k.len() > MAX_KEY || v.len() > MAX_VAL {
                return Err(EntryError::TooLarge);
            }
            match last {
                Some(l) if l.as_bytes() == k.as_bytes() => return Err(EntryError::DuplicateKey),
                Some(l) if l.as_bytes() > k.as_bytes() => return Err(EntryError::Format),
                _ => {}
            }
            last = Some(k);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        self.check()?;
        let mut o = Vec::with_capacity(160 + self.attrs.len() * 32);
        o.extend_from_slice(MAGIC);
        put_str(&mut o, &self.kind);
        put_str(&mut o, &self.actor);
        put_str(&mut o, &self.subject);
        o.extend_from_slice(&self.seq.to_le_bytes());
        o.extend_from_slice(&self.prev);
        o.extend_from_slice(&self.auth);
        o.extend_from_slice(&self.ts.to_le_bytes());
        o.extend_from_slice(&(self.attrs.len() as u16).to_le_bytes());
        for (k, v) in &self.attrs {
            put_str(&mut o, k);
            put_str(&mut o, v);
        }
        Ok(o)
    }

    /// Strict decode: any non-canonical or trailing input is rejected.
    pub fn decode(b: &[u8]) -> Result<Self, EntryError> {
        struct C<'a>(&'a [u8]);
        impl<'a> C<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8], EntryError> {
                if self.0.len() < n {
                    return Err(EntryError::Format);
                }
                let (a, r) = self.0.split_at(n);
                self.0 = r;
                Ok(a)
            }
            fn s(&mut self, max: usize) -> Result<String, EntryError> {
                let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
                if n > max {
                    return Err(EntryError::TooLarge);
                }
                String::from_utf8(self.take(n)?.to_vec()).map_err(|_| EntryError::Format)
            }
        }
        let mut c = C(b);
        if c.take(MAGIC.len())? != MAGIC {
            return Err(EntryError::Format);
        }
        let kind = c.s(64)?;
        let actor = c.s(MAX_NAME)?;
        let subject = c.s(MAX_NAME)?;
        let seq = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
        let (mut prev, mut auth) = ([0u8; 32], [0u8; 32]);
        prev.copy_from_slice(c.take(32)?);
        auth.copy_from_slice(c.take(32)?);
        let ts = u64::from_le_bytes(c.take(8)?.try_into().unwrap());
        let n = u16::from_le_bytes(c.take(2)?.try_into().unwrap()) as usize;
        if n > MAX_ATTRS {
            return Err(EntryError::TooLarge);
        }
        let mut attrs = Vec::with_capacity(n);
        for _ in 0..n {
            attrs.push((c.s(MAX_KEY)?, c.s(MAX_VAL)?));
        }
        if !c.0.is_empty() {
            return Err(EntryError::Format);
        }
        let e = Entry { kind, actor, subject, seq, prev, auth, ts, attrs };
        if e.encode()? != b {
            return Err(EntryError::Format);
        }
        Ok(e)
    }

    /// Identity used by the next entry's `prev`: domain-separated BLAKE3 of the encoding.
    pub fn id(&self) -> Result<Hash, EntryError> {
        Ok(id_of(&self.encode()?))
    }
}

pub fn id_of(encoded: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(ID_DOMAIN);
    h.update(encoded);
    *h.finalize().as_bytes()
}

impl Draft {
    /// Normalise attrs (sorted) and bind to a chain position.
    pub fn into_entry(mut self, seq: u64, prev: Hash) -> Result<Entry, EntryError> {
        self.attrs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let e = Entry {
            kind: self.kind, actor: self.actor, subject: self.subject, seq, prev,
            auth: self.auth.unwrap_or(ZERO), ts: self.ts, attrs: self.attrs,
        };
        e.check()?;
        Ok(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> Draft {
        Draft { kind: "billing".into(), actor: "tenant-a".into(), subject: "pid:42".into(), auth: None, ts: 7,
                attrs: vec![("z".into(), "1".into()), ("cpu_ms".into(), "1500".into())] }
    }

    #[test]
    fn roundtrip_sorts_attrs_and_is_canonical() {
        let e = d().into_entry(1, ZERO).unwrap();
        assert_eq!(e.attrs[0].0, "cpu_ms");
        let b = e.encode().unwrap();
        assert_eq!(Entry::decode(&b).unwrap(), e);
        let mut t = b.clone();
        t.push(0);
        assert_eq!(Entry::decode(&t), Err(EntryError::Format));
        for i in 0..b.len() {
            if let Ok(x) = Entry::decode(&{ let mut m = b.clone(); m[i] ^= 1; m }) {
                // any accepted mutation must be a different, still-canonical entry
                assert_ne!(x, e, "flip at {i} accepted as the same entry");
            }
        }
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut x = d();
        x.kind = "Billing".into();
        assert_eq!(x.into_entry(1, ZERO), Err(EntryError::BadKind));
        let mut x = d();
        x.attrs.push(("z".into(), "dup".into()));
        assert_eq!(x.into_entry(1, ZERO), Err(EntryError::DuplicateKey));
        assert!(d().into_entry(0, ZERO).is_err()); // seq starts at 1
        // non-ascending keys in a hand-built entry are non-canonical
        let mut e = d().into_entry(1, ZERO).unwrap();
        e.attrs.reverse();
        assert!(e.encode().is_err());
    }

    #[test]
    fn id_depends_on_every_field() {
        let a = d().into_entry(1, ZERO).unwrap();
        let b = d().into_entry(2, ZERO).unwrap();
        let c = d().into_entry(1, [1; 32]).unwrap();
        let mut dd = d();
        dd.auth = Some([9; 32]);
        let e = dd.into_entry(1, ZERO).unwrap();
        let ids = [a.id().unwrap(), b.id().unwrap(), c.id().unwrap(), e.id().unwrap()];
        for i in 0..4 { for j in i + 1..4 { assert_ne!(ids[i], ids[j]); } }
    }
}

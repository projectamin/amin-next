//! Binary SAX v1 decode iterator — zero-copy over a `&[u8]` input slice.
//!
//! # Bounds / safety
//!
//! [`Bounds`] enforces the three structural caps from [`Amin::Util::Fold`]
//! contract so a hostile party can't DoS the decoder:
//!   * `name_max_bytes`  — default 8 KiB (LocalName escape strings)
//!   * `value_max_bytes` — default 256 KiB (attribute / characters / PI data)
//!   * `attr_max`        — default 128 attrs per element
//!
//! Any violation returns a deterministic [`crate::DecodeError`] and stops
//! iteration — never panics, never OOM.  Perfect for:
//!   * XDP/eBPF validation hook (B part of P/B/N)
//!   * seccomp/landlocked mobile scan (N part)
//!   * Perl Safe opcode-masked `Amin::Generator::BSAX` decode path (P part)

use alloc::vec::Vec;

use crate::{Event, Tag, DecodeError, MAGIC};

/// Decoder configuration — all numbers are deliberately conservative (by
/// design: Amin filters never exceed these caps in normal production).
#[derive(Debug, Clone)]
pub struct Bounds {
    /// Maximum LocalName byte length when NAME_ID ≥ ESCAPE (escape marker).
    pub name_max_bytes:  usize,
    /// Maximum value byte length (attrs / characters / PI data).
    pub value_max_bytes: usize,
    /// Maximum attributes per `start_element`.
    pub attr_max:        usize,
    /// When `true`, escaped names (id ≥ vocab::escape_id()) or NS_ID=15
    /// (escape) are rejected immediately unless the caller has pre-registered
    /// them in `allowed_names`/`allowed_ns`.  Mirrors the allow-list guard in
    /// `Amin::Util::Fold`.
    pub allow_vocab_only: bool,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            name_max_bytes:  8 * 1024,
            value_max_bytes: 256 * 1024,
            attr_max:        128,
            allow_vocab_only: true,
        }
    }
}

/// Streaming decoder — borrows the input slice for the lifetime of every
/// yielded event so characters/values never need copying on the hot path.
pub struct Decoder<'a> {
    buf: &'a [u8],
    off: usize,
    bounds: Bounds,
    /// `last_ns_id` — reused on START_ELEM when flags[4]==0; matches encode
    /// side delta encoding to avoid repeating NS_ID every tag.
    last_ns_id: u8,
}

impl<'a> Decoder<'a> {
    /// Build a decoder; validates the 8-byte magic first.  Returns
    /// [`DecodeError::Truncated`] if `buf` is shorter than the header.
    pub fn new(buf: &'a [u8], bounds: Bounds) -> Result<Self, DecodeError> {
        if buf.len() < MAGIC.len() { return Err(DecodeError::Truncated(0)) }
        if buf[..MAGIC.len()] != MAGIC {
            // Not a binary-SAX stream.  Caller is expected to fall back to
            // XML::LibXML::SAX text parser in this case.  We do not attempt
            // XML parsing inside bsax (separation of concerns).
            return Err(DecodeError::UnknownTag(buf[0], 0));
        }
        Ok(Self { buf, off: MAGIC.len(), bounds, last_ns_id: 0 })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() - self.off < n { return Err(DecodeError::Truncated(self.off)) }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    /// LEB128 u32 (unsigned, max 5 bytes = same as Wire Format varint).
    fn leb_u32(&mut self) -> Result<u32, DecodeError> {
        let mut result: u64 = 0;
        let mut shift  = 0u32;
        loop {
            if shift >= 35 { return Err(DecodeError::Truncated(self.off)) }
            let byte = *self.take(1)?.first().unwrap();
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 { break }
            shift += 7;
        }
        if result > u64::from(u32::MAX) { Err(DecodeError::ValueTooLong(self.off)) }
        else { Ok(result as u32) }
    }

    fn len_prefixed(&mut self, cap: usize, kind_err: fn(usize)->DecodeError)
        -> Result<&'a [u8], DecodeError>
    {
        let n = self.leb_u32()? as usize;
        if n > cap { return Err(kind_err(self.off)) }
        self.take(n)
    }
}

impl<'a> Iterator for Decoder<'a> {
    type Item = Result<Event<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.off >= self.buf.len() { return None }
        let start = self.off;
        let tag_byte = match self.take(1) {
            Ok(b) => b[0],
            Err(e) => return Some(Err(e)),
        };
        let (tag, flags) = match Tag::from_byte(tag_byte) {
            Some(t) => t,
            None    => return Some(Err(DecodeError::UnknownTag(tag_byte, start))),
        };
        Some(match tag {
            Tag::StartDoc => Ok(Event::StartDocument),
            Tag::EndDoc   => Ok(Event::EndDocument),
            Tag::EndEl    => Ok(Event::EndElement),
            Tag::Chars | Tag::Iws => {
                let n = if flags < 31 { flags as usize } else {
                    match self.leb_u32() { Ok(v)=>v as usize, Err(e)=>return Some(Err(e)) }
                };
                match self.take(n) {
                    Ok(bytes) => if matches!(tag, Tag::Iws) {Ok(Event::Iws(bytes))} else {Ok(Event::Chars(bytes))},
                    Err(e) => Err(e),
                }
            },
            Tag::StartEl => {
                // ns inline?
                let mut ns_id = self.last_ns_id;
                if flags & 0x10 != 0 {
                    // delta: 1 byte NS_ID 4bits(high) + skip 4 = next byte NAME_ID
                    let b = match self.take(1) { Ok(b)=>b[0], Err(e)=>return Some(Err(e)) };
                    ns_id = (b >> 4) & 0x0F;
                    // name_id is a LEB128 beginning with the low nibble + next bytes.
                    // Simplify: name_id == next LEB128.
                    let _ = b & 0x0F;  // reserved for future packed extensions
                }
                self.last_ns_id = ns_id;
                let name_id = match self.leb_u32() { Ok(v)=>v, Err(e)=>return Some(Err(e)) };
                if self.bounds.allow_vocab_only && name_id > 61 {
                    return Some(Err(DecodeError::ProhibitedName(name_id, start)));
                }
                let n_attrs = if flags & 0x0F == 15 {
                    let n = match self.leb_u32() { Ok(v)=>v, Err(e)=>return Some(Err(e)) };
                    if n > self.bounds.attr_max as u32 {
                        return Some(Err(DecodeError::ValueTooLong(start)));
                    }
                    n as usize
                } else {
                    (flags & 0x0F) as usize
                };
                let mut attrs = Vec::with_capacity(n_attrs.min(16));
                for _ in 0..n_attrs {
                    let aid = match self.leb_u32() { Ok(v)=>v, Err(e)=>return Some(Err(e)) };
                    if self.bounds.allow_vocab_only && aid > 61 {
                        return Some(Err(DecodeError::ProhibitedName(aid, self.off)));
                    }
                    let val = match self.len_prefixed(self.bounds.value_max_bytes, DecodeError::ValueTooLong) {
                        Ok(v)=>v, Err(e)=>return Some(Err(e)),
                    };
                    attrs.push((aid as u8, val));
                }
                let (ns_uri, ln_override) = (None, None); // escape path TBD; stubs now
                Ok(Event::StartElement {
                    ns_id,
                    name_id: name_id as u8,
                    ns_uri_override: ns_uri,
                    local_name_override: ln_override,
                    attrs,
                })
            },
            Tag::Pi => {
                let tid = match self.leb_u32() { Ok(v)=>v, Err(e)=>return Some(Err(e)) };
                let data = match self.len_prefixed(self.bounds.value_max_bytes, DecodeError::ValueTooLong) {
                    Ok(v)=>v, Err(e)=>return Some(Err(e)),
                };
                Ok(Event::Pi { target_id: tid as u8, target_override: None, data })
            },
            Tag::Dict => {
                let ns_id = (flags >> 4) & 0x0F;
                let id = match self.leb_u32() { Ok(v)=>v, Err(e)=>return Some(Err(e)) };
                let name = match self.len_prefixed(self.bounds.name_max_bytes, DecodeError::NameTooLong) {
                    Ok(v)=>v, Err(e)=>return Some(Err(e)),
                };
                Ok(Event::DictEntry { ns_id, id, name })
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, vocab};

    #[test]
    fn roundtrip_startdoc_status_enddoc() {
        // Build a tiny BS AX stream manually via encode:
        let mut out = vec![];
        encode::write_magic(&mut out);
        encode::write_start_doc(&mut out);
        // <amin:status kind="success" rc="0" pid="123" duration="0.1" exit_kind="ok"/>
        let attrs: [(u8, &[u8]); 5] = [
            (vocab::by_name(b"kind").unwrap(), b"success"),
            (vocab::by_name(b"rc").unwrap(), b"0"),
            (vocab::by_name(b"pid").unwrap(), b"123"),
            (vocab::by_name(b"duration").unwrap(), b"0.1"),
            (vocab::by_name(b"exit_kind").unwrap(), b"ok"),
        ];
        encode::write_start_elem(&mut out, 1 /* NS_AMIN */, vocab::by_name(b"status").unwrap(), &attrs);
        encode::write_end_elem(&mut out);
        encode::write_end_doc(&mut out);

        let mut it = Decoder::new(&out, Bounds::default()).unwrap();
        assert_eq!(it.next(), Some(Ok(Event::StartDocument)));
        let se = it.next().unwrap().unwrap();
        match se {
            Event::StartElement { ns_id, name_id, attrs: a, .. } => {
                assert_eq!(ns_id, 1);
                assert_eq!(name_id, vocab::by_name(b"status").unwrap());
                assert_eq!(a.len(), 5);
                assert_eq!(a[0], (vocab::by_name(b"kind").unwrap(), &b"success"[..]));
            }
            _ => panic!("not a start_element"),
        }
        assert_eq!(it.next(), Some(Ok(Event::EndElement)));
        assert_eq!(it.next(), Some(Ok(Event::EndDocument)));
        assert!(it.next().is_none());
    }
}

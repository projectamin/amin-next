//! Binary SAX v1 encode — appends encoded bytes to any `BufMut` target.
//!
//! Encoder is deliberately tiny: the 5-position SAX chain ends with the
//! encode call, so **encode is on the CRITICAL PATH for hyperscale** (a
//! single large fabric emits millions of `<amin:status>` events / sec).

use bytes::BufMut;

use crate::{MAGIC, Tag};

/// Write the 8-byte stream magic.  Call exactly once per stream, before any
/// event.  (Multiple concatenated streams each start with their own magic.)
pub fn write_magic<B: BufMut>(out: &mut B) {
    out.put_slice(&MAGIC);
}

/// `start_document` — 1 byte tag.
pub fn write_start_doc<B: BufMut>(out: &mut B) {
    out.put_u8(Tag::StartDoc as u8);
}

/// `end_document` — 1 byte tag.
pub fn write_end_doc<B: BufMut>(out: &mut B) {
    out.put_u8(Tag::EndDoc as u8);
}

/// `end_element` — 1 byte tag.  Name is NEVER repeated (decoder pops stack).
pub fn write_end_elem<B: BufMut>(out: &mut B) {
    out.put_u8(Tag::EndEl as u8);
}

/// `start_element`.  `attrs` are `(name_id, value_bytes)` — name_id MUST be
/// obtained via [`crate::vocab::by_name`] (0..=61) to keep wire bytes tight.
///
/// Panic-free contract: `ns_id ∈ 0..16`, `attr_count ∈ 0..=attr_max`.
pub fn write_start_elem<B: BufMut>(
    out: &mut B,
    ns_id: u8,
    name_id: u8,
    attrs: &[(u8, impl AsRef<[u8]>)],
) {
    // flags high bit 4 = NS inline; low 4 = count or 15 escape
    let ns_inline: u8 = 1; // always emit inline NS on start to keep decoder
                           // state machine stateless for replay/frame split.
                           // (cost 1 extra byte/el → negligible vs savings from NS delta on inner siblings)
    let count = attrs.len() as u8;
    let count_field = if count <= 14 { count } else { 15 };
    let first_byte = Tag::StartEl as u8 | (ns_inline << 4) | count_field;
    out.put_u8(first_byte);
    // NS: 4 bits high + reserved 0x00 = next byte
    out.put_u8((ns_id & 0x0F) << 4);
    leb_u32(out, u32::from(name_id));
    if count > 14 { leb_u32(out, u32::from(count)) }
    for (aid, v) in attrs {
        leb_u32(out, u32::from(*aid));
        let vb = v.as_ref();
        leb_u32(out, vb.len() as u32);
        out.put_slice(vb);
    }
}

/// `characters` — raw UTF-8 bytes, length-prefixed with short-form optim.
pub fn write_chars<B: BufMut>(out: &mut B, data: &[u8]) {
    let len = data.len();
    if len < 32 {
        out.put_u8(Tag::Chars as u8 | (len as u8));
        out.put_slice(data);
    } else {
        out.put_u8(Tag::Chars as u8 | 0x1F);
        leb_u32(out, len as u32);
        out.put_slice(data);
    }
}

/// `ignorable_whitespace` (rare; filters drop it anyway).
pub fn write_iws<B: BufMut>(out: &mut B, data: &[u8]) {
    let len = data.len();
    if len < 32 {
        out.put_u8(Tag::Iws as u8 | (len as u8));
        out.put_slice(data);
    } else {
        out.put_u8(Tag::Iws as u8 | 0x1F);
        leb_u32(out, len as u32);
        out.put_slice(data);
    }
}

/// LEB128 unsigned 32-bit variable-length integer (same as protobuf/wire format).
#[inline]
pub fn leb_u32<B: BufMut>(out: &mut B, mut v: u32) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 { out.put_u8(b); return }
        out.put_u8(b | 0x80);
    }
}

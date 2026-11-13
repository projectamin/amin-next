//! Binary SAX v1 **streaming** decoder — resumable over arbitrary chunk
//! boundaries, zero-copy over an owned internal buffer.
//!
//! BSAX is a streamed protocol: a caller pushes transport chunks in with
//! [`StreamDecoder::feed`] and pulls decoded events out with
//! [`StreamDecoder::poll_event`].  An event is only emitted once its last
//! byte has arrived; a partial event yields [`Poll::NeedMore`] and the bytes
//! are retained until the next chunk, so events never straddle a chunk
//! boundary incorrectly.
//!
//! # Bounds / safety
//!
//! [`Bounds`] enforces the three structural caps from [`Amin::Util::Fold`]
//! contract so a hostile party can't DoS the decoder:
//!   * `name_max_bytes`  — default 8 KiB (LocalName / NS-escape strings)
//!   * `value_max_bytes` — default 256 KiB (attribute / characters / PI data)
//!   * `attr_max`        — default 128 attrs per element
//!
//! Any violation returns a deterministic [`crate::DecodeError`] and stops
//! iteration — never panics, never OOM.  Perfect for:
//!   * XDP/eBPF validation hook (B part of P/B/N)
//!   * seccomp/landlocked mobile scan (N part)
//!   * Perl Safe opcode-masked `Amin::Generator::BSAX` decode path (P part)

use alloc::vec::Vec;

use crate::{Attr, DecodeError, Event, Tag, MAGIC};

/// Decoder configuration — all numbers are deliberately conservative (by
/// design: Amin filters never exceed these caps in normal production).
#[derive(Debug, Clone)]
pub struct Bounds {
    /// Maximum byte length of an escaped LocalName / NS URI string.
    pub name_max_bytes:  usize,
    /// Maximum value byte length (attrs / characters / PI data).
    pub value_max_bytes: usize,
    /// Maximum attributes per `start_element`.
    pub attr_max:        usize,
    /// When `true`, escaped names (id ≥ vocab::escape_id()) or NS_ID=15
    /// (escape) are rejected with [`DecodeError::ProhibitedName`].  The
    /// escaped bytes are still consumed first so the stream stays aligned.
    /// Mirrors the allow-list guard in `Amin::Util::Fold`.
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

/// Outcome of one [`StreamDecoder::poll_event`] call.
#[derive(Debug)]
pub enum Poll<'a> {
    /// A fully-decoded event, borrowing from the decoder's internal buffer.
    /// The borrow ends when the value is dropped (before the next poll).
    Event(Event<'a>),
    /// The buffered bytes are a valid prefix of an event but not yet a whole
    /// one; feed more bytes and poll again.  State is preserved.
    NeedMore,
    /// The stream ended cleanly (`end_document` was seen).
    Done,
}

/// Resumable streaming decoder.  Owns a growable buffer of not-yet-consumed
/// bytes; consumed bytes are reclaimed at the next poll, so memory tracks the
/// size of the current event, not the document.
pub struct StreamDecoder {
    buf: Vec<u8>,
    off: usize,
    bounds: Bounds,
    /// NS_ID reused on START_ELEM when the inline-NS flag is clear (matches the
    /// encode-side delta so the element's namespace isn't repeated every tag).
    last_ns_id: u8,
    magic_seen: bool,
    finished: bool,
}

impl StreamDecoder {
    /// Build a decoder.  No magic check happens until the first 8 bytes have
    /// been fed, so the header may itself straddle a chunk boundary.
    #[must_use]
    pub fn new(bounds: Bounds) -> Self {
        Self {
            buf: Vec::new(),
            off: 0,
            bounds,
            last_ns_id: 0,
            magic_seen: false,
            finished: false,
        }
    }

    /// Append the next transport chunk.  May be called with any chunk size
    /// (including 1 byte) and any number of times.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Pull the next event out of the buffer, consuming it.
    ///
    /// Returns [`Poll::NeedMore`] when the buffer holds only a prefix of an
    /// event (no bytes are consumed); [`Poll::Done`] once `end_document` has
    /// been seen; and [`DecodeError`] on a malformed stream (bad magic,
    /// unknown tag, or a bounds violation).
    pub fn poll_event(&mut self) -> Result<Poll<'_>, DecodeError> {
        // Reclaim the prefix consumed by the previous event.  Safe here: the
        // previous event's borrow has ended before the caller polls again.
        if self.off > 0 {
            self.buf.drain(..self.off);
            self.off = 0;
        }
        if self.finished {
            return Ok(Poll::Done);
        }

        if !self.magic_seen {
            if self.buf.len() < MAGIC.len() {
                return Ok(Poll::NeedMore);
            }
            if self.buf[..MAGIC.len()] != MAGIC {
                // Not a binary-SAX stream — caller falls back to the XML
                // parser.  bsax never parses XML itself (separation of
                // concerns).
                return Err(DecodeError::UnknownTag(self.buf[0], 0));
            }
            self.buf.drain(..MAGIC.len());
            self.magic_seen = true;
        }

        let last_ns = self.last_ns_id;
        match parse_event(&self.buf, &mut self.off, last_ns, &self.bounds)? {
            None => Ok(Poll::NeedMore),
            Some((event, ns_id)) => {
                self.last_ns_id = ns_id;
                if matches!(event, Event::EndDocument) {
                    self.finished = true;
                }
                Ok(Poll::Event(event))
            }
        }
    }

    /// `true` once `end_document` has been decoded.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// Read `n` bytes, advancing `off`; `None` if fewer than `n` remain.
fn take<'a>(buf: &'a [u8], off: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = off.checked_add(n)?;
    if end > buf.len() {
        return None;
    }
    let s = &buf[*off..end];
    *off = end;
    Some(s)
}

/// LEB128 u32 (unsigned, ≤5 bytes like the Wire Format varint).  `None` means
/// "need more input"; an over-long encoding is a hard error.
fn leb(buf: &[u8], off: &mut usize) -> Result<Option<u32>, DecodeError> {
    let start = *off;
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if shift >= 35 {
            return Err(DecodeError::ValueTooLong(start));
        }
        let byte = match take(buf, off, 1) { Some(s) => s[0], None => return Ok(None) };
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    if result > u64::from(u32::MAX) {
        Err(DecodeError::ValueTooLong(start))
    } else {
        Ok(Some(result as u32))
    }
}

/// LEB128 length prefix + that many raw bytes, capped.  `None` = need more.
fn len_prefixed<'a>(
    buf: &'a [u8],
    off: &mut usize,
    cap: usize,
    over: fn(usize) -> DecodeError,
) -> Result<Option<&'a [u8]>, DecodeError> {
    let n = match leb(buf, off)? { Some(v) => v as usize, None => return Ok(None) };
    if n > cap {
        return Err(over(*off));
    }
    Ok(take(buf, off, n))
}

/// Parse exactly one event from `buf` starting at `*off`.  Transactional: on
/// `None` (need more input) `*off` is left untouched, so a later poll retries
/// the same event from the start.
fn parse_event<'a>(
    buf: &'a [u8],
    off: &mut usize,
    last_ns_id: u8,
    bounds: &Bounds,
) -> Result<Option<(Event<'a>, u8)>, DecodeError> {
    if *off >= buf.len() {
        return Ok(None);
    }
    let start = *off;
    let tag_byte = buf[start];
    let (tag, flags) = match Tag::from_byte(tag_byte) {
        Some(t) => t,
        None => return Err(DecodeError::UnknownTag(tag_byte, start)),
    };

    // Local cursor; only committed to `*off` when the whole event is present.
    let mut p = start + 1;
    let (event, ns_id) = match tag {
        Tag::StartDoc => (Event::StartDocument, last_ns_id),
        Tag::EndDoc   => (Event::EndDocument, last_ns_id),
        Tag::EndEl    => (Event::EndElement, last_ns_id),
        Tag::Chars | Tag::Iws => {
            let n = if flags < 31 {
                flags as usize
            } else {
                match leb(buf, &mut p)? { Some(v) => v as usize, None => return Ok(None) }
            };
            if n > bounds.value_max_bytes {
                return Err(DecodeError::ValueTooLong(start));
            }
            let bytes = match take(buf, &mut p, n) { Some(b) => b, None => return Ok(None) };
            let ev = if matches!(tag, Tag::Iws) { Event::Iws(bytes) } else { Event::Chars(bytes) };
            (ev, last_ns_id)
        },
        Tag::StartEl => {
            let mut ns_id = last_ns_id;
            let mut ns_uri_override = None;
            if flags & 0x10 != 0 {
                let b = match take(buf, &mut p, 1) { Some(b) => b[0], None => return Ok(None) };
                ns_id = (b >> 4) & 0x0F;
                if ns_id == crate::vocab::ns_id::ESCAPE {
                    // NS_ESCAPE (15): a length-prefixed UTF-8 URI rides inline.
                    // Consuming it is what keeps the following NAME_ID LEB and
                    // attribute block from being misread (the desync bug).
                    ns_uri_override =
                        match len_prefixed(buf, &mut p, bounds.name_max_bytes, DecodeError::NameTooLong)? {
                            Some(u) => Some(u),
                            None => return Ok(None),
                        };
                }
            }
            let name_id = match leb(buf, &mut p)? { Some(v) => v, None => return Ok(None) };
            let mut local_name_override = None;
            if name_id >= crate::vocab::escape_id() {
                local_name_override =
                    match len_prefixed(buf, &mut p, bounds.name_max_bytes, DecodeError::NameTooLong)? {
                        Some(n) => Some(n),
                        None => return Ok(None),
                    };
            }
            if bounds.allow_vocab_only
                && (name_id >= crate::vocab::escape_id() || ns_id == crate::vocab::ns_id::ESCAPE)
            {
                return Err(DecodeError::ProhibitedName(name_id, start));
            }
            let n_attrs = if flags & 0x0F == 15 {
                let n = match leb(buf, &mut p)? { Some(v) => v, None => return Ok(None) };
                if n > bounds.attr_max as u32 {
                    return Err(DecodeError::ValueTooLong(start));
                }
                n as usize
            } else {
                (flags & 0x0F) as usize
            };
            let mut attrs: Vec<Attr<'a>> = Vec::with_capacity(n_attrs.min(16));
            for _ in 0..n_attrs {
                let aid = match leb(buf, &mut p)? { Some(v) => v, None => return Ok(None) };
                let mut name_override = None;
                if aid >= crate::vocab::escape_id() {
                    name_override =
                        match len_prefixed(buf, &mut p, bounds.name_max_bytes, DecodeError::NameTooLong)? {
                            Some(s) => Some(s),
                            None => return Ok(None),
                        };
                    if bounds.allow_vocab_only {
                        return Err(DecodeError::ProhibitedName(aid, p));
                    }
                }
                let value = match len_prefixed(buf, &mut p, bounds.value_max_bytes, DecodeError::ValueTooLong)? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                attrs.push(Attr { name_id: aid as u8, name_override, value });
            }
            (
                Event::StartElement {
                    ns_id,
                    name_id: name_id as u8,
                    ns_uri_override,
                    local_name_override,
                    attrs,
                },
                ns_id,
            )
        },
        Tag::Pi => {
            let tid = match leb(buf, &mut p)? { Some(v) => v, None => return Ok(None) };
            let mut target_override = None;
            if tid >= crate::vocab::escape_id() {
                target_override =
                    match len_prefixed(buf, &mut p, bounds.name_max_bytes, DecodeError::NameTooLong)? {
                        Some(s) => Some(s),
                        None => return Ok(None),
                    };
            }
            let data = match len_prefixed(buf, &mut p, bounds.value_max_bytes, DecodeError::ValueTooLong)? {
                Some(d) => d,
                None => return Ok(None),
            };
            (Event::Pi { target_id: tid as u8, target_override, data }, last_ns_id)
        },
        Tag::Dict => {
            let ns_id = (flags >> 4) & 0x0F;
            let id = match leb(buf, &mut p)? { Some(v) => v, None => return Ok(None) };
            let name = match len_prefixed(buf, &mut p, bounds.name_max_bytes, DecodeError::NameTooLong)? {
                Some(n) => n,
                None => return Ok(None),
            };
            (Event::DictEntry { ns_id, id, name }, last_ns_id)
        },
    };

    *off = p;
    Ok(Some((event, ns_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, vocab};

    fn feed_all(bytes: &[u8]) -> StreamDecoder {
        let mut d = StreamDecoder::new(Bounds::default());
        d.feed(bytes);
        d
    }

    #[test]
    fn roundtrip_startdoc_status_enddoc() {
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
        encode::write_start_elem(&mut out, vocab::ns_id::AMIN, vocab::by_name(b"status").unwrap(), &attrs);
        encode::write_end_elem(&mut out);
        encode::write_end_doc(&mut out);

        let mut d = feed_all(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement { ns_id, name_id, attrs: a, .. }) => {
                assert_eq!(ns_id, 1);
                assert_eq!(name_id, vocab::by_name(b"status").unwrap());
                assert_eq!(a.len(), 5);
                assert_eq!(a[0].name_id, vocab::by_name(b"kind").unwrap());
                assert_eq!(a[0].name_override, None);
                assert_eq!(a[0].value, &b"success"[..]);
                assert_eq!(a[0].local_name(), Some(&b"kind"[..]));
            },
            other => panic!("not a start_element: {other:?}"),
        }
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndElement))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndDocument))));
        assert!(matches!(d.poll_event(), Ok(Poll::Done)));
    }

    #[test]
    fn chunked_one_byte_at_a_time_yields_identical_events() {
        let mut out = vec![];
        encode::write_magic(&mut out);
        encode::write_start_doc(&mut out);
        let attrs: [(u8, &[u8]); 1] = [(vocab::by_name(b"kind").unwrap(), b"success")];
        encode::write_start_elem(&mut out, vocab::ns_id::AMIN, vocab::by_name(b"status").unwrap(), &attrs);
        // 40-byte characters payload forces the long form (len >= 31).
        encode::write_chars(&mut out, &b"x".repeat(40));
        encode::write_end_elem(&mut out);
        encode::write_end_doc(&mut out);

        let mut d = StreamDecoder::new(Bounds::default());
        let mut seen_len = None;
        let mut n_events = 0;
        for chunk in out.chunks(1) {
            d.feed(chunk);
            loop {
                match d.poll_event() {
                    Ok(Poll::Event(Event::StartDocument)) => n_events += 1,
                    Ok(Poll::Event(Event::StartElement { .. })) => n_events += 1,
                    Ok(Poll::Event(Event::Chars(c))) => { seen_len = Some(c.len()); n_events += 1 },
                    Ok(Poll::Event(Event::EndElement)) => n_events += 1,
                    Ok(Poll::Event(Event::EndDocument)) => n_events += 1,
                    Ok(Poll::Event(_)) => n_events += 1,
                    Ok(Poll::NeedMore) | Ok(Poll::Done) => break,
                    Err(e) => panic!("decode error at byte boundary: {e}"),
                }
            }
        }
        assert_eq!(n_events, 5, "one partial chunk must not lose or duplicate an event");
        assert_eq!(seen_len, Some(40));
    }

    #[test]
    fn escaped_ns_uri_and_names_are_consumed_not_desynced() {
        // Hand-build the NS_ESCAPE path the encoder writes:
        //   START_ELEM(ns_inline=1, count=1)  0x51
        //   ns byte = 0x0F << 4               0xF0
        //   leb(uri_len) + uri
        //   leb(ESCAPE) + leb(name_len) + name
        //   attr: leb(ESCAPE) + leb(an_len) + an + leb(val_len) + val
        //   END_ELEM / END_DOC
        let uri = b"https://corp.example.test/ns/sox/v1";
        let name = b"audit-trail";
        let an = b"id";
        let val = b"corp-1";
        let mut out = vec![];
        out.extend_from_slice(&MAGIC);
        out.push(0x00); // StartDoc
        out.push(0x40 | 0x10 | 1); // StartEl, ns inline, 1 attr
        out.push(0x0F << 4); // NS_ID = ESCAPE
        encode::leb_u32(&mut out, uri.len() as u32);
        out.extend_from_slice(uri);
        encode::leb_u32(&mut out, vocab::escape_id());
        encode::leb_u32(&mut out, name.len() as u32);
        out.extend_from_slice(name);
        encode::leb_u32(&mut out, vocab::escape_id());
        encode::leb_u32(&mut out, an.len() as u32);
        out.extend_from_slice(an);
        encode::leb_u32(&mut out, val.len() as u32);
        out.extend_from_slice(val);
        out.push(0x60); // EndEl
        out.push(0x20); // EndDoc

        let bounds = Bounds { allow_vocab_only: false, ..Bounds::default() };
        let mut d = StreamDecoder::new(bounds);
        d.feed(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement { ns_id, name_id, ns_uri_override, local_name_override, attrs }) => {
                assert_eq!(ns_id, vocab::ns_id::ESCAPE);
                assert_eq!(name_id as u32, vocab::escape_id());
                assert_eq!(ns_uri_override, Some(&uri[..]));
                assert_eq!(local_name_override, Some(&name[..]));
                assert_eq!(attrs.len(), 1);
                assert_eq!(attrs[0].name_id as u32, vocab::escape_id());
                assert_eq!(attrs[0].local_name(), Some(&an[..]));
                assert_eq!(attrs[0].value, &val[..]);
            },
            other => panic!("not an escaped start_element: {other:?}"),
        }
        // The stream stays aligned: EndEl + EndDoc still decode cleanly.
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndElement))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndDocument))));
    }

    #[test]
    fn vocab_only_bounds_rejects_escaped_names() {
        // Hand-build MAGIC + START_ELEM(ns_inline, 0 attrs) with an escaped
        // (id == ESCAPE) element name.  With the default `allow_vocab_only`
        // the decoder must refuse it rather than surface a non-vocab name.
        let mut out = vec![];
        out.extend_from_slice(&MAGIC);
        out.push(0x40 | 0x10); // StartEl, ns inline, 0 attrs
        out.push(0x01 << 4); // NS_ID = AMIN
        encode::leb_u32(&mut out, vocab::escape_id());
        encode::leb_u32(&mut out, 3);
        out.extend_from_slice(b"zzz");
        out.push(0x60);
        let mut d = StreamDecoder::new(Bounds::default());
        d.feed(&out);
        // The escaped name bytes are walked (so we know where the name ends)
        // before the guard rejects it — no desync, just a deterministic Err.
        match d.poll_event() {
            Err(DecodeError::ProhibitedName(id, _)) => assert_eq!(id, vocab::escape_id()),
            other => panic!("expected ProhibitedName, got {other:?}"),
        }
    }

    #[test]
    fn iws_emits_ignorable_whitespace_distinct_from_chars() {
        // IWS (0xA0) must surface as Event::Iws and never be folded into Chars —
        // the 1:1 analogue of XML::SAX firing `ignorable_whitespace` rather
        // than `characters` for whitespace-only text nodes.
        let mut out = vec![];
        encode::write_magic(&mut out);
        encode::write_start_doc(&mut out);
        encode::write_chars(&mut out, b"hi");
        encode::write_iws(&mut out, b"\n  ");
        encode::write_end_doc(&mut out);

        let mut d = feed_all(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::Chars(c))) if c == b"hi"));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::Iws(w))) if w == b"\n  "));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndDocument))));
        assert!(matches!(d.poll_event(), Ok(Poll::Done)));
    }

    #[test]
    fn pi_with_escaped_target_and_data() {
        // PI (0xC0): LEB(target_id); when target_id == ESCAPE a len-prefixed
        // target name follows; the data blob is ALWAYS len-prefixed — the 1:1
        // analogue of XML::SAX `processing_instruction(Target, Data)`.
        let target = b"xml-stylesheet";
        let data = b"type=\"text/xsl\"";
        let mut out = vec![];
        out.extend_from_slice(&MAGIC);
        out.push(0x00); // StartDoc
        out.push(0xC0); // PI
        encode::leb_u32(&mut out, vocab::escape_id());
        encode::leb_u32(&mut out, target.len() as u32);
        out.extend_from_slice(target);
        encode::leb_u32(&mut out, data.len() as u32);
        out.extend_from_slice(data);
        out.push(0x20); // EndDoc

        let bounds = Bounds { allow_vocab_only: false, ..Bounds::default() };
        let mut d = StreamDecoder::new(bounds);
        d.feed(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event().unwrap() {
            Poll::Event(Event::Pi { target_id, target_override, data: pd }) => {
                assert_eq!(u32::from(target_id), vocab::escape_id());
                assert_eq!(target_override, Some(&target[..]));
                assert_eq!(pd, &data[..]);
            },
            other => panic!("not a PI: {other:?}"),
        }
        // Stream stays aligned after the PI: EndDoc still decodes cleanly.
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndDocument))));
    }
}

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

use crate::vocab::Vocab;
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
    /// Opt-in closed-world hardening for a *consumer* that wants it.  When
    /// `true`, a name on the **inline-escape** path (`id ==
    /// vocab::escape_id()`) or NS_ID=15 (escape) is rejected with
    /// [`DecodeError::ProhibitedName`]; the escaped bytes are still consumed
    /// first so the stream stays aligned.  A **spec-declared band** id is
    /// accepted — it names vocabulary the consumer's own spec handed the
    /// decoder.
    ///
    /// Defaults to `false`: BSAX is a **pure 1:1 mirror of the XML event set**
    /// (see crate docs, "Escape hatches are not a trust boundary").  The codec
    /// is not a policy point, so unknown names ride the escape path exactly as
    /// the XML parser would surface them.  Closed-world enforcement belongs in
    /// the filter chain (`Amin::Filter::UI::Guard`, ainit's own stage filter);
    /// a consumer may still arm this at its own boundary as belt-and-braces.
    pub allow_vocab_only: bool,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            name_max_bytes:  8 * 1024,
            value_max_bytes: 256 * 1024,
            attr_max:        128,
            allow_vocab_only: false,
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
    /// The consumer spec's declared NAME_ID band — resolves band ids
    /// (`> vocab::escape_id()`) to the LocalNames the producer's matching spec
    /// declared.  Empty ⇒ only the compiled core table resolves, byte-identical
    /// to the pre-band codec.
    vocab: Vocab,
    /// NS_ID reused on START_ELEM when the inline-NS flag is clear (matches the
    /// encode-side delta so the element's namespace isn't repeated every tag).
    last_ns_id: u8,
    magic_seen: bool,
    finished: bool,
}

impl StreamDecoder {
    /// Build a decoder with no spec-declared band.  No magic check happens
    /// until the first 8 bytes have been fed, so the header may itself straddle
    /// a chunk boundary.
    #[must_use]
    pub fn new(bounds: Bounds) -> Self {
        Self::with_vocab(bounds, Vocab::empty())
    }

    /// Build a decoder carrying the consumer spec's declared NAME_ID band —
    /// see [`crate::vocab::Vocab`].  Pass the SAME spec the producer encoded
    /// against so band ids resolve; an id past the declared band is a loud
    /// [`DecodeError::NameOutOfBand`].
    #[must_use]
    pub fn with_vocab(bounds: Bounds, vocab: Vocab) -> Self {
        Self {
            buf: Vec::new(),
            off: 0,
            bounds,
            vocab,
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
        match parse_event(&self.buf, &mut self.off, last_ns, &self.bounds, &self.vocab)? {
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

/// Resolve a NAME_ID to its LocalName override bytes.
///
/// The NAME_ID space has three regions (the "three-region rule"):
///   * `id <  escape_id()` — a compiled core slot; `Ok(Some(None))` (the caller
///     resolves it via [`crate::vocab::BY_ID`]);
///   * `id == escape_id()` — an inline, length-prefixed UTF-8 name follows;
///   * `escape_id() < id` — a spec-declared band slot, resolved via `vocab`.
///
/// Returns `Ok(None)` when more input is needed (transactional: `off` may have
/// advanced only for the escape form's length prefix, and a later poll retries
/// from the event start), `Err(..)` on a bounds violation or a band id the
/// consumer's spec never declared ([`DecodeError::NameOutOfBand`]).
// The outer/none `Option` is "need more input"; the inner `Option` is "is there
// an override at all" — the two questions are genuinely distinct.
#[allow(clippy::option_option)]
fn resolve_name<'a>(
    buf: &'a [u8],
    off: &mut usize,
    name_id: u32,
    vocab: &'a Vocab,
    bounds: &Bounds,
    at: usize,
) -> Result<Option<Option<&'a [u8]>>, DecodeError> {
    let esc = crate::vocab::escape_id();
    if name_id < esc {
        return Ok(Some(None));
    }
    if name_id == esc {
        return match len_prefixed(buf, off, bounds.name_max_bytes, DecodeError::NameTooLong)? {
            Some(n) => Ok(Some(Some(n))),
            None => Ok(None),
        };
    }
    match vocab.band_name(name_id) {
        Some(n) => Ok(Some(Some(n))),
        None => Err(DecodeError::NameOutOfBand(name_id, at)),
    }
}

/// Parse exactly one event from `buf` starting at `*off`.  Transactional: on
/// `None` (need more input) `*off` is left untouched, so a later poll retries
/// the same event from the start.
fn parse_event<'a>(
    buf: &'a [u8],
    off: &mut usize,
    last_ns_id: u8,
    bounds: &Bounds,
    vocab: &'a Vocab,
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
            let local_name_override =
                match resolve_name(buf, &mut p, name_id, vocab, bounds, start)? {
                    Some(n) => n,
                    None => return Ok(None),
                };
            // Closed-world hardening (opt-in): the inline escape is what breaks
            // the closed world — a spec-declared band id is vocabulary the
            // consumer's own spec handed the decoder, so it is allowed.
            if bounds.allow_vocab_only
                && (name_id == crate::vocab::escape_id() || ns_id == crate::vocab::ns_id::ESCAPE)
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
                let at = p;
                let name_override =
                    match resolve_name(buf, &mut p, aid, vocab, bounds, at)? {
                        Some(n) => n,
                        None => return Ok(None),
                    };
                if bounds.allow_vocab_only && aid == crate::vocab::escape_id() {
                    return Err(DecodeError::ProhibitedName(aid, p));
                }
                let value = match len_prefixed(buf, &mut p, bounds.value_max_bytes, DecodeError::ValueTooLong)? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                attrs.push(Attr { name_id: aid, name_override, value });
            }
            (
                Event::StartElement {
                    ns_id,
                    name_id,
                    ns_uri_override,
                    local_name_override,
                    attrs,
                },
                ns_id,
            )
        },
        Tag::Pi => {
            let tid = match leb(buf, &mut p)? { Some(v) => v, None => return Ok(None) };
            let target_override = match resolve_name(buf, &mut p, tid, vocab, bounds, start)? {
                Some(n) => n,
                None => return Ok(None),
            };
            let data = match len_prefixed(buf, &mut p, bounds.value_max_bytes, DecodeError::ValueTooLong)? {
                Some(d) => d,
                None => return Ok(None),
            };
            (Event::Pi { target_id: tid, target_override, data }, last_ns_id)
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
        let attrs: [(u32, &[u8]); 5] = [
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
        let attrs: [(u32, &[u8]); 1] = [(vocab::by_name(b"kind").unwrap(), b"success")];
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
                assert_eq!(name_id, vocab::escape_id());
                assert_eq!(ns_uri_override, Some(&uri[..]));
                assert_eq!(local_name_override, Some(&name[..]));
                assert_eq!(attrs.len(), 1);
                assert_eq!(attrs[0].name_id, vocab::escape_id());
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
        // (id == ESCAPE) element name.  `allow_vocab_only` is now OPT-IN
        // (default false — the codec is a pure 1:1 mirror), so a consumer that
        // wants closed-world hardening must arm it explicitly.
        let mut out = vec![];
        out.extend_from_slice(&MAGIC);
        out.push(0x40 | 0x10); // StartEl, ns inline, 0 attrs
        out.push(0x01 << 4); // NS_ID = AMIN
        encode::leb_u32(&mut out, vocab::escape_id());
        encode::leb_u32(&mut out, 3);
        out.extend_from_slice(b"zzz");
        out.push(0x60);
        let bounds = Bounds { allow_vocab_only: true, ..Bounds::default() };
        let mut d = StreamDecoder::new(bounds);
        d.feed(&out);
        // The escaped name bytes are walked (so we know where the name ends)
        // before the guard rejects it — no desync, just a deterministic Err.
        match d.poll_event() {
            Err(DecodeError::ProhibitedName(id, _)) => assert_eq!(id, vocab::escape_id()),
            other => panic!("expected ProhibitedName, got {other:?}"),
        }
    }

    #[test]
    fn escaped_names_decode_cleanly_by_default() {
        // The pure-1:1 default: the SAME escaped-name stream the opt-in guard
        // rejects above must decode without error, surfacing the raw LocalName
        // via `local_name_override` — exactly how the XML parser would surface
        // an unknown element.  No Amin-core edit is needed for an external
        // filter's name.
        let mut out = vec![];
        out.extend_from_slice(&MAGIC);
        out.push(0x00); // StartDoc
        out.push(0x40 | 0x10); // StartEl, ns inline, 0 attrs
        out.push(0x01 << 4); // NS_ID = AMIN
        encode::leb_u32(&mut out, vocab::escape_id());
        encode::leb_u32(&mut out, 3);
        out.extend_from_slice(b"zzz");
        out.push(0x60);
        out.push(0x20);
        let mut d = StreamDecoder::new(Bounds::default());
        d.feed(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement { local_name_override, .. }) => {
                assert_eq!(local_name_override, Some(&b"zzz"[..]));
            },
            other => panic!("not an escaped start_element: {other:?}"),
        }
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndElement))));
    }

    #[test]
    fn dict_entry_tag_is_rejected_as_unknown() {
        // DICT_ENTRY (0xE0) is retired: it has no XML::SAX analogue, so a pure
        // 1:1 codec has no event for it.  0xE0 now maps to no known tag, i.e.
        // the same deterministic rejection both fronts give any unknown byte.
        assert_eq!(Tag::from_byte(0xE0), None);
        let mut out = vec![];
        out.extend_from_slice(&MAGIC);
        out.push(0xE0); // was DICT_ENTRY
        let mut d = StreamDecoder::new(Bounds::default());
        d.feed(&out);
        match d.poll_event() {
            Err(DecodeError::UnknownTag(0xE0, _)) => {},
            other => panic!("expected UnknownTag(0xE0), got {other:?}"),
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
                assert_eq!(target_id, vocab::escape_id());
                assert_eq!(target_override, Some(&target[..]));
                assert_eq!(pd, &data[..]);
            },
            other => panic!("not a PI: {other:?}"),
        }
        // Stream stays aligned after the PI: EndDoc still decodes cleanly.
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndDocument))));
    }

    #[test]
    fn document_grammar_rides_amin_ns() {
        // Platform document grammar is an `amin:` vocabulary — it travels on
        // NS_AMIN with plain vocab NAME_IDs and no escaped namespace URI.
        // Mirrors t/64-content-xlsx.t § 5 (`amin:document/sheet/cell`).
        let mut out = vec![];
        encode::write_magic(&mut out);
        encode::write_start_doc(&mut out);
        let doc_attrs: [(u32, &[u8]); 4] = [
            (vocab::by_name(b"format").unwrap(), b"xlsx"),
            (vocab::by_name(b"title").unwrap(),  b"Q3"),
            (vocab::by_name(b"out").unwrap(),    b"out/q3.xlsx"),
            (vocab::by_name(b"sheets").unwrap(), b"1"),
        ];
        encode::write_start_elem(
            &mut out, vocab::ns_id::AMIN, vocab::by_name(b"document").unwrap(), &doc_attrs,
        );
        encode::write_start_elem(
            &mut out, vocab::ns_id::AMIN, vocab::by_name(b"sheet").unwrap(),
            &[(vocab::by_name(b"name").unwrap(), b"Report")],
        );
        encode::write_start_elem(
            &mut out, vocab::ns_id::AMIN, vocab::by_name(b"cell").unwrap(),
            &[(vocab::by_name(b"type").unwrap(), b"number")],
        );
        encode::write_end_elem(&mut out);
        encode::write_end_elem(&mut out);
        encode::write_end_elem(&mut out);
        encode::write_end_doc(&mut out);

        let mut d = feed_all(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement {
                ns_id, name_id, ns_uri_override, local_name_override, attrs,
            }) => {
                // Core NS, plain vocab name — an app filter registered on its
                // own URI cannot be mistaken for this element.
                assert_eq!(ns_id, vocab::ns_id::AMIN);
                assert_eq!(ns_uri_override, None);
                assert_eq!(local_name_override, None);
                assert_eq!(name_id, 137);
                assert_eq!(vocab::BY_ID[name_id as usize], b"document");
                assert_eq!(attrs.len(), 4);
                for a in &attrs {
                    assert_eq!(a.name_override, None);
                }
                assert_eq!(attrs[0].name_id, vocab::by_name(b"format").unwrap());
                assert_eq!(attrs[0].local_name(), Some(&b"format"[..]));
                assert_eq!(attrs[0].value, b"xlsx");
                assert_eq!(attrs[2].local_name(), Some(&b"out"[..]));
                assert_eq!(attrs[3].local_name(), Some(&b"sheets"[..]));
            },
            other => panic!("not an amin:document start_element: {other:?}"),
        }
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement { ns_id, name_id, attrs, .. }) => {
                assert_eq!(ns_id, vocab::ns_id::AMIN);
                // Shared LocalName (`sheet`) still resolves to its existing
                // slot; the NS nibble is what makes it an amin:sheet here.
                assert_eq!(name_id, 50);
                assert_eq!(attrs[0].local_name(), Some(&b"name"[..]));
            },
            other => panic!("not an amin:sheet start_element: {other:?}"),
        }
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement { ns_id, name_id, attrs, .. }) => {
                assert_eq!(ns_id, vocab::ns_id::AMIN);
                assert_eq!(name_id, 68);
                assert_eq!(attrs[0].local_name(), Some(&b"type"[..]));
            },
            other => panic!("not an amin:cell start_element: {other:?}"),
        }
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndElement))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndElement))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndElement))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndDocument))));
    }

    #[test]
    fn app_namespace_document_keeps_its_own_uri() {
        // An application filter may define its own `document` element.  It
        // rides NS_ESCAPE with an inline URI while reusing vocab NAME_IDs —
        // the decoder reports the raw id and the URI override so the consumer
        // resolves `app:document` without ever seeing the core NS.
        // Mirrors t/64-content-xlsx.t (`$APP_NS` + `app:document`).
        let uri = b"https://apps.example.test/ns/doc/1";
        let mut out = vec![];
        out.extend_from_slice(&MAGIC);
        out.push(0x00); // StartDoc
        out.push(0x40 | 0x10 | 1); // StartEl, ns inline, 1 attr
        out.push(0x0F << 4); // NS_ID = ESCAPE
        encode::leb_u32(&mut out, uri.len() as u32);
        out.extend_from_slice(uri);
        encode::leb_u32(&mut out, vocab::by_name(b"document").unwrap());
        encode::leb_u32(&mut out, vocab::by_name(b"format").unwrap());
        encode::leb_u32(&mut out, 4);
        out.extend_from_slice(b"acme");
        out.push(0x60); // EndEl
        out.push(0x20); // EndDoc

        let bounds = Bounds { allow_vocab_only: false, ..Bounds::default() };
        let mut d = StreamDecoder::new(bounds);
        d.feed(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement {
                ns_id, name_id, ns_uri_override, local_name_override, attrs,
            }) => {
                assert_eq!(ns_id, vocab::ns_id::ESCAPE);
                assert_eq!(ns_uri_override, Some(&uri[..]));
                assert_eq!(local_name_override, None);
                // Same LocalName slot as the platform grammar, but the URI is
                // the app's — no collision at the SAX boundary.
                assert_eq!(name_id, 137);
                assert_eq!(vocab::BY_ID[name_id as usize], b"document");
                assert_eq!(attrs.len(), 1);
                assert_eq!(attrs[0].name_id, vocab::by_name(b"format").unwrap());
                assert_eq!(attrs[0].name_override, None);
                assert_eq!(attrs[0].local_name(), Some(&b"format"[..]));
                assert_eq!(attrs[0].value, b"acme");
            },
            other => panic!("not an app-namespaced start_element: {other:?}"),
        }
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndElement))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::EndDocument))));
    }

    #[test]
    fn band_ids_resolve_via_vocab_and_out_of_band_is_loud() {
        // Spec-declared band (mirrors Perl t/11 §9): `frob`/`widget` are not in
        // the compiled core, so they take band ids `band_start()`/`+1`.  The
        // decoder resolves them from the consumer's `Vocab`; the SAME bytes
        // under a decoder whose spec declares no such names is a loud
        // `NameOutOfBand`, never a silent desync.
        let names: &[&[u8]] = &[b"id", b"frob", b"widget", b"status", b"frob"];
        let encoder_vocab = vocab::Vocab::from_names(names);
        let frob = encoder_vocab.name_id(b"frob").unwrap();
        let widget = encoder_vocab.name_id(b"widget").unwrap();
        assert_eq!(frob, vocab::band_start());

        let mut out = vec![];
        encode::write_magic(&mut out);
        encode::write_start_doc(&mut out);
        encode::write_start_elem(&mut out, vocab::ns_id::AMIN, frob, &[(widget, b"v")]);
        encode::write_end_elem(&mut out);
        encode::write_end_doc(&mut out);

        // Same spec ⇒ band ids resolve to the declared LocalNames.
        let decoder_vocab = vocab::Vocab::from_names(names);
        let mut d = StreamDecoder::with_vocab(Bounds::default(), decoder_vocab);
        d.feed(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event().unwrap() {
            Poll::Event(Event::StartElement { name_id, local_name_override, attrs, .. }) => {
                assert_eq!(name_id, frob);
                assert_eq!(local_name_override, Some(&b"frob"[..]));
                assert_eq!(attrs.len(), 1);
                assert_eq!(attrs[0].name_id, widget);
                assert_eq!(attrs[0].local_name(), Some(&b"widget"[..]));
            },
            other => panic!("not a band start_element: {other:?}"),
        }

        // A decoder that declares NO band cannot resolve the id: loud error.
        let mut d = StreamDecoder::new(Bounds::default());
        d.feed(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        match d.poll_event() {
            Err(DecodeError::NameOutOfBand(id, _)) => assert_eq!(id, frob),
            other => panic!("expected NameOutOfBand, got {other:?}"),
        }

        // Closed-world hardening ACCEPTS a declared band id (it is the
        // consumer's own spec vocabulary) — only the inline escape is barred.
        let bounds = Bounds { allow_vocab_only: true, ..Bounds::default() };
        let band_names: &[&[u8]] = &[b"frob", b"widget"];
        let decoder_vocab = vocab::Vocab::from_names(band_names);
        let mut d = StreamDecoder::with_vocab(bounds, decoder_vocab);
        d.feed(&out);
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartDocument))));
        assert!(matches!(d.poll_event(), Ok(Poll::Event(Event::StartElement { .. }))));
    }
}

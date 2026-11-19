//! The BSAX front — the Rust peer of `Amin::Generator::BSAX`.
//!
//! `Amin->parse` hands the *bytes* of a document to one of two generators:
//! `Amin::Generator::XML` when it opens (after optional whitespace) with `<`,
//! otherwise `Amin::Generator::BSAX`. Both drive the SAME
//! [`Dispatcher`](crate::Machine) chain, so the dialect is *sniffed*, never
//! configured. This module is the Rust half of that front: it decodes a BSAX
//! byte stream into [`ContentHandler`] calls, applying exactly the namespace
//! rules `Amin::Generator::BSAX` applies, so a Rust node runs a BSAX document
//! through the identical chain an XML document would take — the equivalence
//! that keeps the auto-detected transport from becoming a parser differential.
//!
//! The spec-declared BSAX vocabulary band (see [`crate::Spec::vocab`]) is
//! threaded into the decoder here, so a spec-declared element name rides the
//! tight NAME_ID path with no name wired into Amin core.
//!
//! Two places mirror Perl 1:1 and MUST stay in sync:
//!
//! * the **attribute namespace region rule** — an attribute's namespace is
//!   derived from the vocabulary *region* of its NAME_ID, with element-aware
//!   overrides for `ui:` form attributes and the `amin:` document grammar;
//! * the **element namespace/prefix map** — `amin`/`ui`/`map`/`bc`/`sec`, else
//!   no prefix.

use amin_sax::{Attribute, AttributeList, ContentHandler, SaxError};
use bsax::decode::{Bounds, Poll, StreamDecoder};
use bsax::vocab::ns_id::{AMIN, BITCACHE, ESCAPE, MAP, SEC, UI};
use bsax::vocab::{self, Vocab};
use bsax::{Attr, Event};

// The core NS URIs — 1:1 with Perl `Generator::BSAX` `%NSBYID`.
const NS_AMIN_URI: &str = "http://projectamin.org/ns/2026/";
const NS_UI_URI: &str = "http://projectamin.org/ns/ui/1";
const NS_MAP_URI: &str = "http://projectamin.org/ns/map/1";
const NS_BITCACHE_URI: &str = "http://projectamin.org/ns/bc/";
const NS_SEC_URI: &str = "http://projectamin.org/ns/sec/1";

/// Platform document-generation elements: the grammar lives in `NS_AMIN`, so
/// their attributes are `amin:*` even when the attribute's LocalName occupies
/// an earlier vocabulary region (`id`/`name`/`type`/`size`/`title`/`min`/`max`
/// are shared LocalNames). 1:1 with Perl `%AMIN_DOC_ELEM`.
const AMIN_DOC_ELEM: [&str; 9] = [
    "document",
    "style",
    "sheet",
    "column",
    "row",
    "cell",
    "freeze",
    "autofilter",
    "merge",
];

/// Whether `source` is XML rather than BSAX, by the Perl `Amin->parse` rule:
/// optional whitespace then `<` within the first 64 bytes ⇒ XML; anything else
/// is BSAX.
#[must_use]
pub(crate) fn is_xml(source: &[u8]) -> bool {
    let window = &source[..source.len().min(64)];
    let mut i = 0;
    while i < window.len() && window[i].is_ascii_whitespace() {
        i += 1;
    }
    window.get(i) == Some(&b'<')
}

/// Decode a whole BSAX document into `handler`, resolving spec-declared band
/// names via `vocab`.  A truncated stream or a malformed tag is a loud fault
/// (never a silent partial document) — the codec equivalent of Perl's
/// `finish` refusing a short stream.
pub(crate) fn drive<H: ContentHandler>(
    source: &[u8],
    vocab: Vocab,
    handler: &mut H,
) -> Result<(), SaxError> {
    let mut decoder = StreamDecoder::with_vocab(Bounds::default(), vocab);
    decoder.feed(source);
    let mut bridge = Bridge {
        handler,
        stack: Vec::new(),
        last_ns_id: 0,
        last_ns_uri: String::new(),
    };
    loop {
        match decoder.poll_event() {
            Ok(Poll::Event(event)) => bridge.dispatch(event)?,
            Ok(Poll::Done) => return Ok(()),
            Ok(Poll::NeedMore) => {
                return Err(SaxError::NotRecognized(
                    "bsax: truncated stream (an event is incomplete)".to_string(),
                ))
            }
            Err(e) => return Err(SaxError::NotRecognized(format!("bsax: {e}"))),
        }
    }
}

/// The decoding bridge: turns `bsax::Event`s into [`ContentHandler`] calls,
/// holding the two pieces of stream state the wire omits — the open-element
/// stack (`END_ELEM` repeats no name) and the last resolved namespace (an
/// inline escape URI rides only the element that declared it).
struct Bridge<'h, H: ContentHandler> {
    handler: &'h mut H,
    /// Open elements, deepest last: `(namespace_uri, local_name, q_name)`.
    stack: Vec<(String, String, String)>,
    /// The NS_ID of the last `START_ELEM`, so an inline-NS start can be told
    /// from a namespace-reuse one.
    last_ns_id: u8,
    /// The URI `last_ns_id` resolved to.
    last_ns_uri: String,
}

impl<H: ContentHandler> Bridge<'_, H> {
    fn dispatch(&mut self, event: Event<'_>) -> Result<(), SaxError> {
        match event {
            Event::StartDocument => self.handler.start_document(),
            Event::EndDocument => self.handler.end_document(),
            Event::StartElement {
                ns_id,
                name_id,
                ns_uri_override,
                local_name_override,
                attrs,
            } => self.start_element(ns_id, name_id, ns_uri_override, local_name_override, &attrs),
            Event::EndElement => {
                if let Some((uri, local, qname)) = self.stack.pop() {
                    self.handler.end_element(&uri, &local, &qname)?;
                }
                Ok(())
            }
            Event::Chars(data) => {
                let text = as_utf8(data)?;
                self.handler.characters(text)
            }
            Event::Iws(data) => {
                let text = as_utf8(data)?;
                self.handler.ignorable_whitespace(text)
            }
            Event::Pi {
                target_id,
                target_override,
                data,
            } => {
                let target = as_utf8(resolve_name(target_id, target_override))?;
                let data = as_utf8(data)?;
                self.handler.processing_instruction(target, data)
            }
        }
    }

    fn start_element(
        &mut self,
        ns_id: u8,
        name_id: u32,
        ns_uri_override: Option<&[u8]>,
        local_name_override: Option<&[u8]>,
        attrs: &[Attr<'_>],
    ) -> Result<(), SaxError> {
        // Resolve the namespace URI. An inline escape URI is carried ONLY on
        // the element that declared it, so a namespace-reuse start inherits
        // the previous URI — mirroring Perl's `last_ns` / `last_ns_uri`.
        if let Some(uri) = ns_uri_override {
            self.last_ns_uri = as_utf8(uri)?.to_string();
        } else if ns_id != self.last_ns_id {
            self.last_ns_uri = ns_by_id(ns_id).to_string();
        }
        self.last_ns_id = ns_id;
        let ns_uri = self.last_ns_uri.clone();

        let local = as_utf8(resolve_name(name_id, local_name_override))?.to_string();
        let pfx = prefix_for_ns(ns_id);
        let qname = if pfx.is_empty() {
            local.clone()
        } else {
            format!("{pfx}:{local}")
        };

        let mut list = AttributeList::with_capacity(attrs.len());
        for a in attrs {
            let an = as_utf8(resolve_name(a.name_id, a.name_override))?.to_string();
            let a_ns = attr_ns_id(a.name_id, ns_id, &local);
            let a_uri = if a_ns == ESCAPE {
                ns_uri.as_str()
            } else {
                ns_by_id(a_ns)
            };
            let a_pfx = prefix_for_ns(a_ns);
            let a_qname = if a_pfx.is_empty() {
                an.clone()
            } else {
                format!("{a_pfx}:{an}")
            };
            list.push(Attribute {
                prefix: a_pfx.to_string(),
                local_name: an,
                namespace_uri: a_uri.to_string(),
                q_name: a_qname,
                value: as_utf8(a.value)?.to_string(),
            });
        }

        self.handler.start_element(&ns_uri, &local, &qname, &list)?;
        self.stack.push((ns_uri, local, qname));
        Ok(())
    }
}

/// Resolve a NAME_ID to its LocalName: a compiled core slot, else the override
/// (an inline escaped name or a spec-declared band name). The three-region
/// decision and the band bounds are the decoder's
/// ([`bsax::decode::StreamDecoder`] raises `NameOutOfBand` before this is
/// reached); this only maps an already-validated id to bytes.
fn resolve_name(name_id: u32, override_: Option<&[u8]>) -> &[u8] {
    match vocab::BY_ID.get(name_id as usize) {
        Some(name) => name,
        None => override_.unwrap_or(&[]),
    }
}

/// The 4-bit NS_ID → URI. `NONE`, the reserved slots and anything out of range
/// resolve to the empty string, exactly as Perl's `%NSBYID // ''`.
fn ns_by_id(ns_id: u8) -> &'static str {
    match ns_id {
        AMIN => NS_AMIN_URI,
        UI => NS_UI_URI,
        MAP => NS_MAP_URI,
        BITCACHE => NS_BITCACHE_URI,
        SEC => NS_SEC_URI,
        _ => "",
    }
}

/// The prefix an element/attribute of namespace `ns_id` is spelled with —
/// 1:1 with the Perl `Generator::BSAX` prefix map.
fn prefix_for_ns(ns_id: u8) -> &'static str {
    match ns_id {
        AMIN => "amin",
        UI => "ui",
        MAP => "map",
        BITCACHE => "bc",
        SEC => "sec",
        _ => "",
    }
}

/// The namespace of an attribute, from the vocabulary *region* of its NAME_ID,
/// then the element-aware overrides — 1:1 with the Perl `Generator::BSAX`
/// attribute rule.
fn attr_ns_id(aid: u32, elem_ns_id: u8, elem_local: &str) -> u8 {
    let esc = vocab::escape_id();
    let mut a_ns = if aid < 23 {
        AMIN
    } else if aid < 37 {
        MAP
    } else if aid < 83 {
        UI
    } else if aid < 102 {
        BITCACHE
    } else if aid < 108 {
        AMIN
    } else if aid < 137 {
        SEC
    } else if aid < esc {
        AMIN
    } else {
        // A band/escape id carries no region hint: inherit the element's NS.
        elem_ns_id
    };
    // An application element in a custom namespace has no low NS_ID slot, so
    // every one of its attributes inherits that element's (escaped) URI.
    if elem_ns_id == ESCAPE {
        a_ns = ESCAPE;
    }
    // `type`/`name`/`value` are ui: form attributes whose LocalNames also sit
    // in earlier regions: every attribute of a ui: element is ui:*.
    if elem_ns_id == UI && aid < esc {
        a_ns = UI;
    }
    // Same for the amin: document grammar (shared LocalNames on
    // document/sheet/row/cell/… are amin:*).
    if elem_ns_id == AMIN && AMIN_DOC_ELEM.contains(&elem_local) && aid < esc {
        a_ns = AMIN;
    }
    a_ns
}

/// BSAX text is UTF-8 by the SAX contract; a non-UTF-8 byte is a stream fault.
fn as_utf8(bytes: &[u8]) -> Result<&str, SaxError> {
    std::str::from_utf8(bytes)
        .map_err(|_| SaxError::NotRecognized("bsax: stream carries non-UTF-8 text".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsax::encode;
    use std::cell::RefCell;
    use std::rc::Rc;

    use amin_sax::Attributes;

    /// A handler that records every call, so the bridge's exact output can be
    /// asserted against what `Amin::Generator::BSAX` would emit.
    struct Spy {
        log: Rc<RefCell<Vec<String>>>,
    }

    impl Spy {
        fn rec(&self, s: String) {
            self.log.borrow_mut().push(s);
        }
    }

    impl ContentHandler for Spy {
        fn start_document(&mut self) -> Result<(), SaxError> {
            self.rec("start_document".into());
            Ok(())
        }

        fn end_document(&mut self) -> Result<(), SaxError> {
            self.rec("end_document".into());
            Ok(())
        }

        fn start_element(
            &mut self,
            uri: &str,
            local: &str,
            qname: &str,
            atts: &dyn Attributes,
        ) -> Result<(), SaxError> {
            let mut line = format!("start_element({uri}|{local}|{qname})");
            for i in 0..atts.length() {
                line.push_str(&format!(
                    " [{}|{}|{}={}]",
                    atts.uri(i),
                    atts.local_name(i),
                    atts.q_name(i),
                    atts.value(i)
                ));
            }
            self.rec(line);
            Ok(())
        }

        fn end_element(&mut self, uri: &str, local: &str, qname: &str) -> Result<(), SaxError> {
            self.rec(format!("end_element({uri}|{local}|{qname})"));
            Ok(())
        }

        fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
            self.rec(format!("characters({ch})"));
            Ok(())
        }
    }

    #[test]
    fn is_xml_matches_the_perl_sniff_rule() {
        assert!(is_xml(b"<amin:profile/>"));
        assert!(is_xml(b"\n\t  <?xml version=\"1.0\"?>"));
        assert!(!is_xml(b"AMINBSA1\x00"));
        // Whitespace-then-not-`<` within the window is BSAX.
        assert!(!is_xml(b"   x"));
        // A document that is empty is not XML (Perl: no leading `<`).
        assert!(!is_xml(b""));
    }

    #[test]
    fn attribute_namespace_region_rule_matches_perl() {
        // amin core id (e.g. `kind` = 9) on a non-document element → amin.
        assert_eq!(attr_ns_id(9, AMIN, "request"), AMIN);
        // a map-region id (23..36) → map.
        assert_eq!(attr_ns_id(30, AMIN, "request"), MAP);
        // ui-region id (37..82) → ui.
        assert_eq!(attr_ns_id(37, MAP, "link"), UI);
        // The element-aware ui override: a shared LocalName (`type` = 20, an
        // amin region id) on a ui: element is ui:*, not amin:*.
        assert_eq!(attr_ns_id(20, UI, "field"), UI);
        // The amin document-grammar override: a shared LocalName on
        // amin:cell stays amin:*.
        assert_eq!(attr_ns_id(20, AMIN, "cell"), AMIN);
        // A band id (>= escape) inherits the element's namespace.
        assert_eq!(attr_ns_id(vocab::band_start(), MAP, "link"), MAP);
        // A custom (escape) element forces every attribute to its URI.
        assert_eq!(attr_ns_id(9, ESCAPE, "widget"), ESCAPE);
    }

    #[test]
    fn band_name_resolves_and_out_of_band_is_loud() {
        // A spec band declaring `widget` ⇒ band id resolves through the front.
        let vocab = Vocab::from_names(&[&b"widget"[..]]);
        let widget = vocab.name_id(b"widget").unwrap();

        let mut out = vec![];
        encode::write_magic(&mut out);
        encode::write_start_doc(&mut out);
        let no_attrs: &[(u32, &[u8])] = &[];
        encode::write_start_elem(&mut out, AMIN, widget, no_attrs);
        encode::write_end_elem(&mut out);
        encode::write_end_doc(&mut out);

        let log = Rc::new(RefCell::new(Vec::new()));
        let mut spy = Spy { log: log.clone() };
        drive(&out, vocab, &mut spy).unwrap();
        assert_eq!(
            *log.borrow(),
            vec![
                "start_document".to_string(),
                format!("start_element({NS_AMIN_URI}|widget|amin:widget)"),
                format!("end_element({NS_AMIN_URI}|widget|amin:widget)"),
                "end_document".to_string(),
            ]
        );

        // The SAME bytes under a front that declares no band is a loud fault —
        // never a silent inline read (mirrors Perl's `_lex_name` die).
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut spy = Spy { log: log.clone() };
        let err = drive(&out, Vocab::empty(), &mut spy).unwrap_err();
        assert!(
            matches!(&err, SaxError::NotRecognized(m) if m.contains("out of band") || m.contains("band")),
            "got {err:?}"
        );
    }
}

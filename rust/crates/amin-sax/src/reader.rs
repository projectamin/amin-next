//! The push-based XML reader.
//!
//! [`Reader`] is the concrete `org.xml.sax.XMLReader`: it holds the content
//! handler, error handler and entity resolver, and drives them from the scanned
//! bytes. [`parse`] is the ergonomic one-shot form for callers that already
//! hold a handler.
//!
//! The scanner is deliberately **not** a DOM builder: it never retains a tree,
//! it calls the handler as it scans, and it can therefore parse documents
//! larger than memory — the same property the Perl path (`XML::LibXML::SAX`)
//! relies on.

use std::rc::Rc;

use crate::attributes::{Attribute, AttributeList};
use crate::error::{ParseError, SaxError};
use crate::handler::{ContentHandler, EntityResolver, ErrorHandler};
use crate::locator::{self, Locator};
use crate::{InputSource, XMLReader, XML_NS};

/// Parse `xml`, driving `handler` with the SAX2 event stream.
///
/// The reader calls [`ContentHandler::set_document_locator`] once, then
/// `start_document`, the element/character/PI events, and finally
/// `end_document`. The first fatal error ends the parse and is returned.
pub fn parse<H: ContentHandler>(xml: &str, handler: &mut H) -> Result<(), SaxError> {
    Scanner::new(handler, locator::shared(""), xml).run()
}

/// A SAX2 reader (≈ `org.xml.sax.XMLReader`).
///
/// Owns the three handler slots and parses on demand. Handlers are held as
/// `Box<dyn …>` because a filter chain threads them through, exactly as an
/// `XMLFilter` does in Java.
#[derive(Default)]
pub struct Reader {
    content: Option<Box<dyn ContentHandler>>,
    error: Option<Box<dyn ErrorHandler>>,
    resolver: Option<Box<dyn EntityResolver>>,
}

impl Reader {
    /// An empty reader with no handlers set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl XMLReader for Reader {
    fn set_content_handler(&mut self, handler: Box<dyn ContentHandler>) {
        self.content = Some(handler);
    }

    fn set_error_handler(&mut self, handler: Box<dyn ErrorHandler>) {
        self.error = Some(handler);
    }

    fn set_entity_resolver(&mut self, resolver: Box<dyn EntityResolver>) {
        self.resolver = Some(resolver);
    }

    fn parse(&mut self, source: &InputSource) -> Result<(), SaxError> {
        let text = source
            .text()
            .ok_or_else(|| SaxError::Io("source is not UTF-8 text".to_string()))?;

        let mut loc = Locator::new(source.system_id().unwrap_or(""));
        if let Some(public) = source.public_id() {
            loc.set_public_id(public);
        }
        let loc = Rc::new(loc);

        // Split the three fields so the scanner can borrow the handler and the
        // error handler independently.
        let Self { content, error, .. } = self;
        let handler: &mut dyn ContentHandler = content
            .as_deref_mut()
            .ok_or_else(|| SaxError::NotRecognized("no ContentHandler is set".to_string()))?;

        match Scanner::new(handler, Rc::clone(&loc), text).run() {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(h) = error.as_deref_mut() {
                    h.fatal_error(&e)?;
                }
                Err(e)
            }
        }
    }
}

/// A resolved, open element (drives end-tag matching and prefix unmapping).
struct Open {
    qname: String,
    local: String,
    uri: String,
    /// Prefixes this element declared, in document order.
    prefixes: Vec<String>,
}

/// The scanning state for one parse. Short-lived: built inside `parse`/`run`.
struct Scanner<'a> {
    src: &'a str,
    b: &'a [u8],
    i: usize,
    line: usize,
    col: usize,
    loc: Rc<Locator>,
    handler: &'a mut dyn ContentHandler,
    /// Namespace scopes, outermost first; each holds `(prefix, uri)` in
    /// document order so prefix mappings can be replayed in order.
    ns: Vec<Vec<(String, String)>>,
    stack: Vec<Open>,
}

impl<'a> Scanner<'a> {
    fn new(handler: &'a mut dyn ContentHandler, loc: Rc<Locator>, src: &'a str) -> Self {
        Self {
            src,
            b: src.as_bytes(),
            i: 0,
            line: 1,
            col: 1,
            loc,
            handler,
            ns: vec![vec![(String::from("xml"), String::from(XML_NS))]],
            stack: Vec::new(),
        }
    }

    fn run(&mut self) -> Result<(), SaxError> {
        if self.b.starts_with(&[0xEF, 0xBB, 0xBF]) {
            self.i = 3; // UTF-8 BOM, not counted as a column
            self.loc.set_position(1, 1);
        }
        self.handler.set_document_locator(Rc::clone(&self.loc));
        self.handler.start_document()?;

        while self.i < self.b.len() {
            if self.b[self.i] == b'<' {
                self.markup()?;
            } else {
                self.text()?;
            }
        }

        if let Some(open) = self.stack.last() {
            return Err(self.err(ParseError::UnclosedElement(open.qname.clone())));
        }
        self.handler.end_document()
    }

    fn markup(&mut self) -> Result<(), SaxError> {
        if self.starts("<?") {
            return self.pi();
        }
        if self.starts("<!--") {
            return self.comment();
        }
        if self.starts("<![CDATA[") {
            return self.cdata();
        }
        if self.starts("<!") {
            return self.declaration();
        }
        if self.starts("</") {
            return self.end_tag();
        }
        self.start_tag()
    }

    // ── position ──────────────────────────────────────────────────────────

    fn err(&self, kind: ParseError) -> SaxError {
        SaxError::Parse {
            kind,
            line: self.line,
            column: self.col,
        }
    }

    /// Advance to `target`, counting lines and character columns on the way,
    /// then publish the position to the shared locator.
    fn seek(&mut self, target: usize) {
        while self.i < target {
            let c = self.b[self.i];
            if c == b'\n' {
                self.line += 1;
                self.col = 1;
            } else if c & 0xC0 != 0x80 {
                self.col += 1; // a UTF-8 lead byte starts a character
            }
            self.i += 1;
        }
        self.loc.set_position(self.line, self.col);
    }

    fn starts(&self, s: &str) -> bool {
        self.b[self.i..].starts_with(s.as_bytes())
    }

    fn find(&self, needle: &str, from: usize) -> Option<usize> {
        self.src[from..].find(needle).map(|p| from + p)
    }

    fn skip_ws(&mut self) {
        let mut j = self.i;
        while j < self.b.len() && matches!(self.b[j], b' ' | b'\t' | b'\r' | b'\n') {
            j += 1;
        }
        self.seek(j);
    }

    /// Read a name at `i`, returning its `[start, end)` byte range.
    fn read_name(&self, i: usize) -> Result<(usize, usize), SaxError> {
        let mut j = i;
        while j < self.b.len() {
            if matches!(self.b[j], b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>' | b'=') {
                break;
            }
            j += 1;
        }
        if j == i {
            return Err(self.err(ParseError::Malformed));
        }
        Ok((i, j))
    }

    // ── constructs ────────────────────────────────────────────────────────

    fn pi(&mut self) -> Result<(), SaxError> {
        let start = self.i + 2;
        let end = self
            .find("?>", start)
            .ok_or_else(|| self.err(ParseError::UnexpectedEof("processing instruction")))?;
        let (target, data) = split_pi(&self.src[start..end]);
        self.handler.processing_instruction(target, data)?;
        self.seek(end + 2);
        Ok(())
    }

    fn comment(&mut self) -> Result<(), SaxError> {
        let end = self
            .find("-->", self.i + 4)
            .ok_or_else(|| self.err(ParseError::UnexpectedEof("comment")))?;
        self.seek(end + 3);
        Ok(())
    }

    fn cdata(&mut self) -> Result<(), SaxError> {
        let start = self.i + "<![CDATA[".len();
        let end = self
            .find("]]>", start)
            .ok_or_else(|| self.err(ParseError::UnexpectedEof("CDATA section")))?;
        let text = &self.src[start..end];
        if !text.is_empty() {
            self.handler.characters(text)?;
        }
        self.seek(end + 3);
        Ok(())
    }

    /// `<!DOCTYPE …>` — skipped, not processed. Bracket-aware so an internal
    /// subset (`[ … ]`) containing `>` is not truncated.
    fn declaration(&mut self) -> Result<(), SaxError> {
        let mut j = self.i + 2;
        loop {
            match self.b.get(j) {
                None => return Err(self.err(ParseError::UnexpectedEof("declaration"))),
                Some(b'>') => {
                    j += 1;
                    break;
                }
                Some(b'[') => {
                    let close = self.b[j..]
                        .iter()
                        .position(|&c| c == b']')
                        .ok_or_else(|| self.err(ParseError::UnexpectedEof("internal subset")))?;
                    j += close + 1;
                }
                Some(_) => j += 1,
            }
        }
        self.seek(j);
        Ok(())
    }

    fn text(&mut self) -> Result<(), SaxError> {
        let start = self.i;
        let end = self.src[start..]
            .find('<')
            .map_or(self.b.len(), |p| start + p);
        let raw = &self.src[start..end];
        if raw.contains('&') {
            let decoded = decode_entities(raw).map_err(|k| self.err(k))?;
            self.handler.characters(&decoded)?;
        } else if !raw.is_empty() {
            self.handler.characters(raw)?;
        }
        self.seek(end);
        Ok(())
    }

    fn read_attr_value(&mut self) -> Result<String, SaxError> {
        if self.i >= self.b.len() {
            return Err(self.err(ParseError::UnexpectedEof("attribute value")));
        }
        let quote = self.b[self.i];
        if quote != b'"' && quote != b'\'' {
            return Err(self.err(ParseError::Malformed));
        }
        self.seek(self.i + 1);
        let start = self.i;
        let mut j = self.i;
        while j < self.b.len() && self.b[j] != quote {
            j += 1;
        }
        if j >= self.b.len() {
            return Err(self.err(ParseError::UnexpectedEof("attribute value")));
        }
        let value = decode_entities(&self.src[start..j]).map_err(|k| self.err(k))?;
        self.seek(j + 1);
        Ok(value)
    }

    // ── elements ──────────────────────────────────────────────────────────

    fn start_tag(&mut self) -> Result<(), SaxError> {
        let (ns, ne) = self.read_name(self.i + 1)?;
        let qname = self.src[ns..ne].to_string();
        let (prefix, local) = split_qname(&qname);
        self.seek(ne);

        let mut raw: Vec<(String, String)> = Vec::new();
        let mut self_closing = false;
        loop {
            self.skip_ws();
            if self.i >= self.b.len() {
                return Err(self.err(ParseError::UnexpectedEof("start tag")));
            }
            match self.b[self.i] {
                b'>' => {
                    self.seek(self.i + 1);
                    break;
                }
                b'/' => {
                    if self.b.get(self.i + 1) == Some(&b'>') {
                        self.seek(self.i + 2);
                        self_closing = true;
                        break;
                    }
                    return Err(self.err(ParseError::Malformed));
                }
                _ => {
                    let (ans, ane) = self.read_name(self.i)?;
                    let aqname = self.src[ans..ane].to_string();
                    self.seek(ane);
                    self.skip_ws();
                    if self.b.get(self.i) != Some(&b'=') {
                        return Err(self.err(ParseError::Malformed));
                    }
                    self.seek(self.i + 1);
                    self.skip_ws();
                    let value = self.read_attr_value()?;
                    raw.push((aqname, value));
                }
            }
        }

        // Namespace declarations on this element, in document order.
        let mut decls: Vec<(String, String)> = Vec::new();
        for (q, v) in &raw {
            if q == "xmlns" {
                decls.push((String::new(), v.clone()));
            } else if let Some(p) = q.strip_prefix("xmlns:") {
                decls.push((p.to_string(), v.clone()));
            }
        }
        self.ns.push(decls.clone());

        let uri = self.resolve(&prefix)?;
        let mut prefixes: Vec<String> = Vec::with_capacity(decls.len());
        for (p, u) in &decls {
            self.handler.start_prefix_mapping(p, u)?;
            prefixes.push(p.clone());
        }

        let mut atts = AttributeList::with_capacity(raw.len());
        for (q, v) in raw {
            if q == "xmlns" || q.starts_with("xmlns:") {
                continue; // delivered as prefix mappings, not attributes
            }
            let (ap, al) = split_qname(&q);
            let auri = if ap.is_empty() {
                String::new()
            } else {
                self.resolve(&ap)?
            };
            atts.push(Attribute {
                prefix: ap,
                local_name: al,
                namespace_uri: auri,
                q_name: q,
                value: v,
            });
        }

        self.handler.start_element(&uri, &local, &qname, &atts)?;

        if self_closing {
            self.ns.pop();
            self.handler.end_element(&uri, &local, &qname)?;
            for p in prefixes.iter().rev() {
                self.handler.end_prefix_mapping(p)?;
            }
        } else {
            self.stack.push(Open {
                qname,
                local,
                uri,
                prefixes,
            });
        }
        Ok(())
    }

    fn end_tag(&mut self) -> Result<(), SaxError> {
        let (ns, ne) = self.read_name(self.i + 2)?;
        let qname = self.src[ns..ne].to_string();
        self.seek(ne);
        self.skip_ws();
        if self.b.get(self.i) != Some(&b'>') {
            return Err(self.err(ParseError::Malformed));
        }
        self.seek(self.i + 1);

        let Some(open) = self.stack.pop() else {
            return Err(self.err(ParseError::Malformed));
        };
        if open.qname != qname {
            return Err(self.err(ParseError::MismatchedEnd {
                expected: open.qname,
                found: qname,
            }));
        }
        self.ns.pop();
        self.handler.end_element(&open.uri, &open.local, &open.qname)?;
        for p in open.prefixes.iter().rev() {
            self.handler.end_prefix_mapping(p)?;
        }
        Ok(())
    }

    /// Resolve a prefix in the scope chain. An empty prefix resolves the
    /// default namespace, which may be absent (`""`).
    fn resolve(&self, prefix: &str) -> Result<String, SaxError> {
        for scope in self.ns.iter().rev() {
            for (p, u) in scope.iter().rev() {
                if p == prefix {
                    return Ok(u.clone());
                }
            }
        }
        if prefix.is_empty() {
            Ok(String::new())
        } else {
            Err(self.err(ParseError::UnboundPrefix(prefix.to_string())))
        }
    }
}

fn split_qname(q: &str) -> (String, String) {
    match q.split_once(':') {
        Some((p, l)) => (p.to_string(), l.to_string()),
        None => (String::new(), q.to_string()),
    }
}

/// Split `<?target data?>`'s body into target and data.
fn split_pi(body: &str) -> (&str, &str) {
    match body.find(char::is_whitespace) {
        Some(s) => (&body[..s], body[s..].trim_start()),
        None => (body, ""),
    }
}

/// Decode the five predefined entities and numeric character references.
fn decode_entities(raw: &str) -> Result<String, ParseError> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let semi = after
            .find(';')
            .ok_or_else(|| ParseError::UnknownEntity(after.to_string()))?;
        let ent = &after[..semi];
        match ent {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let cp = if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X"))
                {
                    u32::from_str_radix(hex, 16)
                        .map_err(|_| ParseError::BadCharRef(ent.to_string()))?
                } else if let Some(dec) = ent.strip_prefix('#') {
                    dec.parse::<u32>()
                        .map_err(|_| ParseError::BadCharRef(ent.to_string()))?
                } else {
                    return Err(ParseError::UnknownEntity(ent.to_string()));
                };
                out.push(char::from_u32(cp).ok_or_else(|| ParseError::BadCharRef(ent.to_string()))?);
            }
        }
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

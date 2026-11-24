//! The dumb XHTML serializer — the Rust form of `Amin::Handler::HTML`.
//!
//! Byte-critical. The rules, exactly as the Perl handler implements them:
//!
//! * `start_document` emits the doctype `<!DOCTYPE html>\n` and nothing else;
//! * only `http://www.w3.org/1999/xhtml`-namespace elements are emitted (a
//!   `ui:`, `amin:` or stray filter element is dropped, but still opens a scope);
//! * thirteen **void** elements self-close as `/>\n` and open no scope;
//! * a non-void element opens with `>\n` and closes with `</tag>\n`;
//! * attributes are sorted by local name and formatted ` name="value"`, with
//!   the value escaped; `xmlns` attributes are dropped;
//! * text is escaped and emitted only when it sits directly inside a kept
//!   (XHTML) element — text from a dropped scope is discarded; `<script>` and
//!   `<style>` are raw-text elements, so their content is emitted verbatim;
//! * escaping covers exactly `< > & "` (the five-char form belongs to
//!   [`crate::formcodec`], which prepares input *for* this one).
//!
//! This is the single escaper on the render path (§4.5): no markup is ever
//! built from a string.

use amin_sax::{Attributes, ContentHandler, SaxError};

use crate::XHTML_NS;

/// The thirteen XHTML void elements, verbatim from `Amin::Handler::HTML`.
const VOID: [&str; 13] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track",
    "wbr",
];

/// A dumb, byte-stable XHTML serializer (≈ `Amin::Handler::HTML`).
///
/// Accumulates into `out`. `stack` holds the open element local names awaiting
/// a close; `scope` records, per open element, whether it is a kept (XHTML)
/// element, so [characters](ContentHandler::characters) can tell whether text
/// belongs in the page. `raw` counts open `<script>`/`<style>` elements, whose
/// content is code rather than character data. When `text_mode` is set the
/// serializer is instead the plain-text sink (≈ `Amin::Handler::Text`): it emits
/// no doctype, ignores every element, and passes character data through verbatim.
#[derive(Debug, Default)]
pub struct HtmlSerializer {
    out: String,
    stack: Vec<String>,
    scope: Vec<bool>,
    raw: usize,
    text_mode: bool,
}

impl HtmlSerializer {
    /// A fresh serializer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh plain-text serializer (≈ `Amin::Handler::Text`): no doctype, no
    /// element tags, character data verbatim.
    #[must_use]
    pub fn new_text() -> Self {
        Self {
            text_mode: true,
            ..Self::default()
        }
    }

    /// The document serialised so far.
    #[must_use]
    pub fn output(&self) -> &str {
        &self.out
    }

    /// Consume the serializer and return the finished document.
    #[must_use]
    pub fn into_output(self) -> String {
        self.out
    }

    /// Start an XHTML element with `(local_name, value)` attributes — the
    /// helper the HTML target and the app filter use, so a projected fragment
    /// and a hand-written one go down the identical path.
    pub fn xhtml_start(&mut self, local: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError> {
        let list = attr_list(attrs);
        self.start_element(XHTML_NS, local, local, &list)
    }

    /// Close an XHTML element opened with [`HtmlSerializer::xhtml_start`].
    pub fn xhtml_end(&mut self, local: &str) -> Result<(), SaxError> {
        self.end_element(XHTML_NS, local, local)
    }

    /// Emit character data (escaped, if it lands in a kept element).
    pub fn text(&mut self, data: &str) -> Result<(), SaxError> {
        self.characters(data)
    }

    /// Start a `ui:` element — never serialised, only scoped, so intermediate
    /// character data inside it is dropped exactly as in the Perl chain.
    pub fn ui_start(&mut self, local: &str) -> Result<(), SaxError> {
        let empty = amin_sax::AttributeList::new();
        let q = format!("ui:{local}");
        self.start_element(crate::UI_NS, local, &q, &empty)
    }

    /// Close a `ui:` element opened with [`HtmlSerializer::ui_start`].
    pub fn ui_end(&mut self, local: &str) -> Result<(), SaxError> {
        let q = format!("ui:{local}");
        self.end_element(crate::UI_NS, local, &q)
    }

    fn push(&mut self, s: &str) {
        self.out.push_str(s);
    }
}

impl ContentHandler for HtmlSerializer {
    fn start_document(&mut self) -> Result<(), SaxError> {
        if self.text_mode {
            return Ok(());
        }
        self.push("<!DOCTYPE html>\n");
        Ok(())
    }

    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        _q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        if self.text_mode {
            return Ok(()); // text mode ignores every element
        }
        let html = uri == XHTML_NS;
        // A void element is self-contained: it can hold no content, so it
        // neither opens a scope nor waits for a close.
        let void = html && !local_name.is_empty() && VOID.contains(&local_name);
        if !void {
            self.scope.push(html);
        }
        if !html {
            return Ok(());
        }
        self.push("<");
        self.push(local_name);

        // Attribute order must not depend on map iteration: byte-stable pages.
        let mut attrs: Vec<(&str, &str)> = Vec::with_capacity(atts.length());
        for i in 0..atts.length() {
            let an = atts.local_name(i);
            // A namespace declaration is delivered as a prefix-mapping event,
            // never as an attribute, so this mirrors the Perl guard exactly.
            if an.is_empty() || an == "xmlns" || atts.q_name(i).starts_with("xmlns:") {
                continue;
            }
            attrs.push((an, atts.value(i)));
        }
        attrs.sort_by(|a, b| a.0.cmp(b.0));

        for (an, av) in attrs {
            self.push(" ");
            self.push(an);
            self.push("=\"");
            self.push(&escape(av));
            self.push("\"");
        }

        if VOID.contains(&local_name) {
            self.push("/>\n");
        } else {
            // Raw text: script/style content is code, not escaped character
            // data (an escaped CSS child selector silently stops matching).
            if local_name == "script" || local_name == "style" {
                self.raw += 1;
            }
            self.stack.push(local_name.to_string());
            self.push(">\n");
        }
        Ok(())
    }

    fn end_element(&mut self, _uri: &str, local_name: &str, _q_name: &str) -> Result<(), SaxError> {
        if self.text_mode {
            return Ok(()); // text mode ignores every element
        }
        if !local_name.is_empty() && VOID.contains(&local_name) {
            return Ok(()); // void: nothing was opened, nothing to close
        }
        match self.scope.pop() {
            Some(true) => {}
            _ => return Ok(()), // a dropped (non-html) scope: nothing to close
        }
        if let Some(top) = self.stack.pop() {
            self.push("</");
            self.push(&top);
            self.push(">\n");
            if (top == "script" || top == "style") && self.raw > 0 {
                self.raw -= 1;
            }
        }
        Ok(())
    }

    fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
        if self.text_mode {
            // Text mode: characters verbatim, no escaping, no scope check.
            if !ch.is_empty() {
                self.push(ch);
            }
            return Ok(());
        }
        // Emit only text sitting directly inside a kept element.
        if self.scope.last() != Some(&true) {
            return Ok(());
        }
        if ch.is_empty() {
            return Ok(());
        }
        if self.raw > 0 {
            self.push(ch);
        } else {
            self.push(&escape(ch));
        }
        Ok(())
    }
}

/// Escape `< > & "` for one attribute value or text run (NOT `'`).
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Build an [`AttributeList`](amin_sax::AttributeList) of unprefixed attributes.
pub(crate) fn attr_list(attrs: &[(&str, &str)]) -> amin_sax::AttributeList {
    let mut list = amin_sax::AttributeList::with_capacity(attrs.len());
    for (k, v) in attrs {
        list.push(amin_sax::Attribute {
            prefix: String::new(),
            local_name: (*k).to_string(),
            namespace_uri: String::new(),
            q_name: (*k).to_string(),
            value: (*v).to_string(),
        });
    }
    list
}

#[cfg(test)]
mod tests {
    use super::HtmlSerializer;
    use amin_sax::{AttributeList, ContentHandler};

    #[test]
    fn text_mode_ignores_elements_and_emits_characters_verbatim() {
        let mut s = HtmlSerializer::new_text();
        s.start_document().expect("start_document");
        let empty = AttributeList::new();
        s.start_element(crate::XHTML_NS, "p", "p", &empty)
            .expect("start_element");
        s.characters("<b>&\"x\"</b>").expect("characters");
        s.end_element(crate::XHTML_NS, "p", "p")
            .expect("end_element");
        // No doctype, no tags, and no escaping: the run is byte-exact.
        assert_eq!(s.into_output(), "<b>&\"x\"</b>");
    }
}

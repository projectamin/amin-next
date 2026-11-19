//! The `ui:` → `html:` projection — the Rust form of `Amin::UI::Target::HTML`
//! (with the closed-world kind set from `Amin::Filter::UI::Guard`).
//!
//! A target is driven one element at a time (axa-plan §4.3, "no DOM
//! anywhere"): [`HtmlTarget::open`] then nested opens/closes, then
//! [`HtmlTarget::close`]. It holds only a bounded frame stack — one small
//! record per currently-open element — never a child subtree. Where the
//! source dialects accumulate a string and hand it on, the HTML dialect emits
//! real `html:` XHTML events straight to the serializer, so markup is never
//! built from a string (§4.5) and every attribute and text run is escaped in
//! exactly one place.
//!
//! The projection tables, the per-kind open/close semantics (which kinds carry
//! a heading, which pull attributes from the IR, which flush their text on
//! close) and the `cell`→`th`/`td` and `field` void-`<input>` rules are the
//! Perl target's, verbatim, because the pages it produces must be identical.

use std::collections::HashMap;

use amin_sax::{Attributes, SaxError};

use crate::serializer::HtmlSerializer;

/// A `ui:` element's attributes, keyed in Clark notation (`{uri}local`, or
/// `{}local` for an unprefixed attribute) — exactly the key form the Perl
/// target reads.
pub type Attrs = HashMap<String, String>;

/// Collect an [`Attributes`] view into a Clark-keyed [`Attrs`] map
/// (≈ `Amin::Filter::UI::Element::Base::_clark`).
#[must_use]
pub fn clark_attrs(atts: &dyn Attributes) -> Attrs {
    let mut map = Attrs::new();
    for i in 0..atts.length() {
        let local = atts.local_name(i);
        if local.is_empty() {
            continue;
        }
        let ns = atts.uri(i);
        let key = if ns.is_empty() {
            format!("{{}}{local}")
        } else {
            format!("{{{ns}}}{local}")
        };
        map.insert(key, atts.value(i).to_string());
    }
    map
}

/// An unprefixed `ui:` attribute value (`attr($a, $name)`), or `""`.
#[must_use]
pub fn attr<'a>(a: &'a Attrs, name: &str) -> &'a str {
    a.get(&format!("{{}}{name}")).map_or("", String::as_str)
}

/// An unprefixed `ui:` attribute value, or `None` when absent — the `//`
/// distinction the route selector needs.
#[must_use]
pub fn attr_opt<'a>(a: &'a Attrs, name: &str) -> Option<&'a str> {
    a.get(&format!("{{}}{name}")).map(String::as_str)
}

/// The 33 element LocalNames of the closed-world `ui:` vocabulary
/// (≈ `Amin::Filter::UI::Guard`). An unknown kind is an error whose subtree is
/// dropped.
#[must_use]
pub fn is_known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "app" | "scene"
            | "list"
            | "row"
            | "column"
            | "hstack"
            | "vstack"
            | "stack"
            | "grid"
            | "section"
            | "card"
            | "progress"
            | "alert"
            | "sheet"
            | "toolbar"
            | "searchable"
            | "item"
            | "label"
            | "text"
            | "badge"
            | "sparkline"
            | "button"
            | "navigate"
            | "image"
            | "asyncimage"
            | "form"
            | "field"
            | "select"
            | "option"
            | "table"
            | "tr"
            | "cell"
            | "style"
    )
}

/// A sink for canonical `ui:` IR events. The app filter emits into this; the
/// render pipeline ([`crate::render::Renderer`]) implements it to drive the
/// projection and the serializer.
pub trait UiSink {
    /// Open a `ui:` container/leaf element.
    fn start(&mut self, kind: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError>;
    /// Emit character data belonging to the innermost open element.
    fn text(&mut self, text: &str) -> Result<(), SaxError>;
    /// Close the innermost open `ui:` element.
    fn end(&mut self, kind: &str) -> Result<(), SaxError>;
    /// Open and immediately close a `ui:` element (a void one, e.g. `ui:field`).
    fn void(&mut self, kind: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError> {
        self.start(kind, attrs)?;
        self.end(kind)
    }
}

/// The HTML dialect: one frame per open `ui:` element, each recording the
/// XHTML tags to close and whether its text is flushed on close.
#[derive(Debug, Default)]
pub struct HtmlTarget {
    stack: Vec<Frame>,
}

#[derive(Debug)]
struct Frame {
    kind: String,
    text: String,
    closes: Vec<String>,
    leaf: bool,
}

/// Container kinds → `(tag, static attributes)` — `%TAG`, verbatim.
fn static_tag(kind: &str) -> Option<(&'static str, &'static [(&'static str, &'static str)])> {
    Some(match kind {
        "scene" => ("main", &[]),
        "list" => ("ul", &[]),
        "row" => ("li", &[]),
        "item" => ("li", &[]),
        "column" => ("div", &[("class", "column")]),
        "hstack" => ("div", &[("class", "hstack")]),
        "vstack" => ("div", &[("class", "vstack")]),
        "stack" => ("div", &[("class", "stack")]),
        "grid" => ("div", &[("class", "grid")]),
        "card" => ("article", &[]),
        "button" => ("button", &[]),
        "toolbar" => ("nav", &[]),
        "sheet" => ("dialog", &[]),
        "alert" => ("div", &[("role", "alert")]),
        "table" => ("table", &[]),
        "tr" => ("tr", &[]),
        _ => return None,
    })
}

/// Leaf kinds → `(tag, static attributes)` — `%LEAF`, verbatim.
fn static_leaf(kind: &str) -> Option<(&'static str, &'static [(&'static str, &'static str)])> {
    Some(match kind {
        "text" => ("p", &[]),
        "label" => ("span", &[("class", "label")]),
        "badge" => ("span", &[("class", "badge")]),
        "progress" => ("progress", &[]),
        "sparkline" => ("canvas", &[("class", "sparkline")]),
        "style" => ("style", &[]),
        _ => return None,
    })
}

impl HtmlTarget {
    /// A fresh target with an empty frame stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The kind of the innermost open element, or `None`.
    #[must_use]
    pub fn top_kind(&self) -> Option<&str> {
        self.stack.last().map(|f| f.kind.as_str())
    }

    /// Accumulate character data into the innermost frame (flushed on close if
    /// the frame is a leaf).
    pub fn text(&mut self, t: &str) {
        if let Some(f) = self.stack.last_mut() {
            f.text.push_str(t);
        }
    }

    /// Open a `ui:` element: push a frame, emit the opening XHTML events.
    ///
    /// A void element (`img`, `input`) closes itself and has no content; an
    /// unknown kind emits nothing (the Guard has already dropped it).
    pub fn open(
        &mut self,
        kind: &str,
        a: &Attrs,
        h: &mut HtmlSerializer,
    ) -> Result<(), SaxError> {
        let mut f = Frame {
            kind: kind.to_string(),
            text: String::new(),
            closes: Vec::new(),
            leaf: false,
        };
        let title = attr(a, "title").to_string();

        match kind {
            "app" => {
                h.xhtml_start("html", &[("lang", "en")])?;
                h.xhtml_start("head", &[])?;
                inline(h, "title", &title)?;
                h.xhtml_end("head")?;
                h.xhtml_start("body", &[])?;
                f.closes = vec!["body".to_string(), "html".to_string()];
            }
            "section" => {
                h.xhtml_start("section", &[])?;
                inline(h, "h2", &title)?;
                f.closes = vec!["section".to_string()];
            }
            "navigate" => {
                h.xhtml_start("a", &[("href", attr(a, "to"))])?;
                h.text(&title)?;
                f.closes = vec!["a".to_string()];
            }
            "button" => {
                h.xhtml_start("button", &[])?;
                h.text(&title)?;
                f.closes = vec!["button".to_string()];
            }
            "image" => {
                h.xhtml_start("img", &[("src", &title), ("alt", &title)])?;
            }
            "asyncimage" => {
                h.xhtml_start("img", &[("src", attr(a, "url")), ("alt", "")])?;
            }
            "searchable" => {
                h.xhtml_start("input", &[("type", "search")])?;
            }
            "form" => {
                let mut at: Vec<(&str, &str)> = Vec::new();
                let method = attr(a, "method");
                if !method.is_empty() {
                    at.push(("method", method));
                }
                let action = attr(a, "action");
                if !action.is_empty() {
                    at.push(("action", action));
                }
                h.xhtml_start("form", &at)?;
                f.closes = vec!["form".to_string()];
            }
            "select" => {
                let mut at: Vec<(&str, &str)> = Vec::new();
                let name = attr(a, "name");
                if !name.is_empty() {
                    at.push(("name", name));
                }
                h.xhtml_start("select", &at)?;
                f.closes = vec!["select".to_string()];
            }
            "field" => {
                // a void element: <input> closes itself and has no content
                let type_attr = attr(a, "type");
                let mut at: Vec<(&str, &str)> = Vec::new();
                at.push(("type", if type_attr.is_empty() { "text" } else { type_attr }));
                for n in ["name", "value", "placeholder", "min", "max"] {
                    let v = attr(a, n);
                    if !v.is_empty() {
                        at.push((n, v));
                    }
                }
                h.xhtml_start("input", &at)?;
            }
            "option" => {
                let mut at: Vec<(&str, &str)> = Vec::new();
                let value = attr(a, "value");
                if !value.is_empty() {
                    at.push(("value", value));
                }
                if !attr(a, "selected").is_empty() {
                    at.push(("selected", "selected"));
                }
                h.xhtml_start("option", &at)?;
                f.closes = vec!["option".to_string()];
                f.leaf = true;
            }
            "cell" => {
                let tag = if attr(a, "header").is_empty() { "td" } else { "th" };
                h.xhtml_start(tag, &[])?;
                f.closes = vec![tag.to_string()];
            }
            _ => {
                if let Some((tag, sa)) = static_tag(kind) {
                    h.xhtml_start(tag, sa)?;
                    f.closes = vec![tag.to_string()];
                } else if let Some((tag, sa)) = static_leaf(kind) {
                    h.xhtml_start(tag, sa)?;
                    f.closes = vec![tag.to_string()];
                    f.leaf = true;
                }
            }
        }
        // A cell (<td>/<th>) and an alert (<div role=alert>) hold their text
        // inline: like a leaf, that text is the element's sole content and is
        // flushed on close.
        if kind == "cell" || kind == "alert" {
            f.leaf = true;
        }
        self.stack.push(f);
        Ok(())
    }

    /// Close the innermost element: flush a leaf's accumulated text, then close
    /// its tags (LIFO, matching the serializer's stack).
    pub fn close(&mut self, _kind: &str, h: &mut HtmlSerializer) -> Result<(), SaxError> {
        let f = match self.stack.pop() {
            Some(f) => f,
            None => return Ok(()),
        };
        if f.leaf {
            h.text(&f.text)?;
        }
        for name in f.closes.iter().rev() {
            h.xhtml_end(name)?;
        }
        Ok(())
    }
}

/// `start / text / end` for a small inline element (a heading, a link label).
fn inline(h: &mut HtmlSerializer, ln: &str, t: &str) -> Result<(), SaxError> {
    h.xhtml_start(ln, &[])?;
    h.text(t)?;
    h.xhtml_end(ln)
}

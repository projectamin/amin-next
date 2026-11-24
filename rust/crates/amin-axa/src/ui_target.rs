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

/// The HTML target's default look, emitted in `<head>` before any app CSS.
///
/// Verbatim from `Amin::UI::Target::HTML::Material::$CSS`: zero-specificity
/// `:where()` selectors and Material role variables, so an app's `ui:style`
/// still wins. Byte-identical CSS is part of the Perl/Rust page contract.
const MATERIAL_CSS: &str = r#":root{color-scheme:light dark;
--md-primary:#6750a4;--md-on-primary:#fff;--md-primary-container:#eaddff;--md-on-primary-container:#21005d;
--md-secondary-container:#e8def8;--md-on-secondary-container:#1d192b;
--md-background:#fef7ff;--md-on-background:#1d1b20;
--md-surface:#fef7ff;--md-on-surface:#1d1b20;--md-on-surface-variant:#49454f;
--md-surface-container:#f3edf7;--md-surface-container-high:#ece6f0;
--md-outline:#79747e;--md-outline-variant:#cac4d0;--md-error:#b3261e;
--md-radius-s:8px;--md-radius-m:12px;--md-radius-full:999px;
--md-font:Roboto,system-ui,-apple-system,'Segoe UI',sans-serif;
--md-mono:ui-monospace,'JetBrains Mono',Consolas,monospace}
@media (prefers-color-scheme:dark){:root{
--md-primary:#d0bcff;--md-on-primary:#381e72;--md-primary-container:#4f378b;--md-on-primary-container:#eaddff;
--md-secondary-container:#4a4458;--md-on-secondary-container:#e8def8;
--md-background:#141218;--md-on-background:#e6e0e9;
--md-surface:#141218;--md-on-surface:#e6e0e9;--md-on-surface-variant:#cac4d0;
--md-surface-container:#211f26;--md-surface-container-high:#2b2930;
--md-outline:#938f99;--md-outline-variant:#49454f;--md-error:#f2b8b5}}
:where(*){box-sizing:border-box}
:where(body){margin:0;background:var(--md-background);color:var(--md-on-background);font:14px/1.5 var(--md-font)}
:where(p){margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
:where(h2){margin:0;font:500 14px/1.4 var(--md-font);color:var(--md-on-surface-variant);letter-spacing:.01em}
:where(section){display:flex;flex-direction:column;gap:12px}
:where(a){color:var(--md-primary)}
:where(.hstack){display:flex;align-items:center;gap:8px;min-width:0}
:where(.vstack){display:flex;flex-direction:column;gap:6px;min-width:0}
:where(.column){display:flex;flex-direction:column;gap:12px;min-width:0}
:where(.stack){display:flex;min-width:0}
:where(.grid){display:grid;gap:8px}
:where(main){display:block;padding:16px;max-width:880px;margin:0 auto}
:where(main>.column){gap:16px}
:where(main:has(>.hstack)){max-width:1280px}
:where(main>.hstack){align-items:flex-start;gap:16px}
:where(main>.hstack>.column){flex:1 1 0;min-width:0}
@media (max-width:800px){:where(main>.hstack){flex-direction:column;align-items:stretch}}
:where(nav){display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:56px;padding:0 16px;background:var(--md-surface-container);color:var(--md-on-surface);border-bottom:1px solid var(--md-outline-variant)}
:where(nav form){flex-direction:row}
:where(article){display:flex;flex-direction:column;gap:12px;padding:16px;background:var(--md-surface-container);color:var(--md-on-surface);border-radius:var(--md-radius-m)}
:where(article article){background:var(--md-surface-container-high)}
:where(form){margin:0;display:flex;flex-direction:column;gap:12px}
:where(span.label){color:var(--md-on-surface-variant);font-size:12px;letter-spacing:.03em}
:where(span.badge){display:inline-flex;align-items:center;justify-content:center;min-width:20px;height:20px;padding:0 8px;border-radius:var(--md-radius-s);background:var(--md-secondary-container);color:var(--md-on-secondary-container);font:500 12px/1 var(--md-font)}
:where(input,textarea,select){width:100%;padding:10px 12px;background:transparent;color:var(--md-on-surface);border:1px solid var(--md-outline);border-radius:var(--md-radius-s);font:inherit}
:where(textarea){resize:vertical;font-family:var(--md-mono);font-size:13px}
:where(input::placeholder,textarea::placeholder){color:var(--md-on-surface-variant);opacity:.7}
:where(input:focus,textarea:focus,select:focus){outline:2px solid var(--md-primary);outline-offset:-1px;border-color:var(--md-primary)}
:where(input[type=checkbox]){width:18px;height:18px;padding:0;accent-color:var(--md-primary)}
:where(input[type=number]){width:96px}
:where(button){padding:9px 20px;border:0;border-radius:var(--md-radius-full);background:var(--md-primary);color:var(--md-on-primary);font:500 14px var(--md-font);letter-spacing:.01em;cursor:pointer}
:where(button:hover){filter:brightness(1.08)}
:where(button:focus-visible){outline:2px solid var(--md-primary);outline-offset:2px}
:where(nav button,article>.hstack button){background:transparent;color:var(--md-primary);padding:6px 12px}
:where(nav button:hover,article>.hstack button:hover){background:var(--md-secondary-container);filter:none}
:where(audio){width:100%}
:where(progress){width:100%;accent-color:var(--md-primary)}
:where(div[role=alert]){padding:12px 16px;border-radius:var(--md-radius-s);background:var(--md-surface-container-high);color:var(--md-error);border:1px solid var(--md-error)}
:where(table){border-collapse:collapse;width:100%}
:where(th,td){padding:8px 12px;text-align:left;border-bottom:1px solid var(--md-outline-variant)}
:where(dialog){background:var(--md-surface-container-high);color:var(--md-on-surface);border:0;border-radius:28px;padding:24px}
:where(ul){margin:0;padding-left:20px}
"#;

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
                h.xhtml_start(
                    "meta",
                    &[
                        ("content", "width=device-width,initial-scale=1"),
                        ("name", "viewport"),
                    ],
                )?;
                h.xhtml_end("meta")?;
                // The target's default look; zero specificity, so an app's
                // ui:style still wins (same order as the Perl target).
                inline(h, "style", MATERIAL_CSS)?;
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

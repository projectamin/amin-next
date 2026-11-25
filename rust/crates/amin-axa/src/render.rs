//! The render pipeline — the Rust form of `Amin::AXA::HTTP::render` and the
//! chain it drives.
//!
//! One render inflates the app's declared fragment (placeholders → values),
//! wraps it in the `<amin:profile xmlns:amin xmlns:shop>` envelope, and pushes
//! it through the specialised chain: the app element filter ([`crate::shop::Shop`])
//! swallows its own `<shop:request>`/`<shop:action>` element and emits the
//! canonical `ui:` IR, the [`HtmlTarget`] projects each `ui:` element into real
//! `html:*` XHTML events, and the [`HtmlSerializer`] escapes and serialises
//! them.  Nothing retains a child subtree and nothing builds markup from a
//! string — the SAX contract (axa-plan §4.3/§4.5) holds end to end.
//!
//! The response media type is a property of the route/action (`type=`, default
//! `text/html`): the adapter resolves it to a content type and passes it to
//! [`render_page`], and a `text/plain` content type selects the byte-exact
//! serializer ([`HtmlSerializer::new_text`], ≈ `Amin::Handler::Text`), which
//! emits only character data and ignores every element; anything else renders
//! HTML.
//!
//! The `ui:` element and its projected sibling are emitted in the same order
//! the Perl filter fleet emits them: the projection first ([`HtmlTarget::open`]),
//! then the `ui:` element itself forwarded (additive).  That ordering is what
//! makes the serializer drop the intermediate character data and flush a
//! leaf's text on close, so the two implementations render byte-identical
//! pages.

use std::collections::HashMap;
use std::sync::Arc;

use amin_sax::{Attributes, ContentHandler, SaxError};

use crate::acme::AcmeKey;
use crate::app::Product;
use crate::formcodec::inflate;
pub use crate::formcodec::Values;
use crate::serializer::HtmlSerializer;
use crate::shop::Shop;
use crate::store::Store;
use crate::ui_target::{Attrs, HtmlTarget, UiSink};
use crate::{AMIN_NS, SHOP_NS};

/// A failure on the render path.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// The inflated document (or the fragment within it) did not parse.
    #[error("xml: {0}")]
    Xml(#[from] SaxError),
}

/// The per-render context: the catalogue the app declared (read-only during a
/// render) and the session store the cart lives behind.
///
/// This is the Rust form of the Perl chain's two globals — `App->default`
/// (the catalogue) and `Store->default` (the cart) — injected rather than
/// global, so a render is a pure function of its arguments plus this state
/// (axa-plan §4.9).
#[derive(Debug)]
pub struct RenderCtx {
    /// The app's catalogue, in document order.
    pub catalog: Vec<Product>,
    /// The session-scoped store (state lives here, keyed by session id).
    pub store: Store,
    /// The ACME account key for the app's HTTP-01 responder, when the bundle
    /// declares one (proxy-plan §5.5). `Ok(None)` is "no responder declared":
    /// the `amin:acme-challenge` element is then inert, exactly as an element
    /// no filter claims. `Err` records a key the bundle declared but that would
    /// not open — the responder then fails the render, as the Perl filter dies.
    pub acme: Result<Option<Arc<AcmeKey>>, String>,
}

impl Default for RenderCtx {
    fn default() -> Self {
        Self {
            catalog: Vec::new(),
            store: Store::default(),
            acme: Ok(None),
        }
    }
}

impl RenderCtx {
    /// An empty context: no catalogue, no sessions, no responder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// A rendered response (≈ a PSGI response triple).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// HTTP status code.
    pub status: u16,
    /// Response headers, in emission order.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: String,
}

/// Drives the `ui:` projection and the serializer together as one `ui:` sink.
///
/// It is the single shared render context of the Perl fleet, ported: every
/// `ui:` event is projected (`HtmlTarget`) and forwarded (`HtmlSerializer`) in
/// the Perl order, so a leaf's text is flushed on close and intermediate
/// character data is dropped (see the module docs).
#[derive(Debug, Default)]
pub struct Renderer {
    target: HtmlTarget,
    serializer: HtmlSerializer,
}

impl Renderer {
    /// A fresh renderer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh renderer in plain-text mode (≈ the `Amin::Handler::Text`
    /// serializer): the projection fleet still runs, but the serializer emits
    /// only character data, so the response body is the emitted text verbatim.
    #[must_use]
    pub fn new_text() -> Self {
        Self {
            target: HtmlTarget::new(),
            serializer: HtmlSerializer::new_text(),
        }
    }

    /// Emit the doctype through the serializer (the first byte on the wire).
    ///
    /// # Errors
    /// Propagates a serializer failure.
    pub fn start_document(&mut self) -> Result<(), SaxError> {
        self.serializer.start_document()
    }

    /// Consume the renderer and return the finished document.
    #[must_use]
    pub fn into_output(self) -> String {
        self.serializer.into_output()
    }
}

impl UiSink for Renderer {
    fn start(&mut self, kind: &str, attrs: &[(&str, &str)]) -> Result<(), SaxError> {
        // Project first (the additive sibling), then forward the ui: element
        // itself — the Perl filter's start_element order.
        let map = clark(attrs);
        self.target.open(kind, &map, &mut self.serializer)?;
        self.serializer.ui_start(kind)
    }

    fn text(&mut self, t: &str) -> Result<(), SaxError> {
        // Accumulate into the innermost frame, then forward the characters
        // (dropped, since a ui: scope sits on top of the serializer's stack).
        self.target.text(t);
        self.serializer.text(t)
    }

    fn end(&mut self, kind: &str) -> Result<(), SaxError> {
        // Forward the close first (pops the ui: scope), then close: a leaf
        // flushes its text now, while its projected element is on top.
        self.serializer.ui_end(kind)?;
        self.target.close(kind, &mut self.serializer)
    }
}

/// Convert a `(name, value)` slice into the Clark-keyed map the projection
/// reads — unprefixed attributes file under `{}name`, the Perl form.
fn clark(attrs: &[(&str, &str)]) -> Attrs {
    let mut map = Attrs::new();
    for (k, v) in attrs {
        map.insert(format!("{{}}{k}"), (*v).to_string());
    }
    map
}

/// Drives the app fragment: the `<amin:profile>` root and its single
/// `<shop:request>`/`<shop:action>` child.
///
/// The `<shop:...>` element is swallowed by the app filter ([`Shop`]), built
/// around the renderer, which emits the `ui:` IR straight into it.  Document
/// level character data is forwarded to the renderer: in HTML mode the
/// serializer drops it (no kept XHTML scope is open, so the envelope
/// contributes nothing), while in text mode it is emitted verbatim — exactly as
/// the Perl chain does.
///
/// An `<amin:acme-challenge>` element is the HTTP-01 responder
/// ([`crate::acme`], ≈ `Amin::Filter::Acme`): its key authorization is emitted
/// as character data, so a `text/plain` route serves it byte-exact.  An
/// `acme-order` element (the issuance client) is driven out of band by
/// `amin-acme`/the Perl filter, never on the render path.
struct DocDriver<'a> {
    catalog: &'a [Product],
    store: &'a mut Store,
    acme: &'a Result<Option<Arc<AcmeKey>>, String>,
    out: &'a mut Renderer,
}

impl ContentHandler for DocDriver<'_> {
    fn start_element(
        &mut self,
        uri: &str,
        local: &str,
        _q: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        if uri == SHOP_NS {
            let a = attr_map(atts);
            let mut shop = Shop::new(self.catalog, &mut *self.store, &mut *self.out);
            match local {
                "request" => shop.request(&a)?,
                "action" => shop.action(&a)?,
                _ => {}
            }
        } else if uri == crate::UI_NS {
            // A fragment may be canonical `ui:` IR: project it exactly as the
            // Perl fleet's element filters do (the HtmlTarget owns the mapping).
            let mut a: Vec<(&str, &str)> = Vec::with_capacity(atts.length());
            for i in 0..atts.length() {
                let ln = atts.local_name(i);
                if !ln.is_empty() {
                    a.push((ln, atts.value(i)));
                }
            }
            self.out.start(local, &a)?;
        } else if uri == AMIN_NS && local == "acme-challenge" {
            // The key authorization is a pure function of the account key, so
            // the responder holds no per-challenge state.
            let token = atts.value_of_local("token").unwrap_or("");
            match self.acme {
                Ok(Some(key)) => self.out.text(&key.key_authorization(token))?,
                Ok(None) => {} // no responder declared: the element is inert
                Err(e) => return Err(SaxError::NotRecognized(format!("acme: {e}"))),
            }
        }
        Ok(())
    }

    fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
        self.out.text(ch)
    }

    fn end_element(&mut self, uri: &str, local: &str, _q: &str) -> Result<(), SaxError> {
        if uri == crate::UI_NS {
            self.out.end(local)?;
        }
        Ok(())
    }
}

/// The app element's attributes, keyed by local name (≈ the Perl filter's `%a`).
fn attr_map(atts: &dyn Attributes) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for i in 0..atts.length() {
        let ln = atts.local_name(i);
        if ln.is_empty() {
            continue;
        }
        map.insert(ln.to_string(), atts.value(i).to_string());
    }
    map
}

/// Whether a resolved content type selects the plain-text serializer
/// (a case-insensitive `text/plain` prefix).
fn is_text_plain(content_type: &str) -> bool {
    content_type
        .as_bytes()
        .get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"text/plain"))
}

/// Inflate, envelope, and drive the fragment through the chain, returning the
/// serialized document.  `text` selects the plain-text serializer.
fn render_into(
    frag: &str,
    values: &Values,
    text: bool,
    ctx: &mut RenderCtx,
) -> Result<String, RenderError> {
    let inflated = inflate(frag, values);
    let doc = format!(
        "<amin:profile xmlns:amin=\"{AMIN_NS}\" xmlns:shop=\"{SHOP_NS}\">{inflated}\n</amin:profile>"
    );

    let mut renderer = if text {
        Renderer::new_text()
    } else {
        Renderer::new()
    };
    renderer.start_document()?;
    {
        let mut driver = DocDriver {
            catalog: &ctx.catalog,
            store: &mut ctx.store,
            acme: &ctx.acme,
            out: &mut renderer,
        };
        amin_sax::parse(&doc, &mut driver)?;
    }
    Ok(renderer.into_output())
}

/// Render `frag` (placeholders intact) with `values` and return a full page:
/// status 200, the declared `content_type`, and any `extra_headers` a streaming
/// caller needs folded in up front (≈ `Amin::AXA::HTTP::render`).  A
/// `content_type` naming `text/plain` selects the byte-exact plain-text
/// serializer (≈ `Amin::Handler::Text`); anything else renders HTML.
///
/// # Errors
/// [`RenderError::Xml`] when the inflated fragment does not parse — the
/// adapter turns that into a 500.
pub fn render_page(
    frag: &str,
    values: &Values,
    extra_headers: &[(&str, &str)],
    content_type: &str,
    ctx: &mut RenderCtx,
) -> Result<Page, RenderError> {
    let body = render_into(frag, values, is_text_plain(content_type), ctx)?;
    let mut headers = vec![("Content-Type".to_string(), content_type.to_string())];
    for (k, v) in extra_headers {
        headers.push(((*k).to_string(), (*v).to_string()));
    }
    Ok(Page {
        status: 200,
        headers,
        body,
    })
}

/// Render `frag` and return just the body (always as HTML).
///
/// `extra_headers` is accepted so this buffered entry and [`render_page`]
/// share one call shape; a body-only caller has no response to attach them to.
///
/// # Errors
/// As [`render_page`].
pub fn render_fragment(
    frag: &str,
    values: &Values,
    extra_headers: &[(&str, &str)],
    ctx: &mut RenderCtx,
) -> Result<String, RenderError> {
    render_page(frag, values, extra_headers, "text/html; charset=utf-8", ctx).map(|p| p.body)
}

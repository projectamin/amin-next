//! The app bundle loader — the Rust form of `Amin::AXA::App`.
//!
//! Loads a bundle's OWN declarations (axa-plan §4.1/§4.2): `axa.xml` carries
//! the routing table (path/method → the fragment the app declares, placeholders
//! intact) and `data/catalog.xml` the demo catalogue. Boot-time only and
//! read-only afterwards (§4.9), so the parsed declarations can be kept for the
//! process lifetime. Route/action lookup lives here because it reads
//! declarations; substituting request values is [`crate::formcodec`]'s job.
//! Neither knows what a shop is.

use std::collections::BTreeMap;

use amin_sax::{Attributes, ContentHandler, SaxError};

use crate::AXA_NS;

/// One catalogue product (`<shop:product>`), attributes as declared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Product {
    /// Stock-keeping unit.
    pub sku: String,
    /// Display name.
    pub name: String,
    /// Price, verbatim (a string, numeric conversion is the app's job).
    pub price: String,
    /// Stock count, verbatim.
    pub stock: String,
}

/// A `GET` route: a path/method pair and the fragment the app declares for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Path template this route answers (a `:name` segment captures).
    pub path: String,
    /// Uppercased HTTP method (default `GET`).
    pub method: String,
    /// The response media type this declaration produces (`type="..."`);
    /// `None` ⇒ `text/html`.
    pub r#type: Option<String>,
    /// The declared fragment, placeholders intact.
    pub fragment: String,
}

/// A `POST` action: a name plus the path/method it is posted to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// Action name (`cart.add`) — the `axa.action` value that selects it.
    pub name: String,
    /// Path template this action is posted to (a `:name` segment captures).
    pub path: String,
    /// Uppercased HTTP method (default `POST`).
    pub method: String,
    /// The response media type this declaration produces (`type="..."`);
    /// `None` ⇒ `text/html`.
    pub r#type: Option<String>,
    /// The declared fragment, placeholders intact.
    pub fragment: String,
}

/// Errors loading an app bundle.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// A filesystem read failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The bundle's XML could not be parsed.
    #[error("xml: {0}")]
    Xml(#[from] SaxError),
    /// A declaration was missing or malformed.
    #[error("{0}")]
    Bad(String),
}

/// A loaded app bundle: its declarations and its catalogue.
#[derive(Debug, Clone)]
pub struct App {
    id: String,
    dir: String,
    routes: Vec<Route>,
    actions: Vec<Action>,
    catalog: Vec<Product>,
    /// The ACME account key path the bundle's own `machine_spec.xml` declares
    /// for its `Amin::Filter::Acme` HTTP-01 responder, if any (the app-level
    /// filter half of RFC 8555 — proxy-plan §5.5).
    acme_challenge_key: Option<String>,
}

impl App {
    /// Load a bundle from `dir` (≈ `Amin::AXA::App::load`).
    ///
    /// # Errors
    /// Fails when `dir` is not a directory, when `axa.xml` is absent or
    /// malformed, or when a declaration is incomplete.
    pub fn load(dir: &str) -> Result<Self, AppError> {
        let path = std::path::Path::new(dir);
        if !path.is_dir() {
            return Err(AppError::Bad(format!("app bundle not a directory: {dir}")));
        }
        let axa = path.join("axa.xml");
        if !axa.is_file() {
            return Err(AppError::Bad(format!(
                "app bundle missing axa.xml: {}",
                axa.display()
            )));
        }
        let xml = std::fs::read_to_string(&axa)?;

        let mut builder = Builder::default();
        amin_sax::parse(&xml, &mut builder)?;
        if builder.routes.is_empty() {
            return Err(AppError::Bad("axa.xml declares no routes".to_string()));
        }

        let id = if builder.id.is_empty() {
            if builder.name.is_empty() {
                dir.to_string()
            } else {
                builder.name.clone()
            }
        } else {
            builder.id.clone()
        };

        let catalog = load_catalog(&path.join("data").join("catalog.xml"))?;
        let acme_challenge_key = load_machine_spec(&path.join("machine_spec.xml"))?;

        Ok(Self {
            id,
            dir: dir.to_string(),
            routes: builder.routes,
            actions: builder.actions,
            catalog,
            acme_challenge_key,
        })
    }

    /// The bundle id (root `id`, else `name`, else the directory).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The bundle directory.
    #[must_use]
    pub fn dir(&self) -> &str {
        &self.dir
    }

    /// The loaded catalogue.
    #[must_use]
    pub fn catalog(&self) -> &[Product] {
        &self.catalog
    }

    /// The ACME account key path the bundle declared for its HTTP-01 responder
    /// (`Amin::Filter::Acme`, `element="acme-challenge"`), if any.
    #[must_use]
    pub fn acme_challenge_key(&self) -> Option<&str> {
        self.acme_challenge_key.as_deref()
    }

    /// Match `path` against a declared path template (≈
    /// `Amin::AXA::App::match_path`), returning the captured parameters.
    ///
    /// A template is `/`-separated segments: a segment of length > 1 whose
    /// first byte is `:` captures the corresponding request segment (which must
    /// be non-empty) under the rest of the segment as its name, and every other
    /// segment must equal the request segment literally. Capture is RAW — the
    /// request path is compared byte for byte and never percent-decoded.
    #[must_use]
    pub fn match_path(template: &str, path: &str) -> Option<BTreeMap<String, String>> {
        // `str::split` on an empty string yields one empty field rather than
        // Perl's empty list; paths/templates here always begin with `/`, so
        // this never diverges from the Perl matcher.
        let t: Vec<&str> = template.split('/').collect();
        let p: Vec<&str> = path.split('/').collect();
        if t.len() != p.len() {
            return None;
        }
        let mut params = BTreeMap::new();
        for (seg, pseg) in t.iter().zip(&p) {
            if seg.len() > 1 && seg.as_bytes()[0] == b':' {
                if pseg.is_empty() {
                    return None;
                }
                params.insert(seg[1..].to_string(), (*pseg).to_string());
            } else if seg != pseg {
                return None;
            }
        }
        Some(params)
    }

    /// The first `GET` route whose template matches `path`, with its captures.
    #[must_use]
    pub fn get_route(&self, path: &str) -> Option<(&Route, BTreeMap<String, String>)> {
        self.routes.iter().find_map(|r| {
            if r.method != "GET" {
                return None;
            }
            Self::match_path(&r.path, path).map(|params| (r, params))
        })
    }

    /// Every route whose template matches `path`.
    #[must_use]
    pub fn routes_at(&self, path: &str) -> Vec<&Route> {
        self.routes
            .iter()
            .filter(|r| Self::match_path(&r.path, path).is_some())
            .collect()
    }

    /// Every action whose template matches `path`.
    #[must_use]
    pub fn actions_at(&self, path: &str) -> Vec<&Action> {
        self.actions
            .iter()
            .filter(|a| Self::match_path(&a.path, path).is_some())
            .collect()
    }

    /// The action named `name`, if any.
    #[must_use]
    pub fn action_named(&self, name: &str) -> Option<&Action> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// The catalogue product with `sku`, if any.
    #[must_use]
    pub fn product(&self, sku: &str) -> Option<&Product> {
        self.catalog.iter().find(|p| p.sku == sku)
    }

    /// The first route whose template matches `path`, whatever its method.
    #[must_use]
    pub fn route_at_path(&self, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .find(|r| Self::match_path(&r.path, path).is_some())
    }
}

/// Parse `data/catalog.xml` if present (≈ `Amin::AXA::App::_load_catalog`).
fn load_catalog(file: &std::path::Path) -> Result<Vec<Product>, AppError> {
    if !file.is_file() {
        return Ok(Vec::new());
    }
    let xml = std::fs::read_to_string(file)?;
    let mut cat = CatalogBuilder::default();
    amin_sax::parse(&xml, &mut cat)?;
    Ok(cat.products)
}

/// Read the bundle's own `machine_spec.xml` (app-bundle-contract) if present,
/// returning the account key its ACME HTTP-01 responder (`Amin::Filter::Acme`,
/// `element="acme-challenge"`) is declared with.
///
/// The Rust front is a specialised chain rather than a spec-driven one (see the
/// crate docs), so only the one declaration the render path needs is lifted out
/// here; the always-present machine filters are byte-neutral for an app
/// document.
fn load_machine_spec(file: &std::path::Path) -> Result<Option<String>, AppError> {
    if !file.is_file() {
        return Ok(None);
    }
    let xml = std::fs::read_to_string(file)?;
    let mut spec = MachineSpecBuilder::default();
    amin_sax::parse(&xml, &mut spec)?;
    Ok(spec.acme_challenge_key)
}

/// Collects the ACME responder's `key` from a `machine_spec.xml`.
#[derive(Default)]
struct MachineSpecBuilder {
    acme_challenge_key: Option<String>,
}

impl ContentHandler for MachineSpecBuilder {
    fn start_element(
        &mut self,
        _uri: &str,
        local: &str,
        _q: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        // A machine spec's `<filter>` is unprefixed (no namespace), and the
        // Perl collector matches it by local name alone — so must this.
        if local == "filter" {
            let class = atts
                .value_of_local("class")
                .or_else(|| atts.value_of_local("name"))
                .unwrap_or("");
            let element = atts.value_of_local("element").unwrap_or("");
            if class == "Amin::Filter::Acme" && element == "acme-challenge" {
                if let Some(key) = atts.value_of_local("key").filter(|k| !k.is_empty()) {
                    self.acme_challenge_key = Some(key.to_string());
                }
            }
        }
        Ok(())
    }

    fn end_element(&mut self, _uri: &str, _local: &str, _q: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

/// Collects `<product>` elements from `catalog.xml`, in document order.
#[derive(Default)]
struct CatalogBuilder {
    products: Vec<Product>,
}

impl ContentHandler for CatalogBuilder {
    fn start_element(
        &mut self,
        _uri: &str,
        local: &str,
        _q: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        if local == "product" {
            let get = |n: &str| atts.value_of_local(n).unwrap_or("").to_string();
            self.products.push(Product {
                sku: get("sku"),
                name: get("name"),
                price: get("price"),
                stock: get("stock"),
            });
        }
        Ok(())
    }

    fn end_element(&mut self, _uri: &str, _local: &str, _q: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

/// Builds the routing table from `axa.xml`, reconstructing each fragment from
/// the raw child serialization (≈ `join '', map { $_->toString } childNodes`).
#[derive(Default)]
struct Builder {
    depth: usize,
    id: String,
    name: String,
    routes: Vec<Route>,
    actions: Vec<Action>,
    capture: Option<Capture>,
    pending_route: Option<(String, String, Option<String>)>,
    pending_action: Option<(String, String, String, Option<String>)>,
    /// Namespace declarations for the element about to start (SAX delivers
    /// them as prefix mappings, never as attributes), re-emitted onto that
    /// element so a captured fragment still binds the dialects it declares.
    prefixes: Vec<(String, String)>,
}

/// One frame of a fragment capture: an element's qualified name, its
/// serialized attributes, and its accumulated children.
struct CapFrame {
    qname: String,
    attrs: String,
    children: String,
}

/// Accumulates the serialized children of a `route`/`action` element.
struct Capture {
    stack: Vec<CapFrame>,
}

impl Capture {
    fn new() -> Self {
        // The base frame is the route/action element itself: never emitted, only
        // its `children` is the fragment.
        Self {
            stack: vec![CapFrame {
                qname: String::new(),
                attrs: String::new(),
                children: String::new(),
            }],
        }
    }

    /// Declarations for the next element are captured here and written onto
    /// it, in document order, when its `start_element` arrives.
    fn push(&mut self, qname: &str, atts: &dyn Attributes, decls: &[(String, String)]) {
        let mut attrs = String::new();
        for (prefix, uri) in decls {
            attrs.push_str(if prefix.is_empty() { " xmlns=\"" } else { " xmlns:" });
            if !prefix.is_empty() {
                attrs.push_str(prefix);
                attrs.push_str("=\"");
            }
            attrs.push_str(&escape_attr(uri));
            attrs.push('"');
        }
        for i in 0..atts.length() {
            let n = atts.q_name(i);
            if n.is_empty() {
                continue;
            }
            attrs.push(' ');
            attrs.push_str(n);
            attrs.push_str("=\"");
            attrs.push_str(&escape_attr(atts.value(i)));
            attrs.push('"');
        }
        self.stack.push(CapFrame {
            qname: qname.to_string(),
            attrs,
            children: String::new(),
        });
    }

    fn text(&mut self, ch: &str) {
        if let Some(f) = self.stack.last_mut() {
            f.children.push_str(&escape_text(ch));
        }
    }

    fn pop(&mut self) -> String {
        let f = match self.stack.pop() {
            Some(f) => f,
            None => return String::new(),
        };
        if f.children.is_empty() {
            format!("<{}{}/>", f.qname, f.attrs)
        } else {
            format!("<{}{}>{}</{}>", f.qname, f.attrs, f.children, f.qname)
        }
    }

    fn finish(mut self) -> String {
        self.stack.pop().map_or_else(String::new, |f| f.children)
    }
}

fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_attr(s: &str) -> String {
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

impl ContentHandler for Builder {
    fn start_prefix_mapping(&mut self, prefix: &str, uri: &str) -> Result<(), SaxError> {
        self.prefixes.push((prefix.to_string(), uri.to_string()));
        Ok(())
    }

    fn start_element(
        &mut self,
        uri: &str,
        local: &str,
        q: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        self.depth += 1;
        match self.depth {
            1 => {
                if uri == AXA_NS {
                    self.id = atts.value_of_local("id").unwrap_or("").to_string();
                    self.name = atts.value_of_local("name").unwrap_or("").to_string();
                }
            }
            2 => match local {
                "route" => {
                    self.prefixes.clear(); // declared on the route, not the fragment
                    let path = atts.value_of_local("path").unwrap_or("").to_string();
                    if path.is_empty() {
                        return Err(declaration_error("axa:route missing path"));
                    }
                    let method = atts.value_of_local("method").unwrap_or("GET").to_uppercase();
                    let r#type = atts
                        .value_of_local("type")
                        .filter(|t| !t.is_empty())
                        .map(str::to_string);
                    self.pending_route = Some((path, method, r#type));
                    self.capture = Some(Capture::new());
                }
                "action" => {
                    self.prefixes.clear();
                    let name = atts.value_of_local("name").unwrap_or("").to_string();
                    let path = atts.value_of_local("path").unwrap_or("").to_string();
                    if name.is_empty() {
                        return Err(declaration_error("axa:action missing name"));
                    }
                    if path.is_empty() {
                        return Err(declaration_error("axa:action missing path"));
                    }
                    let method = atts.value_of_local("method").unwrap_or("POST").to_uppercase();
                    let r#type = atts
                        .value_of_local("type")
                        .filter(|t| !t.is_empty())
                        .map(str::to_string);
                    self.pending_action = Some((name, path, method, r#type));
                    self.capture = Some(Capture::new());
                }
                other => {
                    return Err(declaration_error(&format!(
                        "axa.xml: unknown element <axa:{other}>"
                    )))
                }
            },
            _ => {
                if let Some(cap) = self.capture.as_mut() {
                    let decls = std::mem::take(&mut self.prefixes);
                    cap.push(q, atts, &decls);
                }
            }
        }
        Ok(())
    }

    fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
        if let Some(cap) = self.capture.as_mut() {
            cap.text(ch);
        }
        Ok(())
    }

    fn end_element(&mut self, _uri: &str, _local: &str, _q: &str) -> Result<(), SaxError> {
        match self.depth {
            2 => {
                let fragment = self.capture.take().map_or_else(String::new, Capture::finish);
                if let Some((path, method, r#type)) = self.pending_route.take() {
                    self.routes.push(Route {
                        path,
                        method,
                        r#type,
                        fragment,
                    });
                } else if let Some((name, path, method, r#type)) = self.pending_action.take() {
                    self.actions.push(Action {
                        name,
                        path,
                        method,
                        r#type,
                        fragment,
                    });
                }
            }
            1 => {}
            _ => {
                if let Some(cap) = self.capture.as_mut() {
                    let child = cap.pop();
                    if let Some(parent) = cap.stack.last_mut() {
                        parent.children.push_str(&child);
                    }
                }
            }
        }
        if self.depth > 0 {
            self.depth -= 1;
        }
        Ok(())
    }
}

fn declaration_error(msg: &str) -> SaxError {
    SaxError::NotRecognized(msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::{App, Builder, Route};

    #[test]
    fn match_path_exact_has_no_captures() {
        let m = App::match_path("/cart", "/cart").expect("exact match");
        assert!(m.is_empty());
    }

    #[test]
    fn match_path_captures_one_segment() {
        let m = App::match_path("/product/:sku", "/product/sku-2").expect("capture");
        assert_eq!(m.get("sku").map(String::as_str), Some("sku-2"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn match_path_rejects_wrong_segment_count() {
        assert!(App::match_path("/a/b", "/a").is_none());
        assert!(App::match_path("/a", "/a/b").is_none());
    }

    #[test]
    fn match_path_rejects_empty_captured_segment() {
        assert!(App::match_path("/product/:sku", "/product/").is_none());
    }

    #[test]
    fn match_path_captures_multiple_segments() {
        let m = App::match_path("/a/:x/b/:y", "/a/1/b/2").expect("captures");
        assert_eq!(m.get("x").map(String::as_str), Some("1"));
        assert_eq!(m.get("y").map(String::as_str), Some("2"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn fragment_capture_keeps_declared_namespaces_and_qualified_names() {
        // Namespace declarations arrive as prefix mappings, never attributes;
        // the capture must re-emit them or a fragment in a dialect the
        // envelope does not declare (ui:, an app's own) fails to parse.
        let xml = r#"<?xml version="1.0"?>
<axa:app xmlns:axa="http://projectamin.org/ns/axa/1" id="x" name="x">
  <axa:route path="/" method="GET">
    <ui:app xmlns:ui="http://projectamin.org/ns/ui/1" title="T" theme="soft-studio">
      <ui:text title="hi">hello</ui:text>
    </ui:app>
  </axa:route>
</axa:app>"#;
        let mut b = Builder::default();
        amin_sax::parse(xml, &mut b).expect("declaration parses");
        assert_eq!(b.routes.len(), 1);
        let frag = &b.routes[0].fragment;
        assert!(frag.contains(r#"xmlns:ui="http://projectamin.org/ns/ui/1""#), "{frag}");
        assert!(frag.contains(r#"theme="soft-studio""#), "{frag}");
        assert!(frag.contains("<ui:text"), "{frag}");
    }

    #[test]
    fn match_path_literal_template_rejects_other_path() {
        assert!(App::match_path("/cart", "/carts").is_none());
        assert!(App::match_path("/a/b", "/a/c").is_none());
    }

    #[test]
    fn match_path_distinguishes_trailing_slash() {
        // `/cart/` splits to a trailing empty segment; `/cart` does not.
        assert!(App::match_path("/cart", "/cart/").is_none());
        assert!(App::match_path("/cart/", "/cart/").is_some());
        // A trailing slash still captures a non-empty middle segment.
        let m = App::match_path("/:x/", "/a/").expect("capture with trailing slash");
        assert_eq!(m.get("x").map(String::as_str), Some("a"));
    }

    #[test]
    fn get_route_returns_the_captured_params() {
        let app = App {
            id: "test".to_string(),
            dir: ".".to_string(),
            routes: vec![Route {
                path: "/product/:sku".to_string(),
                method: "GET".to_string(),
                r#type: None,
                fragment: r#"<shop:request route="product"/>"#.to_string(),
            }],
            actions: Vec::new(),
            catalog: Vec::new(),
            acme_challenge_key: None,
        };
        let (route, params) = app.get_route("/product/sku-2").expect("route match");
        assert_eq!(route.path, "/product/:sku");
        assert_eq!(params.get("sku").map(String::as_str), Some("sku-2"));
        assert!(app.get_route("/cart").is_none());
    }
}

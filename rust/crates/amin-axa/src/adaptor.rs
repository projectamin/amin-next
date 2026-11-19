//! The HTTP adapter — the Rust form of `Amin::AXA::HTTP::handle`.
//!
//! Framing and transport hygiene only (axa-plan §5.6): body cap, content-type,
//! the method/path matrix, Origin + CSRF.  No `if $element eq`, no role table,
//! no allow-list — what a principal may cause to run lives in the chain, not
//! here.  The adapter reads a request, decides, drives the render path
//! ([`crate::render`]), and returns a response.
//!
//! It is transport-neutral: [`Request`] is the handful of fields the Perl
//! adapter reads off a PSGI env, and [`Page`] is the response triple it
//! returns.  The tokio server in `bin/amin-axa.rs` parses the wire into a
//! [`Request`] and writes the [`Page`] back; nothing here knows about sockets.
//!
//! One [`Service`] is the whole process's app surface: the bundle loaded once
//! at boot (§4.8) and the session store, behind a mutex because a session's
//! cart must survive across requests (§4.7).  Its decisions mirror the Perl
//! adapter's, byte for byte, so the two fronts agree (§7).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use crate::acme::AcmeKey;
use crate::app::App;
use crate::formcodec::Values;
use crate::render::{render_page, Page, RenderCtx};
use crate::session::Session;
use crate::store::{Record, Store};
use crate::BODY_CAP;

/// A transport-neutral HTTP request: the fields the adapter reads.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Request method, uppercased (`GET`, `POST`, …).
    pub method: String,
    /// The request path, without the query string.
    pub path: String,
    /// The raw query string (no leading `?`), or empty.
    pub query: String,
    /// The `Content-Type` header, when present.
    pub content_type: Option<String>,
    /// The `Origin` header, when present.
    pub origin: Option<String>,
    /// The `Host` header as sent, when present.
    pub host: Option<String>,
    /// The `Cookie` header, when present.
    pub cookie: Option<String>,
    /// The request body, already de-chunked and capped by the transport.
    pub body: Vec<u8>,
    /// Whether the transport hit the body cap while reading (a POST then gets
    /// a 413 before any parsing).
    pub body_too_large: bool,
}

/// The app surface: the loaded bundle and the process-scoped session store.
///
/// Boot does the expensive things once (§4.8); a request only reads the
/// declarations and the store.  Sessions live in the store keyed by id, and
/// never carry authority (§5.3).
pub struct Service {
    app: App,
    store: Mutex<Store>,
    /// The app's ACME account key, loaded once and cached (≈ the Perl filter's
    /// memoised `_acme_key`).  `Ok(None)` when the bundle declares no HTTP-01
    /// responder; `Err` when it declared a key that would not open.
    acme: OnceLock<Result<Option<Arc<AcmeKey>>, String>>,
}

impl Service {
    /// Build a service over a loaded bundle.
    #[must_use]
    pub fn new(app: App) -> Self {
        Self {
            app,
            store: Mutex::new(Store::new()),
            acme: OnceLock::new(),
        }
    }

    /// The loaded bundle.
    #[must_use]
    pub fn app(&self) -> &App {
        &self.app
    }

    /// The app's ACME account key, loaded once from the `key` its own
    /// `machine_spec.xml` declares for the HTTP-01 responder (proxy-plan
    /// §5.5).  Lazy so an app with no responder never touches `openssl`.
    fn acme_key(&self) -> &Result<Option<Arc<AcmeKey>>, String> {
        self.acme.get_or_init(|| match self.app.acme_challenge_key() {
            None => Ok(None),
            Some(path) => AcmeKey::load(Path::new(path))
                .map(|k| Some(Arc::new(k)))
                .map_err(|e| e.to_string()),
        })
    }

    /// Handle one request (≈ `Amin::AXA::HTTP::handle`), returning the response.
    pub fn handle(&self, req: &Request) -> Page {
        let method = req.method.as_str();
        let path = req.path.as_str();

        // Framing first (§5.6): cheap transport checks before any work.
        if method == "POST" {
            if req.body_too_large {
                return err(413, "payload too large");
            }
            let ct_ok = req.content_type.as_deref().is_some_and(is_form_content_type);
            if !ct_ok {
                return err(415, "unsupported media type");
            }
        }

        let (sid, rec, minted) = self.session(req);

        let res = if method == "GET" || method == "HEAD" {
            if let Some((r, rparams)) = self.app.get_route(path) {
                let mut vals = self.params(req);
                for (k, v) in &rparams {
                    vals.set(k, v);
                }
                // reserved, applied last
                vals.set("sid", &sid).set("csrf", &rec.csrf);
                self.render(&r.fragment, &vals, content_type_for(r.r#type.as_deref()))
            } else if !self.app.routes_at(path).is_empty() || !self.app.actions_at(path).is_empty() {
                err(405, "method not allowed")
            } else {
                err(404, "not found")
            }
        } else if method == "POST" {
            let params = self.params(req);
            let feasible = !self.app.actions_at(path).is_empty()
                || self.app.routes_at(path).iter().any(|r| r.method == "POST");
            if !feasible {
                if !self.app.routes_at(path).is_empty() || !self.app.actions_at(path).is_empty() {
                    err(405, "method not allowed")
                } else {
                    err(404, "not found")
                }
            } else {
                let name = params.get("axa.action");
                let action = if name.is_empty() {
                    None
                } else {
                    self.app.action_named(name)
                };
                match action.and_then(|a| {
                    App::match_path(&a.path, path).map(|aparams| (a, aparams))
                }) {
                    None => err(422, "unknown action"),
                    Some((a, aparams)) => {
                        if req
                            .origin
                            .as_deref()
                            .is_some_and(|o| !same_origin(o, req.host.as_deref().unwrap_or("")))
                        {
                            err(403, "forbidden origin")
                        } else if params.get("axa.csrf") != rec.csrf.as_str() {
                            err(403, "bad csrf token")
                        } else {
                            let mut vals = action_values(&params);
                            for (k, v) in &aparams {
                                vals.set(k, v);
                            }
                            vals.set("sid", &sid).set("csrf", &rec.csrf);
                            self.render(&a.fragment, &vals, content_type_for(a.r#type.as_deref()))
                        }
                    }
                }
            }
        } else if !self.app.routes_at(path).is_empty() || !self.app.actions_at(path).is_empty() {
            err(405, "method not allowed")
        } else {
            err(404, "not found")
        };

        self.done(res, minted, &sid)
    }

    /// The session record for a request: the cookie only selects which store
    /// record to use, it is never a principal (§5.3).  A stale/unknown cookie
    /// is replaced by a mint (≈ `Amin::AXA::HTTP::session`).
    fn session(&self, req: &Request) -> (String, Record, bool) {
        let mut store = self.store.lock().expect("store mutex");
        if let Some(sid) = Session::cookie_sid(req.cookie.as_deref()) {
            if let Some(rec) = store.get(&sid) {
                return (sid, rec.clone(), false);
            }
        }
        let (sid, csrf) = Session::mint();
        let rec = Record {
            csrf,
            cart: BTreeMap::new(),
        };
        store.set(&sid, rec.clone());
        (sid, rec, true)
    }

    /// The request parameters: query for any method, plus the body for a POST
    /// (≈ `Plack::Request->parameters->flatten`, last wins).
    fn params(&self, req: &Request) -> Values {
        let mut v = Values::new();
        parse_form(&req.query, &mut v);
        if req.method == "POST" {
            let body = String::from_utf8_lossy(&req.body);
            parse_form(&body, &mut v);
        }
        v
    }

    /// Inflate the app's fragment, envelope it, and drive the chain; the
    /// resolved `content_type` (the route/action's declared media type via
    /// [`content_type_for`]) selects the serializer.  A parse failure is a 500
    /// (≈ `Amin::AXA::HTTP::render`).
    fn render(&self, frag: &str, vals: &Values, content_type: &str) -> Page {
        let mut guard = self.store.lock().expect("store mutex");
        let mut ctx = RenderCtx {
            catalog: self.app.catalog().to_vec(),
            store: std::mem::take(&mut *guard),
            acme: self.acme_key().clone(),
        };
        let out = render_page(frag, vals, &[], content_type, &mut ctx);
        *guard = ctx.store;
        drop(guard);
        match out {
            Ok(page) => page,
            Err(e) => {
                eprintln!("[axa] render failed: {e}");
                err(500, "internal error")
            }
        }
    }

    /// Fold the session cookie into the response (≈ `Amin::AXA::HTTP::done`).
    /// A freshly minted session must announce itself on whatever response it
    /// produced, error or page alike.
    fn done(&self, mut res: Page, minted: bool, sid: &str) -> Page {
        if minted {
            res.headers
                .push(("Set-Cookie".to_string(), Session::set_cookie(sid)));
        }
        res
    }
}

/// A `text/plain` error response (≈ `Amin::AXA::HTTP::err`).
fn err(code: u16, msg: &str) -> Page {
    Page {
        status: code,
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: format!("{code} {msg}\n"),
    }
}

/// `^application/x-www-form-urlencoded\b`i — the POST body type the adapter
/// will parse; anything else is 415.
#[must_use]
pub fn is_form_content_type(ct: &str) -> bool {
    const P: &str = "application/x-www-form-urlencoded";
    let lc = ct.to_ascii_lowercase();
    match lc.strip_prefix(P) {
        Some(rest) => match rest.as_bytes().first() {
            None => true,
            Some(&b) => !(b.is_ascii_alphanumeric() || b == b'_'),
        },
        None => false,
    }
}

/// The response content type for a declared route/action media type (≈
/// `Amin::AXA::HTTP::_content_type`): a type matching `^text/plain\b`i selects
/// the byte-exact plain-text serializer, everything else HTML.  `None` (no
/// declared `type`) is `text/html`.
#[must_use]
pub fn content_type_for(ty: Option<&str>) -> &'static str {
    const P: &str = "text/plain";
    let lc = ty.unwrap_or("").to_ascii_lowercase();
    let text = match lc.strip_prefix(P) {
        Some(rest) => match rest.as_bytes().first() {
            None => true,
            Some(&b) => !(b.is_ascii_alphanumeric() || b == b'_'),
        },
        None => false,
    };
    if text {
        "text/plain; charset=utf-8"
    } else {
        "text/html; charset=utf-8"
    }
}

/// `Origin` scheme://host equals the request `Host` (≈ `same_origin`).
#[must_use]
pub fn same_origin(origin: &str, host: &str) -> bool {
    let b = origin.as_bytes();
    if b.first().is_none_or(|c| !c.is_ascii_alphabetic()) {
        return false;
    }
    let mut i = 1;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'+' | b'.' | b'-')) {
        i += 1;
    }
    if !origin[i..].starts_with("://") {
        return false;
    }
    let hostpart = origin[i + 3..].split('/').next().unwrap_or("");
    !hostpart.is_empty() && hostpart == host
}

/// The action's placeholder values: every parameter but the reserved
/// `axa.action`/`axa.csrf`, with each `axa.param.NAME` renamed to `NAME`
/// (≈ the `delete`/rename loop in `handle`).
fn action_values(params: &Values) -> Values {
    let keys: Vec<String> = params.keys().map(str::to_string).collect();
    let mut out = Values::new();
    for k in &keys {
        if k == "axa.action" || k == "axa.csrf" {
            continue;
        }
        match k.strip_prefix("axa.param.") {
            Some(name) if !name.is_empty() => out.set(name, params.get(k)),
            _ => out.set(k, params.get(k)),
        };
    }
    out
}

/// Parse an `application/x-www-form-urlencoded` string into `v`.
///
/// Each `k=v` pair is percent-decoded and set last-wins, matching a flattened
/// parameter list assigned into a hash.
fn parse_form(s: &str, v: &mut Values) {
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, val) = pair.split_once('=').unwrap_or((pair, ""));
        v.set(&decode_form(k), &decode_form(val));
    }
}

/// Percent-decode one form component: `+` → space, `%XX` → byte, else verbatim.
#[must_use]
pub fn decode_form(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => match (hexval(b[i + 1]), hexval(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The value of a hex digit, or `None`.
fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The largest body the transport will hand the adapter — the cap the adapter
/// enforces (axa-plan §4.1 / M2 acceptance).
#[must_use]
pub const fn body_cap() -> usize {
    BODY_CAP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_content_type_matches_the_perl_regex() {
        assert!(is_form_content_type("application/x-www-form-urlencoded"));
        assert!(is_form_content_type(
            "application/x-www-form-urlencoded; charset=utf-8"
        ));
        assert!(is_form_content_type("Application/X-WWW-Form-Urlencoded"));
        assert!(!is_form_content_type("application/json"));
        assert!(!is_form_content_type("application/x-www-form-urlencodedX"));
    }

    #[test]
    fn content_type_for_matches_the_perl_regex() {
        assert_eq!(
            content_type_for(Some("text/plain")),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Some("text/plain; charset=utf-8")),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Some("TEXT/PLAIN")),
            "text/plain; charset=utf-8"
        );
        // The char after "plain" is a word char → not the word boundary → HTML.
        assert_eq!(
            content_type_for(Some("text/plainish")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Some("text/plain_x")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Some("text/html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type_for(None), "text/html; charset=utf-8");
    }

    #[test]
    fn same_origin_compares_scheme_host_to_the_host_header() {
        assert!(same_origin("http://localhost", "localhost"));
        assert!(same_origin("https://a.example:8443", "a.example:8443"));
        assert!(!same_origin("http://evil.example", "localhost"));
        assert!(!same_origin("not-a-url", "localhost"));
    }

    #[test]
    fn decodes_percent_and_plus() {
        assert_eq!(decode_form("a+b"), "a b");
        assert_eq!(decode_form("%3Cscript%3E"), "<script>");
        assert_eq!(decode_form("plain"), "plain");
        assert_eq!(decode_form("%zz"), "%zz");
    }

    #[test]
    fn action_values_renames_axa_param_and_drops_reserved() {
        let mut p = Values::new();
        p.set("axa.action", "cart.add")
            .set("axa.csrf", "tok")
            .set("axa.param.sku", "sku-1")
            .set("other", "x");
        let v = action_values(&p);
        assert_eq!(v.get("sku"), "sku-1");
        assert_eq!(v.get("other"), "x");
        assert!(!v.contains("axa.action"));
        assert!(!v.contains("axa.param.sku"));
    }
}

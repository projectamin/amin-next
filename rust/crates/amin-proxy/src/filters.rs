//! The proxy as the machine's filters (proxy-plan §5.1/§5.2).
//!
//! `amin-proxy` is not a second router: it is `amin` — the [`amin_machine`]
//! filter machine — with two filters registered, `Proxy::Route` and
//! `Proxy::RateLimit`, composed from the *same* shared `machine_spec.xml` the
//! Perl front composes and driven by the same SAX event stream. A request
//! becomes the document
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <amin:profile xmlns:amin="http://projectamin.org/ns/2026/">
//!   <amin:request amin:host="…" amin:method="…" amin:path="…" amin:scheme="…" amin:peer="…" />
//! </amin:profile>
//! ```
//!
//! exactly as the Perl `Amin::Proxy::HTTP::_run_chain` builds it. With only
//! these two classes registered, [`build_chain`](amin_machine::build_chain)
//! composes:
//!
//! ```text
//!   Proxy::RateLimit   (static `begin`, outermost)
//!     └─ LazyGate (begin)  ── splices Proxy::Route on <amin:request>
//!          └─ DecisionCollector  (the adapter-facing base)
//! ```
//!
//! `Proxy::Route` is an element-scoped candidate bound to `<amin:request>`; on
//! that element it emits one `<proxy:backend>` per candidate backend, or a
//! `-6150 <amin:status>` deny. `Proxy::RateLimit` is an element-agnostic static
//! `begin` filter that sheds an over-budget request with a `-7100
//! <amin:status>` *before* routing. The compiled profile is injected through
//! `ChainContext.proxy` — the same channel that injects `Render` in Perl — so
//! no filter owns a table of its own.
//!
//! The decision bytes this produces are identical to the Perl filter's
//! (proxy-plan §7): the shared vocabulary, the same event shapes, the same
//! canonical `<proxy:backend …/>` serialisation.

use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use amin_sax::{Attribute, AttributeList, Attributes, SaxError};

use amin_machine::{
    filter_handler, ChainContext, Filter, FilterArgs, Log, Machine, MachineSpec, Node, Registry,
};

use crate::http::Request;
use crate::listener::RateLimiter;
use crate::{Backend, Compiled, Route, AMIN_NS, PROXY_NS};

/// Status rc emitted for an over-budget request; the HTTP adapter maps it to
/// `429 Too Many Requests` (proxy-plan §P5). The peer of
/// [`crate::RC_NO_ROUTE`].
pub const RC_RATE_LIMITED: i32 = -7100;

/// The injected compiled context: the frozen matcher the routing filter reads
/// and the shared rate buckets the limiter draws from. One per request, built
/// from the [`Front`](crate::listener::Front)'s shared state — the Rust peer of
/// the `Proxy => $self->{config}` injection.
pub(crate) struct ProxyCtx {
    compiled: Arc<Compiled>,
    rate: Option<Arc<RateLimiter>>,
}

/// The adapter-facing decision the chain produced (≈ `Amin::Proxy::HTTP::Decision`):
/// the `<proxy:backend>` elements the routing filter emitted, plus any
/// `<amin:status>`.
#[derive(Default)]
pub(crate) struct DecisionSink {
    backends: Vec<BTreeMap<String, String>>,
    status: Option<BTreeMap<String, String>>,
}

impl DecisionSink {
    /// One canonical `<proxy:backend …/>` line per captured backend, in `to=`
    /// order — the exact bytes [`crate::decision_element`] produces.
    fn canonical(&self) -> Vec<String> {
        self.backends.iter().map(backend_line).collect()
    }
}

/// The outcome of routing one request, resolved before any I/O so no `Rc`
/// chain ever crosses an `.await`.
pub(crate) enum Decision {
    /// No backend was chosen — closed-world. The adapter maps `code`.
    Deny {
        /// The HTTP status the deny maps to.
        code: u16,
    },
    /// The chain chose these candidate backends; the balancer picks one.
    Route {
        /// Candidate backend ids, in `to=` order.
        ids: Vec<String>,
        /// The winning route's path, for prefix stripping (≈ Perl
        /// `_upstream_head`'s re-match).
        route_path: String,
        /// Strip the route's path prefix before forwarding.
        strip_prefix: bool,
        /// Allow an RFC 6455 upgrade on this route.
        ws: bool,
    },
}

// ── the decision collector ──────────────────────────────────────────────────

/// Captures the adapter-facing decision from the chain: the `<proxy:backend>`
/// elements plus any `<amin:status>`, dropping everything else — the front is a
/// pump, not a renderer (≈ `Amin::Proxy::HTTP::Decision`).
struct DecisionCollector {
    out: Rc<RefCell<DecisionSink>>,
    handler: Option<Node>,
}

impl Filter for DecisionCollector {
    filter_handler!();

    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        let ln = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        let surface = surface(atts);
        if uri == PROXY_NS && ln == "backend" {
            self.out.borrow_mut().backends.push(surface);
        } else if ln == "status" && surface.contains_key("rc") {
            self.out.borrow_mut().status = Some(surface);
        }
        Ok(())
    }
}

// ── Proxy::Route ────────────────────────────────────────────────────────────

/// The routing filter (≈ `Amin::Proxy::Route`): an element-scoped `begin`
/// candidate bound to `<amin:request>`.
struct RouteFilter {
    handler: Option<Node>,
    log: Option<Rc<dyn Log>>,
    ctx: Option<Rc<ProxyCtx>>,
}

impl RouteFilter {
    /// Route one `<amin:request>`: emit a `<proxy:backend>` per candidate
    /// backend, or a closed-world `-6150` deny.
    fn route(&self, atts: &dyn Attributes) {
        let host = atts.value_of_local("host").unwrap_or("");
        let path = atts.value_of_local("path").unwrap_or("/");

        let Some(ctx) = &self.ctx else {
            self.deny(host, path, "no_proxy_config");
            return;
        };
        let Some(route) = ctx.compiled.match_route(host, path) else {
            self.deny(host, path, "no_route");
            return;
        };
        for id in &route.to {
            if let Some(b) = ctx.compiled.backends.get(id) {
                self.backend(b, route);
            }
        }
    }

    /// One decision element per candidate backend: transport and destination,
    /// plus the route-level directives, so the adapter needs nothing else.
    fn backend(&self, b: &Backend, route: &Route) {
        let (ep_key, ep_val) = b.endpoint();
        let mut attrs = AttributeList::new();
        push_amin(&mut attrs, "id", &b.id);
        push_amin(&mut attrs, "transport", &b.transport);
        push_amin(&mut attrs, ep_key, ep_val);
        push_amin(&mut attrs, "policy", &route.policy);
        push_amin(
            &mut attrs,
            "strip-prefix",
            if route.strip_prefix { "true" } else { "false" },
        );
        push_amin(&mut attrs, "ws", if route.ws { "on" } else { "off" });
        emit_start(&self.handler, PROXY_NS, "proxy", "backend", &attrs);
        emit_end(&self.handler, PROXY_NS, "proxy", "backend");
    }

    /// Closed-world deny: a `-6150` `<amin:status>`, never a silent default.
    fn deny(&self, host: &str, path: &str, why: &str) {
        let msg = format!("no route for host={host} path={path} ({why})");
        if let Some(log) = &self.log {
            log.warn(&format!("proxy: {msg}"));
        }
        emit_start(&self.handler, AMIN_NS, "amin", "result", &AttributeList::new());
        let mut attrs = AttributeList::new();
        push_amin(&mut attrs, "rc", &format!("{:+}", crate::RC_NO_ROUTE));
        push_amin(&mut attrs, "exit_kind", why);
        push_amin(&mut attrs, "msg", &msg);
        emit_start(&self.handler, AMIN_NS, "amin", "status", &attrs);
        emit_end(&self.handler, AMIN_NS, "amin", "status");
        emit_end(&self.handler, AMIN_NS, "amin", "result");
    }
}

impl Filter for RouteFilter {
    filter_handler!();

    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        let ln = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        if uri == AMIN_NS && ln == "request" {
            self.route(atts);
        }
        if let Some(h) = self.handler.clone() {
            return h.borrow_mut().start_element(uri, local_name, q_name, atts);
        }
        Ok(())
    }
}

// ── Proxy::RateLimit ────────────────────────────────────────────────────────

/// The per-IP rate limit (≈ `Amin::Proxy::RateLimit`): a static `begin` filter
/// that sheds an over-budget request before routing.
struct RateLimitFilter {
    handler: Option<Node>,
    log: Option<Rc<dyn Log>>,
    ctx: Option<Rc<ProxyCtx>>,
    shed: bool,
}

impl RateLimitFilter {
    /// Whether this request may proceed. Opt-in: no limiter injected → always
    /// allow.
    fn allow(&self, atts: &dyn Attributes) -> bool {
        let Some(rate) = self.ctx.as_ref().and_then(|c| c.rate.as_ref()) else {
            return true;
        };
        let ip = atts.value_of_local("peer").unwrap_or("");
        rate.allow(ip, Instant::now())
    }

    /// Over budget: a `-7100` `<amin:status>` the adapter maps to `429`.
    fn deny(&self, atts: &dyn Attributes) {
        let ip = atts.value_of_local("peer").unwrap_or("");
        let msg = format!("rate limit exceeded for peer={ip}");
        if let Some(log) = &self.log {
            log.warn(&format!("proxy: {msg}"));
        }
        emit_start(&self.handler, AMIN_NS, "amin", "result", &AttributeList::new());
        let mut attrs = AttributeList::new();
        push_amin(&mut attrs, "rc", &format!("{:+}", RC_RATE_LIMITED));
        push_amin(&mut attrs, "exit_kind", "rate_limited");
        push_amin(&mut attrs, "msg", &msg);
        emit_start(&self.handler, AMIN_NS, "amin", "status", &attrs);
        emit_end(&self.handler, AMIN_NS, "amin", "status");
        emit_end(&self.handler, AMIN_NS, "amin", "result");
    }
}

impl Filter for RateLimitFilter {
    filter_handler!();

    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        let ln = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        if uri == AMIN_NS && ln == "request" {
            // Within budget — let it flow on to be routed (never consumed here).
            if self.allow(atts) {
                if let Some(h) = self.handler.clone() {
                    return h.borrow_mut().start_element(uri, local_name, q_name, atts);
                }
                return Ok(());
            }
            self.deny(atts);
            self.shed = true; // swallow this element's close too
            return Ok(());
        }
        if let Some(h) = self.handler.clone() {
            return h.borrow_mut().start_element(uri, local_name, q_name, atts);
        }
        Ok(())
    }

    fn end_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
    ) -> Result<(), SaxError> {
        let ln = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        // A shed element is swallowed whole: the matching close is not
        // forwarded either, so nothing downstream ever sees the request.
        if uri == AMIN_NS && ln == "request" && std::mem::take(&mut self.shed) {
            return Ok(());
        }
        if let Some(h) = self.handler.clone() {
            return h.borrow_mut().end_element(uri, local_name, q_name);
        }
        Ok(())
    }
}

// ── registry + constructors ─────────────────────────────────────────────────

/// The filter classes this binary carries: the two proxy filters. `verb` is
/// `Some("")` for both — the Rust form of each class's `sub name { '' }`
/// (element-bound, no verb).
fn registry() -> Registry {
    let mut reg = Registry::new();
    reg.register("Amin::Proxy::Route", Some(""), route_ctor());
    reg.register("Amin::Proxy::RateLimit", Some(""), rate_ctor());
    reg
}

fn route_ctor() -> amin_machine::Constructor {
    Box::new(|args: FilterArgs| {
        Box::new(RouteFilter {
            log: args.log,
            ctx: downcast_ctx(&args.proxy),
            handler: args.handler,
        })
    })
}

fn rate_ctor() -> amin_machine::Constructor {
    Box::new(|args: FilterArgs| {
        Box::new(RateLimitFilter {
            log: args.log,
            ctx: downcast_ctx(&args.proxy),
            handler: args.handler,
            shed: false,
        })
    })
}

/// Recover the injected [`ProxyCtx`] from the `proxy` channel (mirrors the Perl
/// `$self->Proxy`).
fn downcast_ctx(proxy: &Option<Rc<dyn Any>>) -> Option<Rc<ProxyCtx>> {
    proxy.clone().and_then(|p| p.downcast::<ProxyCtx>().ok())
}

// ── running the chain ───────────────────────────────────────────────────────

/// Run one `<amin:profile>` document through the machine and return the
/// decision it produced.
fn run_chain(
    machine: &Machine,
    proxy: Rc<ProxyCtx>,
    doc: &str,
    log: Option<Rc<dyn Log>>,
) -> DecisionSink {
    let sink = Rc::new(RefCell::new(DecisionSink::default()));
    let base = amin_machine::node(DecisionCollector {
        out: sink.clone(),
        handler: None,
    });
    let mut ctx = ChainContext::new(Rc::new(registry()), "run", "tty");
    ctx.log = log;
    ctx.proxy = Some(proxy);
    // The chain is `Rc`-based and never `Send`; it is built and dropped entirely
    // inside this synchronous call, so no node ever crosses an `.await`.
    let _ = machine.run(base, doc, &ctx);
    let out = sink.borrow();
    DecisionSink {
        backends: out.backends.clone(),
        status: out.status.clone(),
    }
}

/// Route one request through the machine and resolve the outcome, before any
/// I/O.
pub(crate) fn decide(
    machine: &Machine,
    compiled: &Arc<Compiled>,
    rate: Option<Arc<RateLimiter>>,
    req: &Request,
) -> Decision {
    let proxy = Rc::new(ProxyCtx {
        compiled: Arc::clone(compiled),
        rate,
    });
    let sink = run_chain(machine, proxy, &request_doc(req), None);

    if sink.backends.is_empty() {
        let rc = sink
            .status
            .as_ref()
            .and_then(|s| s.get("rc"))
            .and_then(|v| v.parse::<i32>().ok());
        return Decision::Deny {
            code: rc_to_http(rc),
        };
    }

    let first = &sink.backends[0];
    let route_path = compiled
        .match_route(&req.host, &req.path)
        .map_or_else(String::new, |r| r.path.clone());
    Decision::Route {
        ids: sink
            .backends
            .iter()
            .filter_map(|b| b.get("id").cloned())
            .collect(),
        route_path,
        strip_prefix: first.get("strip-prefix").is_some_and(|v| v == "true"),
        ws: first.get("ws").is_some_and(|v| v == "on"),
    }
}

/// The decision elements for one profile + request, each already canonical —
/// the bytes [`crate::decision_element`] produces (proxy-parity §7). Runs the
/// machine, so the parity test exercises the real chain, not a side path.
#[must_use]
pub fn decisions(compiled: &Compiled, host: &str, path: &str) -> Vec<String> {
    let machine = Machine::new(MachineSpec::new().spec());
    let proxy = Rc::new(ProxyCtx {
        compiled: Arc::new(compiled.clone()),
        rate: None,
    });
    run_chain(&machine, proxy, &request_doc_parts(host, path), None).canonical()
}

/// The `<amin:profile>` document for one request — the Rust peer of the Perl
/// `_run_chain` XML.
fn request_doc(req: &Request) -> String {
    let mut attrs = String::new();
    for (k, v) in [
        ("host", req.host.as_str()),
        ("method", req.method.as_str()),
        ("path", req.path.as_str()),
        ("scheme", req.scheme),
        ("peer", req.peer.as_str()),
    ] {
        attrs.push_str(" amin:");
        attrs.push_str(k);
        attrs.push_str("=\"");
        attrs.push_str(&esc_attr(v));
        attrs.push('"');
    }
    profile_doc(&attrs)
}

/// The `<amin:profile>` document for a host/path pair (the `proxydump` shape:
/// decisions depend only on the route match, not method/scheme/peer).
fn request_doc_parts(host: &str, path: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let attrs = format!(
        " amin:host=\"{}\" amin:path=\"{}\"",
        esc_attr(host),
        esc_attr(path)
    );
    profile_doc(&attrs)
}

fn profile_doc(attrs: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <amin:profile xmlns:amin=\"{AMIN_NS}\">\n  <amin:request{attrs} />\n</amin:profile>\n"
    )
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Map an Amin status rc to an HTTP status (≈ Perl `_rc_to_http`): a negative
/// rc is a deny, the throttle region (-7xxx) sheds as 429, routing (-6xxx) as
/// 503, the authorization region as 403.
pub(crate) fn rc_to_http(rc: Option<i32>) -> u16 {
    match rc {
        None => 503,
        Some(rc) if rc == RC_RATE_LIMITED => 429,
        Some(rc) if rc <= -6100 => 503,
        Some(rc) if rc < 0 => 403,
        Some(_) => 500,
    }
}

/// The reason phrase for a status code this front emits.
pub(crate) fn reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// Normalise one element's attributes to `LocalName => Value` (≈ `_surface`).
fn surface(atts: &dyn Attributes) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for i in 0..atts.length() {
        let local = atts.local_name(i);
        let name = if local.is_empty() {
            atts.q_name(i)
        } else {
            local
        };
        if !name.is_empty() {
            out.insert(name.to_string(), atts.value(i).to_string());
        }
    }
    out
}

/// Serialise one captured `<proxy:backend>` decision in canonical form:
/// attributes sorted by local name, `amin:`-namespaced, self-closed.
fn backend_line(attrs: &BTreeMap<String, String>) -> String {
    let mut out = String::from("<proxy:backend");
    for (k, v) in attrs {
        out.push_str(" amin:");
        out.push_str(k);
        out.push_str("=\"");
        out.push_str(&crate::xml_escape(v));
        out.push('"');
    }
    out.push_str("/>");
    out
}

/// Push an `amin:`-namespaced attribute (every decision attribute shares the
/// one attribute namespace, proxy-plan §4.3).
fn push_amin(list: &mut AttributeList, local: &str, value: &str) {
    list.push(Attribute {
        prefix: "amin".to_string(),
        local_name: local.to_string(),
        namespace_uri: AMIN_NS.to_string(),
        q_name: format!("amin:{local}"),
        value: value.to_string(),
    });
}

fn emit_start(
    handler: &Option<Node>,
    uri: &str,
    prefix: &str,
    local: &str,
    atts: &AttributeList,
) {
    if let Some(h) = handler {
        let q = format!("{prefix}:{local}");
        let _ = h.borrow_mut().start_element(uri, local, &q, atts);
    }
}

fn emit_end(handler: &Option<Node>, uri: &str, prefix: &str, local: &str) {
    if let Some(h) = handler {
        let q = format!("{prefix}:{local}");
        let _ = h.borrow_mut().end_element(uri, local, &q);
    }
}

/// Escape an attribute value for a double-quoted value in the request document
/// (≈ Perl `_esc`, including `'`).
fn esc_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

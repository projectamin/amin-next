//! # amin-proxy — the L7 reverse-proxy vocabulary (Rust side, P0)
//!
//! This crate is the Rust half of the proxy's **vocabulary + routing** phase
//! (proxy-plan §4/§5). It parses the same `<amin:proxy>` profile the Perl
//! `Amin::Proxy::Config` does, compiles it into a frozen matcher, and emits the
//! **same** `<proxy:backend>` decision elements — byte for byte — so the two
//! language streams stay in step (the project's Perl↔Rust parity rule).
//!
//! It owns no sockets: P0 is the decision vocabulary, not the listener. The
//! listener/TLS contract (P1) and the transport adapters (P2/P3) build on this.
//!
//! The parser is [`amin_sax`], a push-based reader, not a DOM — the profile
//! never becomes a tree on either side.
//!
//! ```
//! use amin_proxy::ProxyConfig;
//! let xml = r#"<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
//!     <amin:backend amin:id="shop-a" amin:transport="http" amin:addr="10.0.0.1:80"/>
//!     <amin:route amin:host="shop.example" amin:path="/cart" amin:to="shop-a"/>
//!   </amin:proxy>"#;
//! let cfg = ProxyConfig::parse_xml(xml).unwrap().compile().unwrap();
//! let lines = amin_proxy::filters::decisions(&cfg, "shop.example", "/cart/1");
//! assert!(lines[0].starts_with("<proxy:backend "));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;

use amin_sax::{Attributes, ContentHandler, SaxError};
use serde::{Deserialize, Serialize};

pub mod backend;
mod fingerprint;
pub mod filters;
pub mod http;
mod h2;
pub mod listener;
mod tls;

/// Core Amin namespace (the `amin:` prefix).
pub const AMIN_NS: &str = "http://projectamin.org/ns/2026/";
/// Proxy decision namespace (the `proxy:` prefix, proxy-plan §4.3).
pub const PROXY_NS: &str = "http://projectamin.org/ns/proxy/1";
/// Status rc emitted for an unmatched request — closed-world default-deny.
pub const RC_NO_ROUTE: i32 = -6150;
/// Load-balancing policy a route inherits when it declares none.
pub const DEFAULT_POLICY: &str = "p2c_ewma";

/// A backend the proxy can hand a request to (proxy-plan §4.1).
///
/// Exactly one of `peer` (mesh identity) or `addr` (host:port literal) is set;
/// [`ProxyConfig::compile`] rejects anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backend {
    /// Route-local id, referenced by `Route::to`.
    pub id: String,
    /// Transport selector: `awp3` or `http`.
    pub transport: String,
    /// Mesh peer identity (`peer=`), when this backend is a mesh member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Literal `host:port` (`addr=`), when this backend is not a mesh member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    /// Health-check selector, carried but not interpreted at P0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hc: Option<String>,
}

impl Backend {
    /// The selector the decision element carries: `("peer", …)` when set,
    /// otherwise `("addr", …)`.
    #[must_use]
    pub fn endpoint(&self) -> (&'static str, &str) {
        match (self.peer.as_deref(), self.addr.as_deref()) {
            (Some(p), _) => ("peer", p),
            (None, Some(a)) => ("addr", a),
            (None, None) => ("addr", ""),
        }
    }
}

/// One routing rule (proxy-plan §4.1). `host` is matched by shape
/// (`*`, `*.suffix`, exact); `path` is a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Host pattern (lower-cased at match time).
    pub host: String,
    /// Path prefix; empty matches every path.
    pub path: String,
    /// Backend ids, in declared order, all sharing one transport.
    pub to: Vec<String>,
    /// Load-balancing policy (`p2c_ewma` when unspecified).
    pub policy: String,
    /// Strip `path` before forwarding.
    pub strip_prefix: bool,
    /// Allow RFC 6455 websocket upgrade on this route.
    pub ws: bool,
    /// Warm Amin provider spec (a path or an addressed `bitcache://` ref).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
}

/// A per-IP rate limit (proxy-plan §P5): a token bucket sized `burst` and
/// refilled at `rps` tokens per second. `rps == 0.0` never refills, so a client
/// IP gets exactly `burst` requests for the front's lifetime.
#[derive(Debug, Clone, PartialEq)]
pub struct RateLimit {
    /// Tokens refilled per second.
    pub rps: f64,
    /// Bucket size — the most a single IP may burst.
    pub burst: u64,
    /// Canonical `rps=<raw>;burst=<raw>` (key-order-normalised), the value the
    /// fingerprint hashes so `rps=10;burst=20` and `burst=20;rps=10` are one
    /// profile. Byte-identical to the Perl `rate_limit->{spec}`.
    pub spec: String,
}

/// The parsed `<amin:proxy>` declaration (proxy-plan §4.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Listener binding, carried for the adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// TLS mode selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// TLS certificate path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// TLS key path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Connection cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_conns: Option<String>,
    /// Idle read timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_timeout: Option<String>,
    /// Per-IP rate-limit declaration (`amin:rate-limit`), parsed at compile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<String>,
    /// Backend table, in document order.
    #[serde(default)]
    pub backends: Vec<Backend>,
    /// Route table, in document order (compiled order is most-specific-first).
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// A configuration error. Every variant is fatal and closed: a bad profile
/// never yields a partially-runnable matcher.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The document was not well-formed XML.
    #[error("proxy config: not valid XML: {0}")]
    Xml(String),
    /// An element was not in the Amin namespace.
    #[error("proxy config: foreign namespace '{0}' on <{1}>")]
    ForeignNamespace(String, String),
    /// An element outside the closed proxy vocabulary appeared.
    #[error("proxy config: unknown element <amin:{0}>")]
    UnknownElement(String),
    /// A `<backend>` had no id.
    #[error("proxy backend: missing id")]
    BackendMissingId,
    /// Two `<backend>` entries shared an id.
    #[error("proxy backend '{0}': duplicate id")]
    DuplicateBackend(String),
    /// A `<backend>` had both or neither of `peer`/`addr`.
    #[error("proxy backend '{0}': exactly one of peer/addr required")]
    BackendPeerOrAddr(String),
    /// A `<backend>` had no transport.
    #[error("proxy backend '{0}': missing transport")]
    BackendMissingTransport(String),
    /// A `<backend>` named a transport other than `awp3`/`http`.
    #[error("proxy backend '{0}': unknown transport '{1}'")]
    BackendTransport(String, String),
    /// No routes were declared.
    #[error("proxy config: no routes declared")]
    NoRoutes,
    /// A `<route>` had no host.
    #[error("proxy route: missing host")]
    RouteMissingHost,
    /// A `<route>` had no `to=`.
    #[error("proxy route (host {0}): missing to")]
    RouteMissingTo(String),
    /// A `<route>`'s `to=` was empty after splitting.
    #[error("proxy route (host {0}): empty to")]
    RouteEmptyTo(String),
    /// A `<route>` referenced a backend id that is not declared.
    #[error("proxy route (host {0}): unknown backend '{1}'")]
    RouteUnknownBackend(String, String),
    /// A `<route>`'s backends did not share one transport.
    #[error("proxy route (host {0}): mixed transports in to='{1}'")]
    RouteMixedTransport(String, String),
    /// A boolean attribute was not on/off/true/false/yes/no/1/0.
    #[error("proxy config: {0} must be on/off, got '{1}'")]
    BadBool(&'static str, String),
    /// A `rate-limit=` value that could not be parsed.
    #[error("proxy config: rate-limit: {0}")]
    BadRateLimit(String),
}

/// A compiled, frozen matcher. Built once at boot; the request path never
/// parses or sorts again (proxy-plan §5.3).
#[derive(Debug, Clone)]
pub struct Compiled {
    /// The config source (path or ref), for logging. Not part of the
    /// fingerprint — the profile's content, not its location, is hashed.
    pub source: String,
    /// Listener binding (`amin:listen`), part of the fingerprint.
    pub listen: Option<String>,
    /// TLS mode (`amin:tls`), part of the fingerprint.
    pub tls: Option<String>,
    /// TLS certificate path (`amin:cert`), part of the fingerprint.
    pub cert: Option<String>,
    /// TLS key path (`amin:key`), part of the fingerprint.
    pub key: Option<String>,
    /// Connection cap (`amin:max-conns`), part of the fingerprint.
    pub max_conns: Option<String>,
    /// Idle read timeout (`amin:read-timeout`), part of the fingerprint.
    pub read_timeout: Option<String>,
    /// Per-IP rate limit, part of the fingerprint, enforced by the front.
    pub rate_limit: Option<RateLimit>,
    /// Backend table, keyed by id.
    pub backends: BTreeMap<String, Backend>,
    /// Routes, most-specific-first.
    pub routes: Vec<Route>,
}

impl ProxyConfig {
    /// Parse a `<amin:proxy>` document. Closed vocabulary: an unknown element
    /// is an error, never a silent no-op.
    pub fn parse_xml(xml: &str) -> Result<Self, ConfigError> {
        let mut collector = Collector::default();
        amin_sax::parse(xml, &mut collector).map_err(|e| ConfigError::Xml(e.to_string()))?;
        match collector.err {
            Some(e) => Err(e),
            None => Ok(collector.cfg),
        }
    }

    /// Validate and freeze into a [`Compiled`] matcher.
    pub fn compile(&self) -> Result<Compiled, ConfigError> {
        let mut backends: BTreeMap<String, Backend> = BTreeMap::new();
        for b in &self.backends {
            if b.id.is_empty() {
                return Err(ConfigError::BackendMissingId);
            }
            if backends.contains_key(&b.id) {
                return Err(ConfigError::DuplicateBackend(b.id.clone()));
            }
            let has_peer = b.peer.as_deref().is_some_and(|s| !s.is_empty());
            let has_addr = b.addr.as_deref().is_some_and(|s| !s.is_empty());
            if has_peer == has_addr {
                return Err(ConfigError::BackendPeerOrAddr(b.id.clone()));
            }
            if b.transport.is_empty() {
                return Err(ConfigError::BackendMissingTransport(b.id.clone()));
            }
            if b.transport != "awp3" && b.transport != "http" {
                return Err(ConfigError::BackendTransport(b.id.clone(), b.transport.clone()));
            }
            backends.insert(b.id.clone(), b.clone());
        }

        if self.routes.is_empty() {
            return Err(ConfigError::NoRoutes);
        }

        // Keep the declaration index so the tie-break is stable and explicit.
        let mut indexed: Vec<(usize, Route)> = Vec::with_capacity(self.routes.len());
        for (idx, r) in self.routes.iter().enumerate() {
            if r.host.is_empty() {
                return Err(ConfigError::RouteMissingHost);
            }
            if r.to.is_empty() {
                return Err(ConfigError::RouteMissingTo(r.host.clone()));
            }
            let mut ids: Vec<&str> = r
                .to
                .iter()
                .map(String::as_str)
                .filter(|s| !s.trim().is_empty())
                .collect();
            if ids.is_empty() {
                return Err(ConfigError::RouteEmptyTo(r.host.clone()));
            }
            let mut transports = std::collections::BTreeSet::new();
            for id in &ids {
                let b = backends
                    .get(*id)
                    .ok_or_else(|| ConfigError::RouteUnknownBackend(r.host.clone(), (*id).to_string()))?;
                transports.insert(b.transport.clone());
            }
            if transports.len() > 1 {
                return Err(ConfigError::RouteMixedTransport(r.host.clone(), r.to.join(",")));
            }
            ids.clear();

            let host = r.host.to_ascii_lowercase();
            let policy = if r.policy.trim().is_empty() {
                DEFAULT_POLICY.to_string()
            } else {
                r.policy.clone()
            };
            indexed.push((
                idx,
                Route {
                    host,
                    path: r.path.clone(),
                    to: r.to.clone(),
                    policy,
                    strip_prefix: r.strip_prefix,
                    ws: r.ws,
                    spec: r.spec.clone(),
                },
            ));
        }

        indexed.sort_by(|(ai, a), (bi, b)| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then(host_rank(&b.host).cmp(&host_rank(&a.host)))
                .then(ai.cmp(bi))
        });

        let rate_limit = parse_rate_limit(self.rate_limit.as_deref())?;

        Ok(Compiled {
            source: String::new(),
            listen: self.listen.clone(),
            tls: self.tls.clone(),
            cert: self.cert.clone(),
            key: self.key.clone(),
            max_conns: self.max_conns.clone(),
            read_timeout: self.read_timeout.clone(),
            rate_limit,
            backends,
            routes: indexed.into_iter().map(|(_, r)| r).collect(),
        })
    }
}

impl Compiled {
    /// Attach a config source label for logging.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// The canonical byte serialisation of this compiled profile — the digest
    /// input the Perl and Rust fronts share (proxy-plan §7). See
    /// [`fingerprint`](crate::fingerprint).
    #[must_use]
    pub fn canonical(&self) -> String {
        fingerprint::canonical(self)
    }

    /// The `X-Amin-Profile-SHA3` value: SHA3-256 of [`Compiled::canonical`],
    /// lowercase hex, so a response can be traced to the profile that served it
    /// (proxy-plan §P5).
    #[must_use]
    pub fn profile_sha3(&self) -> String {
        fingerprint::sha3_256(self)
    }

    /// First route whose host shape and path prefix accept the request, or
    /// `None` — closed-world, an unmatched request is denied, never defaulted.
    ///
    /// The matcher the [`filters`] chain reads (proxy-plan §5.5); the decision
    /// itself is produced by the chain, never here.
    #[must_use]
    pub fn match_route(&self, host: &str, path: &str) -> Option<&Route> {
        let host = host.to_ascii_lowercase();
        let path = if path.is_empty() { "/" } else { path };
        self.routes
            .iter()
            .find(|r| host_ok(r, &host) && path_ok(r, path))
    }
}

/// Element-local rank for route ordering: any(0) < suffix(1) < exact(2).
fn host_rank(host: &str) -> u8 {
    if host == "*" {
        0
    } else if host.starts_with("*.") {
        1
    } else {
        2
    }
}

fn host_ok(route: &Route, host: &str) -> bool {
    match host_rank(&route.host) {
        0 => true,
        1 => {
            let suffix = &route.host[2..];
            host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
        }
        _ => host == route.host,
    }
}

fn path_ok(route: &Route, path: &str) -> bool {
    route.path.is_empty() || path.starts_with(&route.path)
}

/// Escape the five XML specials for a double-quoted attribute value.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// SAX collector for the closed `<amin:proxy>` vocabulary (proxy-plan §4.1).
#[derive(Default)]
struct Collector {
    cfg: ProxyConfig,
    err: Option<ConfigError>,
}

impl Collector {
    fn fail(&mut self, e: ConfigError) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }
}

impl ContentHandler for Collector {
    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        _q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        if !uri.is_empty() && uri != AMIN_NS {
            self.fail(ConfigError::ForeignNamespace(
                uri.to_string(),
                local_name.to_string(),
            ));
            return Ok(());
        }
        match local_name {
            "proxy" => {
                self.cfg.listen = atts.value_of_local("listen").map(str::to_string);
                self.cfg.tls = atts.value_of_local("tls").map(str::to_string);
                self.cfg.cert = atts.value_of_local("cert").map(str::to_string);
                self.cfg.key = atts.value_of_local("key").map(str::to_string);
                self.cfg.max_conns = atts.value_of_local("max-conns").map(str::to_string);
                self.cfg.read_timeout = atts.value_of_local("read-timeout").map(str::to_string);
                self.cfg.rate_limit = atts
                    .value_of_local("rate-limit")
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
            }
            "backend" => match backend(atts) {
                Ok(b) => self.cfg.backends.push(b),
                Err(e) => self.fail(e),
            },
            "route" => match route(atts) {
                Ok(r) => self.cfg.routes.push(r),
                Err(e) => self.fail(e),
            },
            other => self.fail(ConfigError::UnknownElement(other.to_string())),
        }
        Ok(())
    }

    fn end_element(&mut self, _uri: &str, _local_name: &str, _q_name: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

fn backend(atts: &dyn Attributes) -> Result<Backend, ConfigError> {
    Ok(Backend {
        id: atts.value_of_local("id").unwrap_or_default().to_string(),
        transport: atts.value_of_local("transport").unwrap_or_default().to_string(),
        peer: atts.value_of_local("peer").map(str::to_string),
        addr: atts.value_of_local("addr").map(str::to_string),
        hc: atts.value_of_local("hc").map(str::to_string),
    })
}

fn route(atts: &dyn Attributes) -> Result<Route, ConfigError> {
    let to = match atts.value_of_local("to") {
        Some(s) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    };
    Ok(Route {
        host: atts.value_of_local("host").unwrap_or_default().to_string(),
        path: atts.value_of_local("path").unwrap_or_default().to_string(),
        to,
        policy: atts.value_of_local("policy").unwrap_or_default().to_string(),
        strip_prefix: parse_bool(atts.value_of_local("strip-prefix"), "strip-prefix")?,
        ws: parse_bool(atts.value_of_local("ws"), "ws")?,
        spec: atts.value_of_local("spec").map(str::to_string),
    })
}

fn parse_bool(v: Option<&str>, what: &'static str) -> Result<bool, ConfigError> {
    let Some(v) = v else { return Ok(false) };
    if v.is_empty() {
        return Ok(false);
    }
    let lc = v.to_ascii_lowercase();
    match lc.as_str() {
        "1" | "on" | "true" | "yes" => Ok(true),
        "0" | "off" | "false" | "no" => Ok(false),
        _ => Err(ConfigError::BadBool(what, v.to_string())),
    }
}

/// Parse `rate-limit="rps=<num>;burst=<int>"` (proxy-plan §P5). Mirror of the
/// Perl `_rate_limit`: both keys are required, `burst >= 1`, `rps >= 0`, and the
/// canonical `spec` is key-order-normalised so either spelling of the same
/// limit hashes identically (§7).
fn parse_rate_limit(v: Option<&str>) -> Result<Option<RateLimit>, ConfigError> {
    let Some(v) = v else { return Ok(None) };
    if v.is_empty() {
        return Ok(None);
    }
    let (mut rps, mut burst) = (None::<String>, None::<String>);
    for part in v.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, val) = part
            .split_once('=')
            .ok_or_else(|| ConfigError::BadRateLimit(format!("bad term '{part}'")))?;
        let (k, val) = (k.trim(), val.trim());
        let slot = match k {
            "rps" => &mut rps,
            "burst" => &mut burst,
            _ => return Err(ConfigError::BadRateLimit(format!("bad term '{part}'"))),
        };
        if slot.is_some() {
            return Err(ConfigError::BadRateLimit(format!("duplicate '{k}'")));
        }
        *slot = Some(val.to_string());
    }
    let rps = rps.ok_or_else(|| ConfigError::BadRateLimit("rps required".to_string()))?;
    let burst = burst.ok_or_else(|| ConfigError::BadRateLimit("burst required".to_string()))?;
    if !is_decimal(&rps) {
        return Err(ConfigError::BadRateLimit(format!(
            "rps must be a number >= 0, got '{rps}'"
        )));
    }
    if !burst.bytes().all(|c| c.is_ascii_digit()) || burst.is_empty() {
        return Err(ConfigError::BadRateLimit(format!(
            "burst must be an integer >= 1, got '{burst}'"
        )));
    }
    let n: u64 = burst
        .parse()
        .map_err(|_| ConfigError::BadRateLimit(format!("burst must be an integer >= 1, got '{burst}'")))?;
    if n < 1 {
        return Err(ConfigError::BadRateLimit(format!(
            "burst must be an integer >= 1, got '{burst}'"
        )));
    }
    Ok(Some(RateLimit {
        rps: rps.parse().unwrap_or(0.0),
        burst: n,
        spec: format!("rps={rps};burst={burst}"),
    }))
}

/// Whether `s` is a non-negative decimal literal `\d+(\.\d+)?` — the shape both
/// fronts accept for `rps`, so neither rounds a value the other rejects.
fn is_decimal(s: &str) -> bool {
    let (int, frac) = match s.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    !int.is_empty()
        && int.bytes().all(|c| c.is_ascii_digit())
        && frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/"
            amin:listen=":443" amin:tls="on">
  <amin:backend amin:id="shop-a" amin:transport="awp3" amin:peer="shop-a.mesh"
                amin:hc="tcp"/>
  <amin:backend amin:id="shop-b" amin:transport="awp3" amin:peer="shop-b.mesh"/>
  <amin:backend amin:id="legacy"  amin:transport="http" amin:addr="10.0.0.20:80"/>
  <amin:route amin:host="shop.example" amin:path="/cart" amin:to="shop-a,shop-b"
              amin:policy="p2c_ewma"/>
  <amin:route amin:host="*.shop.example" amin:path="/" amin:to="shop-a"/>
  <amin:route amin:host="*" amin:path="/" amin:to="legacy" amin:strip-prefix="on"/>
</amin:proxy>"#;

    fn compiled() -> Compiled {
        ProxyConfig::parse_xml(SAMPLE).unwrap().compile().unwrap()
    }

    #[test]
    fn parses_proxy_attributes() {
        let c = ProxyConfig::parse_xml(SAMPLE).unwrap();
        assert_eq!(c.listen.as_deref(), Some(":443"));
        assert_eq!(c.tls.as_deref(), Some("on"));
        assert_eq!(c.backends.len(), 3);
        assert_eq!(c.routes.len(), 3);
    }

    #[test]
    fn longest_path_wins() {
        let c = compiled();
        let r = c.match_route("shop.example", "/cart/1").unwrap();
        assert_eq!(r.path, "/cart");
        assert_eq!(r.to, vec!["shop-a", "shop-b"]);
    }

    #[test]
    fn suffix_matches_before_wildcard() {
        let c = compiled();
        let r = c.match_route("api.shop.example", "/x").unwrap();
        assert_eq!(r.host, "*.shop.example");
    }

    #[test]
    fn wildcard_is_last_resort() {
        let c = compiled();
        let r = c.match_route("other.example", "/").unwrap();
        assert_eq!(r.host, "*");
        assert_eq!(r.to, vec!["legacy"]);
    }

    #[test]
    fn emits_one_backend_per_candidate_sorted_attrs() {
        let c = compiled();
        let lines = filters::decisions(&c, "shop.example", "/cart");
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            r#"<proxy:backend amin:id="shop-a" amin:peer="shop-a.mesh" amin:policy="p2c_ewma" amin:strip-prefix="false" amin:transport="awp3" amin:ws="off"/>"#
        );
        assert_eq!(
            lines[1],
            r#"<proxy:backend amin:id="shop-b" amin:peer="shop-b.mesh" amin:policy="p2c_ewma" amin:strip-prefix="false" amin:transport="awp3" amin:ws="off"/>"#
        );
    }

    #[test]
    fn addr_backend_and_strip_prefix() {
        let c = compiled();
        let lines = filters::decisions(&c, "nope.example", "/");
        assert_eq!(
            lines[0],
            r#"<proxy:backend amin:addr="10.0.0.20:80" amin:id="legacy" amin:policy="p2c_ewma" amin:strip-prefix="true" amin:transport="http" amin:ws="off"/>"#
        );
    }

    #[test]
    fn closed_world_no_default_route() {
        // No route matches a path that is not under any prefix on an exact host
        // that does not accept it — but '*' catches everything, so use a config
        // without the catch-all.
        let xml = r#"<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
            <amin:backend amin:id="a" amin:transport="http" amin:addr="1.1.1.1:1"/>
            <amin:route amin:host="only.example" amin:path="/x" amin:to="a"/>
        </amin:proxy>"#;
        let c = ProxyConfig::parse_xml(xml).unwrap().compile().unwrap();
        assert!(c.match_route("other.example", "/x").is_none());
        assert!(filters::decisions(&c, "other.example", "/x").is_empty());
    }

    #[test]
    fn profile_sha3_is_stable_lowercase_hex() {
        let a = compiled().profile_sha3();
        assert_eq!(a, compiled().profile_sha3(), "same profile → same digest");
        assert_eq!(a.len(), 64, "SHA3-256 → 32 bytes → 64 hex chars");
        assert!(
            a.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "lowercase hex only, got {a}"
        );
    }

    #[test]
    fn profile_sha3_ignores_source_but_tracks_content() {
        let base = compiled();
        let labelled = base.clone().with_source("/etc/amin/proxy.xml");
        assert_eq!(
            base.profile_sha3(),
            labelled.profile_sha3(),
            "the source path is not part of the profile's identity"
        );

        let mut changed = compiled();
        changed.routes[0].path.push_str("/v2");
        assert_ne!(
            base.profile_sha3(),
            changed.profile_sha3(),
            "a routing change must move the digest"
        );
    }

    #[test]
    fn canonical_form_is_unambiguous() {
        // `name <byte-len> <value>\n` — a value with a space cannot collide
        // with a following field, because the length delimits it.
        assert_eq!(compiled().canonical().lines().next(), Some("amin-proxy-profile/1"));
        let c = compiled();
        let canon = c.canonical();
        assert!(canon.contains("backend-count 3\n"), "backends counted: {canon}");
        assert!(canon.ends_with("route-spec 0 \n"), "last route field terminated: {canon}");
    }

    #[test]
    fn rate_limit_parses_and_normalises_key_order() {
        let rl = parse_rate_limit(Some("rps=10;burst=20")).unwrap().unwrap();
        assert_eq!(
            rl,
            RateLimit { rps: 10.0, burst: 20, spec: "rps=10;burst=20".to_string() }
        );
        // The spec is key-order-normalised, so either spelling is one profile.
        let flipped = parse_rate_limit(Some("burst=20; rps=10")).unwrap().unwrap();
        assert_eq!(flipped.spec, rl.spec);
        assert_eq!(flipped.rps, rl.rps);
        assert_eq!(flipped.burst, rl.burst);
    }

    #[test]
    fn rate_limit_absent_is_none() {
        assert_eq!(parse_rate_limit(None).unwrap(), None);
        assert_eq!(parse_rate_limit(Some("")).unwrap(), None);
    }

    #[test]
    fn rate_limit_rejects_bad_shapes() {
        assert_eq!(
            parse_rate_limit(Some("burst=20")).unwrap_err(),
            ConfigError::BadRateLimit("rps required".to_string())
        );
        assert_eq!(
            parse_rate_limit(Some("rps=1")).unwrap_err(),
            ConfigError::BadRateLimit("burst required".to_string())
        );
        assert_eq!(
            parse_rate_limit(Some("rps=1;burst=0")).unwrap_err(),
            ConfigError::BadRateLimit("burst must be an integer >= 1, got '0'".to_string())
        );
        assert_eq!(
            parse_rate_limit(Some("rps=-1;burst=1")).unwrap_err(),
            ConfigError::BadRateLimit("rps must be a number >= 0, got '-1'".to_string())
        );
        assert_eq!(
            parse_rate_limit(Some("rps=1;rps=2;burst=1")).unwrap_err(),
            ConfigError::BadRateLimit("duplicate 'rps'".to_string())
        );
        assert_eq!(
            parse_rate_limit(Some("rps=1;burst=1;junk=9")).unwrap_err(),
            ConfigError::BadRateLimit("bad term 'junk=9'".to_string())
        );
    }

    #[test]
    fn rate_limit_zero_means_no_refill() {
        let rl = parse_rate_limit(Some("rps=0;burst=3")).unwrap().unwrap();
        assert_eq!(rl.rps, 0.0);
        assert_eq!(rl.burst, 3);
    }

    #[test]
    fn rate_limit_is_part_of_the_fingerprint() {
        let xml = |rl: &str| {
            format!(
                r#"<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/" amin:rate-limit="{rl}">
                   <amin:backend amin:id="a" amin:transport="http" amin:addr="1.1.1.1:1"/>
                   <amin:route amin:host="h" amin:path="/" amin:to="a"/>
                 </amin:proxy>"#
            )
        };
        let a = ProxyConfig::parse_xml(&xml("rps=0;burst=5")).unwrap().compile().unwrap();
        let b = ProxyConfig::parse_xml(&xml("burst=5;rps=0")).unwrap().compile().unwrap();
        let c = ProxyConfig::parse_xml(&xml("rps=0;burst=6")).unwrap().compile().unwrap();
        assert_eq!(a.profile_sha3(), b.profile_sha3(), "key order is not identity");
        assert_ne!(a.profile_sha3(), c.profile_sha3(), "a limit change moves the digest");
    }

    #[test]
    fn unknown_element_is_an_error() {
        let xml = r#"<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
            <amin:frontend amin:id="x"/>
        </amin:proxy>"#;
        assert_eq!(
            ProxyConfig::parse_xml(xml).unwrap_err(),
            ConfigError::UnknownElement("frontend".to_string())
        );
    }

    #[test]
    fn duplicate_backend_id_rejected() {
        let xml = r#"<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
            <amin:backend amin:id="a" amin:transport="http" amin:addr="1.1.1.1:1"/>
            <amin:backend amin:id="a" amin:transport="http" amin:addr="1.1.1.1:2"/>
            <amin:route amin:host="h" amin:path="/" amin:to="a"/>
        </amin:proxy>"#;
        assert_eq!(
            ProxyConfig::parse_xml(xml).unwrap().compile().unwrap_err(),
            ConfigError::DuplicateBackend("a".to_string())
        );
    }

    #[test]
    fn peer_and_addr_are_mutually_exclusive() {
        let xml = r#"<amin:proxy xmlns:amin="http://projectamin.org/ns/2026/">
            <amin:backend amin:id="a" amin:transport="http" amin:addr="1.1.1.1:1" amin:peer="p"/>
            <amin:route amin:host="h" amin:path="/" amin:to="a"/>
        </amin:proxy>"#;
        assert_eq!(
            ProxyConfig::parse_xml(xml).unwrap().compile().unwrap_err(),
            ConfigError::BackendPeerOrAddr("a".to_string())
        );
    }

    #[test]
    fn sax_reads_namespaces_and_entities() {
        let xml = r#"<r xmlns:a="urn:a" xmlns="urn:d"><a:x k="a&amp;b">t&lt;u</a:x></r>"#;
        #[derive(Default)]
        struct Cap {
            seen: Vec<(String, String, String)>,
            text: String,
        }
        impl ContentHandler for Cap {
            fn start_element(
                &mut self,
                uri: &str,
                local_name: &str,
                q_name: &str,
                atts: &dyn Attributes,
            ) -> Result<(), SaxError> {
                self.seen
                    .push((q_name.to_string(), local_name.to_string(), uri.to_string()));
                if let Some(v) = atts.value_of_local("k") {
                    self.text.push_str(&format!("|k={v}"));
                }
                Ok(())
            }
            fn end_element(
                &mut self,
                _uri: &str,
                _local_name: &str,
                _q_name: &str,
            ) -> Result<(), SaxError> {
                Ok(())
            }
            fn characters(&mut self, t: &str) -> Result<(), SaxError> {
                self.text.push_str(t);
                Ok(())
            }
        }
        let mut cap = Cap::default();
        amin_sax::parse(xml, &mut cap).unwrap();
        assert_eq!(cap.seen[0], ("r".into(), "r".into(), "urn:d".into()));
        assert_eq!(cap.seen[1], ("a:x".into(), "x".into(), "urn:a".into()));
        assert_eq!(cap.text, "|k=a&bt<u");
    }

    #[test]
    fn sax_rejects_mismatched_end_tag() {
        let mut sink = NullHandler;
        assert!(matches!(
            amin_sax::parse("<a><b></a></b>", &mut sink),
            Err(SaxError::Parse { kind: amin_sax::ParseError::MismatchedEnd { .. }, .. })
        ));
    }

    #[test]
    fn sax_rejects_unbound_prefix() {
        let mut sink = NullHandler;
        assert!(matches!(
            amin_sax::parse("<z:a/>", &mut sink),
            Err(SaxError::Parse { kind: amin_sax::ParseError::UnboundPrefix(p), .. }) if p == "z"
        ));
    }

    #[test]
    fn sax_reports_position_in_error() {
        let mut sink = NullHandler;
        match amin_sax::parse("<a>\n  <b></c>", &mut sink) {
            Err(SaxError::Parse { line, column, .. }) => {
                assert_eq!(line, 2);
                assert!(column > 1);
            }
            other => panic!("expected a positioned parse error, got {other:?}"),
        }
    }

    struct NullHandler;
    impl ContentHandler for NullHandler {
        fn start_element(
            &mut self,
            _uri: &str,
            _local_name: &str,
            _q_name: &str,
            _atts: &dyn Attributes,
        ) -> Result<(), SaxError> {
            Ok(())
        }
        fn end_element(
            &mut self,
            _uri: &str,
            _local_name: &str,
            _q_name: &str,
        ) -> Result<(), SaxError> {
            Ok(())
        }
    }
}

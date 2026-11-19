//! Minimal, streaming HTTP/1.1 for the Rust proxy front (proxy-plan §3/§5).
//!
//! This is the Rust half's mirror of `Amin::Proxy::HTTP`'s request parse and
//! head serialisation: a parser and a serialiser, not a framework.  Its whole
//! job is that a request arriving at the Rust listener produces the *same*
//! upstream head as the Perl listener would (proxy-plan §7), so it reproduces
//! the Perl rules exactly — header order and case, host extraction, path/query
//! split, hop-by-hop stripping, and the `X-Forwarded-*` fold.  No body is ever
//! buffered: only the head is held, and the body streams through untouched.

/// Hop-by-hop headers (RFC 9110 §7.6.1) — properties of the connection, not
/// the message.  `Transfer-Encoding` is deliberately absent: the body's framing
/// is forwarded verbatim, and de-chunking would require buffering the whole
/// body (proxy-plan §9).
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Whether `name` (matched case-insensitively) is hop-by-hop.
#[must_use]
pub fn is_hop_by_hop(name: &str) -> bool {
    let lc = name.to_ascii_lowercase();
    HOP_BY_HOP.contains(&lc.as_str())
}

/// A parsed request head — request line plus headers, no body.
#[derive(Debug, Clone)]
pub struct Request {
    /// Request method (`GET`, `POST`, …).
    pub method: String,
    /// Raw request target as received (`/path?query`).
    pub target: String,
    /// Target path, before the first `?`.
    pub path: String,
    /// Target query, after the first `?`, when the target carried one.
    pub query: Option<String>,
    /// HTTP version token (`HTTP/1.1`).
    pub version: String,
    /// Headers in arrival order, original name case preserved.
    pub headers: Vec<(String, String)>,
    /// Lower-cased hostname with any port and IPv6 brackets stripped.
    pub host: String,
    /// `http` or `https` (TLS termination, §5.5).
    pub scheme: &'static str,
    /// Peer address of the client.
    pub peer: String,
}

impl Request {
    /// The value of the first header named `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The value of the last header named `name`, matching Perl's last-wins
    /// header table used for the websocket-upgrade test.
    #[must_use]
    pub fn header_last(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The body framing a request declares.
#[derive(Debug)]
pub enum Body {
    /// No body.
    None,
    /// A `Content-Length`-delimited body of the given size.
    Length(u64),
    /// A `Transfer-Encoding: chunked` body; the detector only recognises the
    /// terminator, the body itself is never held.
    Chunked(Chunked),
}

/// The declared body plan for a set of request headers (proxy-plan §5.7).
#[must_use]
pub fn body_plan(headers: &[(String, String)]) -> Body {
    let te = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .map_or("", |(_, v)| v.as_str());
    if te.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked")) {
        return Body::Chunked(Chunked::new());
    }
    if let Some((_, cl)) = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
    {
        if let Ok(n) = cl.parse::<u64>() {
            return Body::Length(n);
        }
    }
    Body::None
}

/// Recognises the terminating zero-length chunk of a chunked body without
/// holding it.  Mirrors `Amin::Proxy::HTTP::Chunked`.
#[derive(Debug)]
pub struct Chunked {
    buf: Vec<u8>,
    left: usize,
    phase: u8,
    done: bool,
}

impl Chunked {
    fn new() -> Self {
        Self { buf: Vec::new(), left: 0, phase: 0, done: false }
    }

    /// Feed the next slice; returns `true` once the terminator is seen.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        self.buf.extend_from_slice(bytes);
        while !self.done {
            if self.phase == 0 {
                let Some(i) = find(&self.buf, b"\r\n") else { return false };
                let line: Vec<u8> = self.buf.drain(..i).collect();
                self.buf.drain(..2);
                let hex: String = String::from_utf8_lossy(&line)
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect();
                match usize::from_str_radix(&hex, 16) {
                    Ok(0) | Err(_) => {
                        self.done = true;
                        return true;
                    }
                    Ok(n) => {
                        self.left = n;
                        self.phase = 1;
                    }
                }
            } else {
                if self.buf.len() < self.left + 2 {
                    return false;
                }
                self.buf.drain(..self.left + 2);
                self.left = 0;
                self.phase = 0;
            }
        }
        true
    }
}

/// Parse a request head (the bytes through the blank line) into a [`Request`].
///
/// Returns `None` for a malformed head — a missing request line, a non-HTTP
/// version, or a header line without a colon — so the caller can answer `400`.
#[must_use]
pub fn parse_request_head(head: &str, scheme: &'static str, peer: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let rl = lines.next()?;
    let mut parts = rl.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    if parts.next().is_some() || !is_http_version(&version) {
        return None;
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let i = line.find(':')?;
        if i == 0 {
            return None;
        }
        let name = line[..i].to_string();
        let value = line[i + 1..].trim_start_matches([' ', '\t']).to_string();
        headers.push((name, value));
    }

    // Host: the last `Host:` wins, the first comma-separated authority is the
    // one that counts, and the port/brackets are stripped (RFC 9110 §7.2).
    let mut host_val = String::new();
    for (n, v) in &headers {
        if n.eq_ignore_ascii_case("host") {
            host_val.clone_from(v);
        }
    }
    let authority = host_val.split(',').next().unwrap_or("").trim();
    let host = host_name(authority);

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.clone(), None),
    };

    Some(Request {
        method,
        target,
        path,
        query,
        version,
        headers,
        host,
        scheme,
        peer: peer.to_string(),
    })
}

/// Build the upstream request head: origin-form target, the backend authority
/// as `Host`, hop-by-hop headers dropped, `X-Forwarded-*` appended.  The
/// caller's authority material (Authorization, cookies, …) is carried
/// untouched (proxy-plan §5.12).
#[must_use]
pub fn upstream_head(
    req: &Request,
    backend_addr: &str,
    route_path: &str,
    strip_prefix: bool,
    ws: bool,
) -> String {
    let mut target = req.path.clone();
    if strip_prefix && !route_path.is_empty() && target.starts_with(route_path) {
        target = target[route_path.len()..].to_string();
        if !target.starts_with('/') {
            target.insert(0, '/');
        }
    }
    if let Some(q) = &req.query {
        if !q.is_empty() {
            target.push('?');
            target.push_str(q);
        }
    }

    // An upgrade is a CONNECT-like promotion: Connection/Upgrade are hop-by-hop
    // in general, but here they ARE the mechanism, so Upgrade must survive when
    // the route allows ws and the client asked to upgrade (proxy-plan §5.8).
    let upgrade = ws
        && req.header_last("upgrade").is_some()
        && req
            .header_last("connection")
            .is_some_and(|c| has_token(c, "upgrade"));

    let mut out: Vec<String> = Vec::new();
    out.push(format!("{} {} HTTP/1.1", req.method, target));
    // Host is the backend authority: the client's own Host is *replaced*, not
    // duplicated (RFC 9110 §7.2 — exactly one).
    out.push(format!("Host: {backend_addr}"));

    let mut prior_xff: Vec<String> = Vec::new();
    for (n, v) in &req.headers {
        let ln = n.to_ascii_lowercase();
        if ln == "host" {
            continue;
        }
        if is_hop_by_hop(&ln) && !(upgrade && ln == "upgrade") {
            continue;
        }
        if ln == "x-forwarded-for" {
            prior_xff.push(v.clone());
            continue;
        }
        if ln == "x-forwarded-proto" || ln == "x-forwarded-host" {
            continue;
        }
        out.push(format!("{n}: {v}"));
    }
    prior_xff.retain(|s| !s.is_empty());
    prior_xff.push(req.peer.clone());
    out.push(format!("X-Forwarded-For: {}", prior_xff.join(", ")));
    out.push(format!("X-Forwarded-Proto: {}", req.scheme));
    out.push(format!("X-Forwarded-Host: {}", req.host));
    out.push(format!("Connection: {}", if upgrade { "Upgrade" } else { "close" }));

    let mut s = out.join("\r\n");
    s.push_str("\r\n\r\n");
    s
}

/// Build the downstream response head: hop-by-hop headers dropped, the profile
/// fingerprint stamped, the front pinning `Connection: close` (proxy-plan
/// §5.8/§P5).
#[must_use]
pub fn downstream_head(
    code: u16,
    reason: &str,
    headers: &[(String, String)],
    profile_sha3: &str,
) -> String {
    let mut out: Vec<String> = Vec::with_capacity(headers.len() + 3);
    out.push(format!("HTTP/1.1 {code} {reason}"));
    for (n, v) in headers {
        if is_hop_by_hop(n) {
            continue;
        }
        out.push(format!("{n}: {v}"));
    }
    out.push(format!("X-Amin-Profile-SHA3: {profile_sha3}"));
    out.push("Connection: close".to_string());
    let mut s = out.join("\r\n");
    s.push_str("\r\n\r\n");
    s
}

/// An upstream status line: `(code, reason, headers)`.
pub type StatusHead = (u16, String, Vec<(String, String)>);

/// Parse an upstream status line + headers.
#[must_use]
pub fn parse_status_head(head: &str) -> Option<StatusHead> {
    let mut lines = head.split("\r\n");
    let sl = lines.next()?;
    let rest = sl.strip_prefix("HTTP/")?;
    let (_, sl) = rest.split_once([' ', '\t'])?;
    let (code, reason) = sl.split_once([' ', '\t']).unwrap_or((sl, ""));
    let code: u16 = code.trim().parse().ok()?;
    if code < 100 {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        if let Some((n, v)) = line.split_once(':') {
            headers.push((n.to_string(), v.trim_start_matches([' ', '\t']).to_string()));
        }
    }
    Some((code, reason.to_string(), headers))
}

/// `HTTP/` followed by `digit.digit`.
fn is_http_version(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("HTTP/") else { return false };
    let b = rest.as_bytes();
    b.len() == 3 && b[0].is_ascii_digit() && b[1] == b'.' && b[2].is_ascii_digit()
}

/// Whether a comma/space-separated header value carries `token` (a `\b`-style
/// token match, as `Amin::Proxy::HTTP` uses for `Connection: upgrade`).
fn has_token(value: &str, token: &str) -> bool {
    value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| t.eq_ignore_ascii_case(token))
}

/// Strip the port and IPv6 brackets from a host authority.  Shared with the
/// HTTP/2 driver, whose routing host arrives in the `:authority` pseudo-header
/// rather than a `Host:` line (proxy-plan §5.6).
#[must_use]
pub(crate) fn host_name(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) => rest[..end].to_string(),
            None => authority.to_string(),
        };
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h.to_string(),
        _ => authority.to_string(),
    }
}

/// First index of `needle` in `hay`.
#[must_use]
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &str = "GET /echo?x=1 HTTP/1.1\r\nHost: only.example\r\nX-Custom: keep-me";

    fn req() -> Request {
        parse_request_head(REQ, "http", "127.0.0.1").unwrap()
    }

    #[test]
    fn parses_request_line_and_headers_in_order() {
        let r = req();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/echo?x=1");
        assert_eq!(r.path, "/echo");
        assert_eq!(r.query.as_deref(), Some("x=1"));
        assert_eq!(r.version, "HTTP/1.1");
        assert_eq!(r.host, "only.example");
        assert_eq!(r.headers[0], ("Host".to_string(), "only.example".to_string()));
        assert_eq!(r.headers[1].0, "X-Custom");
    }

    #[test]
    fn strips_host_port_and_brackets() {
        assert_eq!(host_name("only.example:8080"), "only.example");
        assert_eq!(host_name("[::1]:8443"), "::1");
        assert_eq!(host_name("only.example"), "only.example");
        assert_eq!(host_name("only.example:abc"), "only.example:abc");
    }

    #[test]
    fn upstream_head_drops_hop_by_hop_and_appends_xff() {
        let head = "GET /echo?x=1 HTTP/1.1\r\n\
                    Host: only.example\r\n\
                    X-Custom: keep-me\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    Connection: keep-alive";
        let r = parse_request_head(head, "http", "127.0.0.1").unwrap();
        let out = upstream_head(&r, "10.0.0.20:80", "", false, false);
        assert!(out.starts_with("GET /echo?x=1 HTTP/1.1\r\nHost: 10.0.0.20:80\r\n"));
        assert!(out.contains("\r\nX-Custom: keep-me\r\n"));
        assert!(out.contains("\r\nX-Forwarded-For: 127.0.0.1\r\n"));
        assert!(out.contains("\r\nX-Forwarded-Proto: http\r\n"));
        assert!(out.contains("\r\nX-Forwarded-Host: only.example\r\n"));
        assert!(out.contains("\r\nConnection: close\r\n"));
        assert!(!out.contains("Proxy-Connection"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn upstream_head_strips_prefix_and_folds_prior_xff() {
        let head = "GET /api/v1?y=2 HTTP/1.1\r\nHost: only.example\r\nX-Forwarded-For: 10.0.0.9";
        let r = parse_request_head(head, "http", "127.0.0.1").unwrap();
        let out = upstream_head(&r, "10.0.0.20:80", "/api/", true, false);
        assert!(out.starts_with("GET /v1?y=2 HTTP/1.1\r\n"));
        assert!(out.contains("\r\nX-Forwarded-For: 10.0.0.9, 127.0.0.1\r\n"));
    }

    #[test]
    fn upstream_head_promotes_upgrade_on_a_ws_route() {
        let head = "GET /ws HTTP/1.1\r\nHost: only.example\r\nUpgrade: websocket\r\nConnection: Upgrade";
        let r = parse_request_head(head, "http", "127.0.0.1").unwrap();
        let out = upstream_head(&r, "10.0.0.20:80", "", false, true);
        assert!(out.contains("\r\nUpgrade: websocket\r\n"));
        assert!(out.ends_with("\r\nConnection: Upgrade\r\n\r\n"));
    }

    #[test]
    fn body_plan_reads_length_and_chunked() {
        assert!(matches!(body_plan(&[]), Body::None));
        assert!(matches!(
            body_plan(&[("Content-Length".into(), "42".into())]),
            Body::Length(42)
        ));
        let mut c = match body_plan(&[("Transfer-Encoding".into(), "chunked".into())]) {
            Body::Chunked(c) => c,
            other => panic!("expected chunked, got {other:?}"),
        };
        assert!(!c.feed(b"5\r\nhello\r\n"));
        assert!(c.feed(b"0\r\n\r\n"));
    }

    #[test]
    fn malformed_heads_are_rejected() {
        assert!(parse_request_head("GET /\r\n", "http", "p").is_none());
        assert!(parse_request_head("GET / XHTTP/1.1\r\n", "http", "p").is_none());
        assert!(parse_request_head("GET / HTTP/1.1\r\nnocolon\r\n", "http", "p").is_none());
    }

    #[test]
    fn parses_status_head() {
        let (code, reason, h) = parse_status_head("HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5\r\n").unwrap();
        assert_eq!(code, 200);
        assert_eq!(reason, "OK");
        assert_eq!(h[0], ("Keep-Alive".to_string(), "timeout=5".to_string()));
    }

    #[test]
    fn downstream_head_drops_hop_by_hop() {
        let head = downstream_head(
            200,
            "OK",
            &[("Keep-Alive".to_string(), "timeout=5".to_string())],
            "abc123",
        );
        assert!(!head.contains("Keep-Alive"));
        assert!(head.contains("\r\nX-Amin-Profile-SHA3: abc123\r\n"));
        assert!(head.ends_with("\r\nConnection: close\r\n\r\n"));
    }
}

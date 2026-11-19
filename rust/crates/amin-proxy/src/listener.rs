//! The tokio listener: accept, parse, decide, hop, stream (proxy-plan §5.4).
//!
//! One [`Front`] owns the compiled matcher and the backend pool; each accepted
//! connection is handled on its own task.  Per request it runs the same
//! sequence as the Perl front — parse the head, match a route, pick a backend,
//! open the hop, pump both directions — so the two produce byte-identical
//! upstream heads (proxy-plan §7).  The front is authority-free: it parses the
//! request, it never mints, widens, or decides authority (§5.12).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use amin_machine::{Machine, MachineSpec};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::backend::Pool;
use crate::filters::{self, Decision};
use crate::http::{self, Body, Request};

/// Default cap on a request or response head, in bytes.
const MAX_HEAD: usize = 64 * 1024;

/// One client IP's token bucket.
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-IP token-bucket limiter (proxy-plan §P5).  A bucket holds at most
/// `burst` tokens and refills at `rps` tokens/second; a request costs one
/// token.  `rps == 0.0` never refills, so a client IP gets exactly `burst`
/// requests for the front's lifetime.  The algorithm is the peer of the Perl
/// `Amin::Proxy::RateLimit` filter, so `rps=0` sheds the same request on both
/// fronts (§7).
pub struct RateLimiter {
    rps: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    fn new(rl: &crate::RateLimit) -> Self {
        Self {
            rps: rl.rps,
            burst: rl.burst as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `ip`, or deny.  Mirrors the Perl `_rate_allow`.
    pub fn allow(&self, ip: &str, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let b = buckets
            .entry(ip.to_string())
            .or_insert_with(|| Bucket { tokens: self.burst, last: now });
        let dt = now.saturating_duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens += dt * self.rps;
        if b.tokens > self.burst {
            b.tokens = self.burst;
        }
        if b.tokens < 1.0 {
            return false;
        }
        b.tokens -= 1.0;
        true
    }
}

/// Shared, immutable per-process state.
pub struct Front {
    /// The frozen matcher, reused verbatim from P0.
    pub compiled: Arc<crate::Compiled>,
    /// The machine the filter chain is composed from (the shared
    /// `machine_spec.xml`) — `amin-proxy` is `amin` with the proxy filters.
    pub machine: Machine,
    /// Backend runtime state and the balancer.
    pub pool: Pool,
    /// Scheme label (`http`; TLS termination sets `https`).
    pub scheme: &'static str,
    /// Maximum head size accepted, in bytes.
    pub max_head: usize,
    /// The `X-Amin-Profile-SHA3` value stamped on proxied responses, computed
    /// once from the frozen profile (proxy-plan §P5).
    pub profile_sha3: String,
    /// Per-IP rate limiter, when the profile declares `amin:rate-limit` (§P5).
    pub rate: Option<Arc<RateLimiter>>,
    /// TLS acceptor, when the profile terminates TLS (§5.5).
    tls: Option<TlsAcceptor>,
}

impl Front {
    /// Build a front from a compiled profile.
    #[must_use]
    pub fn new(compiled: crate::Compiled) -> Self {
        let compiled = Arc::new(compiled);
        let profile_sha3 = compiled.profile_sha3();
        let rate = compiled
            .rate_limit
            .as_ref()
            .map(|rl| Arc::new(RateLimiter::new(rl)));
        Self {
            pool: Pool::new(&compiled),
            machine: Machine::new(MachineSpec::new().spec()),
            compiled,
            scheme: "http",
            max_head: MAX_HEAD,
            profile_sha3,
            rate,
            tls: None,
        }
    }

    /// Build a front that terminates TLS from PEM `cert`/`key` files
    /// (proxy-plan §5.5).  ALPN advertises `h2` then `http/1.1`.
    ///
    /// # Errors
    /// The cert/key cannot be read or do not form a usable pair.
    pub fn with_tls_files(compiled: crate::Compiled, cert: &str, key: &str) -> io::Result<Self> {
        let cfg = crate::tls::server_config(Path::new(cert), Path::new(key))?;
        let compiled = Arc::new(compiled);
        let profile_sha3 = compiled.profile_sha3();
        let rate = compiled
            .rate_limit
            .as_ref()
            .map(|rl| Arc::new(RateLimiter::new(rl)));
        Ok(Self {
            pool: Pool::new(&compiled),
            machine: Machine::new(MachineSpec::new().spec()),
            compiled,
            scheme: "https",
            max_head: MAX_HEAD,
            profile_sha3,
            rate,
            tls: Some(TlsAcceptor::from(cfg)),
        })
    }

    /// Bind and serve until the listener errors.  Each connection is handled
    /// on a spawned task; with TLS configured, the handshake runs first and the
    /// negotiated ALPN protocol decides the driver.
    pub async fn serve(self: Arc<Self>, listen: &str) -> io::Result<()> {
        let listener = TcpListener::bind(listen).await?;
        loop {
            let (sock, peer) = listener.accept().await?;
            let front = Arc::clone(&self);
            tokio::spawn(async move {
                let r = match front.tls.clone() {
                    Some(acceptor) => front.accept_tls(acceptor, sock, peer).await,
                    None => front.handle(sock, peer).await,
                };
                if let Err(e) = r {
                    eprintln!("amin-proxyd: connection from {peer}: {e}");
                }
            });
        }
    }

    /// Complete the TLS handshake, then dispatch on the negotiated ALPN
    /// protocol: `h2` to the H2 driver, anything else to the HTTP/1.1 path.
    async fn accept_tls(
        &self,
        acceptor: TlsAcceptor,
        sock: TcpStream,
        peer: SocketAddr,
    ) -> io::Result<()> {
        let tls = match acceptor.accept(sock).await {
            Ok(t) => t,
            Err(e) => {
                // A failed handshake is the client's, not ours; drop it quietly.
                eprintln!("amin-proxyd: tls handshake from {peer}: {e}");
                return Ok(());
            }
        };
        if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
            return crate::h2::serve(self, tls, peer).await;
        }
        self.serve_h1(tls, peer).await
    }

    /// Read one request head, then dispatch it.  A plaintext socket that opens
    /// with the HTTP/2 connection preface is handed to the H2 driver instead
    /// (RFC 9113 §3.4); a TLS socket has already been steered by ALPN.
    async fn handle(&self, sock: TcpStream, peer: SocketAddr) -> io::Result<()> {
        if opens_with_h2_preface(&sock).await {
            return crate::h2::serve(self, sock, peer).await;
        }
        self.serve_h1(sock, peer).await
    }

    /// The HTTP/1.1 path: parse one head, then dispatch.  Generic over the
    /// socket so a plain TCP stream and a TLS stream share it.
    async fn serve_h1<S>(&self, mut sock: S, peer: SocketAddr) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        loop {
            if let Some(i) = http::find(&buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).into_owned();
                let rest = buf[i + 4..].to_vec();
                return self.dispatch(sock, peer, &head, rest).await;
            }
            if buf.len() > self.max_head {
                return reject(sock, 431, "Request Header Fields Too Large").await;
            }
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Route the parsed request and stream it to the picked backend.
    async fn dispatch<S>(
        &self,
        mut sock: S,
        peer: SocketAddr,
        head: &str,
        rest: Vec<u8>,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let peer_s = peer.ip().to_string();
        let Some(req) = http::parse_request_head(head, self.scheme, &peer_s) else {
            return reject(sock, 400, "Bad Request").await;
        };

        // Run the one chain (proxy-plan §5.1): `Proxy::RateLimit` sheds an
        // over-budget request before routing (§P5), `Proxy::Route` emits the
        // candidate `<proxy:backend>` decisions.  The front is a pump — it
        // maps the chain's decision to a status or a hop, nothing more.
        let (ids, route_path, strip_prefix, ws) =
            match filters::decide(&self.machine, &self.compiled, self.rate.clone(), &req) {
                Decision::Deny { code } => {
                    return reject(sock, code, filters::reason(code)).await;
                }
                Decision::Route {
                    ids,
                    route_path,
                    strip_prefix,
                    ws,
                } => (ids, route_path, strip_prefix, ws),
            };
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let Some(picked) = self.pool.pick(&id_refs) else {
            return reject(sock, 503, "Service Unavailable").await;
        };
        let Some(backend) = self.compiled.backends.get(&picked) else {
            return reject(sock, 503, "Service Unavailable").await;
        };

        if backend.transport != "http" {
            // awp3 is the mesh transport (§6); a silent HTTP fallback would be a
            // lie about the trust boundary, so an unspokable transport is a 502.
            return reject(sock, 502, "Bad Gateway").await;
        }
        let Some(addr) = backend.addr.as_deref().filter(|a| !a.is_empty()) else {
            return reject(sock, 502, "Bad Gateway").await;
        };

        let Ok(mut up) = TcpStream::connect(addr).await else {
            self.pool.fail(&picked);
            return reject(sock, 502, "Bad Gateway").await;
        };
        self.pool.begin(&picked);
        let started = Instant::now();

        let head_out = http::upstream_head(&req, addr, &route_path, strip_prefix, ws);
        up.write_all(head_out.as_bytes()).await?;
        forward_body(&mut sock, &mut up, &req, rest).await?;
        relay(&mut up, &mut sock, &self.profile_sha3).await?;
        self.pool.done(&picked, Some(started.elapsed().as_secs_f64()));
        Ok(())
    }
}

/// Stream the client body to the backend as it arrives, accounting only for
/// framing — the bytes are never held (proxy-plan §5.7).
async fn forward_body<S>(
    sock: &mut S,
    up: &mut TcpStream,
    req: &Request,
    rest: Vec<u8>,
) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    match http::body_plan(&req.headers) {
        Body::None => Ok(()),
        Body::Length(n) => {
            let mut left = n;
            let mut pending = rest;
            loop {
                if !pending.is_empty() {
                    let take = usize::try_from(left.min(pending.len() as u64)).unwrap_or(0);
                    up.write_all(&pending[..take]).await?;
                    left -= take as u64;
                    pending.drain(..take);
                }
                if left == 0 {
                    return Ok(());
                }
                if pending.is_empty() {
                    let mut chunk = [0u8; 16384];
                    let r = sock.read(&mut chunk).await?;
                    if r == 0 {
                        return Ok(());
                    }
                    pending.extend_from_slice(&chunk[..r]);
                }
            }
        }
        Body::Chunked(mut det) => {
            let mut pending = rest;
            loop {
                if pending.is_empty() {
                    let mut chunk = [0u8; 16384];
                    let r = sock.read(&mut chunk).await?;
                    if r == 0 {
                        return Ok(());
                    }
                    pending.extend_from_slice(&chunk[..r]);
                }
                up.write_all(&pending).await?;
                let done = det.feed(&pending);
                pending.clear();
                if done {
                    return Ok(());
                }
            }
        }
    }
}

/// Read the upstream response and stream it to the client unchanged but for
/// hop-by-hop stripping on the head and the `X-Amin-Profile-SHA3` stamp, then
/// close (proxy-plan §5.8/§P5).
async fn relay<S>(up: &mut TcpStream, client: &mut S, profile_sha3: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        if let Some(i) = http::find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).into_owned();
            match http::parse_status_head(&head) {
                Some((code, reason, hl)) => {
                    client
                        .write_all(http::downstream_head(code, &reason, &hl, profile_sha3).as_bytes())
                        .await?;
                }
                None => {
                    return reject_head(client, 502, "Bad Gateway").await;
                }
            }
            let rest = buf[i + 4..].to_vec();
            if !rest.is_empty() {
                client.write_all(&rest).await?;
            }
            let mut chunk = [0u8; 16384];
            loop {
                let n = up.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&chunk[..n]).await?;
            }
            return Ok(());
        }
        if buf.len() > MAX_HEAD {
            return Ok(());
        }
        let mut chunk = [0u8; 4096];
        let n = up.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Whether the socket's first bytes are the HTTP/2 connection preface — i.e.
/// the client speaks H2 with prior knowledge on a plain connection (RFC 9113
/// §3.4).  Peeking (never consuming) lets the H2 driver read the preface
/// itself.  Bytes that stop matching the preface at any point mean HTTP/1.1.
async fn opens_with_h2_preface(sock: &TcpStream) -> bool {
    let mut buf = [0u8; 24];
    let mut have = 0;
    loop {
        match sock.peek(&mut buf[have..]).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                have += n;
                if buf[..have] != crate::h2::PREFACE[..have] {
                    return false;
                }
                if have == buf.len() {
                    return true;
                }
            }
        }
    }
}

/// Write a fixed error response head, then close.
async fn reject<S>(mut sock: S, code: u16, reason: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    reject_head(&mut sock, code, reason).await?;
    sock.shutdown().await
}

/// Write a fixed error response head on an already-owned stream.
async fn reject_head<S>(sock: &mut S, code: u16, reason: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = format!("{code} {reason}\n");
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limit(rps: f64, burst: u64) -> crate::RateLimit {
        crate::RateLimit { rps, burst, spec: format!("rps={rps};burst={burst}") }
    }

    #[test]
    fn rps_zero_grants_exactly_burst_then_denies() {
        let lim = RateLimiter::new(&limit(0.0, 3));
        let t = Instant::now();
        assert!(lim.allow("10.0.0.1", t));
        assert!(lim.allow("10.0.0.1", t));
        assert!(lim.allow("10.0.0.1", t));
        assert!(!lim.allow("10.0.0.1", t), "the fourth request is over the burst");
        // Even much later, `rps=0` never refills.
        assert!(!lim.allow("10.0.0.1", t + Duration::from_secs(60)));
        // A different IP has its own budget; buckets are per-IP.
        assert!(lim.allow("10.0.0.2", t));
    }

    #[test]
    fn refill_restores_tokens_over_time() {
        let lim = RateLimiter::new(&limit(1.0, 1));
        let t = Instant::now();
        assert!(lim.allow("10.0.0.1", t));
        assert!(!lim.allow("10.0.0.1", t), "empty until refilled");
        assert!(lim.allow("10.0.0.1", t + Duration::from_secs(1)), "one token refilled");
    }
}


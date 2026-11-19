//! amin-axa — the Rust AXA origin server (proxy-plan §8, P4).
//!
//! The Rust parity peer of `bin/amin axa serve`: it loads the same app bundle,
//! frames and routes the same requests, and renders the same pages as the Perl
//! adapter ([`amin_axa::adaptor::Service`], [`amin_axa::render`]).  The two
//! produce byte-identical pages (proxy-plan §7).
//!
//! ```text
//!   amin-axa --app DIR [--listen ADDR]
//! ```
//!
//! The listener speaks HTTP/1.1 one request per connection and closes.  It
//! parses the head, reads the body under the same 256 KiB cap the adapter
//! enforces, and hands the parsed [`Request`] to the service.
//!
//! Exit codes: 0 OK | 1 runtime error | 2 usage/app I/O | 3 app load error.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use amin_axa::adaptor::{body_cap, Request, Service};
use amin_axa::{App, Page};

/// Cap on a request head, in bytes.
const MAX_HEAD: usize = 64 * 1024;

#[derive(Parser)]
#[command(name = "amin-axa", version, about = "Amin 3 AXA origin server (Rust peer)")]
struct Cli {
    /// Path to an app bundle directory (holding `axa.xml`).
    #[arg(long)]
    app: String,
    /// Listen address (`host:port`).
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let app = match App::load(&cli.app) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("amin-axa: load {}: {e}", cli.app);
            return ExitCode::from(3);
        }
    };
    let listen = cli.listen.unwrap_or_else(|| "127.0.0.1:8787".to_string());
    let service = Arc::new(Service::new(app));

    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("amin-axa: bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("amin-axa: serving {} on {listen}", cli.app);
    loop {
        match listener.accept().await {
            Ok((sock, peer)) => {
                let service = Arc::clone(&service);
                tokio::spawn(async move {
                    if let Err(e) = handle(sock, service).await {
                        eprintln!("amin-axa: connection from {peer}: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("amin-axa: accept: {e}");
                return ExitCode::from(1);
            }
        }
    }
}

/// Read one request, dispatch it, write one response, close.
async fn handle(mut sock: TcpStream, service: Arc<Service>) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).into_owned();
            let rest = buf[i + 4..].to_vec();
            return dispatch(sock, &service, &head, rest).await;
        }
        if buf.len() > MAX_HEAD {
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

/// Parse the head, read the body under the cap, hand the request to the
/// adapter, and write the response.
async fn dispatch(
    mut sock: TcpStream,
    service: &Service,
    head: &str,
    rest: Vec<u8>,
) -> std::io::Result<()> {
    let Some((method, target, headers)) = parse_head(head) else {
        return reject(sock, 400, "Bad Request").await;
    };
    let (path, query) = split_target(&target);

    let method = method.to_ascii_uppercase();
    let te = header(&headers, "transfer-encoding").unwrap_or("");
    let chunked = te
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("chunked"));
    let (body, too_large) = if chunked {
        read_chunked(&mut sock, rest).await?
    } else if let Some(cl) = header(&headers, "content-length").and_then(parse_len) {
        if cl > body_cap() {
            (Vec::new(), true)
        } else {
            read_exact_n(&mut sock, rest, cl).await?
        }
    } else {
        (Vec::new(), false)
    };

    let req = Request {
        method,
        path,
        query,
        content_type: header(&headers, "content-type").map(str::to_string),
        origin: header(&headers, "origin").map(str::to_string),
        host: header(&headers, "host").map(str::to_string),
        cookie: header(&headers, "cookie").map(str::to_string),
        body,
        body_too_large: too_large,
    };
    let head_only = req.method == "HEAD";
    let page = service.handle(&req);
    write_page(sock, &page, head_only).await
}

/// Read `n` body bytes starting from `have`, reading more as needed.
async fn read_exact_n(
    sock: &mut TcpStream,
    mut have: Vec<u8>,
    n: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    while have.len() < n {
        let mut chunk = [0u8; 16384];
        let r = sock.read(&mut chunk).await?;
        if r == 0 {
            break;
        }
        have.extend_from_slice(&chunk[..r]);
    }
    have.truncate(n);
    Ok((have, false))
}

/// De-chunk a body, stopping at the cap on decoded size (≈ `_read_chunked`).
async fn read_chunked(
    sock: &mut TcpStream,
    mut buf: Vec<u8>,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let (line, consumed) = loop {
            if let Some(i) = find(&buf, b"\r\n") {
                break (buf[..i].to_vec(), i + 2);
            }
            if !read_more(sock, &mut buf).await? {
                return Ok((body, false));
            }
        };
        let hex: String = String::from_utf8_lossy(&line)
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        let len = match usize::from_str_radix(&hex, 16) {
            Ok(0) | Err(_) => return Ok((body, false)), // terminator or garbage
            Ok(n) => n,
        };
        if body.len() + len > body_cap() {
            return Ok((body, true));
        }
        buf.drain(..consumed);
        while buf.len() < len + 2 {
            if !read_more(sock, &mut buf).await? {
                return Ok((body, false));
            }
        }
        body.extend_from_slice(&buf[..len]);
        buf.drain(..len + 2);
    }
}

/// Read more bytes into `buf`; `false` at EOF.
async fn read_more(sock: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut chunk = [0u8; 16384];
    let n = sock.read(&mut chunk).await?;
    if n == 0 {
        return Ok(false);
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(true)
}

/// A parsed request head: the method, the request target, and the headers in
/// the order they arrived.
type Head = (String, String, Vec<(String, String)>);

/// Split a request head into `(method, target, headers)`.
fn parse_head(head: &str) -> Option<Head> {
    let mut lines = head.split("\r\n");
    let rl = lines.next()?;
    let mut parts = rl.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        let i = line.find(':')?;
        if i == 0 {
            return None;
        }
        headers.push((
            line[..i].to_string(),
            line[i + 1..].trim_start_matches([' ', '\t']).to_string(),
        ));
    }
    Some((method, target, headers))
}

/// Split a request target into `(path, query)`.
fn split_target(target: &str) -> (String, String) {
    match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    }
}

/// The last value of a header, matched case-insensitively.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// A `Content-Length` value as a count.
fn parse_len(v: &str) -> Option<usize> {
    v.trim().parse::<usize>().ok()
}

/// Write a full response, closing the connection.
async fn write_page(mut sock: TcpStream, page: &Page, head_only: bool) -> std::io::Result<()> {
    let body = page.body.as_bytes();
    let mut head = format!("HTTP/1.1 {} {}\r\n", page.status, reason(page.status));
    for (k, v) in &page.headers {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    sock.write_all(head.as_bytes()).await?;
    if !head_only {
        sock.write_all(body).await?;
    }
    sock.flush().await
}

/// Write a bare `text/plain` rejection with a status code.
async fn reject(mut sock: TcpStream, code: u16, text: &str) -> std::io::Result<()> {
    let body = format!("{code} {text}\n");
    let head = format!(
        "HTTP/1.1 {code} {text}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    sock.write_all(body.as_bytes()).await?;
    sock.flush().await
}

/// The reason phrase for a status code.
fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// First index of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

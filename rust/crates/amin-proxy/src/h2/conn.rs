//! The HTTP/2 connection driver (RFC 9113) — the inbound client hop.
//!
//! This is the stateful half of the H2 stack: it reads and writes frames over
//! one socket, keeps the connection's HPACK dynamic table and flow-control
//! windows, and turns each `HEADERS` stream into work the rest of the front
//! already knows how to do.  The backend hop is **unchanged** — the stream's
//! request is decompressed into a [`crate::http::Request`], run through the one
//! chain (the `Proxy::Route`/`Proxy::RateLimit` filters), and sent to the
//! picked backend as HTTP/1.1 exactly as [`crate::listener`] does, so a request
//! over H2 and the same request over H1.1 produce the same upstream head
//! (proxy-plan §7).
//!
//! # Serial by design
//!
//! The driver completes one stream before reading the next stream's frames, and
//! advertises `SETTINGS_MAX_CONCURRENT_STREAMS = 1` so a conformant client does
//! not open a second stream until the first is closed.  That keeps the
//! flow-control state honest with no interleaving to prove, at the cost of one
//! in-flight request per connection; concurrent streams are a later increment.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::frame::{self, FrameType, Header as FrameHead};
use super::hpack;
use crate::filters::{self, Decision};
use crate::http::{self, Request};
use crate::listener::Front;

/// The client preface is 24 octets (RFC 9113 §3.4).
const PREFACE_LEN: usize = 24;
/// Our advertised HPACK dynamic-table size.
const OUR_HEADER_TABLE_SIZE: u32 = 4096;
/// We complete one stream at a time, so we allow exactly one concurrent stream.
const OUR_MAX_CONCURRENT: u32 = 1;
/// Our advertised initial flow-control window (1 MiB) — generous so small
/// uploads need no mid-body `WINDOW_UPDATE` round trip.
const OUR_INITIAL_WINDOW: u32 = 1 << 20;
/// The initial flow-control window before any SETTINGS (RFC 9113 §6.9.2).
const DEFAULT_WINDOW: i64 = 65_535;
/// Cap on a response head buffered from a backend.
const MAX_HEAD: usize = 64 * 1024;

/// A failure that ends the connection (`Conn`) or just the current stream
/// (`Stream`), or a plain I/O error (`Io`).
#[derive(Debug)]
enum Fail {
    /// An I/O error; the caller sees it.
    Io(io::Error),
    /// A connection error: we send `GOAWAY` with this code, then stop.
    Conn(u32),
    /// The current stream is abandoned; the connection continues.
    Stream,
}

impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Self {
        Fail::Io(e)
    }
}

/// `Result` over [`Fail`].
type R<T> = Result<T, Fail>;

/// What [`Conn::next_stream_frame`] surfaced.
enum Incoming {
    /// A stream-bound frame (`DATA`/`HEADERS`/`CONTINUATION`).
    Frame(FrameHead, Vec<u8>),
    /// The client reset our stream.
    Reset,
    /// The connection is going away (`GOAWAY` or EOF).
    End,
}

/// Serve one accepted HTTP/2 connection to completion.
///
/// The socket is generic over [`AsyncRead`] + [`AsyncWrite`] so a plain TCP
/// socket and a TLS-terminated socket are the same driver.
pub(crate) async fn serve<S>(front: &Front, sock: S, peer: SocketAddr) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = Conn::new(front, sock, peer);
    match conn.drive().await {
        Ok(()) | Err(Fail::Stream) => Ok(()),
        Err(Fail::Io(e)) => Err(e),
        Err(Fail::Conn(code)) => {
            let _ = conn.goaway(code).await;
            Ok(())
        }
    }
}

/// Per-connection state: the socket, the HPACK decoder, and the windows.
struct Conn<'a, S> {
    front: &'a Front,
    sock: S,
    peer: String,
    decoder: hpack::Decoder,
    encoder: hpack::Encoder,
    buf: Vec<u8>,
    /// The peer's advertised maximum frame size.
    peer_max_frame: usize,
    /// The peer's advertised initial stream window (applied per stream).
    peer_initial_window: i64,
    /// Connection-level send window (what we may still send on the connection).
    send_window: i64,
    /// The current stream's send window.
    stream_window: i64,
}

impl<'a, S> Conn<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(front: &'a Front, sock: S, peer: SocketAddr) -> Self {
        Self {
            front,
            sock,
            peer: peer.ip().to_string(),
            decoder: hpack::Decoder::new(OUR_HEADER_TABLE_SIZE as usize),
            encoder: hpack::Encoder,
            buf: Vec::with_capacity(16 * 1024),
            peer_max_frame: frame::DEFAULT_MAX_FRAME,
            peer_initial_window: DEFAULT_WINDOW,
            send_window: DEFAULT_WINDOW,
            stream_window: 0,
        }
    }

    /// The connection loop: preface, our SETTINGS, then frames until EOF.
    async fn drive(&mut self) -> R<()> {
        let mut preface = [0u8; PREFACE_LEN];
        self.sock.read_exact(&mut preface).await?;
        if preface.as_slice() != frame::PREFACE {
            return Err(Fail::Conn(frame::ERR_PROTOCOL));
        }

        self.write_settings().await?;
        // Raise the connection-level receive window to match our advertised
        // stream window, so uploads are not throttled by the 64 KiB default.
        let bump = OUR_INITIAL_WINDOW - DEFAULT_WINDOW as u32;
        self.send_frame(FrameType::WindowUpdate, 0, 0, &bump.to_be_bytes()).await?;

        loop {
            let Some((head, payload)) = self.read_frame().await? else {
                return Ok(());
            };
            match head.typ {
                FrameType::Settings => self.on_settings(&head, &payload).await?,
                FrameType::Ping => self.on_ping(&head, &payload).await?,
                FrameType::WindowUpdate => self.on_window_update(&head, &payload)?,
                FrameType::GoAway => return Ok(()),
                FrameType::Headers => self.on_headers(&head, &payload).await?,
                // Stray DATA (no open stream), PRIORITY, RST_STREAM and unknown
                // types are ignored (RFC 9113 §4.1/§5.4.2).
                FrameType::Data
                | FrameType::Priority
                | FrameType::RstStream
                | FrameType::Unknown(_) => {}
                // A PUSH_PROMISE from a client, or a CONTINUATION with no
                // preceding HEADERS, is a protocol error.
                FrameType::PushPromise | FrameType::Continuation => {
                    return Err(Fail::Conn(frame::ERR_PROTOCOL));
                }
            }
        }
    }

    // ── connection-level frames ────────────────────────────────────────────

    /// Our SETTINGS frame (stream 0).
    async fn write_settings(&mut self) -> R<()> {
        let payload = frame::settings_payload(&[
            (frame::SET_HEADER_TABLE_SIZE, OUR_HEADER_TABLE_SIZE),
            (frame::SET_ENABLE_PUSH, 0),
            (frame::SET_MAX_CONCURRENT, OUR_MAX_CONCURRENT),
            (frame::SET_INITIAL_WINDOW, OUR_INITIAL_WINDOW),
            (frame::SET_MAX_FRAME, frame::DEFAULT_MAX_FRAME as u32),
        ]);
        self.send_frame(FrameType::Settings, 0, 0, &payload).await
    }

    /// Apply a peer SETTINGS frame (and ACK it unless it is itself an ACK).
    async fn on_settings(&mut self, head: &FrameHead, payload: &[u8]) -> R<()> {
        if head.stream != 0 {
            return Err(Fail::Conn(frame::ERR_PROTOCOL));
        }
        if head.flags & frame::FLAG_ACK != 0 {
            return Ok(());
        }
        let pairs =
            frame::parse_settings(payload).map_err(|_| Fail::Conn(frame::ERR_FRAME_SIZE))?;
        for (id, value) in pairs {
            match id {
                frame::SET_INITIAL_WINDOW => {
                    let new = i64::from(value);
                    self.stream_window += new - self.peer_initial_window;
                    self.peer_initial_window = new;
                }
                frame::SET_MAX_FRAME => {
                    if !(16_384..=16_777_215).contains(&value) {
                        return Err(Fail::Conn(frame::ERR_PROTOCOL));
                    }
                    self.peer_max_frame = value as usize;
                }
                _ => {}
            }
        }
        self.send_frame(FrameType::Settings, frame::FLAG_ACK, 0, &[]).await
    }

    /// Echo a PING, unless it is itself an ACK.
    async fn on_ping(&mut self, head: &FrameHead, payload: &[u8]) -> R<()> {
        if head.stream != 0 {
            return Err(Fail::Conn(frame::ERR_PROTOCOL));
        }
        if payload.len() != 8 {
            return Err(Fail::Conn(frame::ERR_FRAME_SIZE));
        }
        if head.flags & frame::FLAG_ACK == 0 {
            self.send_frame(FrameType::Ping, frame::FLAG_ACK, 0, payload).await?;
        }
        Ok(())
    }

    /// Grow a send window by a WINDOW_UPDATE increment.
    fn on_window_update(&mut self, head: &FrameHead, payload: &[u8]) -> R<()> {
        if payload.len() != 4 {
            return Err(Fail::Conn(frame::ERR_FRAME_SIZE));
        }
        let inc = i64::from(
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff,
        );
        if inc == 0 {
            return Err(Fail::Conn(frame::ERR_PROTOCOL));
        }
        if head.stream == 0 {
            self.send_window += inc;
        } else {
            self.stream_window += inc;
        }
        Ok(())
    }

    // ── frame I/O ──────────────────────────────────────────────────────────

    /// Read one frame, refilling the socket buffer as needed.  `None` at a
    /// clean EOF or a truncated frame (the peer is gone).
    async fn read_frame(&mut self) -> R<Option<(FrameHead, Vec<u8>)>> {
        while self.buf.len() < frame::HEADER_LEN {
            if !self.fill().await? {
                return Ok(None);
            }
        }
        let head = FrameHead::parse(&self.buf).expect("at least nine octets");
        if head.len as usize > frame::MAX_ALLOWED_FRAME {
            return Err(Fail::Conn(frame::ERR_FRAME_SIZE));
        }
        let total = frame::HEADER_LEN + head.len as usize;
        while self.buf.len() < total {
            if !self.fill().await? {
                return Ok(None);
            }
        }
        self.buf.drain(..frame::HEADER_LEN);
        let payload: Vec<u8> = self.buf.drain(..head.len as usize).collect();
        Ok(Some((head, payload)))
    }

    /// Pull more bytes from the socket; `false` at EOF.
    async fn fill(&mut self) -> R<bool> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.sock.read(&mut chunk).await?;
        if n == 0 {
            return Ok(false);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(true)
    }

    /// Serialise and write one frame.
    async fn send_frame(
        &mut self,
        typ: FrameType,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> R<()> {
        let mut out = Vec::with_capacity(frame::HEADER_LEN + payload.len());
        FrameHead { len: payload.len() as u32, typ, flags, stream }.write(&mut out);
        out.extend_from_slice(payload);
        self.sock.write_all(&out).await?;
        Ok(())
    }

    /// Send a `GOAWAY` naming no processed stream (we hold one stream at a time).
    async fn goaway(&mut self, code: u32) -> R<()> {
        let mut payload = [0u8; 8];
        payload[4..].copy_from_slice(&code.to_be_bytes());
        self.send_frame(FrameType::GoAway, 0, 0, &payload).await
    }

    // ── streams ────────────────────────────────────────────────────────────

    /// Handle a `HEADERS` frame: collect the block, build the request, hop.
    async fn on_headers(&mut self, head: &FrameHead, payload: &[u8]) -> R<()> {
        match self.handle_stream(head, payload).await {
            Ok(()) | Err(Fail::Stream) => Ok(()),
            other => other,
        }
    }

    /// Collect a header block (with CONTINUATIONs), decode it, and run the hop.
    async fn handle_stream(&mut self, head: &FrameHead, payload: &[u8]) -> R<()> {
        let stream = head.stream;
        if stream == 0 {
            return Err(Fail::Conn(frame::ERR_PROTOCOL));
        }
        self.stream_window = self.peer_initial_window;

        let mut block = header_fragment(head.flags, payload)?.to_vec();
        let mut end_headers = head.flags & frame::FLAG_END_HEADERS != 0;
        let end_stream = head.flags & frame::FLAG_END_STREAM != 0;
        while !end_headers {
            let Some((cont, more)) = self.read_frame().await? else {
                return Err(Fail::Conn(frame::ERR_PROTOCOL));
            };
            if cont.typ != FrameType::Continuation || cont.stream != stream {
                return Err(Fail::Conn(frame::ERR_PROTOCOL));
            }
            block.extend_from_slice(&more);
            end_headers = cont.flags & frame::FLAG_END_HEADERS != 0;
        }

        let fields = self
            .decoder
            .decode(&block)
            .map_err(|_| Fail::Conn(frame::ERR_COMPRESSION))?;

        let front = self.front;
        let Some(req) = build_request(&fields, front.scheme, &self.peer) else {
            return self.send_simple(stream, 400).await;
        };
        // Run the one chain (proxy-plan §5.1) — the same chain the H1 path
        // runs, over the same shared buckets, so an H2 and an H1.1 request from
        // one IP share their rate budget and route identically.
        let (ids, route_path, strip_prefix, ws) =
            match filters::decide(&front.machine, &front.compiled, front.rate.clone(), &req) {
                Decision::Deny { code } => {
                    return self.send_simple(stream, code).await;
                }
                Decision::Route {
                    ids,
                    route_path,
                    strip_prefix,
                    ws,
                } => (ids, route_path, strip_prefix, ws),
            };
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let Some(picked) = front.pool.pick(&id_refs) else {
            return self.send_simple(stream, 503).await;
        };
        let Some(backend) = front.compiled.backends.get(&picked) else {
            return self.send_simple(stream, 503).await;
        };
        // awp3 is the mesh transport (§6); an unspokable transport is a 502.
        let addr = if backend.transport == "http" {
            backend.addr.as_deref().filter(|a| !a.is_empty())
        } else {
            None
        };
        let Some(addr) = addr else {
            return self.send_simple(stream, 502).await;
        };
        let addr = addr.to_string();

        let Ok(mut up) = TcpStream::connect(&addr).await else {
            front.pool.fail(&picked);
            return self.send_simple(stream, 502).await;
        };
        front.pool.begin(&picked);
        let started = Instant::now();
        let head_out = http::upstream_head(&req, &addr, &route_path, strip_prefix, ws);
        up.write_all(head_out.as_bytes()).await?;

        let outcome = self.hop(stream, &mut up, &req, end_stream).await;
        front.pool.done(&picked, Some(started.elapsed().as_secs_f64()));
        outcome
    }

    /// Pump one request body then its response over a single stream.
    async fn hop(
        &mut self,
        stream: u32,
        up: &mut TcpStream,
        req: &Request,
        end_stream: bool,
    ) -> R<()> {
        if !end_stream {
            self.forward_body(stream, up).await?;
        }
        self.relay_response(stream, up, req).await
    }

    /// Forward the client's DATA frames to the backend until END_STREAM.
    async fn forward_body(&mut self, stream: u32, up: &mut TcpStream) -> R<()> {
        loop {
            match self.next_stream_frame(stream).await? {
                Incoming::Frame(head, payload) => match head.typ {
                    FrameType::Data if head.stream == stream => {
                        let data = data_fragment(head.flags, &payload)?;
                        if !data.is_empty() {
                            up.write_all(data).await?;
                        }
                        self.replenish(stream, payload.len()).await?;
                        if head.flags & frame::FLAG_END_STREAM != 0 {
                            return Ok(());
                        }
                    }
                    // A second HEADERS mid-stream cannot happen with our
                    // advertised concurrency of one; anything else is a fault.
                    _ => return Err(Fail::Stream),
                },
                Incoming::Reset | Incoming::End => return Err(Fail::Stream),
            }
        }
    }

    /// Read the backend response head, then stream its body back as H2 frames.
    async fn relay_response(
        &mut self,
        stream: u32,
        up: &mut TcpStream,
        req: &Request,
    ) -> R<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        loop {
            if let Some(i) = http::find(&buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).into_owned();
                let rest = buf[i + 4..].to_vec();
                let Some((code, _reason, headers)) = http::parse_status_head(&head) else {
                    return self.send_simple(stream, 502).await;
                };
                return self.stream_body(stream, up, req, code, &headers, rest).await;
            }
            if buf.len() > MAX_HEAD {
                return self.send_simple(stream, 502).await;
            }
            let mut chunk = [0u8; 16 * 1024];
            let n = up.read(&mut chunk).await?;
            if n == 0 {
                return self.send_simple(stream, 502).await;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Emit the response as a HEADERS frame plus DATA frames, de-chunking and
    /// honouring flow control.  The H2 header set drops the connection-specific
    /// headers H1.1 carries (`transfer-encoding`, hop-by-hop) and stamps the
    /// profile fingerprint (`X-Amin-Profile-SHA3`, proxy-plan §P5).
    async fn stream_body(
        &mut self,
        stream: u32,
        up: &mut TcpStream,
        req: &Request,
        code: u16,
        headers: &[(String, String)],
        rest: Vec<u8>,
    ) -> R<()> {
        let mut out: Vec<(String, String)> = Vec::with_capacity(headers.len() + 2);
        out.push((":status".to_string(), code.to_string()));
        for (name, value) in headers {
            let lc = name.to_ascii_lowercase();
            if http::is_hop_by_hop(&lc) || lc == "transfer-encoding" {
                continue;
            }
            out.push((lc, value.clone()));
        }
        // Field names are lowercase in HTTP/2 (RFC 9113 §8.2).
        out.push(("x-amin-profile-sha3".to_string(), self.front.profile_sha3.clone()));

        // A HEAD request, or a 1xx/204/304 response, carries no body.
        let bodyless = req.method.eq_ignore_ascii_case("HEAD")
            || code == 204
            || code == 304
            || (100..200).contains(&code);
        if bodyless {
            return self.send_headers(stream, &out, true).await;
        }

        let chunked = headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("transfer-encoding")
                && v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        });
        let length = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.trim().parse::<u64>().ok());

        self.send_headers(stream, &out, false).await?;
        let mut pending = rest;

        if chunked {
            let mut dechunk = Dechunk::new();
            loop {
                let (decoded, done) = dechunk.push(&pending);
                pending.clear();
                if !decoded.is_empty() {
                    self.send_data(stream, &decoded, false).await?;
                }
                if done {
                    break;
                }
                let mut chunk = [0u8; 16 * 1024];
                let n = up.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                pending.extend_from_slice(&chunk[..n]);
            }
        } else if let Some(mut left) = length {
            while left > 0 {
                if pending.is_empty() {
                    let mut chunk = [0u8; 16 * 1024];
                    let n = up.read(&mut chunk).await?;
                    if n == 0 {
                        break;
                    }
                    pending.extend_from_slice(&chunk[..n]);
                }
                let take = usize::try_from(left.min(pending.len() as u64)).unwrap_or(0);
                self.send_data(stream, &pending[..take], false).await?;
                left -= take as u64;
                pending.drain(..take);
            }
        } else {
            // No declared framing: the body runs to EOF (we pin
            // `Connection: close` upstream, so the backend closes after it).
            if !pending.is_empty() {
                self.send_data(stream, &pending, false).await?;
            }
            loop {
                let mut chunk = [0u8; 16 * 1024];
                let n = up.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                self.send_data(stream, &chunk[..n], false).await?;
            }
        }

        self.send_data(stream, &[], true).await
    }

    // ── sending ────────────────────────────────────────────────────────────

    /// Send a response header block, splitting into CONTINUATIONs if needed.
    async fn send_headers(&mut self, stream: u32, headers: &[(String, String)], end: bool) -> R<()> {
        let block = self.encoder.encode(headers);
        let mut flags = frame::FLAG_END_HEADERS;
        if end {
            flags |= frame::FLAG_END_STREAM;
        }
        let max = self.peer_max_frame.max(1);
        if block.len() <= max {
            return self.send_frame(FrameType::Headers, flags, stream, &block).await;
        }
        let (first, rest) = block.split_at(max);
        self.send_frame(FrameType::Headers, flags & !frame::FLAG_END_HEADERS, stream, first)
            .await?;
        let mut chunks = rest.chunks(max).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let f = if last { frame::FLAG_END_HEADERS } else { 0 };
            self.send_frame(FrameType::Continuation, f, stream, chunk).await?;
        }
        Ok(())
    }

    /// Send `data` as DATA frames, waiting on flow control as needed; a final
    /// empty DATA carries END_STREAM when `end` is set.
    async fn send_data(&mut self, stream: u32, data: &[u8], end: bool) -> R<()> {
        if data.is_empty() {
            if end {
                self.send_frame(FrameType::Data, frame::FLAG_END_STREAM, stream, &[]).await?;
            }
            return Ok(());
        }
        let mut off = 0;
        while off < data.len() {
            self.await_window(stream).await?;
            let allow = (data.len() - off)
                .min(self.peer_max_frame)
                .min(self.send_window as usize)
                .min(self.stream_window as usize);
            let end_here = end && off + allow == data.len();
            let flags = if end_here { frame::FLAG_END_STREAM } else { 0 };
            self.send_frame(FrameType::Data, flags, stream, &data[off..off + allow]).await?;
            off += allow;
            self.send_window -= allow as i64;
            self.stream_window -= allow as i64;
        }
        Ok(())
    }

    /// Block until the stream and connection send windows have room.
    async fn await_window(&mut self, stream: u32) -> R<()> {
        loop {
            if self.send_window > 0 && self.stream_window > 0 {
                return Ok(());
            }
            let Some((head, payload)) = self.read_frame().await? else {
                return Err(Fail::Stream);
            };
            match head.typ {
                FrameType::WindowUpdate => self.on_window_update(&head, &payload)?,
                FrameType::Settings => self.on_settings(&head, &payload).await?,
                FrameType::Ping => self.on_ping(&head, &payload).await?,
                FrameType::GoAway => return Err(Fail::Stream),
                FrameType::RstStream if head.stream == stream => return Err(Fail::Stream),
                FrameType::Data
                | FrameType::Headers
                | FrameType::Continuation
                | FrameType::PushPromise => {
                    return Err(Fail::Conn(frame::ERR_PROTOCOL));
                }
                FrameType::Priority | FrameType::RstStream | FrameType::Unknown(_) => {}
            }
        }
    }

    /// A fixed `status` response with a one-line text body, then close the
    /// stream.  Used for routing/authority refusals and backend faults.
    async fn send_simple(&mut self, stream: u32, status: u16) -> R<()> {
        let body = format!("{status}\n");
        let headers = [
            (":status".to_string(), status.to_string()),
            ("content-type".to_string(), "text/plain; charset=utf-8".to_string()),
            ("content-length".to_string(), body.len().to_string()),
        ];
        self.send_headers(stream, &headers, false).await?;
        self.send_data(stream, body.as_bytes(), true).await
    }

    /// Confirm our receive window by `consumed` octets on stream and connection.
    async fn replenish(&mut self, stream: u32, consumed: usize) -> R<()> {
        if consumed == 0 {
            return Ok(());
        }
        let inc = consumed as u32;
        self.send_frame(FrameType::WindowUpdate, 0, 0, &inc.to_be_bytes()).await?;
        self.send_frame(FrameType::WindowUpdate, 0, stream, &inc.to_be_bytes()).await
    }

    // ── reading stream frames ──────────────────────────────────────────────

    /// Read the next frame, transparently handling connection-level frames
    /// (SETTINGS/WINDOW_UPDATE/PING) and reporting stream-bound ones.
    async fn next_stream_frame(&mut self, stream: u32) -> R<Incoming> {
        loop {
            let Some((head, payload)) = self.read_frame().await? else {
                return Ok(Incoming::End);
            };
            match head.typ {
                FrameType::Settings => self.on_settings(&head, &payload).await?,
                FrameType::Ping => self.on_ping(&head, &payload).await?,
                FrameType::WindowUpdate => self.on_window_update(&head, &payload)?,
                FrameType::GoAway => return Ok(Incoming::End),
                FrameType::RstStream if head.stream == stream => return Ok(Incoming::Reset),
                FrameType::Data | FrameType::Headers | FrameType::Continuation => {
                    return Ok(Incoming::Frame(head, payload));
                }
                // A client must never send PUSH_PROMISE (RFC 9113 §8.4).
                FrameType::PushPromise => return Err(Fail::Conn(frame::ERR_PROTOCOL)),
                FrameType::Priority | FrameType::RstStream | FrameType::Unknown(_) => {}
            }
        }
    }
}

/// Build a [`Request`] from a decoded H2 header list: the `:method`/`:path`/
/// `:authority`/`:scheme` pseudo-headers plus the regular headers verbatim.
/// Returns `None` when the mandatory pseudo-headers are missing.
fn build_request(fields: &[(Vec<u8>, Vec<u8>)], scheme: &'static str, peer: &str) -> Option<Request> {
    let mut method = None;
    let mut target = None;
    let mut authority = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in fields {
        let name = std::str::from_utf8(name).ok()?;
        let value = String::from_utf8_lossy(value).into_owned();
        match name {
            ":method" => method = Some(value),
            ":path" => target = Some(value),
            ":authority" => authority = Some(value),
            ":scheme" => {}
            _ if name.starts_with(':') => {}
            _ => headers.push((name.to_string(), value)),
        }
    }
    let method = method?;
    let target = target?;
    let authority = authority
        .or_else(|| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.clone())
        })
        .unwrap_or_default();
    let host = http::host_name(&authority);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.clone(), None),
    };
    Some(Request {
        method,
        target,
        path,
        query,
        version: "HTTP/2.0".to_string(),
        headers,
        host,
        scheme,
        peer: peer.to_string(),
    })
}

/// The header block fragment of a HEADERS/PUSH_PROMISE payload, after any pad
/// length octet and priority fields (RFC 9113 §6.2).
fn header_fragment(flags: u8, payload: &[u8]) -> Result<&[u8], Fail> {
    let mut p = payload;
    if flags & frame::FLAG_PADDED != 0 {
        let pad = usize::from(*p.first().ok_or(Fail::Conn(frame::ERR_PROTOCOL))?);
        p = &p[1..];
        if pad > p.len() {
            return Err(Fail::Conn(frame::ERR_PROTOCOL));
        }
        p = &p[..p.len() - pad];
    }
    if flags & frame::FLAG_PRIORITY != 0 {
        if p.len() < 5 {
            return Err(Fail::Conn(frame::ERR_PROTOCOL));
        }
        p = &p[5..];
    }
    Ok(p)
}

/// The data of a DATA frame, after any trailing padding (RFC 9113 §6.1).
fn data_fragment(flags: u8, payload: &[u8]) -> Result<&[u8], Fail> {
    if flags & frame::FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let pad = usize::from(*payload.first().ok_or(Fail::Conn(frame::ERR_PROTOCOL))?);
    let body = &payload[1..];
    if pad > body.len() {
        return Err(Fail::Conn(frame::ERR_PROTOCOL));
    }
    Ok(&body[..body.len() - pad])
}

/// Incremental `Transfer-Encoding: chunked` decoder: it strips chunk framing
/// from an HTTP/1.1 body so it can be re-framed as H2 DATA.  Distinct from
/// [`crate::http::Chunked`], which only detects the terminator.
struct Dechunk {
    buf: Vec<u8>,
    left: usize,
    in_chunk: bool,
}

impl Dechunk {
    fn new() -> Self {
        Self { buf: Vec::new(), left: 0, in_chunk: false }
    }

    /// Feed bytes; return the decoded payload now available and whether the
    /// terminating zero-length chunk has been seen.  Payload is emitted as soon
    /// as it arrives — never buffered for the chunk's trailing CRLF — so a large
    /// body streams through as DATA frames instead of accumulating.
    fn push(&mut self, bytes: &[u8]) -> (Vec<u8>, bool) {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.in_chunk {
                if self.left == 0 {
                    // The chunk's payload is done; consume its trailing CRLF.
                    if self.buf.len() < 2 {
                        break;
                    }
                    self.buf.drain(..2);
                    self.in_chunk = false;
                    continue;
                }
                if self.buf.is_empty() {
                    break;
                }
                let take = self.left.min(self.buf.len());
                out.extend_from_slice(&self.buf[..take]);
                self.buf.drain(..take);
                self.left -= take;
            } else {
                let Some(i) = http::find(&self.buf, b"\r\n") else {
                    break;
                };
                let line: Vec<u8> = self.buf.drain(..i).collect();
                self.buf.drain(..2);
                let hex: String = String::from_utf8_lossy(&line)
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect();
                match usize::from_str_radix(&hex, 16) {
                    Ok(0) | Err(_) => return (out, true),
                    Ok(n) => {
                        self.left = n;
                        self.in_chunk = true;
                    }
                }
            }
        }
        (out, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        pairs
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn builds_request_from_pseudo_headers() {
        let f = fields(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "shop.example:8443"),
            (":path", "/cart/1?x=2"),
            ("accept", "text/html"),
        ]);
        let r = build_request(&f, "https", "127.0.0.1").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/cart/1?x=2");
        assert_eq!(r.path, "/cart/1");
        assert_eq!(r.query.as_deref(), Some("x=2"));
        assert_eq!(r.host, "shop.example");
        assert_eq!(r.version, "HTTP/2.0");
        assert_eq!(r.headers, vec![("accept".to_string(), "text/html".to_string())]);
    }

    #[test]
    fn missing_pseudo_headers_are_rejected() {
        let f = fields(&[(":method", "GET"), ("accept", "text/html")]);
        assert!(build_request(&f, "http", "p").is_none());
    }

    #[test]
    fn authority_falls_back_to_host_header() {
        let f = fields(&[(":method", "GET"), (":path", "/"), ("host", "fallback.example")]);
        let r = build_request(&f, "http", "p").unwrap();
        assert_eq!(r.host, "fallback.example");
    }

    #[test]
    fn header_fragment_strips_padding_and_priority() {
        // PADDED | PRIORITY: pad=2, priority (5 bytes), block "AB", then 2 pad.
        let mut p = vec![2u8];
        p.extend_from_slice(&[0, 0, 0, 1, 16]);
        p.extend_from_slice(b"AB");
        p.extend_from_slice(&[0, 0]);
        let flags = frame::FLAG_PADDED | frame::FLAG_PRIORITY;
        assert_eq!(header_fragment(flags, &p).unwrap(), b"AB");
    }

    #[test]
    fn data_fragment_strips_padding() {
        // pad=1, data "hello", then 1 pad octet.
        let mut p = vec![1u8];
        p.extend_from_slice(b"hello");
        p.push(0);
        assert_eq!(data_fragment(frame::FLAG_PADDED, &p).unwrap(), b"hello");
        assert_eq!(data_fragment(0, b"raw").unwrap(), b"raw");
    }

    #[test]
    fn dechunk_reassembles_across_feeds() {
        let mut d = Dechunk::new();
        let (a, done) = d.push(b"5\r\nhel");
        assert_eq!(a, b"hel");
        assert!(!done);
        let (b, done) = d.push(b"lo\r\n6\r\n world\r\n0\r\n\r\n");
        assert_eq!(b, b"lo world");
        assert!(done);
    }
}

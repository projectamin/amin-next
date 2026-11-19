//! HTTP/2 (RFC 9113) — inbound H2 on the Rust proxy front.
//!
//! The front terminates HTTP/2 itself: it hand-rolls the frame layer
//! ([`frame`]) and HPACK ([`hpack`], over the static Huffman code in
//! [`huffman`]) rather than pulling in a stack, so the byte-level behaviour is
//! ours to prove against the RFC — the same posture the front takes for
//! HTTP/1.1 in [`crate::http`].
//!
//! Only the *client* hop speaks H2.  The backend hop stays HTTP/1.1
//! (proxy-plan §5.6): a stream's request is decompressed into the same
//! [`crate::http::Request`] the H1.1 path builds, run through the same one
//! chain ([`crate::filters`]), and the response is re-framed back into H2.  So
//! H2 is an inbound transport, not a second router — the routing contract and
//! the `X-Forwarded-*` policy are unchanged (§5.12).
//!
//! The [`conn`] driver is deliberately **serial**: it completes one stream's
//! hop before reading the next stream's frames.  That is correct and
//! deadlock-free for a client that eventually sends every stream's frames, and
//! it keeps the flow-control state honest; concurrent streams are a later
//! increment.

mod conn;
mod frame;
mod hpack;
mod huffman;

pub(crate) use conn::serve;
pub(crate) use frame::PREFACE;

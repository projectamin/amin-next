//! HTTP/2 frame codec (RFC 9113 §4 and §6).
//!
//! A frame is a 9-octet header — a 24-bit length, an 8-bit type, 8-bit flags,
//! and a 31-bit stream id — followed by that many payload octets.  This module
//! is the pure half: it names the types and flags, splits and builds the fixed
//! header, and packs/unpacks SETTINGS.  Reading and writing frames over a
//! socket lives in [`super::conn`], because framing is where the connection
//! state lives, not the codec.

/// The client connection preface (RFC 9113 §3.4), sent before any frame.
pub(crate) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A frame header is always nine octets.
pub(crate) const HEADER_LEN: usize = 9;

/// The smallest `SETTINGS_MAX_FRAME_SIZE` a peer may advertise (RFC 9113 §6.5.2).
pub(crate) const DEFAULT_MAX_FRAME: usize = 16_384;
/// The largest frame payload either side may send (RFC 9113 §4.2).
pub(crate) const MAX_ALLOWED_FRAME: usize = 16_777_215;

// ── Error codes (RFC 9113 §7) ───────────────────────────────────────────────
/// The peer violated the protocol.
pub(crate) const ERR_PROTOCOL: u32 = 0x01;
/// A frame was the wrong size.
pub(crate) const ERR_FRAME_SIZE: u32 = 0x06;
/// HPACK compression state broke.
pub(crate) const ERR_COMPRESSION: u32 = 0x09;

// ── SETTINGS identifiers (RFC 9113 §6.5.2) ─────────────────────────────────
/// `SETTINGS_HEADER_TABLE_SIZE`.
pub(crate) const SET_HEADER_TABLE_SIZE: u16 = 0x01;
/// `SETTINGS_ENABLE_PUSH`.
pub(crate) const SET_ENABLE_PUSH: u16 = 0x02;
/// `SETTINGS_MAX_CONCURRENT_STREAMS`.
pub(crate) const SET_MAX_CONCURRENT: u16 = 0x03;
/// `SETTINGS_INITIAL_WINDOW_SIZE`.
pub(crate) const SET_INITIAL_WINDOW: u16 = 0x04;
/// `SETTINGS_MAX_FRAME_SIZE`.
pub(crate) const SET_MAX_FRAME: u16 = 0x05;

// ── Frame types (RFC 9113 §6) ───────────────────────────────────────────────
/// A frame's type octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameType {
    /// `DATA` (0x0).
    Data,
    /// `HEADERS` (0x1).
    Headers,
    /// `PRIORITY` (0x2).
    Priority,
    /// `RST_STREAM` (0x3).
    RstStream,
    /// `SETTINGS` (0x4).
    Settings,
    /// `PUSH_PROMISE` (0x5) — never sent by us, rejected from a client.
    PushPromise,
    /// `PING` (0x6).
    Ping,
    /// `GOAWAY` (0x7).
    GoAway,
    /// `WINDOW_UPDATE` (0x8).
    WindowUpdate,
    /// `CONTINUATION` (0x9).
    Continuation,
    /// Any other type: must be ignored (§4.1).
    Unknown(u8),
}

impl FrameType {
    /// Map a type octet to a [`FrameType`].
    #[must_use]
    pub(crate) fn from_u8(b: u8) -> Self {
        match b {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            other => Self::Unknown(other),
        }
    }

    /// The type octet.
    #[must_use]
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::GoAway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
            Self::Unknown(b) => b,
        }
    }
}

/// `END_STREAM` (DATA, HEADERS).
pub(crate) const FLAG_END_STREAM: u8 = 0x1;
/// `ACK` (SETTINGS, PING) — shares the `END_STREAM` octet.
pub(crate) const FLAG_ACK: u8 = 0x1;
/// `END_HEADERS` (HEADERS, PUSH_PROMISE, CONTINUATION).
pub(crate) const FLAG_END_HEADERS: u8 = 0x4;
/// `PADDED` (DATA, HEADERS, PUSH_PROMISE).
pub(crate) const FLAG_PADDED: u8 = 0x8;
/// `PRIORITY` (HEADERS).
pub(crate) const FLAG_PRIORITY: u8 = 0x20;

/// A frame header, split into its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// Payload length in octets.
    pub len: u32,
    /// Frame type.
    pub typ: FrameType,
    /// Flag bits.
    pub flags: u8,
    /// Stream id (0 for connection-scoped frames).
    pub stream: u32,
}

impl Header {
    /// Split the nine-octet frame header at the front of `buf`.
    #[must_use]
    pub(crate) fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let len = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        let typ = FrameType::from_u8(buf[3]);
        let flags = buf[4];
        // The reserved high bit of the stream id is ignored on receipt (§4.1).
        let stream = ((u32::from(buf[5]) << 24)
            | (u32::from(buf[6]) << 16)
            | (u32::from(buf[7]) << 8)
            | u32::from(buf[8]))
            & 0x7fff_ffff;
        Some(Self { len, typ, flags, stream })
    }

    /// Append this frame header to `out` (the payload follows).
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.push(((self.len >> 16) & 0xff) as u8);
        out.push(((self.len >> 8) & 0xff) as u8);
        out.push((self.len & 0xff) as u8);
        out.push(self.typ.as_u8());
        out.push(self.flags);
        out.extend_from_slice(&(self.stream & 0x7fff_ffff).to_be_bytes());
    }
}

/// Pack `SETTINGS` pairs into a payload.
#[must_use]
pub(crate) fn settings_payload(pairs: &[(u16, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pairs.len() * 6);
    for (id, value) in pairs {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}

/// Unpack a `SETTINGS` payload.
///
/// # Errors
/// A payload whose length is not a multiple of six is a `FRAME_SIZE_ERROR`.
pub(crate) fn parse_settings(payload: &[u8]) -> Result<Vec<(u16, u32)>, &'static str> {
    if payload.len() % 6 != 0 {
        return Err("settings: payload not a multiple of 6");
    }
    Ok(payload
        .chunks_exact(6)
        .map(|c| {
            (
                u16::from_be_bytes([c[0], c[1]]),
                u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let h = Header { len: 0x010203, typ: FrameType::Headers, flags: 0x5, stream: 0x7fff_ffff };
        let mut out = Vec::new();
        h.write(&mut out);
        assert_eq!(out.len(), HEADER_LEN);
        assert_eq!(Header::parse(&out), Some(h));
    }

    #[test]
    fn reserved_bit_is_ignored() {
        let mut buf = vec![0, 0, 4, 0x0, 0x0];
        buf.extend_from_slice(&0x8000_0001u32.to_be_bytes());
        let h = Header::parse(&buf).unwrap();
        assert_eq!(h.stream, 1);
    }

    #[test]
    fn settings_round_trip() {
        let pairs = [(SET_MAX_FRAME, 16_384u32), (SET_ENABLE_PUSH, 0)];
        let p = settings_payload(&pairs);
        assert_eq!(parse_settings(&p).unwrap(), pairs.to_vec());
        assert!(parse_settings(&p[..5]).is_err());
    }

    #[test]
    fn type_octet_round_trips() {
        for t in [0x0u8, 0x1, 0x9, 0x1f, 0xff] {
            assert_eq!(FrameType::from_u8(t).as_u8(), t);
        }
    }

    #[test]
    fn parse_needs_nine_octets() {
        assert!(Header::parse(&[0; 8]).is_none());
    }
}

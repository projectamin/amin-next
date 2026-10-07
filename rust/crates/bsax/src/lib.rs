//! # bsax — Binary SAX v1 codec
//!
//! Serialises / deserialises an *exact copy* of the XML::SAX event set into a
//! compact binary wire format.  The event model is 1:1 with `XML::SAX::Base` so
//! both ends of an Amin AWP/3 transport can plug `bsax` in as a direct
//! replacement for:
//!
//!   * encode → [`Amin::Handler::Writer`] (Perl, XML text)
//!   * decode → `XML::LibXML::SAX` / `XML::SAX::ParserFactory` (Perl, XML parse)
//!
//! The decode path produces `start_element($el)` / `end_element` /
//! `characters` / `start_document` / `end_document` calls into the EXACT SAME
//! 5-position filter chain (begin / late / middle / permanent / end via
//! [`Amin::Machine::Dispatcher`]) that XML input uses.  No semantic
//! differences, no data transformations — only fewer bytes on the wire and
//! zero XML text parsing CPU cost.
//!
//! ## Protocol contract
//!
//! | byte offset |  value          | meaning |
//! |-------------|-----------------|---------|
//! | 0..8        | `AMIN\x00BSAX1` | **stream magic** (8 bytes). Lets any reader auto-detect binary vs XML by peeking 8 bytes; also allows concatenating streams. |
//! | 8..         | event stream    | tag-flat byte stream — no length-prefixes at stream level; frame-level length is handled by [`awp3::frame`] (ASCON-128a AEAD framed). |
//!
//! ### Event tag byte — `high 3 bits = kind`, `low 5 bits = per-kind flags`
//!
//! ```text
//! 0x00  START_DOC     flags=0
//! 0x20  END_DOC       flags=0
//! 0x40  START_ELEM    flags[0..3] = attr_count (0..14); 15 => count follows as LEB128
//!                     flags[4]    = NS inline? (1 = NS_ID:4 + NAME_ID:LEB follows;
//!                                                0 = reuse last NS, NAME_ID:LEB only)
//!                     payload:
//!                       NS_ID:4 + NAME_ID:LEB128    (if flags[4] == 1)
//!                       NAME_ID:LEB128              (if flags[4] == 0)
//!                       [LEB128 count               (if flags[0..3] == 15)]
//!                       × N attrs:
//!                         NAME_ID:LEB128
//!                         LEB128(value_len) + raw UTF-8 value bytes
//! 0x60  END_ELEM      flags=0  (name from decoder stack; always 1 byte tag ONLY)
//! 0x80  CHARS         flags[0..4] = len <32 ? len : 31
//!                     payload: if len==31, LEB128(full_len) follows; then raw bytes
//! 0xA0  IWS           same encoding as CHARS (ignorable whitespace — filters typically skip)
//! 0xC0  PI            flags unused; NAME_ID(target) + LEN_PREFIXED(data)
//! 0xE0  DICT_ENTRY    flags[4] NS_ID:4; flags[0..3] NAME_ID high bits; LEN_PREFIXED(utf8 name)
//! ```
//!
//! ### NAME_ID space (closed-world IDs = 1 byte LEB128; ESCAPE = BY_ID.len())
//!
//! ```text
//!   0..20  Amin core: profile result command stream status cond argv
//!                     id version kind rc pid duration exit_kind name target
//!                     channel dir mode level value type size
//!  21..34  map:*     : region server link node a b cost phase flavor
//!                     latency_ms bw_gbps tier zone  (note: status shared with amin core)
//!  35..61  ui:*      : 25-entry vocabulary per Amin::Filter::UI::SwiftUIView
//!      ESCAPE        → NAME_ID:LEB = BY_ID.len() then LEN_PREFIXED(utf8 raw name) follows
//! ```
//!
//! ### NS_ID (4 bits):
//!
//! ```text
//! 0 = none   1 = http://projectamin.org/ns/2026/
//! 2 = ui/1   3 = map/1   4..14 reserved   15 = escape → LEN_PREFIXED(URI string)
//! ```
//!
//! ## Safety properties (P/B/N decode path)
//!
//! * **P (Perl Safe)** : On the Perl decode side, escaped names (id >= vocab::escape_id())
//!   validated against [`Amin::Util::Fold`] allowed-name hashes BEFORE the
//!   event is forwarded to the 5-position chain.  Unknown names never reach
//!   user filters.
//! * **B (eBPF/ubpf)** : On the Rust side, `decode_iter()` is a single
//!   `&[u8] -> impl Iterator<Item=Event>` function with no heap allocations
//!   inside the `simd-tag` feature loop; perfect for XDP/syscall hook validation.
//! * **N (Landlock/seccomp)** : `bsax::decode` never opens files, never execs,
//!   never touches networking.  All it does is read bytes → emit tagged enums.
//!   A Landlock allow-list of `{}` + seccomp `read/write/exit` only is
//!   sufficient; see [`crate::decode::Bounds`].
//!
//! ## Integration with AWP/3 transport
//!
//! The magic + event stream above is the **payload bytes** of a single
//! [`awp3::frame`] (ASCON-128a AEAD, BLAKE3-chained frame ID).  bsax does NO
//! encryption/authentication itself — it delegates that ENTIRELY to awp3.
//! Therefore bsax frame payloads are plaintext INSIDE AWP/3 (trust boundary at
//! AWP/3 handshake) and ciphertext OUTSIDE.
//!
//! ## Hyperscale + mobile
//!
//! * **zero-copy** — `Event::Chars` returns `&[u8]` pointing into the reader's
//!   original buffer.  On decode paths, only `start_element` attribute values
//!   need copying if the handler keeps them around; streaming line-based
//!   filters (e.g. `gcc` output over `<amin:stream channel=out>`) can compare
//!   byte-slices in place (SIMD `memchr` for newline detection in <1ns/line).
//! * **1-byte END_ELEM** — no name string repeated.  Matches `Amin::Handler::Writer`
//!   (which pops `$self->stack`) exactly.
//! * **Mobile (iOS/Android)** : CPU cost on decoder is dominated by one 256-way
//!   jump table per event tag (3 cycles on modern ARMv8/AArch64). Small binary
//!   + small data = smaller `.text` footprint = fewer iCache misses = better
//!   thermals + longer battery.
#![forbid(unsafe_code)]
#![warn(clippy::pedantic, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

pub mod decode;
pub mod encode;
pub mod vocab;

/// Stream magic written at offset 0 of every binary-SAX stream — 8 bytes.
pub const MAGIC: [u8; 8] = *b"AMINBSA1";

/// Event tags (high 3 bits of the tag byte; low 5 are per-kind flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// `start_document`
    StartDoc = 0x00,
    /// `end_document`
    EndDoc   = 0x20,
    /// `start_element`
    StartEl  = 0x40,
    /// `end_element`
    EndEl    = 0x60,
    /// `characters`
    Chars    = 0x80,
    /// `ignorable_whitespace`
    Iws      = 0xA0,
    /// `processing_instruction`
    Pi       = 0xC0,
    /// `dict_entry` (stream-local name interning)
    Dict     = 0xE0,
}

impl Tag {
    /// Extract tag + flags from a single byte.  `None` if the high 3 bits do
    /// not match any known [`Tag`].
    #[must_use]
    pub fn from_byte(b: u8) -> Option<(Self, u8)> {
        let kind  = b & 0xE0;
        let flags = b & 0x1F;
        let tag = match kind {
            0x00 => Self::StartDoc,
            0x20 => Self::EndDoc,
            0x40 => Self::StartEl,
            0x60 => Self::EndEl,
            0x80 => Self::Chars,
            0xA0 => Self::Iws,
            0xC0 => Self::Pi,
            0xE0 => Self::Dict,
            _    => return None,
        };
        Some((tag, flags))
    }
}

/// A decoded SAX event, borrowing bytes from the original input buffer.
/// Generic over the lifetime of the source slice so the hot path never
/// allocates for characters/attribute values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    /// Corresponds to `start_document()`
    StartDocument,
    /// Corresponds to `end_document()`
    EndDocument,
    /// Corresponds to `start_element($el)`.
    /// `attrs` are `(name_id, value_bytes)` tuples; `name_id < vocab::escape_id()`
    /// → look up via `vocab::BY_ID[name_id]`; else use `local_name_override`.
    StartElement {
        /// 4-bit NS_ID.  If 15 (=escape), read `ns_uri_override` instead.
        ns_id: u8,
        /// `< vocab::escape_id()` → closed-world vocab; else → escaped (raw name follows).
        name_id: u8,
        /// Only populated when `ns_id == 15` (escape).
        ns_uri_override: Option<&'a [u8]>,
        /// Only populated when `name_id >= vocab::escape_id()` (escape).
        local_name_override: Option<&'a [u8]>,
        /// `(name_id, value_bytes)`.
        attrs: Vec<(u8, &'a [u8])>,
    },
    /// Corresponds to `end_element()`. Name is NOT repeated (pop from stack);
    /// the Perl/Rust decoder side maintains `Vec<String>` stack mirroring
    /// `Amin::Handler::Writer` stack.
    EndElement,
    /// Corresponds to `characters($d)`. Bytes are UTF-8 (SAX contract).
    Chars(&'a [u8]),
    /// Corresponds to `ignorable_whitespace`.
    Iws(&'a [u8]),
    /// Corresponds to `processing_instruction`.
    Pi {
        /// NAME_ID of the PI target (>= vocab::escape_id() = escape → raw bytes follow).
        target_id: u8,
        /// Raw target name if escaped.
        target_override: Option<&'a [u8]>,
        /// PI data portion.
        data: &'a [u8],
    },
    /// Stream-local name interning entry (only emitted if NAME_ID escape is
    /// used; normal Amin vocab NEVER emits these).
    DictEntry {
        /// NS_ID (4 bits).
        ns_id: u8,
        /// Assigned name ID (must be ≥ 128 because 0..escape_id are closed-world).
        id: u32,
        /// Raw UTF-8 LocalName.
        name: &'a [u8],
    },
}

/// Error type for decode failures.  All variants are cheap; the P/B/N decode
/// guard returns `Err(DecodeError::ProhibitedName)` rather than panicking so
/// the XDP/eBPF hook can reject malformed frames deterministically.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ran out mid-event.
    #[error("truncated input at offset {0}")]
    Truncated(usize),
    /// High 3 bits of a tag byte did not map to a [`Tag`].
    #[error("unknown tag byte 0x{0:02X} at offset {1}")]
    UnknownTag(u8, usize),
    /// NAME_ID escape but string length exceeds bounds (default 8 KiB cap).
    #[error("name escape exceeds length cap at offset {0}")]
    NameTooLong(usize),
    /// Attribute value exceeds `decode::Bounds::value_max_bytes` (default 256 KiB).
    #[error("attribute/stream value exceeds cap at offset {0}")]
    ValueTooLong(usize),
    /// Event arrives but NAME_ID is not in the allowed-name allow-list passed
    /// to the decoder (via `Amin::Util::Fold`-style contract).
    #[error("prohibited name (id={0}) at offset {1}")]
    ProhibitedName(u32, usize),
}

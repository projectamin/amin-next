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
//! | 0..8        | `AMINBSA1`      | **stream magic** (8 bytes). Lets any reader auto-detect binary vs XML by peeking 8 bytes; also allows concatenating streams. |
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
//! 0xE0  (retired)     was DICT_ENTRY (stream-local interning).  It had no
//!                     XML::SAX analogue, so a pure 1:1 codec has no event for
//!                     it — the byte is now rejected as an unknown tag.
//! ```
//!
//! ### NAME_ID space (closed-world IDs = 1 byte LEB128; ESCAPE = BY_ID.len())
//!
//! ```text
//!   0..22  Amin core: profile result command stream status cond argv
//!                     id version kind rc pid duration exit_kind name target
//!                     channel dir mode level value type size
//!  23..36  map:*     : region server link node a b cost phase flavor
//!                     latency_ms bw_gbps tier zone value
//!  37..82  ui:*      : 46-entry closed-world ui: vocabulary (kinds + attrs)
//!  83..101 bc:*      : projectamin/bitcache 2014 ns — object/signer/networkmap/slab ops
//! 102..107 ainit:*   : init-profile.xml stage vocabulary (PID 1 handoff)
//! 108..121 exec-net  : Sandbox + Net::Fabric + expanded Command surface names
//! 122..136 sec:*     : payload-neutral PQ E2EE (Double Ratchet + PQXDH filter pair)
//! 137..171 document  : amin:* document grammar (platform vocabulary, core NS)
//!      ESCAPE        → NAME_ID:LEB = BY_ID.len() then LEN_PREFIXED(utf8 raw name) follows
//!  ESCAPE+1..       : spec-declared band (a machine spec's own LocalNames — see
//!                     [`vocab::Vocab`]); resolved from the consumer's spec, no
//!                     core edit.  A band id the consumer's spec does not
//!                     declare is a loud [`DecodeError::NameOutOfBand`].
//! ```
//!
//! ### NS_ID (4 bits):
//!
//! ```text
//! 0 = none   1 = http://projectamin.org/ns/2026/
//! 2 = ui/1   3 = map/1   4 = bc/ (Bitcache 2014 legacy)
//! 5 = sec/1 (post-quantum E2EE)   6..14 reserved
//! 15 = escape → LEN_PREFIXED(URI string) — used by third-party corp
//!             custom namespaces without Amin fork (see spec DI-2)
//! ```
//!
//! ## Safety properties (P/B/N decode path)
//!
//! * **P (Perl Safe)** : the Perl decode side is a pure 1:1 mirror — an unknown
//!   name rides the escape path and is surfaced exactly as the XML parser would
//!   surface it.  No name is rejected in the codec; the closed-world contract
//!   is enforced *in the chain* (e.g. `Amin::Filter::UI::Guard`), so a codec
//!   change is never required to admit an external filter's vocabulary.
//! * **B (eBPF/ubpf)** : On the Rust side, [`decode::StreamDecoder`] is a
//!   resumable state machine (`feed` bytes in, `poll_event` out).  No parsing
//!   cost is incurred until a whole event is buffered, so it is safe to drive
//!   from XDP/syscall hooks that see a stream in fragments.
//! * **N (Landlock/seccomp)** : `bsax::decode` never opens files, never execs,
//!   never touches networking.  All it does is read bytes → emit tagged enums.
//!   A Landlock allow-list of `{}` + seccomp `read/write/exit` only is
//!   sufficient; see [`crate::decode::Bounds`].  A consumer on a hard-trust
//!   path may additionally arm [`decode::Bounds::allow_vocab_only`].
//!
//! ## Escape hatches are not a trust boundary
//!
//! Two wire constructs carry **producer-controlled strings outside the
//! closed-world NAME_ID vocabulary**, and are therefore escape hatches rather
//! than named vocabulary:
//!
//! * `PI` (0xC0) — `Target` + `Data`;
//! * `NS_ID` / `NAME_ID` escape — inline UTF-8 URI / LocalName.
//!
//! `PI` is **not** an Amin invention: it is a straight mirror of the XML::SAX
//! `processing_instruction` event (`<?target data?>`), and the codec only gives
//! it a binary tag.  Amin's command event is `processing_command`, not the XML
//! PI; the Dispatcher adds no `processing_instruction` to its forwarded event
//! set, but it does implement `processing_instruction` as **warn-and-drop** —
//! the PI never enters the chain, and the attempt is recorded on the machine's
//! loaded Log so an operator sees that something tried one.
//!
//! Because the transport auto-detects XML vs BSAX by peeking the first byte,
//! dropping or rewriting a PI in the codec would create a **parser
//! differential**: the same document would mean different things depending on
//! its encoding.  Equivalence with the XML path is the security property, so
//! the codec stays 1:1.  Any policy on `Target`/`Data` — allow-list or refusal
//! — belongs in a single gate in the filter chain (where names are
//! allow-listed for P/B/N), never in the codec.
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
            _    => return None,
        };
        Some((tag, flags))
    }
}

/// One decoded attribute of a `start_element`.
///
/// `name_id < vocab::escape_id()` names a compiled closed-world vocabulary
/// slot, looked up via `vocab::BY_ID[name_id]`.  When `name_id ==
/// vocab::escape_id()` the LocalName was not in the vocabulary and is carried
/// verbatim in `name_override` (a length-prefixed UTF-8 string on the wire).
/// When `name_id > vocab::escape_id()` it addresses the consumer's spec-declared
/// band, also surfaced in `name_override`.  Use [`Attr::local_name`] to resolve
/// any case without branching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr<'a> {
    /// `< vocab::escape_id()` → compiled core vocab; `>= escape_id()` → override.
    pub name_id: u32,
    /// Raw UTF-8 LocalName, populated on the escape (inline) and spec-band paths.
    pub name_override: Option<&'a [u8]>,
    /// Attribute value bytes (UTF-8 by the SAX contract).
    pub value: &'a [u8],
}

impl<'a> Attr<'a> {
    /// Resolve the LocalName: the compiled core vocab entry when `name_id`
    /// addresses one, otherwise the override (an inline escaped name or a
    /// spec-declared band name).  `None` only if the id is neither in range nor
    /// accompanied by an override (malformed).
    #[must_use]
    pub fn local_name(&self) -> Option<&'a [u8]> {
        match vocab::BY_ID.get(self.name_id as usize) {
            Some(name) => Some(name),
            None => self.name_override,
        }
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
    /// `name_id < vocab::escape_id()` → look up via `vocab::BY_ID[name_id]`;
    /// else use `local_name_override` (inline escape or spec-band name).
    StartElement {
        /// 4-bit NS_ID.  If 15 (=escape), read `ns_uri_override` instead.
        ns_id: u8,
        /// `< vocab::escape_id()` → core vocab; else → override (escape or band).
        name_id: u32,
        /// Only populated when `ns_id == 15` (escape).
        ns_uri_override: Option<&'a [u8]>,
        /// Inline escaped name (`name_id == escape_id()`) or a spec-declared
        /// band name (`name_id > escape_id()`); `None` for a compiled core name.
        local_name_override: Option<&'a [u8]>,
        /// Decoded attributes in wire order.
        attrs: Vec<Attr<'a>>,
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
        /// NAME_ID of the PI target (`> escape_id()` = escape → raw bytes follow).
        target_id: u32,
        /// Raw target name if escaped or a spec-band name.
        target_override: Option<&'a [u8]>,
        /// PI data portion.
        data: &'a [u8],
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
    /// NAME_ID addresses the spec-declared [`vocab::Vocab`] band
    /// (`> vocab::escape_id()`) but the consumer's spec does not declare that
    /// slot.  This is a loud contract mismatch — the id names a vocabulary the
    /// consumer was never handed — never a silent desync, and never mistaken
    /// for an inline escaped name that was not written on the wire.
    #[error("NAME_ID {0} past the spec's declared band (band ends before it) at offset {1}")]
    NameOutOfBand(u32, usize),
}

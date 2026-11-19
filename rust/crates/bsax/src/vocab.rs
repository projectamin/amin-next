//! Closed-world Amin NAME_ID vocabulary — shared verbatim between Rust bsax
//! crate and Perl Amin::{Handler,Generator}::BSAX packages.
//!
//! *WARNING:* Any change to this slice must be mirrored in both Perl source
//! files (`perl-lib/Amin/Handler/BSAX.pm` and `perl-lib/Amin/Generator/BSAX.pm`)
//! — the decoder/encoder only stay 1:1 if the byte-level vocab order matches.
//!
//! Escape marker is auto-derived as `BY_ID.len() as u32` (currently 172 → a
//! 2-byte LEB128 code point).  Crossing 128 was the deliberate
//! "name-id-2-byte-mode" revision that let the ui: form vocabulary grow; the
//! name ids themselves are unchanged in meaning, only their wire width.  Any
//! LocalName unknown to this table is sent on the wire as the escape marker +
//! length-prefixed UTF-8 (larger + slower).
//!
//! # The spec-declared band
//!
//! `BY_ID` is the **compiled core** closed world.  A machine spec may declare
//! its own element/attribute LocalNames (`<filter element=…>` + optional
//! `<vocab><name>`); those ride a **dynamic band** appended past the fixed
//! escape sentinel — see [`Vocab`].  Both the Rust and Perl codecs derive the
//! identical band from the same signed spec, so an external filter's vocabulary
//! never has to be wired into Amin core to keep BSAX tight.

use alloc::vec::Vec;

/// 4-bit NS_ID inline constants.  MUST stay 1:1 with Perl Handler/Generator::BSAX
/// `use constant { NS_NONE => 0, NS_AMIN => 1, NS_UI => 2, NS_MAP => 3, NS_BITCACHE => 4,
/// NS_SEC => 5, NS_ESCAPE => 15 }` blocks.  Values 6..=14 remain reserved for
/// future forward-compatible Amin-owned namespace slots; any third-party custom
/// namespace uses NS_ESCAPE (15) with length-prefixed UTF-8 URI inline so
/// CORP-style filter custom NSes work without Amin fork (see spec DI-2 / NS_ESCAPE=15 path).
///
/// Platform-shipped document generation deliberately uses `AMIN` (no dedicated
/// slot): every filter that ships with Amin owns its XML vocabulary in the
/// Amin namespace, leaving application/Rust filters free to register their own
/// URI without colliding with core semantics.
#[allow(dead_code)]
pub mod ns_id {
    /// Empty / no namespace (`xmlns=""`).
    pub const NONE: u8     = 0;
    /// Amin core SAX namespace — `http://projectamin.org/ns/2026/`.
    pub const AMIN: u8     = 1;
    /// Amin UI filter namespace — `http://projectamin.org/ns/ui/1`.
    pub const UI: u8       = 2;
    /// Amin Topology map filter namespace — `http://projectamin.org/ns/map/1`.
    pub const MAP: u8      = 3;
    /// Legacy Bitcache 2014 object/signer envelope namespace — `http://projectamin.org/ns/bc/`.
    pub const BITCACHE: u8 = 4;
    /// Amin `sec:` post-quantum E2EE namespace — `http://projectamin.org/ns/sec/1`.
    /// Payload-neutral end-to-end encryption: the Double Ratchet + PQXDH exposed
    /// as a SAX filter pair, not a chat-specific construct.  First Amin-owned use
    /// of the `5..=14` reserved slot range.
    pub const SEC: u8      = 5;
    /// Escape hatch — `NS_ESCAPE` means a length-prefixed UTF-8 namespace URI
    /// string is carried inline on the wire.  Used by CORP custom filters to
    /// preserve extensibility (see spec § DI-2).
    pub const ESCAPE: u8   = 15;
}

/// Closed-world vocabulary slice.  `BY_ID[id as usize]` returns the LocalName
/// as UTF-8 bytes.  Sorted into eight contiguous regions for human reader
/// convenience only — encode/decode treat the whole list as flat, and new
/// regions are always APPENDED so existing NAME_IDs keep their wired byte value.
pub const BY_ID: &[&[u8]] = &[
    // ── Amin core: elements + attribute LocalNames used by inner SAX chain
    b"profile", b"result", b"command", b"stream", b"status", b"cond", b"argv",
    b"id", b"version", b"kind", b"rc", b"pid", b"duration", b"exit_kind",
    b"name", b"target", b"channel", b"dir", b"mode", b"level", b"value",
    b"type", b"size",
    // ── map:* — Amin::Filter::Map::Topology element+attr LocalNames
    b"region", b"server", b"link", b"node", b"a", b"b", b"cost", b"phase",
    b"flavor", b"latency_ms", b"bw_gbps", b"tier", b"zone", b"value",
    // ── ui:*  — closed-world ui: vocabulary (33 kinds) + late-sax attrs
    //      The 8 form/table/style kinds and 7 form attrs were grown IN PLACE
    //      (the deliberate 2-byte NAME_ID revision): appended to the ui: slice,
    //      shifting every downstream region's NAME_ID by 15 while the ui: ids
    //      themselves stay stable.
    b"app", b"scene", b"list", b"row", b"column", b"hstack", b"vstack",
    b"stack", b"grid", b"section", b"card", b"progress", b"alert", b"sheet",
    b"toolbar", b"searchable", b"item", b"label", b"text", b"badge",
    b"sparkline", b"button", b"navigate", b"image", b"asyncimage",
    b"form", b"field", b"select", b"option", b"table", b"tr", b"cell",
    b"style",
    b"title", b"spacing", b"points", b"for-each", b"bind", b"url",
    b"action", b"method", b"min", b"max", b"placeholder", b"selected",
    b"header",
    // ── bc:*  — projectamin/bitcache 2014 namespace LocalNames
    //      (object/signer envelope, networkmap mesh, slab lifecycle ops)
    b"object", b"hash", b"date", b"signer", b"networkmap", b"server",
    b"ip", b"port", b"search", b"ref", b"refcount", b"stripe", b"parity",
    b"redundancy", b"slab", b"snap", b"gc", b"pull", b"push",
    // ── ainit stage vocabulary for init-profile.xml PID 1 handoff
    b"stage", b"order", b"node_id", b"refused", b"init_profile_ref",
    b"slab_dev",
    // ── exec+net: Sandbox + Net::Fabric + expanded Command surface inner names
    b"exec", b"spawn", b"signal", b"sandbox", b"cpu_max", b"memory_high",
    b"landlock_ro", b"seccomp", b"vpc", b"subnet", b"lb", b"vip",
    b"backends", b"netpolicy",
    // ── sec:*  — payload-neutral post-quantum E2EE surface (Double Ratchet +
    //      PQXDH as a SAX filter pair; also the on-device `rctool` bridge).
    //      Appended LAST so every NAME_ID above keeps its wired byte value.
    b"seal", b"sealed", b"ciphertext", b"header",
    b"ratchet", b"prev_count", b"msg_index",
    b"session", b"prekey", b"pqprekey", b"onetime", b"bundle",
    b"senderkey", b"identity", b"require",
    // ── document generation grammar + attributes (amin:document/sheet/cell/…
    //      — platform vocabulary in the core NS).  Names already in the table
    //      (sheet/row/column/cell/style/title/id/name/type/ref/min/max/size/
    //      hash/kind/rc/exit_kind) are not repeated.  Appended LAST so every
    //      NAME_ID above keeps its wired byte value.
    b"document", b"merge", b"freeze", b"autofilter",
    b"index", b"width", b"hidden", b"height", b"ht", b"r", b"range",
    b"bold", b"italic", b"underline", b"font", b"color", b"fill",
    b"numfmt", b"format",
    b"align", b"valign", b"wrap", b"tab-color",
    b"author", b"subject", b"keywords", b"description", b"out", b"root",
    b"mime", b"path", b"sheets", b"rows", b"cells", b"msg",
];

/// Number of compiled core NAME_ID slots (the closed world shared verbatim
/// with Perl). `0..CORE_LEN` index [`BY_ID`]; `CORE_LEN` itself is the
/// inline-escape sentinel.
pub const CORE_LEN: u32 = BY_ID.len() as u32;

/// NAME_ID escape marker: always the first ID past the last core vocab slot.
/// Held FIXED at [`CORE_LEN`] so the sentinel never moves when a machine spec
/// declares a [`Vocab`] band — a name the consumer cannot resolve stays on the
/// escape path, byte-identical to the pre-band codec.
#[inline] pub const fn escape_id() -> u32 { CORE_LEN }

/// First NAME_ID a spec-declared band name may take (`escape_id() + 1`).
#[inline] pub const fn band_start() -> u32 { CORE_LEN + 1 }

/// Build-time reverse map into the compiled core: LocalName → NAME_ID.
/// `None` ⇒ the name is not in the core table (use [`escape_id`] or a
/// [`Vocab`] band).
pub const fn by_name(name: &[u8]) -> Option<u32> {
    let mut i = 0usize;
    while i < BY_ID.len() {
        if slices_eq(BY_ID[i], name) { return Some(i as u32) }
        i += 1;
    }
    None
}

const fn slices_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] { return false }
        i += 1;
    }
    true
}

/// Spec-declared NAME_ID band — the dynamic half of the NAME_ID space.
///
/// A machine spec may declare element/attribute LocalNames (`<filter
/// element=…>` plus optional `<vocab><name>`).  Names not already in the
/// compiled core table [`BY_ID`] are assigned NAME_IDs `band_start(),
/// band_start()+1, …` in first-seen order (core wins, first-seen wins).  Both
/// the Rust and Perl codecs derive the identical map from the same signed spec,
/// so an external filter's vocabulary rides the tight NAME_ID path without a
/// single name being wired into Amin core.  An empty band is byte-identical to
/// the pre-band codec — every undeclared name simply rides the escape path.
///
/// Band ids are `u32` because a NAME_ID is a LEB128 `u32` on the wire and the
/// Perl codec derives the same unbounded space; storing them in a narrower type
/// would silently truncate a large spec's names.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Vocab {
    /// Spec-declared names in first-seen order, core names and duplicates
    /// already excluded.  Index `i` ⇒ NAME_ID `band_start() + i`.
    band: Vec<Vec<u8>>,
}

impl Vocab {
    /// An empty band — resolution falls back to the compiled core table alone.
    #[must_use]
    pub const fn empty() -> Self { Self { band: Vec::new() } }

    /// Derive the band from spec-declared names in document order.
    #[must_use]
    pub fn from_names<S: AsRef<[u8]>>(names: &[S]) -> Self {
        let mut band: Vec<Vec<u8>> = Vec::new();
        for n in names {
            let n = n.as_ref();
            if n.is_empty() { continue }
            if by_name(n).is_some() { continue }                    // core wins
            if band.iter().any(|b| b.as_slice() == n) { continue }  // first-seen wins
            band.push(n.to_vec());
        }
        Self { band }
    }

    /// Number of spec-declared band names.
    #[must_use] pub fn len(&self) -> usize { self.band.len() }

    /// `true` when the spec declared no LocalName outside the core vocabulary.
    #[must_use] pub fn is_empty(&self) -> bool { self.band.is_empty() }

    /// LocalName → NAME_ID: the core table first, then the band.  `None` ⇒ the
    /// name is unknown to this spec and must ride the escape path.
    #[must_use]
    pub fn name_id(&self, name: &[u8]) -> Option<u32> {
        if let Some(id) = by_name(name) { return Some(id) }
        self.band
            .iter()
            .position(|b| b.as_slice() == name)
            .map(|i| band_start() + i as u32)
    }

    /// NAME_ID → LocalName for a spec-declared **band** id (`> escape_id()`).
    ///
    /// `None` for a core id, the `escape_id()` sentinel, or a band id this spec
    /// never declared — the last is the loud contract error the decoder raises
    /// ([`crate::DecodeError::NameOutOfBand`]) rather than reading an inline
    /// name that was never written.
    #[must_use]
    pub fn band_name(&self, id: u32) -> Option<&[u8]> {
        let idx = id.checked_sub(band_start())? as usize;
        self.band.get(idx).map(Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocab_count_kept_in_sync_with_perl() {
        // Perl's @VOCAB currently has 172 entries across
        // amin/map/ui/bc/ainit/exec-net/sec/document-generation.
        // If this fails, update both sides together with the same reordering.
        assert_eq!(BY_ID.len(), 172);
        assert_eq!(escape_id(), 172);
        // Architecture guard (AC-2): the vocabulary is in the 2-byte LEB128
        // "name-id-2-byte-mode" (>127) introduced for the ui: form surface, so
        // every NAME_ID now costs two LEB bytes.  That revision was a one-off:
        // stay under 256 (still a 2-byte LEB) and talk to the spec owner before
        // any further growth, because the next threshold changes the wire size
        // of ALL inner elements again.
        assert!(BY_ID.len() <= 255, "VOCAB exceeded 255 entries — requires another wire-format spec revision");
    }
    #[test]
    fn amin_kind_maps_id_9() {
        assert_eq!(by_name(b"kind"), Some(9));
        assert_eq!(BY_ID[9], b"kind");
    }
    #[test]
    fn amin_rc_maps_id_10() {
        // 0:profile 1:result 2:command 3:stream 4:status 5:cond 6:argv
        // 7:id 8:version 9:kind 10:rc ...
        assert_eq!(by_name(b"rc"), Some(10));
        assert_eq!(BY_ID[10], b"rc");
    }
    #[test]
    fn ui_app_maps_id_37() {
        // 23 amin + 14 map = 37 → ui:* region starts at index 37 (not 35)
        assert_eq!(by_name(b"app"), Some(37));
        assert_eq!(BY_ID[37], b"app");
    }
    #[test]
    fn ui_form_region_appended_in_place() {
        // The 8 new kinds sit between the original 25 kinds and the attrs.
        assert_eq!(by_name(b"asyncimage"), Some(61));
        assert_eq!(by_name(b"form"),  Some(62));
        assert_eq!(by_name(b"style"), Some(69));
        // New attrs follow the original 6 (title..url @70..75).
        assert_eq!(by_name(b"url"),     Some(75));
        assert_eq!(by_name(b"action"),  Some(76));
        // `header` reuses the sec: LocalName (multi-region name, like value/
        // server); by_name returns the FIRST match, the ui: slot.
        assert_eq!(by_name(b"header"),  Some(82));
    }
    #[test]
    fn bc_object_region_starts_at_83() {
        // 23 amin + 14 map + 46 ui = 83 → bc:* region starts at index 83
        assert_eq!(by_name(b"object"), Some(83));
        assert_eq!(BY_ID[83], b"object");
        // Final bc entry push sits at 83 + 18 = 101
        assert_eq!(by_name(b"push"), Some(101));
        assert_eq!(BY_ID[101], b"push");
    }
    #[test]
    fn ainit_stage_region_starts_at_102() {
        assert_eq!(by_name(b"stage"), Some(102));
        assert_eq!(BY_ID[102], b"stage");
        assert_eq!(by_name(b"slab_dev"), Some(107));
    }
    #[test]
    fn exec_net_region_starts_at_108() {
        assert_eq!(by_name(b"exec"), Some(108));
        assert_eq!(BY_ID[108], b"exec");
        // Final entry netpolicy sits at 108 + 13 = 121 (last vocab index; escape = 122)
        assert_eq!(by_name(b"netpolicy"), Some(121));
        assert_eq!(BY_ID[121], b"netpolicy");
    }
    #[test]
    fn sec_region_starts_at_122() {
        // 23 amin + 14 map + 46 ui + 19 bc + 6 ainit + 14 exec-net = 122
        // → the sec:* region is appended at index 122.
        assert_eq!(by_name(b"seal"), Some(122));
        assert_eq!(BY_ID[122], b"seal");
        assert_eq!(by_name(b"sealed"), Some(123));
        // The Double Ratchet header fields sit contiguously.
        assert_eq!(by_name(b"ratchet"), Some(126));
        assert_eq!(by_name(b"prev_count"), Some(127));
        assert_eq!(by_name(b"msg_index"), Some(128));
        // Final sec entry `require` sits at 122 + 14 = 136 (escape was 137).
        assert_eq!(by_name(b"require"), Some(136));
        assert_eq!(BY_ID[136], b"require");
    }
    #[test]
    fn content_region_starts_at_137() {
        assert_eq!(by_name(b"document"), Some(137));
        assert_eq!(BY_ID[137], b"document");
        // Shared names keep their earlier ids; the Perl generator's
        // document-element override re-homes them on amin:* grammar elements.
        assert_eq!(by_name(b"sheet"),  Some(50));
        assert_eq!(by_name(b"cell"),   Some(68));
        assert_eq!(by_name(b"format"), Some(155));
        // Final document-grammar entry `msg` sits at 137 + 34 = 171 (escape = 172).
        assert_eq!(by_name(b"msg"), Some(171));
        assert_eq!(BY_ID[171], b"msg");
    }
    #[test]
    fn ns_sec_constant_matches_perl_handler() {
        // Perl Handler/Generator::BSAX both say NS_SEC = 5, the first Amin-owned
        // slot of the reserved 5..14 range.  A mismatch would send every sec:*
        // element down the NS_ESCAPE path (length-prefixed URI per element).
        use ns_id::*;
        assert_eq!(SEC, 5);
    }
    #[test]
    fn ns_bitcache_constant_matches_perl_handler() {
        // Perl Handler::BSAX says NS_BITCACHE = 4; also same for Generator::BSAX constant.
        // If this test fails, BSAX encode/decode round-trip of bc:*-namespaced
        // elements will silently drop them into NS_ESCAPE, growing wire size
        // for every Bitcache object envelope (millions/sec on a busy node).
        use ns_id::*;
        assert_eq!(BITCACHE, 4);
        assert_eq!(AMIN,     1);
        assert_eq!(UI,       2);
        assert_eq!(MAP,      3);
        assert_eq!(NONE,     0);
        assert_eq!(ESCAPE,  15);
    }
    #[test]
    fn unknown_returns_none_for_escape_marker() {
        assert_eq!(by_name(b"custom-widget-99"), None);
    }

    #[test]
    fn band_is_derived_core_wins_first_seen() {
        // Spec-declared names in document order; `id`/`status` are core (wins),
        // the repeated `frob` proves first-seen order ⇒ band = [frob, widget].
        // Mirrors Perl t/11 §9 (`@vocab = qw(id frob widget status frob)`).
        let names: &[&[u8]] = &[b"id", b"frob", b"widget", b"status", b"frob"];
        let v = Vocab::from_names(names);
        assert_eq!(v.len(), 2);
        assert_eq!(v.name_id(b"id"), by_name(b"id"));            // core wins
        assert_eq!(v.name_id(b"status"), by_name(b"status"));    // core wins
        assert_eq!(v.name_id(b"frob"), Some(band_start()));
        assert_eq!(v.name_id(b"widget"), Some(band_start() + 1));
        assert_eq!(v.name_id(b"nope"), None);                    // ⇒ escape path
        assert_eq!(v.band_name(band_start()), Some(&b"frob"[..]));
        assert_eq!(v.band_name(band_start() + 1), Some(&b"widget"[..]));
        assert_eq!(v.band_name(band_start() + 2), None);         // undeclared
        assert_eq!(v.band_name(escape_id()), None);              // the sentinel
        assert_eq!(v.band_name(9), None);                        // a core id
    }

    #[test]
    fn empty_band_resolves_only_core() {
        let v = Vocab::empty();
        assert!(v.is_empty());
        assert_eq!(v.name_id(b"status"), by_name(b"status"));
        assert_eq!(v.name_id(b"frob"), None);
        assert_eq!(v.band_name(band_start()), None);
    }
}

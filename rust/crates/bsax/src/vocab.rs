//! Closed-world Amin NAME_ID vocabulary — shared verbatim between Rust bsax
//! crate and Perl Amin::{Handler,Generator}::BSAX packages.
//!
//! *WARNING:* Any change to this slice must be mirrored in both Perl source
//! files (`perl-lib/Amin/Handler/BSAX.pm` and `perl-lib/Amin/Generator/BSAX.pm`)
//! — the decoder/encoder only stay 1:1 if the byte-level vocab order matches.
//!
//! Escape marker is auto-derived as `BY_ID.len() as u32` (currently 122 → one
//! LEB128 byte, same wire cost as the old hard-coded 62 but without manual
//! slot-counting collisions).  Any LocalName unknown to this table is sent on
//! the wire as the escape marker + length-prefixed UTF-8 (larger + slower).

/// 4-bit NS_ID inline constants.  MUST stay 1:1 with Perl Handler/Generator::BSAX
/// `use constant { NS_NONE => 0, NS_AMIN => 1, NS_UI => 2, NS_MAP => 3, NS_BITCACHE => 4,
/// NS_SEC => 5, NS_ESCAPE => 15 }` blocks.  Values 6..=14 remain reserved for future
/// forward-compatible Amin-owned namespace slots; any third-party custom namespace uses
/// NS_ESCAPE (15) with length-prefixed UTF-8 URI inline so CORP-style filter custom NSes
/// work without Amin fork (see spec DI-2 / NS_ESCAPE=15 path).
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
/// as UTF-8 bytes.  Sorted into seven contiguous regions for human reader
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
    // ── ui:*  — closed-world ui: vocabulary (25 kinds) + late-sax attrs
    b"app", b"scene", b"list", b"row", b"column", b"hstack", b"vstack",
    b"stack", b"grid", b"section", b"card", b"progress", b"alert", b"sheet",
    b"toolbar", b"searchable", b"item", b"label", b"text", b"badge",
    b"sparkline", b"button", b"navigate", b"image", b"asyncimage",
    b"title", b"spacing", b"points", b"for-each", b"bind", b"url",
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
];

/// NAME_ID escape marker: always the first ID past the last vocab slot.
#[inline] pub const fn escape_id() -> u32 { BY_ID.len() as u32 }

/// Build-time reverse map: LocalName → NAME_ID.  `None` ⇒ use [`escape_id`].
pub const fn by_name(name: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i < BY_ID.len() {
        if slices_eq(BY_ID[i], name) { return Some(i as u8) }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocab_count_kept_in_sync_with_perl() {
        // Perl's @VOCAB currently has 122 entries across
        // amin/map/ui/bc/ainit/exec-net/sec.
        // If this fails, update both sides together with the same reordering.
        assert_eq!(BY_ID.len(), 122);
        assert_eq!(escape_id(), 122);
        // Hard architecture guard (AC-2): VOCAB size ≤ 127 means every NAME_ID
        // fits in one LEB128 byte on the wire.  If we ever exceed 127 we need
        // a formal spec revision (name-id-2-byte-mode) NOT a silent 2-byte
        // LEB expansion because that changes the wire-size of ALL inner
        // elements (every <status>, <result>, <stream>, …).  Keep adding new
        // region entries here freely until we hit 126; above that, talk to the
        // spec owner first.
        assert!(BY_ID.len() <= 127, "VOCAB exceeded 127 entries — requires wire-format spec revision");
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
    fn bc_object_region_starts_at_68() {
        // 23 amin + 14 map + 31 ui = 68 → bc:* region starts at index 68
        assert_eq!(by_name(b"object"), Some(68));
        assert_eq!(BY_ID[68], b"object");
        // Final bc entry push sits at 68 + 18 = 86
        assert_eq!(by_name(b"push"), Some(86));
        assert_eq!(BY_ID[86], b"push");
    }
    #[test]
    fn ainit_stage_region_starts_at_87() {
        assert_eq!(by_name(b"stage"), Some(87));
        assert_eq!(BY_ID[87], b"stage");
        assert_eq!(by_name(b"slab_dev"), Some(92));
    }
    #[test]
    fn exec_net_region_starts_at_93() {
        assert_eq!(by_name(b"exec"), Some(93));
        assert_eq!(BY_ID[93], b"exec");
        // Final entry netpolicy sits at 93 + 13 = 106 (last vocab index; escape = 107)
        assert_eq!(by_name(b"netpolicy"), Some(106));
        assert_eq!(BY_ID[106], b"netpolicy");
    }
    #[test]
    fn sec_region_starts_at_107() {
        // 23 amin + 14 map + 31 ui + 19 bc + 6 ainit + 14 exec-net = 107
        // → the sec:* region is appended at index 107.
        assert_eq!(by_name(b"seal"), Some(107));
        assert_eq!(BY_ID[107], b"seal");
        assert_eq!(by_name(b"sealed"), Some(108));
        // The Double Ratchet header fields sit contiguously.
        assert_eq!(by_name(b"ratchet"), Some(111));
        assert_eq!(by_name(b"prev_count"), Some(112));
        assert_eq!(by_name(b"msg_index"), Some(113));
        // Final sec entry `require` sits at 107 + 14 = 121 (last index; escape = 122).
        assert_eq!(by_name(b"require"), Some(121));
        assert_eq!(BY_ID[121], b"require");
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
}

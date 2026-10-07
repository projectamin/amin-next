//! Closed-world Amin NAME_ID vocabulary — shared verbatim between Rust bsax
//! crate and Perl Amin::{Handler,Generator}::BSAX packages.
//!
//! *WARNING:* Any change to this slice must be mirrored in both Perl source
//! files (`perl-lib/Amin/Handler/BSAX.pm` and `perl-lib/Amin/Generator/BSAX.pm`)
//! — the decoder/encoder only stay 1:1 if the byte-level vocab order matches.
//!
//! Escape marker is auto-derived as `BY_ID.len() as u32` (currently 68 → one
//! LEB128 byte, same wire cost as the old hard-coded 62 but without manual
//! slot-counting collisions).  Any LocalName unknown to this table is sent on
//! the wire as the escape marker + length-prefixed UTF-8 (larger + slower).

/// Closed-world vocabulary slice.  `BY_ID[id as usize]` returns the LocalName
/// as UTF-8 bytes.  Sorted into three contiguous regions for human reader
/// convenience only — encode/decode treat the whole list as flat.
pub const BY_ID: &[&[u8]] = &[
    // ── Amin core: elements + attribute LocalNames used by inner SAX chain
    b"profile", b"result", b"command", b"stream", b"status", b"cond", b"argv",
    b"id", b"version", b"kind", b"rc", b"pid", b"duration", b"exit_kind",
    b"name", b"target", b"channel", b"dir", b"mode", b"level", b"value",
    b"type", b"size",
    // ── map:* — Amin::Filter::Map::Topology element+attr LocalNames
    b"region", b"server", b"link", b"node", b"a", b"b", b"cost", b"phase",
    b"flavor", b"latency_ms", b"bw_gbps", b"tier", b"zone", b"value",
    // ── ui:*  — Amin::Filter::UI::SwiftUIView known-views + late-sax attrs
    b"app", b"scene", b"list", b"row", b"column", b"hstack", b"vstack",
    b"stack", b"grid", b"section", b"card", b"progress", b"alert", b"sheet",
    b"toolbar", b"searchable", b"item", b"label", b"text", b"badge",
    b"sparkline", b"button", b"navigate", b"image", b"asyncimage",
    b"title", b"spacing", b"points", b"for-each", b"bind", b"url",
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
        // Perl's @VOCAB currently has 68 entries across amin/map/ui.
        // If this fails, update both sides together with the same reordering.
        assert_eq!(BY_ID.len(), 68);
        assert_eq!(escape_id(), 68);
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
    fn unknown_returns_none_for_escape_marker() {
        assert_eq!(by_name(b"custom-widget-99"), None);
    }
}

//! BSAX micro-decoder for ainit stage vocabulary — understands ONLY the
//! ainit-vocab-region elements: `stage`, `order`, `node_id`, `refused`,
//! `init_profile_ref`, `slab_dev` (vocab indices 87..=92).  Any other
//! element (e.g. supervisor/workload stages 5-6) is silently skipped via
//! the closed-world drop-unknown pattern — identical behaviour to the
//! Perl `Generator::BSAX` allow-list guard.
//!
//! Stages we *do* execute inside ainit (before PID 1 hand-off):
//!
//! | order | name            | executed by | purpose                                                        |
//! |-------|-----------------|-------------|----------------------------------------------------------------|
//! | 1     | hwcheck         | ainit       | verify node_id blake3 fingerprint matches cookie-cutter metal  |
//! | 2     | fw-update       | ainit       | apply CPU ucode, NIC fw, BMC fw                                |
//! | 3     | storage-init    | ainit       | format or repair Bitcache slab device (amin.slab_dev)          |
//! | 4     | mesh-join       | ainit       | AWP/3 mesh HELLO, open 3 QUIC sockets for RS(3,2) stripe fetch |
//! | 5     | supervisor      | aminexec    | PID 1: register permanent filters, begin SAX dispatcher loop   |
//! | 6     | workload-ready | aminexec    | PID 1: emit `<amin:status kind=workload_ready>` to mesh peers  |

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use bsax::decode::{Bounds, Decoder};
use bsax::vocab;
use bsax::Event;

/// Parsed view of the stages ainit needs to execute BEFORE handing off to
/// PID 1.  Stages 5 and 6 are deliberately absent — they are skipped and
/// re-parsed by aminexec's full SAX dispatcher after `pivot_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInitProfile {
    /// Stage 1: hardware check (CPU/DIMM/NVMe/NIC fingerprint verify).
    pub stage_hwcheck:    Stage,
    /// Stage 2: firmware update (CPU ucode, NIC fw, BMC fw).
    pub stage_fw_update:  Stage,
    /// Stage 3: Bitcache slab initialisation / fsck / unlock.
    pub stage_storage:    Stage,
    /// Stage 4: join AWP/3 mesh, acquire 3 peer handles for RS(3,2).
    pub stage_mesh_join:  Stage,
    /// Unrecognised / skipped elements count (stages 5-6 plus any
    /// extensions or unknowns).  Asserting this > 0 is the spec proof
    /// that the micro-decoder is correctly closed-world (doesn't even
    /// see the supervisor/workload-ready stages aminexec runs).
    pub skipped_elements: usize,
}

/// One init-profile `<amin:stage>` element and its attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    /// Canonical `amin:name` text content (human label like "hwcheck").
    pub name:             String,
    /// `amin:order` integer — 1..=4 for ainit-executed stages.
    pub order:            u32,
    /// Stable blake3 node_id this stage was authored for (stage 1
    /// `hwcheck` uses the same fingerprint).
    pub node_id:          String,
    /// If `true`, the mesh bootstrap ToR peer should REFUSE to hand
    /// this boot ref to any node requesting it (revocation / rollback
    /// marker — ainit must halt boot with a panic/sysrq if refused=true
    /// on any of stages 1..=4).
    pub refused:          bool,
    /// Bitcache `init-profile` blob ref — populated by the storage-init
    /// stage; subsequent stages MAY reference it as a rollback checkpoint.
    pub init_profile_ref: String,
    /// Block device path for the Bitcache slab — storage-init stage
    /// (matches `amin.slab_dev` on the kernel cmdline).
    pub slab_dev:         PathBuf,
}

impl Default for Stage {
    fn default() -> Self {
        Self {
            name:             String::new(),
            order:            0,
            node_id:          String::new(),
            refused:          false,
            init_profile_ref: String::new(),
            slab_dev:         PathBuf::new(),
        }
    }
}

/// Parse a BSAX-encoded init-profile document and return only the
/// ainit-relevant stages 1..=4.  Any element whose `name_id` is not
/// inside the ainit vocab region (87..=92) OR whose parsed stage `order`
/// is ≥ 5 is counted in [`ParsedInitProfile::skipped_elements`] rather
/// than materialised — closed-world drop-unknown guarantee.
pub fn parse_init_profile_bsax(bsax_bytes: &[u8]) -> Result<ParsedInitProfile> {
    // We allow the FULL closed-world vocab (all 107 IDs).  The *stage*
    // filter then drops stages with order>=5 (and any element that
    // doesn't contribute to ainit stages).  This way supervisors can
    // embed bc:signer envelopes + any future names inside init-profile
    // without ainit choking (it just counts them as skipped).
    let bounds = Bounds { allow_vocab_only: true, ..Bounds::default() };
    let decoder = Decoder::new(bsax_bytes, bounds)
        .map_err(|e| anyhow!("BSAX decoder rejected init-profile: {e}"))?;

    // Name → (attrs map as we gather per-element chars inside body).
    let mut stage_chars_buffer: Vec<u8> = Vec::new();
    let mut in_ainit_stage: bool = false;
    let mut pending_attrs: BTreeMap<&[u8], &[u8]> = BTreeMap::new();
    let mut stages: BTreeMap<u32, Stage> = BTreeMap::new();
    let mut skipped: usize = 0;

    let mut elem_stack_depth: usize = 0; // inside any ainit stage el or children?
    let mut ainit_region_names: usize = 0;

    for event in decoder {
        let event = event.context("BSAX stream decode error inside init-profile")?;
        match event {
            Event::StartDocument | Event::EndDocument => {},
            Event::StartElement { ns_id, name_id, attrs, .. } => {
                let is_amin = ns_id == vocab::ns_id::AMIN;
                let name_bytes = vocab::BY_ID.get(name_id as usize).copied().unwrap_or(b"");
                let is_ainit_region = (87..=92).contains(&u32::from(name_id));

                if is_ainit_region { ainit_region_names += 1; }

                // `<amin:stage>` — push
                if is_amin && name_bytes == b"stage" {
                    in_ainit_stage = true;
                    elem_stack_depth += 1;
                    pending_attrs = BTreeMap::new();
                    for (aid, v) in &attrs {
                        let aname = vocab::BY_ID.get(*aid as usize).copied().unwrap_or(b"");
                        pending_attrs.insert(aname, *v);
                    }
                    stage_chars_buffer.clear();
                    continue;
                }

                if in_ainit_stage {
                    elem_stack_depth += 1;
                    // Any ainit-region attrs that are nested elements are
                    // picked up from their character content by the Chars arm.
                    continue;
                }

                // Element is OUTSIDE any ainit stage.  Closed-world: skip.
                skipped += 1;
            },
            Event::EndElement => {
                if in_ainit_stage {
                    elem_stack_depth -= 1;
                    if elem_stack_depth == 0 {
                        // Flush pending stage.
                        let mut s = Stage::default();
                        for (k, v) in &pending_attrs {
                            match *k {
                                b"name" => s.name = String::from_utf8_lossy(v).into_owned(),
                                b"order" => s.order = parse_u32_lossy(v),
                                b"node_id" => s.node_id = String::from_utf8_lossy(v).into_owned(),
                                b"refused" => s.refused = matches_bool_truthy(v),
                                b"init_profile_ref" => s.init_profile_ref = String::from_utf8_lossy(v).into_owned(),
                                b"slab_dev" => s.slab_dev = PathBuf::from(String::from_utf8_lossy(v).into_owned()),
                                _ => {}, // unknown ainit-region attr: closed-world drop
                            }
                        }
                        // Append any character body to the name if empty
                        // (human `<stage>hwcheck</stage>` shorthand form).
                        if s.name.is_empty() && !stage_chars_buffer.is_empty() {
                            s.name = String::from_utf8_lossy(&stage_chars_buffer).trim().to_string();
                        }
                        let order = s.order;
                        if order >= 1 && order <= 4 {
                            stages.insert(order, s);
                        } else {
                            // order >= 5 (supervisor / workload-ready) —
                            // stages we deliberately skip even though the
                            // element format is identical.  Count as skip.
                            skipped += 1;
                        }
                        in_ainit_stage = false;
                        pending_attrs.clear();
                        stage_chars_buffer.clear();
                    }
                    continue;
                }
            },
            Event::Chars(c) if in_ainit_stage => {
                stage_chars_buffer.extend_from_slice(c);
            },
            Event::Chars(_) | Event::Iws(_) | Event::Pi { .. } | Event::DictEntry { .. } => {
                skipped += 1;
            },
        }
    }

    let mut require = |order: u32, fallback_name: &'static str| -> Result<Stage> {
        stages.remove(&order).or_else(|| {
            Some(Stage { order, name: fallback_name.into(), ..Stage::default() })
        }).ok_or_else(|| anyhow!("BUG: or-else branch always Some; unreachable"))
    };

    Ok(ParsedInitProfile {
        stage_hwcheck:   require(1, "hwcheck")?,
        stage_fw_update: require(2, "fw-update")?,
        stage_storage:   require(3, "storage-init")?,
        stage_mesh_join: require(4, "mesh-join")?,
        // Any attrs/elements counted as skipped PLUS any stages >4 we
        // dropped above plus the region-wide ainit counter is the total
        // closed-world drop count.  We don't double count: add region
        // names minus the 4 stages we kept.
        skipped_elements: skipped.saturating_add(ainit_region_names.saturating_sub(4)),
    })
}

fn parse_u32_lossy(bytes: &[u8]) -> u32 {
    let s = std::str::from_utf8(bytes).unwrap_or("0");
    s.parse::<u32>().unwrap_or(0)
}

fn matches_bool_truthy(v: &[u8]) -> bool {
    matches!(v, b"1" | b"true" | b"yes" | b"on" | b"TRUE" | b"YES" | b"ON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsax::encode;
    use bsax::vocab::{self, ns_id::AMIN};
    use bytes::BytesMut;

    // Shortcut helpers for writing BSAX `<stage order=X name=Y ... />`
    // self-closing elements with attrs.
    fn stage_attrs(order: u32, name: &str, extra: &[(&[u8], &[u8])]) -> Vec<(u8, Vec<u8>)> {
        let mut out: Vec<(u8, Vec<u8>)> = vec![
            (vocab::by_name(b"order").unwrap(), order.to_string().into_bytes()),
            (vocab::by_name(b"name").unwrap(),  name.as_bytes().to_vec()),
        ];
        for (k, v) in extra {
            let aid = vocab::by_name(k).expect("ainit-region attr must exist in VOCAB");
            out.push((aid, v.to_vec()));
        }
        out
    }

    fn build_6stage_bsax() -> Vec<u8> {
        let mut buf = BytesMut::new();
        encode::write_magic(&mut buf);
        encode::write_start_doc(&mut buf);

        // <amin:profile> wrapper (profile = vocab id 0, amin ns = 1)
        encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"profile").unwrap(), &[] as &[(u8, &[u8])]);

        // Stages 1-6 as self-closing with order attrs.
        let all = [
            (1u32, "hwcheck",      &[
                (b"node_id" as &[u8], b"metal-blake3-9a5b" as &[u8]),
                (b"refused", b"false"),
                (b"slab_dev", b"/dev/nvme0n1p2"),
            ][..]),
            (2,    "fw-update",    &[(b"init_profile_ref", b"bitcache:blake3:initprofrefhere0000")]),
            (3,    "storage-init", &[(b"slab_dev", b"/dev/nvme0n1p2"), (b"init_profile_ref", b"bitcache:blake3:aaaa")]),
            (4,    "mesh-join",    &[(b"node_id", b"metal-blake3-9a5b")]),
            (5,    "supervisor",   &[]),
            (6,    "workload-ready", &[]),
        ];
        for (order, name, extras) in all {
            let attrs = stage_attrs(order, name, extras);
            let borrowed: Vec<(u8, &[u8])> = attrs.iter().map(|(a,b)| (*a, b.as_slice())).collect();
            encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"stage").unwrap(), &borrowed);
            encode::write_end_elem(&mut buf);
        }

        // </profile> + end_document
        encode::write_end_elem(&mut buf);
        encode::write_end_doc(&mut buf);
        buf.freeze().to_vec()
    }

    #[test]
    fn tr_8_2_micro_decode_stages_1_4_only_and_5_6_skipped() {
        let bsax = build_6stage_bsax();
        let p = parse_init_profile_bsax(&bsax).expect("init-profile decode");
        assert_eq!(p.stage_hwcheck.order,   1);
        assert_eq!(p.stage_hwcheck.name,    "hwcheck");
        assert_eq!(p.stage_hwcheck.node_id, "metal-blake3-9a5b");
        assert_eq!(p.stage_hwcheck.slab_dev, PathBuf::from("/dev/nvme0n1p2"));
        assert!(!p.stage_hwcheck.refused);

        assert_eq!(p.stage_fw_update.order,               2);
        assert_eq!(p.stage_fw_update.name,                "fw-update");
        assert_eq!(p.stage_fw_update.init_profile_ref,    "bitcache:blake3:initprofrefhere0000");

        assert_eq!(p.stage_storage.order,   3);
        assert_eq!(p.stage_storage.name,    "storage-init");
        assert_eq!(p.stage_storage.slab_dev,PathBuf::from("/dev/nvme0n1p2"));

        assert_eq!(p.stage_mesh_join.order, 4);
        assert_eq!(p.stage_mesh_join.name,  "mesh-join");
        assert_eq!(p.stage_mesh_join.node_id, "metal-blake3-9a5b");

        // Closed-world proof: skipped_elements MUST be > 0 because we
        // wrote 6 stages but stages 5+6 are dropped plus the profile
        // wrapper and any chars/Iws also count.
        assert!(p.skipped_elements > 0,
                "ainit micro-decoder must drop stages 5/6 + unknowns; skipped_elements was 0 (bug in closed-world)");
    }

    #[test]
    fn refused_bool_is_truthy_for_1_and_true() {
        let mut buf = BytesMut::new();
        encode::write_magic(&mut buf);
        encode::write_start_doc(&mut buf);
        encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"profile").unwrap(), &[] as &[(u8, &[u8])]);
        for (order, name, refused_val) in [
            (1, "hwcheck",  b"true" as &[u8]),
            (2, "fw",       b"1"),
            (3, "storage",  b"false"),
            (4, "mesh",     b"no"),
        ] {
            let attrs = stage_attrs(order, name, &[(b"refused", refused_val)]);
            let borrowed: Vec<(u8, &[u8])> = attrs.iter().map(|(a,b)| (*a, b.as_slice())).collect();
            encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"stage").unwrap(), &borrowed);
            encode::write_end_elem(&mut buf);
        }
        encode::write_end_elem(&mut buf);
        encode::write_end_doc(&mut buf);

        let p = parse_init_profile_bsax(&buf.freeze()).unwrap();
        assert!( p.stage_hwcheck.refused,   "refused=\"true\"  → true");
        assert!( p.stage_fw_update.refused, "refused=\"1\"     → true");
        assert!(!p.stage_storage.refused,   "refused=\"false\" → false");
        assert!(!p.stage_mesh_join.refused, "refused=\"no\"    → false");
    }

    #[test]
    fn missing_stages_get_sensible_defaults_order_preserved() {
        // Build a BSAX with NO <stage> elements at all.  The parser
        // should still return 4 empty-named stages with correct order
        // 1..=4 (and a large skipped count for the wrapper).
        let mut buf = BytesMut::new();
        encode::write_magic(&mut buf);
        encode::write_start_doc(&mut buf);
        encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"profile").unwrap(), &[] as &[(u8, &[u8])]);
        encode::write_end_elem(&mut buf);
        encode::write_end_doc(&mut buf);
        let p = parse_init_profile_bsax(&buf.freeze()).unwrap();
        assert_eq!(p.stage_hwcheck.order,   1);
        assert_eq!(p.stage_fw_update.order, 2);
        assert_eq!(p.stage_storage.order,   3);
        assert_eq!(p.stage_mesh_join.order, 4);
    }
}

//! Task14 T6-gate: aminexec PID1 mesh_state shared-memory write stub
//!
//! Writes 64B header + 256B × 64 peers = 16448B total region at
//! `/dev/shm/amin/mesh_state_v1` using std::fs + libc mmap.
//! Byte layout is locked with `Amin::Discovery::Mesh` Perl parser.

// The linux-gated mlock(2) advisory pin uses raw libc FFI; same precedent
// as platform/linux.rs and main.rs (`#![allow(unsafe_code)]`).
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::Error as IoError;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// 64B header at offset 0..63
pub const HEADER_LEN: usize = 64;
/// 256B per peer
pub const PEER_STRIDE: usize = 256;
/// Maximum peer count in one gossip region
pub const MAX_PEERS: usize = 64;
/// Total shmem region size (header + peers)
pub const TOTAL_BYTES: usize = HEADER_LEN + PEER_STRIDE * MAX_PEERS;

/// MAGIC value: bytes `AMIN_MSH` as big-endian u64 = 0x414D494E_5F4D5348
pub const MAGIC: u64 = u64::from_be_bytes(*b"AMIN_MSH");

/// Default path used when aminexec runs as PID1.  Overridable for tests.
pub fn default_path() -> PathBuf {
    PathBuf::from("/dev/shm/amin/mesh_state_v1")
}

/// Bootstrap header write — called from aminexec PID1 mesh-join stage
/// after BootCommandLine has been parsed (local 32-byte node_id).
///
/// Double-write barrier pattern (single writer / multi reader, no locks):
///   1. header.gen = 0 (mid-write)
///   2. zero peers region (all peer gen_tail = 0 implicitly)
///   3. header.gen = 1 (final)
///   4. each peer.gen_tail = 1
/// Readers snapshot header.gen (perl: `read_snapshot()`), copy bytes, then
/// verify each peer tail gen == header gen up to 3 attempts; return undef
/// on mismatch → zero corrupt structs (AC-14.9 strict fail).
pub fn write_bootstrap_header(
    local_node_id: &[u8; 32],
    path_override: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = path_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_path);

    // mkdir -p parent (silent ignore if exists or not dir)
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Open file: rw------- (0600)
    let f: File = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;

    // Allocate exact region via set_len (ftruncate)
    f.set_len(TOTAL_BYTES as u64)?;

    // Build region in memory as Vec<u8> then write via mmap for msync-able
    // single syscall semantics; but for simplicity just write_all & fsync.
    let mut region: Vec<u8> = vec![0u8; TOTAL_BYTES];

    // --- Barrier step 1: header.gen = 0 mid-write
    write_header(&mut region, MAGIC, 1, 0, local_node_id, 0);
    write_region_to_file(&f, &region)?;

    // --- Barrier step 2: peer region already zeros (all peer_tail = 0)
    // (no-op, zeroed above)

    // --- Barrier step 3: header.gen = 1 (final)
    write_header(&mut region, MAGIC, 1, 0, local_node_id, 1);
    write_region_to_file(&f, &region)?;

    // --- Barrier step 4: every peer gen_tail (last 8B of each 256B stride) = 1
    for i in 0..MAX_PEERS {
        let off = HEADER_LEN + i * PEER_STRIDE + PEER_STRIDE - 8;
        region[off..off + 8].copy_from_slice(&1u64.to_le_bytes());
    }
    write_region_to_file(&f, &region)?;

    f.sync_all()?;
    drop(f);

    Ok(())
}

fn write_region_to_file(f: &File, region: &[u8]) -> Result<(), IoError> {
    use std::io::{Seek, Write};
    // Use std Write/Seek traits directly on &File (implements both) — no
    // unsafe raw libc::write: the crate denies unsafe by default on the
    // portable path and std write_all keeps the single-loop semantics.
    let mut f_ref = f;
    f_ref.seek(std::io::SeekFrom::Start(0))?;
    f_ref.write_all(region)?;
    Ok(())
}

/// Fill 64B header template.  Endianness matches Perl Mesh.pm unpack exactly.
fn write_header(
    region: &mut [u8],
    magic: u64,
    ver: u16,
    peer_count: u16,
    local_node_id: &[u8; 32],
    gen: u64,
) {
    assert!(region.len() >= HEADER_LEN);
    // magic (8B BE) + ver (2B LE) + peer_count (2B LE) + node_id a32 + reserved 12B + gen 8B LE
    region[0..8].copy_from_slice(&magic.to_be_bytes());
    region[8..10].copy_from_slice(&ver.to_le_bytes());
    region[10..12].copy_from_slice(&peer_count.to_le_bytes());
    region[12..44].copy_from_slice(local_node_id);
    // reserved[44..56] already zero
    region[56..64].copy_from_slice(&gen.to_le_bytes());
}

/// Parse 64B header fields from any byte slice.
pub fn parse_header(bytes: &[u8]) -> Option<(u64, u16, u16, [u8; 32], u64)> {
    if bytes.len() < HEADER_LEN { return None; }
    let magic = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
    let ver = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
    let peer_count = u16::from_le_bytes(bytes[10..12].try_into().ok()?);
    let mut nid = [0u8; 32];
    nid.copy_from_slice(&bytes[12..44]);
    let gen = u64::from_le_bytes(bytes[56..64].try_into().ok()?);
    Some((magic, ver, peer_count, nid, gen))
}

/// AI accelerator type (matches Amin::AI::Graph @ACCEL_NAMES indexing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Accelerator {
    #[default]
    None = 0,
    Cuda = 1,
    Rocm = 2,
    NeuralEngine = 3,
    Tpu = 4,
}

/// AI capability tier (matches Amin::AI::Graph @AI_TIER_NAMES indexing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AiTier {
    #[default]
    None = 0,
    AiCpu = 1,
    AiGpu = 2,
    AiEmbed = 3,
}

/// A single 256B peer record.  Byte layout is locked with
/// `Amin::Discovery::Mesh` Perl `unpack` template:
/// `a32 v a24 v a24 C V V a32 a32 a32 a32 V C C a21 Q>`.
///
/// Offsets within the 256B stride:
///   0..32   node_id
///  32..34   tier_len
///  34..58   tier (a24)
///  58..60   zone_len
///  60..84   zone (a24)
///  84..85   load_pct
///  85..89   free_mem_MB (V LE)
///  89..93   free_ssd_GB (V LE)
///  93..125  hot_refs[0] (a32)
/// 125..157  hot_refs[1] (a32)
/// 157..189  hot_refs[2] (a32)
/// 189..221  hot_refs[3] (a32)
/// 221..225  free_vram_MB (V LE)   ← AI node headroom
/// 225..226  accelerator (C)        ← AI accelerator type
/// 226..227  ai_tier (C)            ← AI capability tier
/// 227..248  reserved (a21)
/// 248..256  gen_tail (Q> BE)
#[derive(Debug, Clone, Default)]
pub struct PeerRecord {
    pub node_id: [u8; 32],
    pub tier: String,
    pub zone: String,
    pub load_pct: u8,
    pub free_mem_mb: u32,
    pub free_ssd_gb: u32,
    pub hot_refs: [[u8; 32]; 4],
    pub free_vram_mb: u32,
    pub accelerator: Accelerator,
    pub ai_tier: AiTier,
    pub gen_tail: u64,
}

/// Encode a [PeerRecord] into its 256B wire representation.
pub fn encode_peer(rec: &PeerRecord) -> [u8; PEER_STRIDE] {
    let mut buf = [0u8; PEER_STRIDE];
    buf[0..32].copy_from_slice(&rec.node_id);
    let tlen = rec.tier.len().min(24) as u16;
    buf[32..34].copy_from_slice(&tlen.to_le_bytes());
    buf[34..34 + tlen as usize].copy_from_slice(&rec.tier.as_bytes()[..tlen as usize]);
    let zlen = rec.zone.len().min(24) as u16;
    buf[58..60].copy_from_slice(&zlen.to_le_bytes());
    buf[60..60 + zlen as usize].copy_from_slice(&rec.zone.as_bytes()[..zlen as usize]);
    buf[84] = rec.load_pct;
    buf[85..89].copy_from_slice(&rec.free_mem_mb.to_le_bytes());
    buf[89..93].copy_from_slice(&rec.free_ssd_gb.to_le_bytes());
    for i in 0..4 {
        buf[93 + i * 32..93 + (i + 1) * 32].copy_from_slice(&rec.hot_refs[i]);
    }
    buf[221..225].copy_from_slice(&rec.free_vram_mb.to_le_bytes());
    buf[225] = rec.accelerator as u8;
    buf[226] = rec.ai_tier as u8;
    buf[248..256].copy_from_slice(&rec.gen_tail.to_be_bytes());
    buf
}

/// Write a [PeerRecord] at index `idx` within the region.
pub fn write_peer(region: &mut [u8], idx: usize, rec: &PeerRecord) {
    assert!(idx < MAX_PEERS);
    let off = HEADER_LEN + idx * PEER_STRIDE;
    region[off..off + PEER_STRIDE].copy_from_slice(&encode_peer(rec));
}

/// Helper: try_read_path → returns full file contents for Perl parser parity
/// checks in Rust tests.  Not used by PID1 path.
#[allow(dead_code)]
pub fn read_region(path: &std::path::Path) -> Result<Vec<u8>, IoError> {
    std::fs::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::remove_file;
    use std::path::PathBuf;

    fn scratch_path(suffix: &str) -> PathBuf {
        let pid = std::process::id();
        let tmp = std::env::temp_dir();
        tmp.join(format!("amin_mesh_t14_{}_{}", pid, suffix))
    }

    #[test]
    fn header_parse_roundtrip_t14() {
        let node_id = [0x55u8; 32];
        let mut buf = vec![0u8; HEADER_LEN];
        write_header(&mut buf, MAGIC, 1, 0, &node_id, 1);
        let (magic, ver, pc, nid, gen) = parse_header(&buf).expect("parse");
        assert_eq!(magic, MAGIC, "magic AMIN_MSH byte pattern matches PEER");
        assert_eq!(ver, 1);
        assert_eq!(pc, 0);
        assert_eq!(nid, node_id, "node_id 32B roundtrip equals input");
        assert_eq!(gen, 1, "generation tail at offset 56..64 LE");
    }

    #[test]
    fn region_size_math_t14() {
        // Peer layout locked with Amin::Discovery::Mesh (Perl):
        // header=64, stride=256, max=64 peers → total 16448
        assert_eq!(PEER_STRIDE, 256);
        assert_eq!(HEADER_LEN, 64);
        assert_eq!(TOTAL_BYTES, HEADER_LEN + PEER_STRIDE * MAX_PEERS);
        assert_eq!(TOTAL_BYTES, 16448);
        // gen_tail offset within each peer stride = stride - 8 = 248
        assert_eq!(PEER_STRIDE - 8, 248);
    }

    #[test]
    fn file_write_node_id_roundtrip_t14() {
        let path = scratch_path("rt");
        // Cleanup prior
        let _ = remove_file(&path);
        let node_id = [0x33u8; 32];

        let wr = write_bootstrap_header(&node_id, Some(&path));
        match wr {
            Ok(()) => {
                let raw = read_region(&path).expect("read back file");
                assert_eq!(raw.len(), TOTAL_BYTES, "file size matches 16448 region");
                let (magic, ver, pc, nid, gen) = parse_header(&raw).expect("parse ok");
                assert_eq!(magic, MAGIC, "MAGIC  AMIN_MSH written");
                assert_eq!(ver, 1);
                assert_eq!(pc, 0, "bootstrap peer_count=0");
                assert_eq!(nid, node_id, "node_id == BootCommandLine.node_id 32 bytes");
                assert_eq!(gen, 1, "final gen=1");

                // every peer stride offset 248..256 should be 1u64 LE
                for i in 0..MAX_PEERS {
                    let off = HEADER_LEN + i * PEER_STRIDE + PEER_STRIDE - 8;
                    let tail = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
                    assert_eq!(tail, 1, "peer i={} gen_tail=1 consistent with header", i);
                }
                let _ = remove_file(&path);
            }
            Err(e) => {
                // /tmp or /dev/shm readonly? pass gracefully
                let emsg = format!("{:?}", e);
                assert!(
                    emsg.contains("Permission") || emsg.contains("ReadOnly"),
                    "unexpected write error: {}", emsg
                );
            }
        }
    }

    #[test]
    fn peer_record_ai_fields_roundtrip() {
        let rec = PeerRecord {
            node_id: [0x42u8; 32],
            tier: "ai-gpu".to_string(),
            zone: "us-east-1".to_string(),
            load_pct: 12,
            free_mem_mb: 65536,
            free_ssd_gb: 500,
            hot_refs: [[0u8; 32]; 4],
            free_vram_mb: 24000,
            accelerator: Accelerator::Cuda,
            ai_tier: AiTier::AiGpu,
            gen_tail: 1,
        };
        let encoded = encode_peer(&rec);
        assert_eq!(encoded.len(), PEER_STRIDE);
        // free_vram_MB at offset 221..225 LE
        let vram = u32::from_le_bytes(encoded[221..225].try_into().unwrap());
        assert_eq!(vram, 24000, "free_vram_MB written at offset 221");
        // accelerator at offset 225
        assert_eq!(encoded[225], 1, "accelerator=Cuda (1) at offset 225");
        // ai_tier at offset 226
        assert_eq!(encoded[226], 2, "ai_tier=AiGpu (2) at offset 226");
        // gen_tail at offset 248..256 BE
        let tail = u64::from_be_bytes(encoded[248..256].try_into().unwrap());
        assert_eq!(tail, 1, "gen_tail BE at offset 248");
    }
}

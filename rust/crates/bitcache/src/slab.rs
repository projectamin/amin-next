use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::{BitcacheError, Result};
use crate::index::{IdxEntry, ShmemIndex};

/// 32-byte blake3 object identity — matches the `<bc:hash>` attribute LocalName
/// vocabulary slot 69 (`bc/0` = hash).  The wire format carries it as
/// length-prefixed bytes in BSAX; 32 bytes + 1 LEB is 33 bytes on BSAX (under
/// the single-LEB guard AC-2 since NAME_ID < 127).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ObjRef(pub [u8; 32]);
impl ObjRef {
    /// Returns a borrowed slice of the 32-byte hash digest.
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}
impl std::ops::Deref for ObjRef {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target { &self.0 }
}

/// 4 KiB alignment for O_DIRECT writes.  Any buffer passed to `put` whose
/// `buf.len() + HEADER_LEN` is not a multiple of 4 KiB will be zero-padded on
/// the wire; the reader truncates using the stored 4-byte `actual_len` header
/// field so callers never see the padding.
pub const ALIGN: usize = 4096;
const HEADER_LEN: usize = 4 + 4 + 32;  // actual_len(u32) + pad(u32) + blake3(32)

/// On-disk object layout, one after another, 4 KiB aligned:
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │  actual_len  │  pad_len  │  blake3(32)  │   data   │  0s   │
/// │    u32 LE    │   u32 LE  │    digest    │  (actual)│(pad) │
/// │         ( 4 + 4 + 32 = 40 bytes header )                  │
/// └─────────────────────────────────────────────────────────────┘
/// ```
/// `round_up_to_ALIGN(40 + actual_len)` bytes occupy one slot.
fn slot_size(payload: usize) -> usize {
    let s = HEADER_LEN + payload;
    (s + ALIGN - 1) / ALIGN * ALIGN
}

/// One append-only / random-read slab file.  Locked with `flock LOCK_EX` so two
/// aminexec instances don't double-write to the same slab.
pub struct SlabFile {
    path:   PathBuf,
    file:   File,
    /// The shmem mmapped index.  `(ObjRef) -> (offset, len, refcount, atime)`.
    index:  ShmemIndex,
}

impl SlabFile {
    /// Open or create the slab at `path`; its shmem sidecar lives next to it
    /// with suffix `.idx` (PID 1 ainit guarantees this via `pivot_root`-safe
    /// absolute paths under `/srv/amin/slabs/`).
    pub fn open_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        // O_DIRECT + flock LOCK_EX; file size grows by append.
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        if cfg!(not(miri)) {
            opts.custom_flags(libc_like_o_direct());
        }
        let file = opts.open(&path)?;
        // Flock exclusive — aminexec is single-writer per slab (multiple
        // processes hold shared handles but only one owns the flock; the
        // waiters spin on flock until the writer releases the lock — that's
        // our fine-grained per-slab write lock; mesh-fanout uses separate
        // slabs so cross-process contention is low).
        flock_ex(&file)?;
        let idx_path = PathBuf::from(format!("{}.idx", path.display()));
        let index    = ShmemIndex::open_or_create(idx_path)?;
        Ok(Self { path, file, index })
    }

    /// Put `data` into the slab.  Returns the object ref (blake3 digest).
    /// Deduplicated: if the ref is already present we bump the refcount and
    /// write **0** new bytes.
    pub fn put(&mut self, data: &[u8]) -> Result<ObjRef> {
        let digest = blake3::hash(data);
        let r      = ObjRef(*digest.as_bytes());
        if let Some(mut e) = self.index.get(&r)? {
            // Dedup: ref already in slab → bump refcount + touch atime.
            e.refcount  = e.refcount.saturating_add(1);
            e.atime     = now_secs();
            self.index.put(&r, e)?;
            return Ok(r);
        }
        // Compose one 4K-aligned slot for the object.
        let slot = slot_size(data.len());
        let mut buf: Vec<u8> = vec![0u8; slot];
        buf[0..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let pad = slot - HEADER_LEN - data.len();
        buf[4..8].copy_from_slice(&(pad as u32).to_le_bytes());
        buf[8..40].copy_from_slice(digest.as_bytes());
        buf[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
        // pad bytes already zeroed in vec![0..]

        let file = &mut self.file;
        let off  = file.seek(SeekFrom::End(0))?;
        let aligned = aligned_4k_copy(&buf);
        file.write_all(&aligned)?;
        file.flush()?;
        // fsync every slot — PID 1 metal mode means losing a slot to power
        // loss loses a signed deliverable; fsync here is the commit.
        file.sync_all()?;

        self.index.put(&r, IdxEntry {
            offset:   off,
            len:      slot as u32,
            refcount: 1,
            atime:    now_secs(),
        })?;
        Ok(r)
    }

    /// Retrieve the object referenced by `r`.  Returns the raw user bytes
    /// (header + zero-padding stripped, verified against the stored blake3
    /// digest — mismatch is HashMismatch which MUST fail closed).
    pub fn get(&mut self, r: &ObjRef) -> Result<Vec<u8>> {
        let entry = self.index.get(r)?.ok_or_else(||
            BitcacheError::ObjectMissing(r.to_vec().into_boxed_slice()))?;
        // Update atime — GC uses min_age(atime).
        let mut touched = entry.clone();
        touched.atime = now_secs();
        self.index.put(r, touched)?;

        let file = &mut self.file;
        file.seek(SeekFrom::Start(entry.offset))?;
        let slot_bytes = entry.len as usize;
        let raw = vec![0u8; slot_bytes];
        let mut aligned = aligned_4k_copy(&raw);
        let saw = file.read(&mut aligned_keep_mut(&mut aligned, slot_bytes))?;
        if saw != slot_bytes {
            return Err(BitcacheError::CorruptedRead {
                offset: entry.offset, expected: slot_bytes, saw,
            });
        }
        let actual_len = u32::from_le_bytes(aligned[0..4].try_into().unwrap()) as usize;
        let pad_len    = u32::from_le_bytes(aligned[4..8].try_into().unwrap()) as usize;
        let stored     = <[u8; 32]>::try_from(&aligned[8..40]).unwrap();
        let payload    = &aligned[HEADER_LEN..][..actual_len];
        // Close-by-hash: if an attacker wrote the data field but missed the
        // blake3 stored digest, fail here.  Combined with ML-DSA signed outer
        // envelopes (`<bc:signer>` in the XML profile) this gives us two
        // independent integrity proofs.
        let computed = blake3::hash(payload);
        if *computed.as_bytes() != stored {
            return Err(BitcacheError::HashMismatch { offset: entry.offset });
        }
        // Sanity-check pad math.
        assert_eq!(HEADER_LEN + actual_len + pad_len, slot_bytes);
        Ok(payload.to_vec())
    }

    /// Garbage-collect: if slab usage (file len / capacity) >= `threshold`
    /// (e.g. 0.85) then evict entries whose `atime` is older than `min_age`
    /// (e.g. 7 days) with refcount <= 1.  Returns (freed_slots, freed_bytes).
    ///
    /// Note: this is a simple compacting GC for the shmem index; the actual
    /// slab bytes remain on disk and will be overwritten on the next
    /// `put_batch` (not implemented — for Phase 1 we rely on 1 TiB max slabs
    /// rolling over to a new file).
    pub fn gc(&mut self, threshold: f64, min_age: Duration)
             -> Result<(usize, u64)>
    {
        let cap = self.slab_capacity_bytes();
        let used = self.file.metadata()?.len();
        if (used as f64) < threshold * (cap as f64) {
            return Ok((0, 0));
        }
        let oldest_ok = now_secs().saturating_sub(min_age.as_secs());
        let mut freed_slots = 0usize;
        let mut freed_bytes = 0u64;
        self.index.retain(|_r, e| {
            let keep = e.refcount > 1 || e.atime >= oldest_ok;
            if !keep {
                freed_slots += 1;
                freed_bytes += e.len as u64;
            }
            keep
        })?;
        Ok((freed_slots, freed_bytes))
    }

    /// 1 TiB default slab capacity.  Phase 0 / 1 hardcode (Phase 2 adds
    /// multi-slab rollover).
    fn slab_capacity_bytes(&self) -> u64 { 1 << 40 }

    /// Path to this slab (for logging / ainit stage 4 audit).
    pub fn path(&self) -> &Path { &self.path }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

fn flock_ex(f: &File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = f.as_raw_fd();
    // SAFETY: flock(2) has no memory-safety concerns.
    let r = unsafe { libc_flock(fd, libc_lock_ex()) };
    if r != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Platform flock + O_DIRECT shims.  For Linux we use the raw libc constants;
/// on non-Linux we drop O_DIRECT (the unit tests still pass because the
/// dedup+integrity logic does not depend on the O_DIRECT flag being honoured —
/// only on the 4K alignment of buffers we ourselves guarantee).
#[cfg(target_os = "linux")]
fn libc_like_o_direct() -> i32 { 0o40000 } // O_DIRECT Linux x86_64/aarch64
#[cfg(not(target_os = "linux"))]
fn libc_like_o_direct() -> i32 { 0 }

#[cfg(target_os = "linux")]
fn libc_lock_ex() -> i32 { 2 } // LOCK_EX on Linux / *BSD (FreeBSD: also 2, Open: 2)
#[cfg(not(target_os = "linux"))]
fn libc_lock_ex() -> i32 { 2 }

#[cfg(target_os = "linux")]
unsafe fn libc_flock(fd: i32, op: i32) -> i32 { libc_raw::flock(fd, op) }
#[cfg(not(target_os = "linux"))]
unsafe fn libc_flock(_fd: i32, _op: i32) -> i32 { 0 } // no-op on unsupported

#[cfg(target_os = "linux")]
mod libc_raw {
    #[link(name = "c")]
    extern "C" { pub fn flock(fd: i32, op: i32) -> i32; }
}

/// Allocate a Vec<u8> whose `.as_ptr()` is 4 KiB aligned AND whose `.len()`
/// equals exactly `size` (which must be a multiple of ALIGN).  Returns the
/// Vec filled with the bytes from `src` (src.len() == size must hold).
///
/// O_DIRECT requires the user buffer to be size-aligned *and* pointer-aligned
/// to the filesystem block size; we always use 4 KiB which works on every
/// filesystem Amin runs on (Linux ext4 / xfs / btrfs).  Using GlobalAlloc
/// with an explicit layout is the only portable way to guarantee pointer
/// alignment without pulling in an extra `aligned-vec` dependency.
fn aligned_4k_copy(src: &[u8]) -> Vec<u8> {
    use std::alloc::{alloc, handle_alloc_error, Layout};
    use std::ptr::copy_nonoverlapping;

    let size = src.len();
    assert!(size > 0, "slab slot must be non-empty");
    assert_eq!(size % ALIGN, 0, "slab slot size must be 4K multiple; got {size}");

    // SAFETY: ALIGN is non-zero power-of-two (4096).  size is nonzero.
    // size + ALIGN - 1 could theoretically overflow usize for silly sizes
    // (1 TiB slab — our slab_capacity_bytes is 1<<40 which fits in usize).
    let layout = Layout::from_size_align(size, ALIGN)
        .expect("size 1 TiB or less; power-of-two align; must fit layout");
    let raw = unsafe { alloc(layout) };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    // SAFETY: layout guarantees size bytes valid for writes, `src` has size
    // bytes, regions don't overlap (separate allocations).
    unsafe {
        copy_nonoverlapping(src.as_ptr(), raw, size);
    }
    // Wrap into a Vec so the caller can use normal slice APIs; Vec will
    // deallocate the memory on drop using the same global allocator that
    // produced it (Vec's default allocator is std::alloc::System which
    // matches std::alloc::alloc above).
    unsafe { Vec::from_raw_parts(raw, size, size) }
}
fn aligned_keep_mut(buf: &mut [u8], take: usize) -> &mut [u8] {
    &mut buf[..take]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn put_dedup_idempotent() {
        // 100 MB identical payload written twice → slab size stays < data
        // size (not 2x).  Asserts blake3 dedup on fast path.
        let tmp = tempdir().unwrap();
        let mut slab = SlabFile::open_or_create(
            tmp.path().join("dedup.slab")).unwrap();
        let big: Vec<u8> = vec![0xAB; 100 * 1024 * 1024];
        let r1 = slab.put(&big).unwrap();
        let r2 = slab.put(&big).unwrap();
        assert_eq!(r1, r2);
        let slab_bytes = slab.file.metadata().unwrap().len() as usize;
        // 100 MB + ~40 B header + align — definitely < 101 MB.
        assert!(slab_bytes < 101 * 1024 * 1024,
                "slab grew to {slab_bytes} B; expected single write <101 MB");
        let back = slab.get(&r1).unwrap();
        assert_eq!(back.len(), big.len());
        assert_eq!(back.first(), Some(&0xAB));
        assert_eq!(back.last(),  Some(&0xAB));
    }

    #[test]
    fn ten_thousand_64kb_roundtrip_no_corruption() {
        let tmp = tempdir().unwrap();
        let mut slab = SlabFile::open_or_create(
            tmp.path().join("rt.slab")).unwrap();
        let mut refs = Vec::with_capacity(10_000);
        for i in 0u32..10_000 {
            // Seeded 64KiB payload from u32 index bytes + b"Amin3!" tail
            // (deterministic, distinct).
            let mut buf = vec![0u8; 65536];
            buf[0..4].copy_from_slice(&i.to_le_bytes());
            buf[65536 - 6..].copy_from_slice(b"Amin3!");
            refs.push(slab.put(&buf).unwrap());
        }
        // Read back in REVERSE order (catching any offset-mangle bugs that
        // sequential read accidentally masks).
        for (i, r) in refs.iter().enumerate().rev() {
            let got = slab.get(r).expect(&format!("slot {i} missing"));
            assert_eq!(got.len(), 65536, "slot {i} length corrupted");
            let idx = u32::from_le_bytes(got[0..4].try_into().unwrap());
            assert_eq!(idx, i as u32, "slot {i} header mismatch => got idx={idx}");
            assert_eq!(&got[65536 - 6..], b"Amin3!",
                        "slot {i} payload tail corrupted");
        }
    }

    #[test]
    fn gc_frees_old_cold_entries() {
        let tmp = tempdir().unwrap();
        let mut slab = SlabFile::open_or_create(
            tmp.path().join("gc.slab")).unwrap();
        // Put 4 objects each 1 MB (4 MB total); keep 1 hot at refcount 2.
        let _ = slab.put(&vec![1u8; 1_048_576]).unwrap();
        let r_b = slab.put(&vec![2u8; 1_048_576]).unwrap();
        let _ = slab.put(&vec![3u8; 1_048_576]).unwrap();
        let r_d = slab.put(&vec![4u8; 1_048_576]).unwrap();
        // Make r_b hot (refcount 2)
        let rb2 = slab.put(&vec![2u8; 1_048_576]).unwrap();
        assert_eq!(rb2, r_b);
        // Make r_d just-touched, r_a/r_c artificially cold.
        // Mutate index directly via retain() to simulate passage of time.
        // Cheat by poking atime to 0 for 2 entries: iterate all, force atime
        // of entries != r_b and != r_d to epoch 0.
        slab.index.force_poke_all(|r, e| {
            if *r != r_b && *r != r_d {
                e.atime = 0;
            }
        }).unwrap();
        // Threshold set very low (0.0) so GC always runs regardless of
        // actual file size.
        let (freed, bytes) = slab.gc(0.0, Duration::from_secs(1)).unwrap();
        assert_eq!(freed, 2, "expected exactly 2 cold single-ref evictions");
        assert!(bytes > 2_000_000, "freed {bytes} B (expected > 2 MiB)");
        // Hot entry and just-touched survive.
        assert!(slab.get(&r_b).is_ok(), "hot entry (refcount=2) wrongly evicted");
        assert!(slab.get(&r_d).is_ok(), "new entry wrongly evicted");
    }
}

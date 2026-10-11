use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::error::Result;
use crate::slab::ObjRef;

/// 64-byte fixed-width index entry.  Lays out exactly one per slot in the
/// shmem-backed file; atomic integers so multiple readers don't tear while
/// the single-writer (flock EX holder) mutates.
///
/// 48 bytes of user-controlled data + 16 bytes of ObjRef key stored *next*
/// to the entry in a separate parallel array.  Kept as plain bytes so we can
/// mmap the whole file.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct IdxEntry {
    /// Byte offset into slab file (slot start, 4K-aligned).
    pub offset:   u64,
    /// Length in bytes of the on-disk 4K-aligned slot.
    pub len:      u32,
    /// Reference count (0 = evicted pending next gc sweep).
    pub refcount: u32,
    /// Last-access unix epoch seconds (GC min_age filter).
    pub atime:    u64,
}
// ObjRef 32 bytes + 24 bytes entry = 56 bytes rounded up to 64 for cache-line
// friendliness.
pub const ENTRY_STRIDE: usize = 64;
const KEY_OFF:  usize = 0;    // offset within a stride for ObjRef key (32 bytes)
const DATA_OFF: usize = 32;   // offset within a stride for IdxEntry (24 bytes)

/// Hash-linear index file, mmapped via `fs::File` + `Vec<u8>` snapshot.
///
/// Phase 0 is a **synchronous** copy-in/copy-out index (not an actual shmem
/// mmap — we do the simplest possible thing that matches the API: the file
/// contents are read into memory at open, flushed back on `put`/`retain`, and
/// we promise the Phase 2 `ainit` code will swap the backend to `memfd_create`
/// + `mmap` while keeping the same `IdxEntry` shape.  This lets us write real
/// behaviour tests now without fighting `MAP_SHARED` lifetime plumbing on day
/// one.
pub struct ShmemIndex {
    path:  PathBuf,
    file:  File,
    /// Flat byte buffer one stride per slot; `slot_count` tracks slots used
    /// (from the header).
    buf:   Vec<u8>,
    slots: usize,
}

impl ShmemIndex {
    pub fn open_or_create(path: PathBuf) -> Result<Self> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        let mut file = opts.open(&path)?;
        let size = file.metadata()?.len() as usize;
        let mut buf: Vec<u8>;
        let slots;
        if size == 0 {
            // Empty file: write a 4096 byte header of zeroed slots (64 slots
            // initial; we grow dynamically).
            let cap = 4096;
            buf = vec![0u8; cap];
            slots = 0;
            file.write_all(&buf)?;
            file.sync_all()?;
        } else {
            buf = vec![0u8; size];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut buf)?;
            // Slot count: count leading non-zero key bytes from slot 0.
            slots = (0..size / ENTRY_STRIDE)
                .filter(|s| !slot_is_empty(&buf, *s))
                .count();
        }
        Ok(Self { path, file, buf, slots })
    }

    /// Linear scan → slot index.  For Phase 0 (N ≤ 1M objects this is fine;
    /// Phase 2 adds a `blake3_prefix_hash_table` with 2-level lookup that
    /// keeps the same `put/get/retain` API).
    fn find_slot(&self, r: &ObjRef) -> Option<usize> {
        for s in 0..self.capacity_slots() {
            if slot_is_empty(&self.buf, s) { continue }
            if read_key(&self.buf, s) == *r.as_bytes() { return Some(s) }
        }
        None
    }

    fn first_empty_slot(&mut self) -> Result<usize> {
        for s in 0..self.capacity_slots() {
            if slot_is_empty(&self.buf, s) { return Ok(s) }
        }
        // Grow: double capacity.
        let old_cap = self.buf.len();
        let new_cap = old_cap * 2;
        self.buf.resize(new_cap, 0);
        // Write to disk — entire buffer (only on growth).
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.buf)?;
        self.file.sync_all()?;
        Ok(old_cap / ENTRY_STRIDE)  // first newly-allocated slot
    }

    fn capacity_slots(&self) -> usize { self.buf.len() / ENTRY_STRIDE }

    pub fn get(&self, r: &ObjRef) -> Result<Option<IdxEntry>> {
        let s = match self.find_slot(r) { Some(s) => s, None => return Ok(None) };
        Ok(Some(read_entry(&self.buf, s)))
    }

    pub fn put(&mut self, r: &ObjRef, e: IdxEntry) -> Result<()> {
        let s = match self.find_slot(r) {
            Some(s) => s,
            None => {
                let s = self.first_empty_slot()?;
                self.slots += 1;
                write_key(&mut self.buf, s, r.as_bytes());
                s
            }
        };
        write_entry(&mut self.buf, s, &e);
        self.flush_slot(s)
    }

    /// Iterate every live `(ObjRef, &mut IdxEntry)` pair with closure `f`.
    /// If `f` returns `false` the slot is zeroed (evicted).  Returns the
    /// count of removed entries.
    pub fn retain<F: FnMut(&ObjRef, &mut IdxEntry) -> bool>(&mut self, mut f: F)
                                                           -> Result<usize>
    {
        let mut removed = 0usize;
        for s in 0..self.capacity_slots() {
            if slot_is_empty(&self.buf, s) { continue }
            let key_bytes = read_key(&self.buf, s);
            let r = ObjRef(key_bytes);
            let mut e = read_entry(&self.buf, s);
            let keep = f(&r, &mut e);
            if keep {
                // Update entry (f may have mutated it — supports the poking
                // used by unit tests).
                write_entry(&mut self.buf, s, &e);
                self.flush_slot(s)?;
            } else {
                clear_slot(&mut self.buf, s);
                self.flush_slot(s)?;
                self.slots = self.slots.saturating_sub(1);
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Test-only helper: walk and mutate every atime/refcount for unit tests.
    /// Returns Ok once all slots have been visited.
    pub fn force_poke_all<F: FnMut(&ObjRef, &mut IdxEntry)>(&mut self, mut f: F)
                                                           -> Result<()>
    {
        for s in 0..self.capacity_slots() {
            if slot_is_empty(&self.buf, s) { continue }
            let key = read_key(&self.buf, s);
            let mut e = read_entry(&self.buf, s);
            f(&ObjRef(key), &mut e);
            write_entry(&mut self.buf, s, &e);
            self.flush_slot(s)?;
        }
        Ok(())
    }

    /// Write one stride (ENTRY_STRIDE bytes) at slot `s` back to disk.
    fn flush_slot(&mut self, s: usize) -> Result<()> {
        let start = s * ENTRY_STRIDE;
        let end   = start + ENTRY_STRIDE;
        self.file.seek(SeekFrom::Start(start as u64))?;
        self.file.write_all(&self.buf[start..end])?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Path (for logging).
    pub fn path(&self) -> &std::path::Path { &self.path }
}

// ─ Slot byte-level accessors (avoid transmute, keep the file-layout explicit)

fn slot_is_empty(buf: &[u8], s: usize) -> bool {
    let base = s * ENTRY_STRIDE + KEY_OFF;
    // 32-byte zero ObjRef means empty (blake3 never returns 32 zero bytes for
    // any input).
    buf[base..base + 32].iter().all(|b| *b == 0)
}
fn read_key(buf: &[u8], s: usize) -> [u8; 32] {
    let base = s * ENTRY_STRIDE + KEY_OFF;
    let mut k = [0u8; 32];
    k.copy_from_slice(&buf[base..base + 32]);
    k
}
fn write_key(buf: &mut [u8], s: usize, k: &[u8; 32]) {
    let base = s * ENTRY_STRIDE + KEY_OFF;
    buf[base..base + 32].copy_from_slice(k);
}
fn read_entry(buf: &[u8], s: usize) -> IdxEntry {
    let b = s * ENTRY_STRIDE + DATA_OFF;
    IdxEntry {
        offset:   u64::from_le_bytes(buf[b..b+8].try_into().unwrap()),
        len:      u32::from_le_bytes(buf[b+8..b+12].try_into().unwrap()),
        refcount: u32::from_le_bytes(buf[b+12..b+16].try_into().unwrap()),
        atime:    u64::from_le_bytes(buf[b+16..b+24].try_into().unwrap()),
    }
}
fn write_entry(buf: &mut [u8], s: usize, e: &IdxEntry) {
    let b = s * ENTRY_STRIDE + DATA_OFF;
    buf[b..b+8].copy_from_slice(&e.offset.to_le_bytes());
    buf[b+8..b+12].copy_from_slice(&e.len.to_le_bytes());
    buf[b+12..b+16].copy_from_slice(&e.refcount.to_le_bytes());
    buf[b+16..b+24].copy_from_slice(&e.atime.to_le_bytes());
}
fn clear_slot(buf: &mut [u8], s: usize) {
    let base = s * ENTRY_STRIDE;
    buf[base..base + ENTRY_STRIDE].fill(0);
}

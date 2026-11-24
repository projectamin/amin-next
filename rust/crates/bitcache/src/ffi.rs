//! C ABI over the trust-layer verifiers, for the Perl bridge.
//!
//! `Amin::Crypto::Verify` binds this `cdylib` with `FFI::Platypus`.  Perl
//! never carries a second implementation of any check: ML-DSA-87, zcap.v1 and
//! UCC instrument verification all run the code in [`crate::trust`].
//!
//! Every entry returns an `i32`: `0` accepted, negative rejected —
//!
//! ```text
//!   -1 Format   -2 UnknownKid   -3 BadSig   -9 BadArgument
//! ```
//!
//! Null pointers, oversize lengths and any internal failure are rejections;
//! no path returns success unless the verifier itself said so.

#![allow(unsafe_code)]

use core::slice;

use crate::signer::{mldsa87_verify, MLDSA87_VK_LEN};
use crate::nodecert::NodeCert;
use crate::trust::{self, RC_BAD_ARG, RC_BAD_SIG, RC_NOT_VALID_AT, RC_OK};

/// Upper bound for any single caller-supplied buffer (defence in depth).
const MAX_LEN: usize = 16 * 1024 * 1024;

unsafe fn rs<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len > MAX_LEN || (p.is_null() && len != 0) {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    Some(slice::from_raw_parts(p, len))
}

unsafe fn rstr<'a>(p: *const u8, len: usize) -> Option<&'a str> {
    core::str::from_utf8(rs(p, len)?).ok()
}

/// Verify a raw ML-DSA-87 signature.  `vk` is 2592 B, `sig` 4627 B.
///
/// # Safety
/// Pointers must be valid for their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn bitcache_mldsa87_verify(
    vk: *const u8, vk_len: usize,
    sig: *const u8, sig_len: usize,
    msg: *const u8, msg_len: usize,
) -> i32 {
    let (Some(vk), Some(sig), Some(msg)) = (rs(vk, vk_len), rs(sig, sig_len), rs(msg, msg_len)) else {
        return RC_BAD_ARG;
    };
    if mldsa87_verify(vk, msg, sig) { RC_OK } else { RC_BAD_SIG }
}

/// Verify a zcap.v1 token against `n_anchors` raw VKs packed back to back
/// (`anchors` is `n_anchors * 2592` bytes).  `n_anchors == 0` rejects.
///
/// # Safety
/// Pointers must be valid for their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn bitcache_zcap_verify(
    token: *const u8, token_len: usize,
    anchors: *const u8, n_anchors: usize,
) -> i32 {
    let Some(total) = n_anchors.checked_mul(MLDSA87_VK_LEN) else { return RC_BAD_ARG };
    let (Some(tok), Some(a)) = (rs(token, token_len), rs(anchors, total)) else {
        return RC_BAD_ARG;
    };
    let list: Vec<&[u8]> = a.chunks_exact(MLDSA87_VK_LEN).collect();
    match trust::zcap_verify(tok, &list) {
        Ok(_) => RC_OK,
        Err(r) => r.code(),
    }
}

/// Verify a UCC Art.3 instrument signature.
///
/// # Safety
/// Pointers must be valid for their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn bitcache_instrument_verify(
    maker: *const u8, maker_len: usize,
    payee: *const u8, payee_len: usize,
    amount: *const u8, amount_len: usize,
    kind: *const u8, kind_len: usize,
    vk: *const u8, vk_len: usize,
    sig: *const u8, sig_len: usize,
) -> i32 {
    let (Some(m), Some(p), Some(a), Some(k), Some(vk), Some(sig)) = (
        rstr(maker, maker_len), rstr(payee, payee_len), rstr(amount, amount_len),
        rstr(kind, kind_len), rs(vk, vk_len), rs(sig, sig_len),
    ) else {
        return RC_BAD_ARG;
    };
    match trust::instrument_verify(m, p, a, k, vk, sig) {
        Ok(()) => RC_OK,
        Err(r) => r.code(),
    }
}

/// Verify a node certificate under `authority_vk` and require it to be valid at
/// authority-log position `pos`.  On success (`0`) the certified node-key hash
/// is written to `vk_hash_out` (32 bytes) and the certificate's boot counter to
/// `boot_counter_out`; `-4` means authentic but not valid at `pos`.
///
/// # Safety
/// Pointers must be valid for their stated lengths; the out pointers for 32
/// and 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn bitcache_nodecert_verify(
    cert: *const u8, cert_len: usize,
    authority_vk: *const u8, vk_len: usize,
    pos: u64,
    vk_hash_out: *mut u8, boot_counter_out: *mut u64,
) -> i32 {
    let (Some(c), Some(vk)) = (rs(cert, cert_len), rs(authority_vk, vk_len)) else {
        return RC_BAD_ARG;
    };
    if vk_hash_out.is_null() || boot_counter_out.is_null() {
        return RC_BAD_ARG;
    }
    match NodeCert::verify(c, vk) {
        Err(r) => r.code(),
        Ok(n) if !n.valid_at(pos) => RC_NOT_VALID_AT,
        Ok(n) => {
            slice::from_raw_parts_mut(vk_hash_out, 32).copy_from_slice(&n.node_vk_hash);
            *boot_counter_out = n.boot_counter;
            RC_OK
        }
    }
}

// ── transparency log ────────────────────────────────────────────────────────

use crate::tlog;

unsafe fn h32(p: *const u8) -> Option<tlog::Hash> {
    if p.is_null() {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(slice::from_raw_parts(p, 32));
    Some(h)
}

unsafe fn hashes(p: *const u8, n: usize) -> Option<Vec<tlog::Hash>> {
    if n > 4096 || (p.is_null() && n != 0) {
        return None;
    }
    Some((0..n).map(|i| h32(p.add(i * 32)).unwrap()).collect())
}

/// `out32 = H(0x00 ‖ data)`.
#[no_mangle]
pub unsafe extern "C" fn bitcache_tlog_leaf_hash(data: *const u8, len: usize, out32: *mut u8) -> i32 {
    let Some(d) = rs(data, len) else { return RC_BAD_ARG };
    if out32.is_null() {
        return RC_BAD_ARG;
    }
    slice::from_raw_parts_mut(out32, 32).copy_from_slice(&tlog::leaf_hash(d));
    RC_OK
}

/// 0 if `leaf` is entry `index` of the tree of `size` leaves with `root`.
#[no_mangle]
pub unsafe extern "C" fn bitcache_tlog_verify_inclusion(
    leaf: *const u8, index: u64, size: u64, path: *const u8, n: usize, root: *const u8,
) -> i32 {
    let (Some(l), Some(r), Some(p)) = (h32(leaf), h32(root), hashes(path, n)) else { return RC_BAD_ARG };
    if tlog::verify_inclusion(&l, index, size, &p, &r) { RC_OK } else { RC_BAD_SIG }
}

/// 0 if the tree of `second` leaves is an append-only extension of `first`.
#[no_mangle]
pub unsafe extern "C" fn bitcache_tlog_verify_consistency(
    first: u64, first_root: *const u8, second: u64, second_root: *const u8, proof: *const u8, n: usize,
) -> i32 {
    let (Some(a), Some(b), Some(p)) = (h32(first_root), h32(second_root), hashes(proof, n)) else { return RC_BAD_ARG };
    if tlog::verify_consistency(first, &a, second, &b, &p) { RC_OK } else { RC_BAD_SIG }
}

/// Verify a signed checkpoint (see `checkpoint`).  `roster_packed` is `n_roster`
/// concatenated ML-DSA-87 verifying keys.  On success writes the checkpoint
/// size and root, and the origin (≤256 bytes) with its length.
#[no_mangle]
pub unsafe extern "C" fn bitcache_ckpt_verify(
    wire: *const u8, wire_len: usize,
    authority_vk: *const u8, vk_len: usize,
    pos: u64,
    roster_packed: *const u8, n_roster: usize, quorum: usize,
    size_out: *mut u64, root_out: *mut u8, origin_out: *mut u8, origin_len_out: *mut u32,
) -> i32 {
    let (Some(w), Some(avk)) = (rs(wire, wire_len), rs(authority_vk, vk_len)) else { return RC_BAD_ARG };
    if size_out.is_null() || root_out.is_null() || origin_out.is_null() || origin_len_out.is_null() || n_roster > 64 {
        return RC_BAD_ARG;
    }
    let Some(rbytes) = rs(roster_packed, n_roster * MLDSA87_VK_LEN) else { return RC_BAD_ARG };
    let roster: Vec<&[u8]> = rbytes.chunks(MLDSA87_VK_LEN).collect();
    match crate::checkpoint::verify(w, avk, pos, &roster, quorum) {
        Err(e) => e.code(),
        Ok(ck) => {
            *size_out = ck.size;
            slice::from_raw_parts_mut(root_out, 32).copy_from_slice(&ck.root);
            slice::from_raw_parts_mut(origin_out, ck.origin.len()).copy_from_slice(ck.origin.as_bytes());
            *origin_len_out = ck.origin.len() as u32;
            RC_OK
        }
    }
}

/// Verify a join snapshot (see `snapshot`): signed checkpoint chained to the
/// authority, frontier folds to the root, committed heads, state entry is the
/// last leaf.  Outputs mirror `bitcache_ckpt_verify`.
#[no_mangle]
pub unsafe extern "C" fn bitcache_snapshot_verify(
    snap: *const u8, snap_len: usize,
    authority_vk: *const u8, vk_len: usize,
    pos: u64,
    roster_packed: *const u8, n_roster: usize, quorum: usize,
    size_out: *mut u64, root_out: *mut u8, origin_out: *mut u8, origin_len_out: *mut u32,
) -> i32 {
    let (Some(w), Some(avk)) = (rs(snap, snap_len), rs(authority_vk, vk_len)) else { return RC_BAD_ARG };
    if size_out.is_null() || root_out.is_null() || origin_out.is_null() || origin_len_out.is_null() || n_roster > 64 {
        return RC_BAD_ARG;
    }
    let Some(rbytes) = rs(roster_packed, n_roster * MLDSA87_VK_LEN) else { return RC_BAD_ARG };
    let roster: Vec<&[u8]> = rbytes.chunks(MLDSA87_VK_LEN).collect();
    let snapshot = match crate::snapshot::Snapshot::decode(w) {
        Ok(s) => s,
        Err(e) => return e.code(),
    };
    match snapshot.verify(avk, pos, &roster, quorum) {
        Err(e) => e.code(),
        Ok(j) => {
            *size_out = j.checkpoint.size;
            slice::from_raw_parts_mut(root_out, 32).copy_from_slice(&j.checkpoint.root);
            slice::from_raw_parts_mut(origin_out, j.checkpoint.origin.len()).copy_from_slice(j.checkpoint.origin.as_bytes());
            *origin_len_out = j.checkpoint.origin.len() as u32;
            RC_OK
        }
    }
}

/// Verify an offline transfer receipt (see `receipt`) against one or more
/// trusted authority keys (`authorities_packed` = `n_auth` ML-DSA-87 keys).
/// On success writes the checkpoint size/root/origin and the entry id.
#[no_mangle]
pub unsafe extern "C" fn bitcache_receipt_verify(
    receipt: *const u8, receipt_len: usize,
    authorities_packed: *const u8, n_auth: usize,
    pos: u64,
    roster_packed: *const u8, n_roster: usize, quorum: usize,
    size_out: *mut u64, root_out: *mut u8, origin_out: *mut u8, origin_len_out: *mut u32, id_out: *mut u8,
) -> i32 {
    let Some(w) = rs(receipt, receipt_len) else { return RC_BAD_ARG };
    if size_out.is_null() || root_out.is_null() || origin_out.is_null() || origin_len_out.is_null()
        || id_out.is_null() || n_roster > 64 || n_auth > 64 {
        return RC_BAD_ARG;
    }
    let (Some(ab), Some(rb)) = (rs(authorities_packed, n_auth * MLDSA87_VK_LEN), rs(roster_packed, n_roster * MLDSA87_VK_LEN))
        else { return RC_BAD_ARG };
    let auths: Vec<&[u8]> = ab.chunks(MLDSA87_VK_LEN).collect();
    let roster: Vec<&[u8]> = rb.chunks(MLDSA87_VK_LEN).collect();
    let r = match crate::receipt::Receipt::decode(w) {
        Ok(r) => r,
        Err(e) => return e.code(),
    };
    match r.verify(&auths, pos, &roster, quorum) {
        Err(e) => e.code(),
        Ok((_e, id, ck)) => {
            *size_out = ck.size;
            slice::from_raw_parts_mut(root_out, 32).copy_from_slice(&ck.root);
            slice::from_raw_parts_mut(origin_out, ck.origin.len()).copy_from_slice(ck.origin.as_bytes());
            *origin_len_out = ck.origin.len() as u32;
            slice::from_raw_parts_mut(id_out, 32).copy_from_slice(&id);
            RC_OK
        }
    }
}

/// Verify an IoT leaf receipt (report → batch root → `iot.batch` entry → signed checkpoint).
/// Outputs as [`bitcache_receipt_verify`], plus the report's Merkle leaf hash
/// (`leaf_out`, 32 bytes) so the caller can bind it to the report it holds.
#[no_mangle]
pub unsafe extern "C" fn bitcache_iot_leaf_verify(
    receipt: *const u8, receipt_len: usize,
    authorities_packed: *const u8, n_auth: usize,
    pos: u64,
    roster_packed: *const u8, n_roster: usize, quorum: usize,
    size_out: *mut u64, root_out: *mut u8, origin_out: *mut u8, origin_len_out: *mut u32, id_out: *mut u8,
    leaf_out: *mut u8,
) -> i32 {
    let Some(w) = rs(receipt, receipt_len) else { return RC_BAD_ARG };
    if size_out.is_null() || root_out.is_null() || origin_out.is_null() || origin_len_out.is_null()
        || id_out.is_null() || leaf_out.is_null() || n_roster > 64 || n_auth > 64 {
        return RC_BAD_ARG;
    }
    let (Some(ab), Some(rb)) = (rs(authorities_packed, n_auth * MLDSA87_VK_LEN), rs(roster_packed, n_roster * MLDSA87_VK_LEN))
        else { return RC_BAD_ARG };
    let auths: Vec<&[u8]> = ab.chunks(MLDSA87_VK_LEN).collect();
    let roster: Vec<&[u8]> = rb.chunks(MLDSA87_VK_LEN).collect();
    let r = match crate::iot::LeafReceipt::decode(w) {
        Ok(r) => r,
        Err(e) => return e.code(),
    };
    match r.verify(&auths, pos, &roster, quorum) {
        Err(e) => e.code(),
        Ok((_rep, entry, ck)) => {
            *size_out = ck.size;
            slice::from_raw_parts_mut(root_out, 32).copy_from_slice(&ck.root);
            slice::from_raw_parts_mut(origin_out, ck.origin.len()).copy_from_slice(ck.origin.as_bytes());
            *origin_len_out = ck.origin.len() as u32;
            let id = entry.id().unwrap_or([0u8; 32]);
            slice::from_raw_parts_mut(id_out, 32).copy_from_slice(&id);
            slice::from_raw_parts_mut(leaf_out, 32).copy_from_slice(&crate::tlog::leaf_hash(&r.report));
            RC_OK
        }
    }
}

/// Derive a leaf's key from the gateway master secret (`key_out` = 32 bytes).
#[no_mangle]
pub unsafe extern "C" fn bitcache_iot_leaf_key(
    master: *const u8, leaf: *const u8, leaf_len: usize, key_out: *mut u8,
) -> i32 {
    let (Some(m), Some(l)) = (rs(master, 32), rs(leaf, leaf_len)) else { return RC_BAD_ARG };
    let Ok(l) = std::str::from_utf8(l) else { return RC_BAD_ARG };
    if key_out.is_null() || l.is_empty() || l.len() > crate::iot::MAX_LEAF {
        return RC_BAD_ARG;
    }
    let mut mm = [0u8; 32];
    mm.copy_from_slice(m);
    slice::from_raw_parts_mut(key_out, 32).copy_from_slice(&crate::iot::leaf_key(&mm, l));
    RC_OK
}

/// Build an authenticated report.  `out` needs room for the wire form (≤ 320 bytes);
/// its length is written to `out_len`.
#[no_mangle]
pub unsafe extern "C" fn bitcache_iot_report_build(
    key: *const u8, leaf: *const u8, leaf_len: usize, ctr: u64,
    payload: *const u8, payload_len: usize, out: *mut u8, out_cap: usize, out_len: *mut usize,
) -> i32 {
    let (Some(k), Some(l), Some(p)) = (rs(key, 32), rs(leaf, leaf_len), rs(payload, payload_len)) else { return RC_BAD_ARG };
    let Ok(l) = std::str::from_utf8(l) else { return RC_BAD_ARG };
    if out.is_null() || out_len.is_null() {
        return RC_BAD_ARG;
    }
    let mut kk = [0u8; 32];
    kk.copy_from_slice(k);
    let Some(r) = crate::iot::Report::new(&kk, l, ctr, p) else { return RC_BAD_ARG };
    let w = r.encode();
    if w.len() > out_cap {
        return RC_BAD_ARG;
    }
    slice::from_raw_parts_mut(out, w.len()).copy_from_slice(&w);
    *out_len = w.len();
    RC_OK
}

/// Check a report's tag under `key`.  `-1` malformed, `-3` bad tag.  On success writes
/// the counter; the leaf name and payload are recovered by the caller from the wire form.
#[no_mangle]
pub unsafe extern "C" fn bitcache_iot_report_check(key: *const u8, wire: *const u8, wire_len: usize, ctr_out: *mut u64) -> i32 {
    let (Some(k), Some(w)) = (rs(key, 32), rs(wire, wire_len)) else { return RC_BAD_ARG };
    if ctr_out.is_null() {
        return RC_BAD_ARG;
    }
    let Some(r) = crate::iot::Report::decode(w) else { return crate::trust::RC_FORMAT };
    let mut kk = [0u8; 32];
    kk.copy_from_slice(k);
    if !r.tag_ok(&kk) {
        return RC_BAD_SIG;
    }
    *ctr_out = r.ctr;
    RC_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{zcap_token_bytes, Keypair, ZcapGrant};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn abi_zcap_and_bad_args() {
        let kp = Keypair::generate(&mut StdRng::from_seed([9; 32]), "t".into());
        let g = ZcapGrant { tiers: vec!["a".into()], zones: vec![], netpolicies: vec![],
            max_redundancy: 1, vpc_quota: 1, memory_tier: 1, tenant_id: "x".into(), ts: 1 };
        let tok = zcap_token_bytes(&kp, &g).unwrap();
        let vk = kp.verifying_key_bytes();
        unsafe {
            assert_eq!(bitcache_zcap_verify(tok.as_ptr(), tok.len(), vk.as_ptr(), 1), 0);
            assert_eq!(bitcache_zcap_verify(tok.as_ptr(), tok.len(), core::ptr::null(), 0), -2);
            assert_eq!(bitcache_zcap_verify(core::ptr::null(), 5, vk.as_ptr(), 1), -9);
            assert_eq!(bitcache_mldsa87_verify(core::ptr::null(), 0, core::ptr::null(), 0, core::ptr::null(), 0), -3);
        }
    }
}

//! `ainit` — Amin 3.0 netboot initrd (PID 1 pre-hand-off supervisor).
//!
//! The metal boot chain is:
//!
//! ```text
//! UEFI HTTP Boot → vmlinuz + ainit.cpio.zst
//!                     ↓ kernel decompresses cpio to rootfs
//!                     ↓ /init = `ainit` binary THIS CRATE
//!   ┌───────────────────────────────────────────────────────────────┐
//!   │  boot_offer:  Mesh HELLO → zcap-signed BOOT_OFFER from ToR    │
//!   │  cas_fetch:   Fetch init-profile.xml.bsax via Bitcache CAS    │
//!   │  stage1..4:  BSAX micro-decode, run hwcheck → fw-update →    │
//!   │              storage-init (slab format/repair) → mesh-join    │
//!   │  fd_handoff: SCM_RIGHTS send 5 fds over unix SOCK_SEQPACKET: │
//!   │              3 mesh QUIC sock + 1 slab fd + 1 seal-log fd     │
//!   └───────────────────────────────────────────────────────────────┘
//!                     ↓ pivot_root into Bitcache-backed Amin rootfs
//!                     ↓ exec /sbin/aminexec → PID 1 perl dispatcher
//!
//! The ainit binary must be **tiny** (≤ 2 MB zstd per TR-8.1): no tokio, no
//! tracing, no proc-macro crates, pure byte-bashing + libc raw syscalls for
//! fd handoff and netdev bring-up.

#![allow(unsafe_code)]
#![deny(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::return_self_not_must_use, clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod boot_offer;
pub mod cas_fetch;
pub mod fd_handoff;
pub mod stage_decoder;

/// Real PID-1 entrypoint on the metal host.  Called from the binary main
/// when `getpid() == 1` on Linux.  Steps (all stubbed in Task 8; the
/// pipeline is wired end-to-end via the `run_simulated_entrypoint` smoke
/// test in main.rs):
///
/// 1. Read kernel cmdline → zcap + bootstrap refs.
/// 2. `boot_offer` mesh HELLO → verified BOOT_OFFER from ToR.
/// 3. `cas_fetch` init-profile + aminexec rootfs blobs via RS(M,K).
/// 4. `stage_decoder` stages 1..4 (hwcheck/fw-update/storage-init/mesh-join).
/// 5. Open slab + seal fds.
/// 6. `fd_handoff::send_handoff` 5 fds to `/run/amin/hand-off.sock`.
/// 7. `pivot_root` + `execve` /sbin/aminexec.
pub fn run_real_pid1_entrypoint() -> anyhow::Result<()> {
    use crate::boot_offer::{BootOffer, MeshHello, TrustedAnchor};
    use crate::stage_decoder;
    use std::path::PathBuf;

    let hello = MeshHello::new([0u8; 32], 0);
    // The actual metal path does network I/O here.  For Task 8 we
    // validate the code *builds* with the real call-path; network logic
    // gets filled in under feature="metal".
    let _ = hello;
    let _ = TrustedAnchor::DevAcceptAll;
    let _ = BootOffer::verify;
    let _ = stage_decoder::parse_init_profile_bsax;
    let _ = PathBuf::from("/sbin/aminexec");
    Ok(())
}

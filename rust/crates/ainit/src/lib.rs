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
//!
//! This crate is **phase 1** of a two-phase PID 1; the `aminexec` crate is
//! phase 2, and the `pivot_root` above is the boundary.  Why the split exists,
//! and the exact hand-off contract that connects the phases, is recorded in
//! `docs/pid1-split.md`.

#![allow(unsafe_code)]
#![deny(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::return_self_not_must_use, clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod boot_offer;
pub mod bootstrap;
pub mod cas_fetch;
pub mod fd_handoff;
pub mod stage_decoder;

/// Real PID-1 entrypoint on the metal host.  Called from the binary main
/// when `getpid() == 1` on Linux.
///
/// `ainit` answers exactly one question — *where is the boot profile* — and
/// then hands it to phase 2 as a single argument:
/// `execve("/sbin/aminexec", ["aminexec", <profile>])`.  The scheme of that
/// ref is the only thing that varies by machine ([`bootstrap::resolve_profile_ref`]):
///
/// - **Served** — a `ToR` `BOOT_OFFER` left a `bitcache:`/`http(s)://` ref on
///   the kernel cmdline; it is passed through untouched (a racked server's
///   first boot).
/// - **Standalone** — no served ref: the profile is a local document on
///   FRAMEBOOT, passed as `local:<path>` (a phone or desktop).
///
/// Either way the last act of phase 1 is `execve("/sbin/aminexec", …)`; only
/// failure returns.  The mesh `BOOT_OFFER`/CAS-fetch leg that would *write* a
/// served ref (step 2-3 of the served path) does network I/O and is not yet
/// implemented — a served cmdline is currently trusted as already-complete.
pub fn run_real_pid1_entrypoint() -> anyhow::Result<()> {
    use anyhow::Context;

    let cmdline = std::fs::read_to_string(bootstrap::CMDLINE)
        .with_context(|| format!("reading {}", bootstrap::CMDLINE))?;
    let profile_ref = bootstrap::resolve_profile_ref(&cmdline)?;
    bootstrap::exec_aminexec(&profile_ref)
}

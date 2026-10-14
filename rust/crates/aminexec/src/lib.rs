//! aminexec  — Amin 3.0 per-process sandbox + execution dispatcher.
//!
//! This crate implements the "outer trust ring": before an untrusted filter
//! (Type P/Perl-Safe, Type B/eBPF, Type N/disposable-child) runs, it is
//! wrapped in a platform-appropriate sandbox.  We never pass commands
//! directly to `/bin/sh -c` unless the target trait explicitly signs off.
//!
//! # Platform traits
//!
//! Every supported OS implements *at minimum* these four traits.  POSIX
//! fallback is no-op (trusts the host, no enforcement), all others add
//! actual enforcement via native kernel facilities.
//!
//! | Trait               | Linux          | FreeBSD           | iOS                      | Android                       |
//! |---------------------|----------------|-------------------|--------------------------|-------------------------------|
//! | [`SandboxBackend`]  | landlock + cg  | jail + capsicum   | App Sandbox + entitlements| SELinux + isolatedProcess   |
//! | [`MetricsBackend`]  | cgroup v2      | rctl              | proc_pid_rusage + OSSignpost| /proc/self/status + atrace |
//! | [`NetworkBackend`]  | XDP + netlink  | pf(4) ioctl       | Network.framework monitor| Netd binder / VpnService    |
//! | [`AuthBackend`]     | pam + TPM      | pam + uefi secure | CryptoKit + Secure Enclave| Keystore 2.0 + StrongBox   |
//!
//! # Execution backends (via the Perl Amin::Exec::Backend trait)
//!
//! - POSIX child (`harness \@cmd`) — default on all hosts
//! - `posix_spawn`     — default on iOS (fork is private API)
//! - JNI / ART bridge  — default on Android for commands that need runtime
//! - LibcNative        — no fork at all; run mkdir/unlink/echo via direct libc

#![cfg_attr(not(any(feature = "posix-minimal", feature = "linux-strict")), deny(unsafe_code))]
#![warn(clippy::pedantic, missing_docs)]

pub mod platform;
#[cfg(target_os = "linux")]
pub mod pid1;
pub mod mesh_state;

/// Protocol version mirrored with the Perl Amin facade.
pub const AMIN_EXEC_ABI: u32 = 0x0001_0000;

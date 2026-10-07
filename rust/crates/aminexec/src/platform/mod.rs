//! Compile-time platform selection.
//!
//! Pick the "best" backend for the current `target_os`; always fall back to
//! [`posix::Backend`] for unknown hosts so the binary can run anywhere with
//! a working C stdlib (including Linux userland on Windows WSL1, etc.).
//!
//! **Selectivity order**:
//! - iOS 14+  → [`ios::Backend`] (App Sandbox, posix_spawn, CryptoKit)
//! - Android 13+ → [`android::Backend`] (SELinux, ART JNI, Keystore 2.0)
//! - Linux 6.2+ → [`linux::Backend`] (Landlock LSM, cgroup v2, seccomp-bpf)
//! - FreeBSD 14+ → [`freebsd::Backend`] (jail, rctl, capsicum)
//! - Other → [`posix::Backend`] (fork/exec + rusage only, no enforcement)

use std::fmt;

/// The four trust traits every platform must implement.  Actual definitions
/// live in [`crate::sandbox`], [`crate::metrics`], etc. — these are opaque
/// marker types in the scaffold so type mismatches surface at compile time
/// rather than linker time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// Minimal POSIX fallback (trusts host, no kernel enforcement).
    PosixMinimal,
    /// Linux >=6.2 with Landlock + seccomp-bpf + cgroup v2.
    LinuxStrict,
    /// FreeBSD >=14 with jail, rctl, capsicum.
    FreeBSDFull,
    /// iOS (non-jailbroken): App Sandbox entitlement gates + posix_spawn.
    IOSAppSandbox,
    /// Android: SELinux + ART JNI + Keystore 2.0 StrongBox where available.
    AndroidSELinux,
    /// Illumos / Solaris derivative: zone(5), privileges(5), priv_drop.
    IllumosZone,
}

pub trait SandboxBackend { /* see crate::sandbox for actual methods */ }
pub trait MetricsBackend { /* see crate::metrics */ }
pub trait NetworkBackend { /* see crate::exec  */ }
pub trait AuthBackend    { /* see crate::exec  */ }

#[cfg(target_os = "linux")]   pub mod linux;
#[cfg(target_os = "freebsd")] pub mod freebsd;
#[cfg(target_os = "illumos")] pub mod illumos;
#[cfg(target_os = "ios")]     pub mod ios;
#[cfg(target_os = "android")] pub mod android;
pub mod posix;

/// Return a backend description of the best available implementation on the
/// current target.  (The actual impl structs are cfg-gated per file.)
#[must_use]
pub fn default_backend() -> BackendKind {
    #[cfg(target_os = "linux")]   { return BackendKind::LinuxStrict;   }
    #[cfg(target_os = "freebsd")] { return BackendKind::FreeBSDFull;   }
    #[cfg(target_os = "illumos")] { return BackendKind::IllumosZone;   }
    #[cfg(target_os = "ios")]     { return BackendKind::IOSAppSandbox; }
    #[cfg(target_os = "android")] { return BackendKind::AndroidSELinux;}
    #[allow(unreachable_code)] { BackendKind::PosixMinimal }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PosixMinimal  => "posix-minimal",
            Self::LinuxStrict   => "linux-strict",
            Self::FreeBSDFull   => "freebsd-full",
            Self::IOSAppSandbox => "ios-app-sandbox",
            Self::AndroidSELinux=> "android-selinux",
            Self::IllumosZone   => "illumos-zone",
        })
    }
}

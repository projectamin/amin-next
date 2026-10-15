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
//!
//! **Adding a platform** is a single entry in [`platform_registry!] below;
//! it simultaneously wires the `#[cfg]` module block, the
//! [`default_backend`] ladder, and the [`BackendKind`] display mapping —
//! the three lists cannot drift.

use std::fmt;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

pub use error::{SandboxError, SandboxResult};

mod error {
    use std::fmt;

    #[derive(Debug)]
    pub enum SandboxError {
        MissingAbi(&'static str),
        Io(std::io::Error),
        Ruleset(String),
    }

    pub type SandboxResult<T> = Result<T, SandboxError>;

    impl fmt::Display for SandboxError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::MissingAbi(abi) => write!(f, "missing sandbox ABI: {abi}"),
                Self::Io(e)            => write!(f, "sandbox io error: {e}"),
                Self::Ruleset(m)       => write!(f, "sandbox ruleset error: {m}"),
            }
        }
    }

    impl std::error::Error for SandboxError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self { Self::Io(e) => Some(e), _ => None }
        }
    }

    impl From<std::io::Error> for SandboxError {
        fn from(e: std::io::Error) -> Self { Self::Io(e) }
    }
}

/// The four trust traits every platform must implement.
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
    /// macOS: per-process rlimits (cgroup-equivalent tier, Phase 1 of
    /// docs/darwin-sandbox-plan.md). Seatbelt joins in Phase 2.
    DarwinRlimit,
}

/// Kernel-level filesystem allow-list + cgroup limits + syscall BPF filter.
pub trait SandboxBackend {
    /// Apply Landlock LSM filesystem allow-list to the calling process.
    ///
    /// **Kernel ordering invariant**: run this BEFORE execve in the child
    /// (between clone and exec).  Internally applies `prctl(NO_NEW_PRIVS)`
    /// then adds all paths then `landlock_restrict_self`.
    fn landlock_enforce(&self, ro_paths: &[&Path], rw_paths: &[&Path]) -> SandboxResult<()>;

    /// Create `/sys/fs/cgroup/amin/<sb_name>/` and write cgroup v2 controller
    /// knobs for cpu/memory/pids/io.  Each arg is Optional; skip when `None`.
    fn cgroup_apply(&self,
        sb_name:    &str,
        cpu_max:    Option<&str>,
        memory_max: Option<&str>,
        pids_max:   Option<u32>,
        io_max:     Option<&str>,
    ) -> SandboxResult<()>;

    /// Move calling pid into the cgroup created by [`Self::cgroup_apply`]
    /// (writes pid into `cgroup.procs`).
    fn cgroup_attach_current(&self, sb_name: &str) -> SandboxResult<()>;

    /// Load pre-compiled seccomp-bpf bytecode into the kernel for this
    /// process.  `bpf_bytes` is a raw array of `struct sock_filter` entries
    /// (8 bytes each).  Requires PR_SET_NO_NEW_PRIVS already set.
    fn seccomp_apply(&self, bpf_bytes: &[u8]) -> SandboxResult<()>;
}

pub trait MetricsBackend { /* see crate::metrics */ }

/// Opaque netns handle returned by netns_unshare_isolated; used later for
/// child-side veth up/addr/route setup inside unshare NEWNET.
#[derive(Debug)]
pub struct NetnsHandle {
    /// File descriptor open on `/proc/self/ns/net` inside the new netns, or
    /// an invalid fd (e.g. -1) if the handle refers to the current netns
    /// (mode=host pass-through).
    pub netns_fd: RawFd,
    /// Host-side veth interface name (for mode=isolated / fabric).
    pub veth_host: String,
    /// ns-side (child) veth interface index after RTM_NEWLINK.
    pub ns_ifindex: i32,
    /// Bind-mount path for fabric shared netns.  Empty for isolated mode.
    pub shared_path: PathBuf,
}

/// Pinned BPF map handles after clsact_attach_progs.  Fds are intentionally
/// left open on successful return; caller is responsible for close() when
/// the spawn scope ends (or holds the map fds for Billing read access).
#[derive(Debug)]
pub struct BpfMapHandles {
    /// P2C EWMA backend_array fd (BPF_MAP_TYPE_ARRAY).
    pub backends_fd: RawFd,
    /// Per-cpu egress bytes counter fd (BPF_MAP_TYPE_PERCPU_ARRAY).
    pub egress_bytes_fd: RawFd,
    /// Netpolicy LPM trie fd (BPF_MAP_TYPE_LPM_TRIE).
    pub policy_lpm_fd: RawFd,
}

/// NetworkBackend — linux dataplane kernel programming interface (netns +
/// veth + clsact BPF + map ops).  Non-Linux backends (posix/freebsd/etc)
/// return MissingAbi for all 5 methods — fail-closed, no unsandboxed
/// fallback to external iproute2/tc shells.
pub trait NetworkBackend {
    /// Create an isolated or fabric-shared netns: clone-unshare CLONE_NEWNET,
    /// then build host↔ns veth pair via RTM_NEWLINK + move ns-end via pidfd.
    /// Host side veth named `veth_host`; ns side eth0 configured with
    /// `ip/subnet/gw` via RTM_NEWADDR + RTM_NEWROUTE.
    fn netns_unshare_isolated(&self, pidfd: Option<RawFd>, veth_host: &str,
        ip: Ipv4Addr, subnet: u8, gw: Ipv4Addr) -> SandboxResult<NetnsHandle>;

    /// Join an existing fabric-shared netns via its bindmounted ns path.
    fn netns_join_shared(&self, netns_path: &Path) -> SandboxResult<()>;

    /// Attach clsact qdisc to `iface` then load 2 BPF cls programs via
    /// bpf(PROG_LOAD) bytes: one for P2C_EWMA LB, one for netpolicy LPM.
    /// Returns pinned map handles.  Empty byte-slices mean no prog for that
    /// hook (e.g. no LB = no P2C attach).
    fn clsact_attach_progs(&self, iface: &str, bpf_obj_p2c: &[u8],
        bpf_obj_policy: &[u8]) -> SandboxResult<BpfMapHandles>;

    /// Sum per-cpu BPF egress bytes map slots and return total counter in
    /// bytes.  Used by Net::Fabric→Billing egress_delta() public API.
    fn bpf_map_read_egress_bytes(&self, map_fd: RawFd) -> SandboxResult<u64>;

    /// Update drain bit for `backend_id` inside backends_array so P2C stops
    /// picking this backend (drain flag propagated via BPF map).
    fn bpf_map_update_drain(&self, map_fd: RawFd, backend_id: u32, drain: u8)
        -> SandboxResult<()>;
}

pub trait AuthBackend    { /* see crate::exec  */ }

/// Single-source platform registry.  One entry registers a backend across
/// the three parallel dispatch sites in this module — the `#[cfg]`-gated
/// module block, the [`default_backend`] selection ladder, and the
/// [`BackendKind`] display mapping — so the lists can never drift apart.
/// Anything not registered falls through to [`posix::Backend`].
macro_rules! platform_registry {
    ($( $kind:ident => module $module:ident, cfg $cfg:meta, display $display:literal ),+ $(,)?) => {
        $( #[cfg($cfg)] pub mod $module; )+

        /// Return the best available backend kind on this target.
        #[must_use]
        pub fn default_backend() -> BackendKind {
            $(
                #[cfg($cfg)]
                { return BackendKind::$kind; }
            )+
            // Exactly one entry above matches any target; the allowance
            // mirrors the pre-macro code that same shape required.
            #[allow(unreachable_code)]
            BackendKind::PosixMinimal
        }

        impl fmt::Display for BackendKind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    Self::PosixMinimal   => "posix-minimal",
                    $( BackendKind::$kind => $display, )+
                })
            }
        }
    };
}

platform_registry! {
    LinuxStrict    => module linux,   cfg target_os = "linux",   display "linux-strict",
    FreeBSDFull    => module freebsd, cfg target_os = "freebsd", display "freebsd-full",
    IllumosZone    => module illumos, cfg target_os = "illumos", display "illumos-zone",
    IOSAppSandbox  => module ios,     cfg target_os = "ios",     display "ios-app-sandbox",
    AndroidSELinux => module android, cfg target_os = "android", display "android-selinux",
    DarwinRlimit   => module darwin,  cfg target_os = "macos",   display "darwin-rlimit",
}

pub mod posix;

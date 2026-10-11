//! POSIX minimal fallback platform — no kernel enforcement, universal fallback.
//!
//! Used on: NetBSD, OpenBSD, Darwin (non-iOS), Haiku, Windows+Cygwin, WSL1, …
//! Every platform-trait method delegates to standard POSIX calls: fork+exec,
//! wait4, getrusage, getifaddrs, pam.  This is the baseline "it runs"
//! implementation; stronger sandboxes are per-OS opt-ins above.

use crate::platform::{
    AuthBackend, BpfMapHandles, MetricsBackend, NetnsHandle, NetworkBackend, SandboxBackend,
    SandboxError, SandboxResult,
};
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::path::Path;

pub struct Backend;

impl SandboxBackend for Backend {
    fn landlock_enforce(&self, _ro: &[&Path], _rw: &[&Path]) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi("landlock unavailable on non-Linux platforms (posix fallback)"))
    }
    fn cgroup_apply(&self, _sb: &str, _c: Option<&str>, _m: Option<&str>, _p: Option<u32>, _i: Option<&str>) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi("cgroup v2 unavailable on non-Linux platforms"))
    }
    fn cgroup_attach_current(&self, _sb: &str) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi("cgroup v2 unavailable on non-Linux platforms"))
    }
    fn seccomp_apply(&self, _b: &[u8]) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi("seccomp-bpf unavailable on non-Linux platforms"))
    }
}

impl MetricsBackend for Backend {}
impl AuthBackend    for Backend {}

impl NetworkBackend for Backend {
    fn netns_unshare_isolated(&self, _: Option<RawFd>, _: &str, _: Ipv4Addr, _: u8, _: Ipv4Addr) -> SandboxResult<NetnsHandle> {
        Err(SandboxError::MissingAbi("netns/veth unavailable on non-Linux platforms (posix fallback)"))
    }
    fn netns_join_shared(&self, _: &Path) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi("netns/veth unavailable on non-Linux platforms"))
    }
    fn clsact_attach_progs(&self, _: &str, _: &[u8], _: &[u8]) -> SandboxResult<BpfMapHandles> {
        Err(SandboxError::MissingAbi("clsact eBPF cls classifier unavailable on non-Linux platforms"))
    }
    fn bpf_map_read_egress_bytes(&self, _: RawFd) -> SandboxResult<u64> {
        Err(SandboxError::MissingAbi("eBPF maps unavailable on non-Linux platforms"))
    }
    fn bpf_map_update_drain(&self, _: RawFd, _: u32, _: u8) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi("eBPF maps unavailable on non-Linux platforms"))
    }
}

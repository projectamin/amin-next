//! Linux platform trait implementations (scaffold stubs).
//!
//! Full implementation (out of scope for v3 bootstrap) uses:
//! - [`landlock`] LSM to restrict filesystem tree per disposable child
//! - cgroup v2 `cpu.max`, `memory.max`, `io.max` via [`sys-mount`]
//! - seccomp-bpf syscall allow-list via [`seccompiler`]
//! - Linux namespaces via `clone3` (CLONE_NEWNS|NEWPID|NEWNET|NEWUSER) with
//!   `pivot_root` into the Amin App bundle squashfs mount

use crate::platform::{AuthBackend, MetricsBackend, NetworkBackend, SandboxBackend};

pub struct Backend;
impl SandboxBackend for Backend {}
impl MetricsBackend for Backend {}
impl NetworkBackend for Backend {}
impl AuthBackend    for Backend {}

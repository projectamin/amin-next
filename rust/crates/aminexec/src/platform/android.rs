//! Android platform trait implementations — scaffold stubs.
//!
//! Kernel is Linux, but userland diverges: no `/system/bin/bash`, bionic libc
//! instead of glibc, SELinux `untrusted_app` domain blocks most privileged
//! syscalls, only high port (>1024) bind allowed.  Child process spawning
//! goes through `Runtime.getRuntime().exec(...)` via JNI (`android-jni`
//! feature) or `toybox sh -c` wrapped via fork/exec directly.
//!
//! Full implementation uses:
//! - **Sandbox**: SELinux policy `type=untrusted_app_29` for disposable child;
//!   Android 14+ `isolatedSplitSystemServer` for truly isolated processes;
//!   APEX module updates via `PackageInstaller`.
//! - **Exec**: JNI `Runtime.exec` → `android.os.Process.start()` or raw
//!   vfork + execve of bundled toybox binaries in the app's lib/ dir.
//! - **Metrics**: `/proc/self/status` + `TraceWrapper`/`atrace`; cgroup v2
//!   cpu.max/memory.max where available (Android 13+ on modern devices).
//! - **Auth**: Android Keystore 2.0 `setIsStrongBoxBacked(true)` +
//!   TEE-based Keymaster; PQ signatures implemented via `awp3` Rust crate
//!   as JNI-loaded `libawp3.so` (no BoringSSL PQ dependency).

use crate::platform::{AuthBackend, MetricsBackend, NetworkBackend, SandboxBackend};

pub struct Backend;
impl SandboxBackend for Backend {}
impl MetricsBackend for Backend {}
impl NetworkBackend for Backend {}
impl AuthBackend    for Backend {}

/// Minimum Android SDK level (API level) we commit to support.
/// Android 13 = API 33 — first release with full SELinux io_uring mediation,
/// mandatory app-scoped storage, per-process Memory Advice API.
pub const MIN_ANDROID_API: u32 = 33;

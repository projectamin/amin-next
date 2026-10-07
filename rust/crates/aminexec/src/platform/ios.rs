//! iOS (non-jailbroken) platform trait implementations — scaffold stubs.
//!
//! iOS has NO `fork()`.  `posix_spawn(3)` (libSystem.B.dylib) is the only
//! supported child-process API.  3rd-party App Store binaries may only
//! spawn within the App Sandbox container their entitlements declare.
//!
//! Full implementation uses:
//! - **Sandbox**: App Sandbox with explicit `com.apple.security.*` entitlements
//!   per filter.  MDM-provisioned profiles can add CriticalAlert + network
//!   server entitlements.
//! - **Exec**: `NSTask` bridged via `objc` crate or direct `posix_spawnattr_*`
//!   FFI (`posix_spawn($pid, "/bin/sh", $attr, …)`).
//! - **Metrics**: `libproc.h` `proc_pid_rusage()` + `OSSignpostRecord` (iOS 16+)
//!   bound via the `objc` crate (`ios-ffi` feature).
//! - **Crypto**: Swift CryptoKit bindings (or our `awp3` Rust crate cbindgen
//!   C header imported via bridging header).  Secure Enclave used for
//!   ML-DSA-65 + ed25519 composite signer; iOS 18 PostQuantum framework for
//!   the ML-KEM-768 leg of hybrid KEX.

use crate::platform::{AuthBackend, MetricsBackend, NetworkBackend, SandboxBackend};

pub struct Backend;
impl SandboxBackend for Backend {}
impl MetricsBackend for Backend {}
impl NetworkBackend for Backend {}
impl AuthBackend    for Backend {}

/// Minimum iOS major version we commit to support.
pub const MIN_IOS_MAJOR: u32 = 14;

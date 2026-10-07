//! POSIX minimal fallback platform — no kernel enforcement, universal fallback.
//!
//! Used on: NetBSD, OpenBSD, Darwin (non-iOS), Haiku, Windows+Cygwin, WSL1, …
//! Every platform-trait method delegates to standard POSIX calls: fork+exec,
//! wait4, getrusage, getifaddrs, pam.  This is the baseline "it runs"
//! implementation; stronger sandboxes are per-OS opt-ins above.

use crate::platform::{AuthBackend, MetricsBackend, NetworkBackend, SandboxBackend};

pub struct Backend;
impl SandboxBackend for Backend {}
impl MetricsBackend for Backend {}
impl NetworkBackend for Backend {}
impl AuthBackend    for Backend {}

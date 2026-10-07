//! FreeBSD platform trait implementations (scaffold stubs).
//!
//! Full implementation uses:
//! - [`capsicum`] to enter capability mode after exec
//! - `jail(2)` + `rctl(8)` for per-process memory/CPU limits

use crate::platform::{AuthBackend, MetricsBackend, NetworkBackend, SandboxBackend};

pub struct Backend;
impl SandboxBackend for Backend {}
impl MetricsBackend for Backend {}
impl NetworkBackend for Backend {}
impl AuthBackend    for Backend {}

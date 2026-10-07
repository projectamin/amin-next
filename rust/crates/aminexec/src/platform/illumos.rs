//! Illumos / Oracle Solaris derivative platform stubs.
//!
//! Trait impls use: zone(5) for per-process sandbox, privileges(5) with
//! `priv_set(PRIV_ON, PRIV_INHERITABLE, …)` drop list, FSS (Fair Share
//! Scheduler) for CPU, `kstat_rsrc_ctl` memory/IO accounting,
//! ipnetstack for exclusive network stack per zone, ZFS dataset delegation.

use crate::platform::{AuthBackend, MetricsBackend, NetworkBackend, SandboxBackend};

pub struct Backend;
impl SandboxBackend for Backend {}
impl MetricsBackend for Backend {}
impl NetworkBackend for Backend {}
impl AuthBackend    for Backend {}

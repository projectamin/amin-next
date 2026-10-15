//! Darwin (macOS) backend — cgroup-equivalent enforcement via process rlimits.
//!
//! There is NO cgroup ABI on darwin. The platform offers only per-process
//! rlimits (`setrlimit(2)`), which — unlike cgroups — are limits on the
//! exec'd image itself (they are process attributes and survive exec).
//! This backend implements the **"as close as possible" tier** documented in
//! `docs/darwin-sandbox-plan.md`:
//!
//! - `memory_max` → **fail closed** `MissingAbi`. Empirical verification
//!   (t-style probes + staged `ulimit -v` runs, macOS 27.x arm64, October
//!   2026): XNU accepts a lowered RLIMIT_AS/RLIMIT_DATA value above an
//!   undocumented ~460 MiB floor (below it: sporadic EINVAL that differs
//!   between shells!) and then **drops the limit across exec** — the child
//!   reports unlimited again. Identical values intermittently fail. A limit
//!   that (a) has no documented semantics, (b) has no determinate floor, and
//!   (c) does not survive exec is NOT an enforcement ABI — pretending it is
//!   would be exactly the silent-degradation the sandbox contract forbids.
//! - `pids_max`   → `RLIMIT_NPROC` (per-UID on darwin — coarse guard only;
//!   verified honored: child `ulimit -u` reports the declared value).
//! - `memory_high`→ unconstrained (darwin `RLIMIT_RSS` is unenforced; we do
//!   NOT pretend),
//! - `cpu_max`    → fail closed `MissingAbi` (a rate quota has no darwin
//!   equivalent; `RLIMIT_CPU` total-seconds is a *different contract* and is
//!   wired in a later phase as its own manifest field — RLIMIT_CPU lowering
//!   verified honored against child `ulimit -t`).
//! - `io_max`     → fail closed `MissingAbi` (no API),
//! - landlock / seccomp / foreign netns → fail closed `MissingAbi` (Seatbelt
//!   is Phase 2; `net != host` already exits `-4099` in main.rs).
//!
//! Enforcement order in main.rs is preserved: cgroup-equivalent (rlimits)
//! before landlock/seccomp — the same "restrict early, fail closed" ordering
//! contract as the linux backend.

// Module is target-gated (`#[cfg(target_os = "macos")])`; raw libc FFI for
// setrlimit/getrlimit is the only way to reach process rlimits from std —
// same precedent as pid1.rs and main.rs (`#![allow(unsafe_code)]`).
#![allow(unsafe_code)]

use crate::platform::{
    AuthBackend, BpfMapHandles, MetricsBackend, NetnsHandle, NetworkBackend, SandboxBackend,
    SandboxError, SandboxResult,
};
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::path::Path;

pub struct Backend;

/// Parse a cgroup-style size string into bytes.
///
/// Supported (matching what the Perl machine layer may emit and what the
/// linux backend handles as controller text):
/// - `"max"`      → `None` (unlimited/absent — nothing to stage)
/// - plain digits → bytes (cgroup core semantics)
/// - `K|KiB`      → KiB, `M|MiB` → MiB, `G|GiB` → GiB (case-insensitive)
///
/// Anything else is a policy error (`Ruleset`), fail-closed by design.
pub fn parse_cgroup_size(s: &str) -> Option<Result<u64, SandboxError>> {
    let t = s.trim();
    if t.is_empty() {
        return Some(Err(SandboxError::Ruleset("empty size value".into())));
    }
    if t.eq_ignore_ascii_case("max") {
        return None; // unlimited: skip staging entirely
    }
    // Fail-closed: policy input with interior whitespace ("10 GiB",
    // "10000 100000") is never a single size — reject rather than guess.
    if t.chars().any(|c| c.is_ascii_whitespace()) {
        return Some(Err(SandboxError::Ruleset(format!(
            "size value contains whitespace: {s:?}"
        ))));
    }
    // Split numeric part and unit suffix.
    let (digits, unit) = match t.char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
    {
        Some((idx, _)) => (&t[..idx], t[idx..].trim()),
        None           => (t, ""),
    };
    let n: u64 = match digits.parse() {
        Ok(v) => v,
        Err(_) => {
            return Some(Err(SandboxError::Ruleset(format!(
                "unparseable size value {s:?}"
            ))))
        }
    };
    let m: u64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kib" => 1024,
        "m" | "mib" => 1024 * 1024,
        "g" | "gib" => 1024 * 1024 * 1024,
        other => {
            return Some(Err(SandboxError::Ruleset(format!(
                "unsupported size unit {other:?} in {s:?}"
            ))))
        }
    };
    Some(Ok(n * m))
}

/// Lower (or verify) one rlimit to `target_bytes` without privilege:
/// the soft limit can only shrink or stay, and raising the soft limit
/// requires the hard limit to already permit it. Unprivileged runs may only
/// *lower* — this is the enforcement direction for sandboxing anyway.
fn lower_rlimit(resource: libc::c_int, target_bytes: u64) -> SandboxResult<()> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain getrlimit(2) with a valid struct pointer.
    if unsafe { libc::getrlimit(resource, &mut lim) } != 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }
    // Do not exceed the existing hard limit (would need privileges or would
    // simply fail with EPERM per getrlimit(2) semantics).
    let hard: u64 = if lim.rlim_max == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        lim.rlim_max as u64
    };
    let want: u64 = target_bytes.min(hard);
    // Guard against unrepresentable rlim_t values: “big enough to be
    // pseudo-unlimited” maps to RLIM_INFINITY, otherwise cast down.
    let want_rlim: libc::rlim_t = if want >= u64::MAX - 4096
        || want > i64::MAX as u64
    {
        libc::RLIM_INFINITY
    } else {
        want as libc::rlim_t
    };
    // Only monotonic lowering (or no-op) without privilege — never widen.
    if lim.rlim_cur != libc::RLIM_INFINITY && (lim.rlim_cur as u64) <= want {
        return Ok(()); // already at/below target: satisfied
    }
    let new = libc::rlimit { rlim_cur: want_rlim, rlim_max: lim.rlim_max };
    // SAFETY: setrlimit(2) with own-validated struct.
    if unsafe { libc::setrlimit(resource, &new) } != 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

impl SandboxBackend for Backend {
    fn landlock_enforce(&self, _ro: &[&Path], _rw: &[&Path]) -> SandboxResult<()> {
        // Phase 2 (Seatbelt) not implemented yet — fail closed like every
        // other unimplementable class. Never silently allow.
        Err(SandboxError::MissingAbi(
            "landlock unavailable on darwin (Seatbelt Phase 2 pending in docs/darwin-sandbox-plan.md)",
        ))
    }

    fn cgroup_apply(
        &self,
        _sb_name:    &str,
        cpu_max:     Option<&str>,
        memory_max:  Option<&str>,
        pids_max:    Option<u32>,
        io_max:      Option<&str>,
    ) -> SandboxResult<()> {
        // Darwin "cgroup" = per-process rlimits, applied to the current
        // process BEFORE exec; limits are inherited by the exec'd workload.
        // No directory creation, no attach: `cgroup_attach_current` is a
        // no-op on this backend.
        //
        // Fail-closed ordering: cpu_max/io_max declared but unimplementable
        // → error BEFORE staging anything partial (no half-applied tiers).
        // Applies to "max" values too: an unbounded rate is still a rate
        // contract this backend cannot honor.
        if cpu_max.is_some() {
            return Err(SandboxError::MissingAbi(
                "darwin has no CPU rate quota (cpu.max); RLIMIT_CPU total-seconds is a different contract (Phase 4)",
            ));
        }
        if let Some(i) = io_max {
            if !i.is_empty() {
                return Err(SandboxError::MissingAbi(
                    "darwin has no io API (io.max); no cgroup-equivalent io controller",
                ));
            }
        }
        if let Some(_m) = memory_max {
            // See module header: verified unenforceable on darwin 27.x arm64
            // (dropped across exec, indeterminite EINVAL floor). Fail closed.
            return Err(SandboxError::MissingAbi(
                "darwin has no enforceable memory ABI (RLIMIT_AS/RLIMIT_DATA dropped across exec, undocumented EINVAL floor); see docs/darwin-sandbox-plan.md",
            ));
        }
        if let Some(p) = pids_max {
            // Per-UID on darwin (XNU maxprocperuid): coarse guard, not an
            // isolated workload budget — documented in the tier contract.
            lower_rlimit(libc::RLIMIT_NPROC, u64::from(p))?;
        }
        Ok(())
    }

    fn cgroup_attach_current(&self, _sb_name: &str) -> SandboxResult<()> {
        // Rlimits are process state — "attach" happens by construction:
        // the exec'd image inherits them. No-op by design, not by skipping.
        Ok(())
    }

    fn seccomp_apply(&self, _b: &[u8]) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi(
            "seccomp-bpf unavailable on darwin (no third-party syscall filtering ABI)",
        ))
    }
}

impl MetricsBackend for Backend {}
impl AuthBackend    for Backend {}

impl NetworkBackend for Backend {
    fn netns_unshare_isolated(&self, _: Option<RawFd>, _: &str, _: Ipv4Addr, _: u8, _: Ipv4Addr) -> SandboxResult<NetnsHandle> {
        Err(SandboxError::MissingAbi(
            "netns/veth unavailable on darwin (NetworkExtension is a different trust model)",
        ))
    }
    fn netns_join_shared(&self, _: &Path) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi(
            "netns/veth unavailable on darwin (NetworkExtension is a different trust model)",
        ))
    }
    fn clsact_attach_progs(&self, _: &str, _: &[u8], _: &[u8]) -> SandboxResult<BpfMapHandles> {
        Err(SandboxError::MissingAbi(
            "clsact eBPF unavailable on darwin",
        ))
    }
    fn bpf_map_read_egress_bytes(&self, _: RawFd) -> SandboxResult<u64> {
        Err(SandboxError::MissingAbi(
            "eBPF maps unavailable on darwin",
        ))
    }
    fn bpf_map_update_drain(&self, _: RawFd, _: u32, _: u8) -> SandboxResult<()> {
        Err(SandboxError::MissingAbi(
            "eBPF maps unavailable on darwin",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::SandboxError;

    /// Unwrap helper: `SandboxError` intentionally has no `PartialEq`, so
    /// tests assert on the payload instead of byte-comparing the enum.
    fn ok_bytes(r: Option<Result<u64, SandboxError>>) -> u64 {
        match r { Some(Ok(b)) => b, other => panic!("expected Some(Ok(..)), got {other:?}") }
    }

    // ── parse_cgroup_size ────────────────────────────────────────────────
    #[test]
    fn parse_max_is_none_unlimited() {
        assert!(parse_cgroup_size("max").is_none());
        assert!(parse_cgroup_size("MAX").is_none());
        assert!(parse_cgroup_size(" max ").is_none());
    }

    #[test]
    fn parse_plain_bytes() {
        assert_eq!(ok_bytes(parse_cgroup_size("1048576")), 1_048_576);
        assert_eq!(ok_bytes(parse_cgroup_size("0")),       0);
    }

    #[test]
    fn parse_suffix_units() {
        assert_eq!(ok_bytes(parse_cgroup_size("1K")),   1024);
        assert_eq!(ok_bytes(parse_cgroup_size("1M")),   1_048_576);
        assert_eq!(ok_bytes(parse_cgroup_size("512M")), 512 * 1024 * 1024);
        assert_eq!(ok_bytes(parse_cgroup_size("2G")),   2 * 1024 * 1024 * 1024);
        assert_eq!(ok_bytes(parse_cgroup_size("1MiB")), 1_048_576);
        assert_eq!(ok_bytes(parse_cgroup_size("1Gib")), 1_073_741_824);
    }

    #[test]
    fn parse_errors_are_fail_closed_ruleset() {
        for bad in ["", "1TB", "M", "10 GiB", "-1M", "1.5M", "abc"] {
            let r = parse_cgroup_size(bad);
            let is_err = matches!(r, Some(Err(SandboxError::Ruleset(_))));
            assert!(is_err, "expected Ruleset error for {bad:?}, got {r:?}");
        }
    }

    #[test]
    fn cpu_max_always_fails_closed_missing_abi() {
        // Even a plain numeric value is a rate contract on darwin — never a
        // silent no-op. (≃ "10000" would be a nonsense quota anyway.)
        let r = Backend.cgroup_apply("sb-test", Some("10000"), None, None, None);
        assert!(matches!(r, Err(SandboxError::MissingAbi(_))), "got {r:?}");
    }

    #[test]
    fn io_max_always_fails_closed_missing_abi() {
        let r = Backend.cgroup_apply("sb-test", None, None, None, Some("rbps=max"));
        assert!(matches!(r, Err(SandboxError::MissingAbi(_))), "got {r:?}");
    }

    #[test]
    fn no_fields_is_a_clean_noopattach() {
        // Nothing requested → nothing staged → Ok. The main.rs flow then
        // calls cgroup_attach_current (a documented no-op here).
        let r = Backend.cgroup_apply("sb-test", None, None, None, None);
        assert!(r.is_ok(), "got {r:?}");
        assert!(Backend.cgroup_attach_current("sb-test").is_ok());
    }

    #[test]
    fn memory_max_always_fails_closed_on_darwin() {
        // Even "max" (unlimited) is a *declared* memory contract that darwin
        // cannot honor mechanically — anything but explicit refusal would
        // silently assume the limit's absence, which the tier forbids.
        for v in ["1073741824", "512M", "max"] {
            let r = Backend.cgroup_apply("sb-test", None, Some(v), None, None);
            assert!(matches!(r, Err(SandboxError::MissingAbi(_))), "for {v:?}: got {r:?}");
        }
    }

    #[test]
    fn pids_max_is_accepted_for_staging() {
        // Interface-level: pids_max accepted (real lowering is asserted e2e in
        // t/47 — in-process NPROC changes would mutate the test binary itself).
        let r = Backend.cgroup_apply("sb-test", None, None, Some(512u32), None);
        assert!(r.is_ok(), "got {r:?}");
    }

    // Real rlimit lowering is verified e2e (t/47 on the darwin host): in-process
    // lowering here would mutate the shared test binary's own limits.
}

# Darwin (macOS) cgroup-equivalent sandbox plan

## Goal

Run the same Amin 3.0 profiles (Sandbox filter scope attrs → `Amin::Sandbox->build_manifest_for` → `aminexec --sandbox-stdin` JSON manifest → backend) on macOS with enforcement **as close as possible** to Linux's `cgroup v2 + landlock + seccomp`, preserving the architectural invariant:

> **Policy is owned by the machine's filter chain, not by `aminexec`.**
> The profile declares intent (tier + scope attrs); `Amin::Sandbox`/`Spawn` own policy and emit the manifest; `aminexec` is the honest executor — it enforces what the manifest asks for on that platform, or **fails closed** (`rc=-4097 sandbox_missing_abi`, `-4099 net_missing_abi`) on what it cannot. It never silently degrades.

## What macOS actually offers (verified 2025-26)

| Linux concept | Darwin reality |
|---|---|
| cgroup v2 `memory.max` | **No reliable enforcement.** `RLIMIT_AS` is not in Apple's documented setrlimit set and is NOT consistently enforced (malloc does not reliably fail at budget) — [Fast Downward issue 825](https://ai-fast-downward.dmi.unibas.ch/issue825), [Apple getrlimit(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getrlimit.2.html) |
| cgroup `pids.max` | `RLIMIT_NPROC` is **per-UID**, not per-workload-tree (XNU `maxprocperuid`) — usable only as a coarse guard |
| cgroup `cpu.max` | No per-process quota API exists. `taskpolicy`/QoS is scheduling *priority* (hint), not a ceiling. `RLIMIT_CPU` bounds cumulative CPU *time* (SIGXCPU) — a different contract |
| landlock | **Seatbelt** (`sandbox_init` in `libsandbox.dylib`, profile string applied pre-exec). Semi-deprecated by Apple, but Chromium's 2025 sandbox design still uses it — [Chromium design](https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/mac/seatbelt_sandbox_design.md) |
| seccomp-bpf | **No equivalent.** No substring/subset syscall filtering for third-party processes on macOS |
| netns/veth/vpc | No per-process netns. NetworkExtension = system-extension filtering (different trust model); EndpointSecurity = event monitoring, not confinement |

## Design: tier contract, not silent degradation

`sandbox_tier` becomes a *contract declaration* the manifest carries. Each tier names which enforcement classes it requires; aminexec validates the manifest's platform against the tier's demands:

- staging-cg2-strict (linux): full contract → everything must enforce or fail closed.
- staging-darwin-rlimit (darwin): declares `fs=seatbelt, mem=rlimit-as(best-effort), pids=rlimit-nproc, cpu=rlimit-cpu-budget, probe=none, net=host` — a weaker but *honest* tier. Requesting `staging-cg2-strict` on darwin fails closed today (current behavior: t/18 test 7).

Capability resolution (machine layer): `Amin::Machine::MachineSpec` exposes a per-host capability vector (`{mem, pids, cpu, fs, probe, net}`); the Sandbox filter clamps or refuses a tier against it. aminexec stays the last-resort guard.

## Implementation phases

### Phase 1 — ✅ SHIPPED: `platform/darwin.rs` rlimit backend (2026-10-15)
Implemented exactly as planned, with one **empirically-decided correction**: direct kernel probes on macOS arm64 (darwin 27.2) proved `RLIMIT_AS`/`RLIMIT_DATA` are NOT an enforcement ABI:
- lowering succeeds only above an undocumented ~460 MiB floor, fails `EINVAL` below it,
- identical values succeed in bash and fail in zsh,
- a *successfully applied* value verifies inside the setting shell, then **drops back to unlimited after exec** (the child reports `ulimit -v` unlimited).

A limit with no documented semantics, no determinate floor, and exec-volatile state cannot honestly claim enforcement — so `memory_max` **fails closed** (`MissingAbi` → `-4097`) instead of fake-enforcing. This is the contract check the plan promised: the verification test decided, and the answer was fail-closed.

**Verified honored end-to-end (t/47, child proves the limit via `ulimit`):**
| Manifest field | darwin handling | verified how |
|---|---|---|
| `pids_max` | `setrlimit(RLIMIT_NPROC)` before exec | child `ulimit -u` reports the declared value (e.g. 512) |
| `memory_max` | **fail closed** `-4097` (unenforceable) | probe evidence + t/47 Case 2 asserts no execution |
| `memory_high` | documented-unconstrained (`RLIMIT_RSS` unenforced) | — |
| `cpu_max` (rate) | fail closed `-4097` | unit tests |
| `io_max` | fail closed `-4097` (no API) | unit tests |
| landlock paths | fail closed `-4097` until Seatbelt (Phase 2) | t/47 Case 3 |
| `seccomp_bpf_base64` | fail closed `-4097` | unit tests |
| net `mode != host` | fail closed `-4099` (main.rs) | unchanged |

A schema bug surfaced by the first *successful* on-darwin manifest run was also fixed at the source: `build_manifest_for` emitted XML-attribute strings for `pids_max` where the manifest schema declares a JSON u32 — now coerced when strictly numeric, left a string otherwise so the Rust layer rejects non-numeric declarations ([Sandbox.pm](../perl-lib/Amin/Sandbox.pm)). Suite: 47 files, 1083 tests, PASS.

### Phase 2 — Seatbelt filesystem confinement
- `dlopen("/usr/lib/libsandbox.dylib")` → `sandbox_init(profile, flags, &err)`, mirroring Chromium's approach (no public header; define the 2 symbols + types manually).
- Manifest `landlock_ro`/`landlock_rw` → generated Seatbelt profile text: default-deny writes, explicit `(allow file-read* (literal|subpath ...))` entries, explicit `(allow process-exec ...)` for the argv binary. Generation lives in Rust so profile and manifest can never disagree.
- Anything the profile can't express → `Err(MissingAbi)` fail closed.
- API is application-at-process-start only: must be called between `chdir/env` setup and `execvpe`, exactly where the current backend calls sit — no flow changes.

### Phase 3 — Machine-layer tier plumbing (policy side)
- `Amin::Sandbox::build_manifest_for` gains a `tier_contract` field written from the resolved capability vector; aminexec cross-checks it against what it applies and errors `sandbox_missing_abi` with a *named class* detail (`tier contract requires probe=seccomp; darwin has none`).
- `MachineSpec` capability vector populated for `darwin` (and reused later for freebsd|jail, illumos|zones — the same contract generalizes; each platform fills one more column of the uniform backend table).
- Spawn/Exec filters keep declaring scope attrs unchanged — profiles stay portable by tier, not by OS.

### Phase 4 — accounting + optional extras
- `MetricsBackend` slot on darwin: `proc_pid_rusage` for per-workload accounting (matches the reserved slot in [lib.rs](../rust/crates/aminexec/src/lib.rs)).
- Optional `taskpolicy`/QoS passthrough as an advisory scheduling preference (never claimed as enforcement).
- Ask-for-more button: EndpointSecurity/network filtering stays out of scope for non-entitled runs.

## Verification

- t/18-style e2e: spawn with `memory_max=1M` + tiny argv; child `/bin/sh -c ulimit -v` reports the applied `RLIMIT_AS`, proving the manifest→darwin backend→exec chain honors declared intent on this host (this test also empirically settles the RLIMIT_AS-enforcement question per macOS release).
- Fail-closed matrix preserved: landlock/seccomp/net-fabric requests on darwin keep producing `-4097`/`-4099` statuses (t/18 tests 6-8 semantics).
- MachineSpec tier-resolution unit tests (requested tier vs host capability vector → clamp/refuse).

## Non-goals

- No fake cgroup emulation layers, LD_PRELOAD trampolines, or entitlement-required system extensions in this plan.
- No platform-specific XML dialects: profiles stay portable; platforms differ only in what they can honor.

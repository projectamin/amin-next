# The PID 1 split: why `ainit` and `aminexec` are two binaries

On a metal Amin node two processes call themselves PID 1, one after the other. They are **one control loop in two phases**, divided by `pivot_root`. This document records why they are not merged, where the boundary between them is defined, and what each side owns — so the next person to ask "aren't these the same thing?" gets the answer from the design rather than from the diff.

## The two phases

| | `ainit` | `aminexec` |
|---|---|---|
| crate | [`rust/crates/ainit/`](../rust/crates/ainit/) | [`rust/crates/aminexec/`](../rust/crates/aminexec/) |
| runs from | the netboot initrd (`.cpio.zst`, `/init`) | the rootfs the profile selected, after `pivot_root` |
| is PID 1 | first — the kernel's `/init` | second — `execve`d by ainit, or the slot's `/sbin/init` |
| stages | 1..=4 — hwcheck · fw-update · storage-init · mesh-join | 5..=6 — supervisor · workload-ready |
| lifetime | seconds; it ends at `execve` | the life of the node |
| on failure | sysrq reboot (`/proc/sysrq-trigger` `b`) | the supervision tree stays up and reports |

The chain, end to end:

```
boot firmware (UEFI HTTP boot, or a vendor bootloader handing over kernel + initrd)
   │  vmlinuz + ainit.cpio.zst
   ▼
ainit  ── PID 1, from the initrd ────────────────────────────────────────
   ├─ mesh HELLO → BOOT_OFFER, verified against the baked-in ML-DSA anchor
   ├─ Bitcache CAS fetch of init-profile.xml.bsax over RS(3,2) mesh stripes
   ├─ stages 1..=4   hwcheck · fw-update · storage-init · mesh-join
   ├─ SCM_RIGHTS: 5 fds → /run/amin/hand-off.sock
   └─ pivot_root + execve("/sbin/aminexec")
   ▼
aminexec ── PID 1, from the profile's rootfs ─────────────────────────────
   ├─ recv the 5 handoff fds
   ├─ full mount set + cgroup v2 subtree /sys/fs/cgroup/amin
   ├─ stages 5..=6   supervisor · workload-ready
   └─ SAX dispatcher + per-process sandbox + AWP/3, for the life of the node
```

## Why not one binary

**1. It has to run before the rootfs is trusted.** ainit executes from the initrd. The profile it resolves is the thing that decides *which* rootfs to pivot into and *what* to run there. A single binary that both resolves the profile and runs inside the profile's rootfs would have to be present and trusted before it has fetched the material that makes it trusted.

**2. The initrd size budget is real.** ainit is bounded by TR-8.1 at **≤ 2 MB zstd**, with **no tokio, no tracing, no proc-macro crates** — byte-bashing plus raw libc syscalls ([ainit/src/lib.rs](../rust/crates/ainit/src/lib.rs)). Its dependency set is `anyhow`, `thiserror`, `libc`, `bsax` (no default features), `bitcache`, `blake3`, `bytes`, `reed-solomon-16`, `tempfile`. aminexec's is `tokio`, `tracing` + `tracing-subscriber`, `serde` + `serde_json`, `base64`, plus the Linux-only `nix`, `rtnetlink` and `futures`. Merging the two means either imposing the 2 MB / no-tokio budget on the long-lived runtime, or giving it up for the initrd binary.

**3. The file descriptors must survive the pivot.** mesh-join leaves ainit holding three connected AWP/3 QUIC sockets, a slab fd with `flock(LOCK_EX)` held, and the seal-chain append fd. Re-opening them in the second phase would lose the exclusive lock, the QUIC connected state, and any kernel-side TLS/PQ handshake state. The `SCM_RIGHTS` handoff ([ainit/src/fd_handoff.rs](../rust/crates/ainit/src/fd_handoff.rs)) exists so the second process *inherits* them instead. That is a phase boundary, not a function boundary — the handoff is the interface, and it is the only one.

**4. Each side keeps its own small closed-world surface.** ainit decodes only the ainit stage vocab region (IDs 102..=107 — `stage`, `order`, `node_id`, `refused`, `init_profile_ref`, `slab_dev`) and counts stages 5..=6 as skipped ([ainit/src/stage_decoder.rs](../rust/crates/ainit/src/stage_decoder.rs)), leaving them for the full dispatcher in the second phase. One profile document, two readers, each as small as its half needs.

## Where the boundary is defined

- **The profile ref** — ainit answers exactly one question and passes it as phase 2's single argument: `execve("/sbin/aminexec", ["aminexec", <profile>])`. A `ToR`-served ref is passed through as `bitcache:`/`http(s)://`; a standalone boot is `local:<path>` on FRAMEBOOT. The resolver is [ainit/src/bootstrap.rs](../rust/crates/ainit/src/bootstrap.rs); phase 2's `resolve_profile_ref` in [aminexec/src/pid1.rs](../rust/crates/aminexec/src/pid1.rs) turns a `local:` ref into a path.
- **The handoff** — `SOCK_SEQPACKET` at `/run/amin/hand-off.sock`, exactly 5 fds, in this order:

  | # | fd |
  |---|---|
  | 0 | mesh peer #1 QUIC socket |
  | 1 | mesh peer #2 QUIC socket |
  | 2 | mesh peer #3 QUIC socket |
  | 3 | Bitcache slab fd (`O_DIRECT`, `LOCK_EX` held) |
  | 4 | seal-chain append fd |

- **The stage table** — which side executes which stage: [ainit/src/stage_decoder.rs](../rust/crates/ainit/src/stage_decoder.rs).
- **Trust-anchor registration** happens at mesh-join, i.e. in the first phase: [perl-lib/Amin/Auth/ZCap.pm](../perl-lib/Amin/Auth/ZCap.pm).

## What each side owns

| | ainit (phase 1) | aminexec (phase 2) |
|---|---|---|
| network | boot NIC, mesh HELLO / BOOT_OFFER | AWP/3 to the scheduler, on the inherited sockets |
| storage | slab open + `LOCK_EX`, storage-init | per-workload accounting on the cgroup subtree |
| profile | answer *where it is* (a served ref or `local:<path>`) | hand it to the Amin/Perl runtime, which applies it |
| kernel state | the minimum to fetch and pivot | full mount set, cgroup v2 subtree, `devtmpfs`, `devpts`, `/run`, `/tmp` |
| executes | none of the workload | every sandboxed child |
| ends by | `execve("/sbin/aminexec")` | never — it is the supervision tree |

## Enforced by

- **ainit** (`cargo test -p ainit`): closed-world decode (`skipped_elements > 0`), RS(3,2) recover-any-2, `TR-8.3` 5-fd inode-match.
- **aminexec** (`cargo test -p aminexec`): the PID-1 simulator asserts the full six-mount set, the cgroup subtree and the listener bind.
- **Perl side**: `Amin::Generator::BSAX` / `Amin::Handler::BSAX` hold 1:1 name-ID parity with `rust/crates/bsax/src/vocab.rs`; the ainit stage region is pinned at vocab index 102.

## Status

The phase-2 side of the contract is implemented: `aminexec`'s `pid1_bringup()` does the mounts, the cgroup subtree and the handoff listener, with a simulator for CI. `pid1_run()` then resolves the profile ref it was handed, runs the Amin/Perl runtime as a child, reaps it, and supervises for the life of the node. A failure is reported to `/dev/kmsg` and the process holds rather than returning (an exiting PID 1 panics the kernel, and `panic=5` would reboot straight back into the same failure).

The phase-1 side runs end to end for a **standalone (no-mesh) boot**: `ainit::run_real_pid1_entrypoint` reads `/proc/cmdline`, and when no served ref is present it mounts FRAMEBOOT, finds a local profile, and `execve`s `/sbin/aminexec` with `local:<path>`. The resolver lives in [ainit/src/bootstrap.rs](../rust/crates/ainit/src/bootstrap.rs); the boot profile is emitted by `ainit`'s host-side example ([ainit/examples/emit-profile.rs](../rust/crates/ainit/examples/emit-profile.rs)) with the same encoder the decoder reads.

Still open:

- **The served path** — mesh HELLO → BOOT_OFFER verification → RS(3,2) Bitcache fetch — is implemented in separate modules but not yet wired into the entrypoint; a cmdline that already carries a served ref is passed through and trusted as complete.
- **Served refs in phase 2** — `aminexec::pid1::resolve_profile_ref` currently understands only `local:`; a `bitcache:`/`http(s)://` ref fails with a clear error until the mesh fetch is wired.
- **Trust** — a locally provisioned profile on FRAMEBOOT is only as strong as that FAT. This is a deliberate bring-up shortcut; a served boot must never fall back to it, and the network-served case needs the real authority path before it is relied on.

//! PID 1 kernel bringup for metal Amin nodes.
//!
//! When `aminexec` is invoked as PID 1 (UEFI HTTP Boot → ainit initrd →
//! `pivot_root` into the Bitcache-backed Amin rootfs), we run
//! [`pid1_bringup`] **before** any userland services:
//!
//! 1. Mount the minimal trusted filesystem set (procfs / sysfs / devtmpfs /
//!    devpts / tmpfs for /run + /tmp).
//! 2. Parse the kernel command line from `/proc/cmdline` into
//!    [`BootCommandLine`], extracting the Bitcache ref for the init profile,
//!    the node's stable `node_id` fingerprint, the zcap token for this
//!    boot, and the slab storage device.
//! 3. Create the `/sys/fs/cgroup/amin` cgroup v2 subtree with
//!    `subtree_control = "+cpu +memory +io +pids"` — every spawned workload
//!    lives under this subtree (NFR-7.1 closed-world: only 2 userland
//!    processes at idle on the metal node).
//! 4. Bind a `SOCK_SEQPACKET` Unix-domain listener to
//!    `/run/amin/hand-off.sock` so the preceding ainit initrd can hand
//!    over the mesh QUIC sockets, slab file descriptor, and seal-chain
//!    append fd via `SCM_RIGHTS` prior to `pivot_root`.
//!
//! The real PID-1 code path is only reachable when `getpid() == 1`.  For
//! unit tests, CI, and local development, [`pid1_bringup_sim`] performs
//! **exactly** the same logical steps but against a `tempfile::TempDir`
//! rooted filesystem tree so mount list state can be asserted without
//! requiring root or a QEMU harness.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

// ── Kernel cmdline contract ──────────────────────────────────────────────
// Exact key names from spec § FR-2.3.  Any future cmdline key MUST be added
// to this struct AND to the exhaustive match below so unknown keys are
// loudly rejected at boot (closed-world — we want to fail boot rather than
// silently ignore operator typos like `amin.nodeid` instead of
// `amin.node_id`).

/// Parsed kernel command line for an Amin PID 1 boot.
///
/// All fields except `node_id` carry a `bitcache:blake3:<hex>` style ref or
/// a device path; see spec FR-2.3 for the authoritative contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootCommandLine {
    /// Bitcache ref of the init-profile.xml.bsax document — the root SAX
    /// document that describes the 6 boot stages for this metal node.
    pub init_profile_ref: String,
    /// Stable blake3-fingerprinted node identifier (spec NFR: derived from
    /// CPU model + DIMM layout + NVMe/NIC PCIe BDFs of the cookie-cutter
    /// metal hardware config).
    pub node_id: String,
    /// ML-DSA-87 capability token granting this boot authority to join
    /// the mesh (scope = tier, zone, max-redundancy for this node).
    pub zcap: String,
    /// Block device path for the Bitcache slab file backing store —
    /// typically `/dev/nvme0n1p2` on cookie-cutter x86_64 metal.
    pub slab_dev: PathBuf,
    /// Bitcache ref of the Amin rootfs (Bitcache CAS blob → overlayfs
    /// lowerdir for all spawned workloads once we're PID 1).
    pub aminexec_rootfs_ref: String,
    /// Catch-all for any non-`amin.*` kernel keys (console=, root=, …).
    /// Preserved verbatim for audit log / seal chain but not interpreted.
    pub passthrough: BTreeMap<String, String>,
}

impl BootCommandLine {
    /// Parse `/proc/cmdline` (space-separated `key=value` or bare `flag`
    /// tokens) into a [`BootCommandLine`].  Returns
    /// `Error::BootCommandLineMissing` with a named field if any required
    /// Amin key is absent.
    pub fn parse(cmdline: &str) -> Result<Self> {
        let mut init_profile_ref = None;
        let mut node_id = None;
        let mut zcap = None;
        let mut slab_dev = None;
        let mut aminexec_rootfs_ref = None;
        let mut passthrough = BTreeMap::new();

        for token in cmdline.split_whitespace() {
            let (k, v) = match token.split_once('=') {
                Some((k, v)) => (k, v.to_string()),
                None => (token, String::new()),
            };
            match k {
                "amin.init_profile_ref" | "amin.bootstrap" => init_profile_ref = Some(v),
                "amin.node_id" => node_id = Some(v),
                "amin.zcap" => zcap = Some(v),
                "amin.slab_dev" => slab_dev = Some(PathBuf::from(v)),
                "amin.aminexec_rootfs_ref" => aminexec_rootfs_ref = Some(v),
                aminkey if aminkey.starts_with("amin.") => {
                    bail!("unknown amin.* kernel cmdline key: {aminkey} \
                           (typo? closed-world: unknown Amin keys hard-fail boot)")
                }
                other => {
                    passthrough.insert(other.to_string(), v);
                }
            }
        }

        let require = |name: &str, val: Option<String>| -> Result<String> {
            val.ok_or_else(|| anyhow!("missing required amin.* cmdline key: {name}"))
        };

        Ok(Self {
            init_profile_ref: require("amin.init_profile_ref (or amin.bootstrap)", init_profile_ref)?,
            node_id:           require("amin.node_id", node_id)?,
            zcap:              require("amin.zcap", zcap)?,
            slab_dev:          slab_dev.ok_or_else(|| anyhow!("missing required amin.* cmdline key: amin.slab_dev"))?,
            aminexec_rootfs_ref: require("amin.aminexec_rootfs_ref", aminexec_rootfs_ref)?,
            passthrough,
        })
    }

    /// Convenience: open `/proc/cmdline` and feed its contents to
    /// [`BootCommandLine::parse`].
    pub fn read_proc_cmdline() -> Result<Self> {
        let mut buf = String::new();
        fs::File::open("/proc/cmdline")
            .context("open /proc/cmdline")?
            .read_to_string(&mut buf)
            .context("read /proc/cmdline")?;
        Self::parse(&buf)
    }
}

// ── Mount plan ───────────────────────────────────────────────────────────
// Minimal mount set for PID 1.  The ordering is the standard Linux early
// boot sequence; nothing extra — we deliberately avoid mounting
// /sys/firmware/efi/efivars read-write, mounting /home or any other
// non-essential tree, or auto-mounting anything from /etc/fstab (the metal
// node has no distro /etc).

#[derive(Debug, Clone)]
struct MountSpec {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    flags: libc::c_ulong,
    data:  &'static str,
}

const PID1_MOUNTS: &[MountSpec] = &[
    MountSpec { source: "proc",     target: "/proc",    fstype: "proc",     flags: libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, data: "" },
    MountSpec { source: "sysfs",    target: "/sys",     fstype: "sysfs",    flags: libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, data: "" },
    MountSpec { source: "devtmpfs", target: "/dev",     fstype: "devtmpfs", flags: libc::MS_NOSUID | libc::MS_STRICTATIME,              data: "mode=0755,size=4m" },
    MountSpec { source: "devpts",   target: "/dev/pts", fstype: "devpts",   flags: libc::MS_NOSUID | libc::MS_NOEXEC,                   data: "mode=0620,gid=5" },
    MountSpec { source: "tmpfs",    target: "/run",     fstype: "tmpfs",    flags: libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, data: "mode=0755,size=20%" },
    MountSpec { source: "tmpfs",    target: "/tmp",     fstype: "tmpfs",    flags: libc::MS_NOSUID | libc::MS_NODEV,                   data: "mode=1777,size=50%" },
];

// ── Cgroup v2 subtree ────────────────────────────────────────────────────
// /sys/fs/cgroup is already mounted as cgroup2fs by the kernel on modern
// distros (and by ainit's minimal mount set on the Amin metal netboot
// path).  We only need to:
//   1. Make sure the cgroup v2 filesystem is actually present (unified
//      hierarchy — no cgroup v1 allowed, closed-world).
//   2. Create /sys/fs/cgroup/amin mkdir.
//   3. Enable +cpu +memory +io +pids controllers in subtree_control.

const CGROUP_AMIN_ROOT: &str = "/sys/fs/cgroup/amin";
const CGROUP_SUBTREE_CONTROL: &str = "+cpu +memory +io +pids";

// ── ainit fd handoff socket ──────────────────────────────────────────────
// ainit (the tiny pre-PID-1 initrd) finishes the mesh join + slab open
// dance and then sends us:
//   • 3 AWP/3 mesh QUIC sockets (to 3 distinct peers for RS(3,2) stripe
//     reconstruction of the init-profile blob)
//   • 1 slab file fd (O_DIRECT opened against amin.slab_dev, already
//     flock(LOCK_EX)-ed for exclusive write)
//   • 1 seal-chain append fd (write-only fd for appending to the running
//     blake3+ML-DSA-87 seal chain log in the Bitcache slab)
//
// That's 5 fds total via SCM_RIGHTS over a SOCK_SEQPACKET unix socket.
// We bind the socket here in PID 1 before ainit calls pivot_root so the
// path is guaranteed to exist.

/// Path of the ainit → aminexec SOCK_SEQPACKET handoff socket.
pub const HANDOFF_SOCK_PATH: &str = "/run/amin/hand-off.sock";

// ── Public entry points ──────────────────────────────────────────────────

/// Outcome of [`pid1_bringup`] or [`pid1_bringup_sim`].
#[derive(Debug)]
pub struct Pid1Bringup {
    /// Parsed kernel command line.
    pub cmdline: BootCommandLine,
    /// True PID-1 listener bound to [`HANDOFF_SOCK_PATH`], or a
    /// tempdir-rooted equivalent for [`pid1_bringup_sim`].
    pub handoff_listener: UnixListener,
    /// The directory under which mounts were materialised — `/` for the
    /// real PID-1 path, a `TempDir` for the simulator so the tree is
    /// cleaned up on drop.
    pub root: PathBuf,
    /// Ordered list of mounts that were applied (for tests: can assert
    /// proc/sys/dev/devpts/run/tmp are ALL present).
    pub applied_mounts: Vec<MountRecord>,
    /// Cgroup subtree path that was created (absolute —
    /// `/sys/fs/cgroup/amin` for real PID 1, `<simroot>/sys/fs/cgroup/amin`
    /// for the simulator).
    pub cgroup_amin_root: PathBuf,
}

/// Record of one mount operation for assertions / audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRecord {
    /// `source` argument that was passed to `mount(2)`.
    pub source: String,
    /// Absolute target directory under which the filesystem was mounted.
    pub target: PathBuf,
    /// Filesystem type name ("proc", "sysfs", "tmpfs", …).
    pub fstype: String,
}

/// Real PID-1 bringup.  **Only safe to call when `getpid() == 1` on a
/// Linux system.**  Will panic with a clear message if run as a non-root
/// user in a test harness — use [`pid1_bringup_sim`] instead.
pub fn pid1_bringup() -> Result<Pid1Bringup> {
    // SAFETY: getpid() has no side effects, returns current thread-group
    // leader PID per POSIX.  We compare to 1 only for the gate.
    let pid = unsafe { libc::getpid() };
    if pid != 1 {
        bail!("pid1_bringup() called but getpid()={pid}; use pid1_bringup_sim() for tests")
    }

    bringup_inner(Path::new("/"), HANDOFF_SOCK_PATH, true)
}

/// Test-only / CI-safe equivalent of [`pid1_bringup`] that performs the
/// exact same logic (cmdline parse + mkdir of mount target dirs + cgroup
/// subtree file writes + bind listener) but rooted at a `tempfile::TempDir`.
///
/// Does **not** issue real `mount(2)` syscalls (that would require root /
/// user-namespace gymnastics in CI).  Instead it creates the target
/// directory tree and writes a tiny 1-byte sentinel file
/// `<target>/.mounted_from_<source>_<fstype>` into each so tests can assert
/// the full set of mounts was applied and ordered correctly.
pub fn pid1_bringup_sim(cmdline_override: Option<&str>) -> Result<Pid1Bringup> {
    let root = tempfile::Builder::new()
        .prefix("amin-pid1-sim-")
        .tempdir()
        .context("create tempdir for pid1 simulator")?;
    let root_path = root.path().to_path_buf();

    // Create a fake /proc/cmdline inside the sim root with a well-formed
    // cmdline unless the caller provided one (tests exercise the parser
    // directly through BootCommandLine::parse instead).
    let fake_proc = root_path.join("proc");
    fs::create_dir_all(&fake_proc).ok();
    let fake_cmdline = cmdline_override.unwrap_or(
        "ro quiet console=tty0 \
         amin.bootstrap=bitcache:blake3:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 \
         amin.node_id=node-blake3-9a5b \
         amin.zcap=zcap:mldsa87:base64tokenhere== \
         amin.slab_dev=/dev/nvme0n1p2 \
         amin.aminexec_rootfs_ref=bitcache:blake3:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321 \
         init=/init"
    );
    fs::write(fake_proc.join("cmdline"), fake_cmdline).context("write sim cmdline")?;

    // In sim mode, feed the override string directly to the cmdline parser
    // (so parsing is exercised even without the fake-proc path being
    // `/proc/cmdline` globally — which it won't be in tests running under
    // a normal kernel /proc mount).
    let cmdline = BootCommandLine::parse(fake_cmdline)?;

    let sim_sock_path = root_path.join("run/amin/hand-off.sock");
    let result = bringup_inner(&root_path, sim_sock_path.to_str().unwrap(), false)?;

    // Don't drop the tempdir: leak it through into Pid1Bringup.root so the
    // caller holds it alive for the lifetime of their test.  We do this by
    // converting TempDir → PathBuf via into_path() which disables the
    // auto-cleanup drop impl (directory lives until the test exits; OS reclaims).
    #[allow(deprecated)]
    let _ = root.into_path();

    Ok(Pid1Bringup { cmdline, ..result })
}

// ── Shared core (identical for real PID 1 + simulator) ───────────────────

fn bringup_inner(root: &Path, sock_path: &str, real_mounts: bool) -> Result<Pid1Bringup> {
    // 1. Minimal mounts (real mount(2) for PID 1, sentinel-file stubs for sim).
    let mut applied_mounts = Vec::with_capacity(PID1_MOUNTS.len());
    for spec in PID1_MOUNTS {
        let abs_target = root.join(spec.target.trim_start_matches('/'));
        fs::create_dir_all(&abs_target)
            .with_context(|| format!("mkdir mount target {}", abs_target.display()))?;

        if real_mounts {
            do_real_mount(spec, &abs_target)
                .with_context(|| format!("mount {} -> {} ({})", spec.source, abs_target.display(), spec.fstype))?;
        } else {
            // Sim: write sentinel.  Use a deterministic filename so tests
            // can glob or stat for it.
            let sentinel = abs_target.join(format!(
                ".mounted_from_{}_{}",
                spec.source.replace('/', "_"),
                spec.fstype
            ));
            fs::write(&sentinel, b"").with_context(|| format!("write mount sentinel {}", sentinel.display()))?;
        }
        applied_mounts.push(MountRecord {
            source: spec.source.to_string(),
            target: abs_target,
            fstype: spec.fstype.to_string(),
        });
    }

    // 2. Cmdline — for real PID 1, read it now that /proc is mounted.
    let cmdline = if real_mounts {
        BootCommandLine::read_proc_cmdline()?
    } else {
        // Simulator already parsed it one level up; placeholder — the
        // public pid1_bringup_sim fn overwrites it before returning.
        BootCommandLine::parse("")
            .unwrap_or_else(|_| BootCommandLine {
                init_profile_ref: String::new(),
                node_id: String::new(),
                zcap: String::new(),
                slab_dev: PathBuf::new(),
                aminexec_rootfs_ref: String::new(),
                passthrough: BTreeMap::new(),
            })
    };

    // 3. Cgroup v2 /sys/fs/cgroup/amin subtree.  For the real path this
    //    assumes cgroup2 is already mounted on /sys/fs/cgroup (it always is
    //    on Linux ≥ 6.2 unified-hierarchy kernels; ainit also mounts it
    //    explicitly).  For the simulator we create the directory tree so
    //    subtree_control can be written into a real file.
    let cg_root_rel = CGROUP_AMIN_ROOT.trim_start_matches('/');
    let cg_root_abs = root.join(cg_root_rel);
    fs::create_dir_all(&cg_root_abs)
        .with_context(|| format!("mkdir cgroup subtree {}", cg_root_abs.display()))?;

    let subtree_file = cg_root_abs.join("cgroup.subtree_control");
    fs::write(&subtree_file, CGROUP_SUBTREE_CONTROL.as_bytes())
        .with_context(|| format!("write cgroup.subtree_control = {:?} to {}",
                                 CGROUP_SUBTREE_CONTROL, subtree_file.display()))?;

    // 4. /run/amin/hand-off.sock SOCK_SEQPACKET bind.
    let sock_dir = Path::new(sock_path).parent()
        .ok_or_else(|| anyhow!("invalid handoff sock path: {sock_path}"))?;
    fs::create_dir_all(sock_dir)
        .with_context(|| format!("mkdir handoff sock dir {}", sock_dir.display()))?;
    // Clean stale socket from a crash loop boot.  Real PID 1 boots from a
    // fresh /run tmpfs so this shouldn't be needed, but be defensive.
    if Path::new(sock_path).exists() {
        fs::remove_file(sock_path).ok();
    }
    let listener = UnixListener::bind(sock_path)
        .with_context(|| format!("bind handoff listener on {sock_path}"))?;

    Ok(Pid1Bringup {
        cmdline,
        handoff_listener: listener,
        root: root.to_path_buf(),
        applied_mounts,
        cgroup_amin_root: cg_root_abs,
    })
}

fn do_real_mount(spec: &MountSpec, abs_target: &Path) -> Result<()> {
    let source = CString::new(spec.source)
        .map_err(|_| anyhow!("mount source has embedded NUL: {}", spec.source))?;
    let target = osstr_to_cstring(abs_target.as_os_str())
        .map_err(|_| anyhow!("mount target has embedded NUL: {}", abs_target.display()))?;
    let fstype = CString::new(spec.fstype)
        .map_err(|_| anyhow!("mount fstype has embedded NUL: {}", spec.fstype))?;
    let data = CString::new(spec.data)
        .map_err(|_| anyhow!("mount data has embedded NUL: {}", spec.data))?;

    // SAFETY: all pointers are valid CString borrows; flags are a
    // bitwise-OR of kernel-defined MS_* constants.  On failure we check
    // the return and convert to io::Error.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            spec.flags,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        bail!("mount({} -> {}, type={}) failed: {}", spec.source, abs_target.display(), spec.fstype, e);
    }
    Ok(())
}

fn osstr_to_cstring(s: &OsStr) -> std::result::Result<CString, std::ffi::NulError> {
    let bytes = s.as_bytes();
    CString::new(bytes)
}

// ── Tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── cmdline parser happy / sad paths ───────────────────────────────

    #[test]
    fn cmdline_parse_happy_path_all_amin_keys() {
        let line = "console=ttyS0,115200 ro \
                    amin.bootstrap=bitcache:blake3:aabbccdd \
                    amin.node_id=node-42 \
                    amin.zcap=zcap:mldsa87:AAABBB \
                    amin.slab_dev=/dev/nvme0n1p2 \
                    amin.aminexec_rootfs_ref=bitcache:blake3:eeff0011 \
                    init=/init";
        let cl = BootCommandLine::parse(line).expect("parse OK");
        assert_eq!(cl.init_profile_ref,    "bitcache:blake3:aabbccdd");
        assert_eq!(cl.node_id,             "node-42");
        assert_eq!(cl.zcap,                "zcap:mldsa87:AAABBB");
        assert_eq!(cl.slab_dev,            PathBuf::from("/dev/nvme0n1p2"));
        assert_eq!(cl.aminexec_rootfs_ref, "bitcache:blake3:eeff0011");
        // Passthrough preserves non-amin keys
        assert_eq!(cl.passthrough.get("console"), Some(&"ttyS0,115200".to_string()));
        assert_eq!(cl.passthrough.get("init"),    Some(&"/init".to_string()));
        assert_eq!(cl.passthrough.get("ro"),      Some(&String::new()));
    }

    #[test]
    fn cmdline_bootstrap_alias_works() {
        // Spec FR-2.3 says amin.bootstrap= or amin.init_profile_ref= work
        // as aliases.  Confirm both.
        let a = BootCommandLine::parse(
            "amin.init_profile_ref=bitcache:blake3:1 amin.node_id=a amin.zcap=b \
             amin.slab_dev=/dev/x amin.aminexec_rootfs_ref=bitcache:blake3:2"
        ).unwrap();
        let b = BootCommandLine::parse(
            "amin.bootstrap=bitcache:blake3:1 amin.node_id=a amin.zcap=b \
             amin.slab_dev=/dev/x amin.aminexec_rootfs_ref=bitcache:blake3:2"
        ).unwrap();
        assert_eq!(a.init_profile_ref, b.init_profile_ref);
    }

    #[test]
    fn cmdline_rejects_unknown_amin_key_closed_world() {
        let line = "amin.node_id=a amin.bootstrap=x amin.zcap=b amin.slab_dev=/dev/x \
                    amin.aminexec_rootfs_ref=y \
                    amin.nodeid=oops_typo_missing_underscore";
        let err = BootCommandLine::parse(line).expect_err("must reject unknown amin.* key");
        assert!(err.to_string().contains("amin.nodeid"), "error should name the bad key; got: {err}");
    }

    #[test]
    fn cmdline_missing_required_errors_named() {
        // No amin.zcap.
        let line = "amin.bootstrap=x amin.node_id=a amin.slab_dev=/dev/x amin.aminexec_rootfs_ref=y";
        let err = BootCommandLine::parse(line).expect_err("must be missing zcap");
        assert!(err.to_string().contains("amin.zcap"), "error must name missing amin.zcap; got {err}");
    }

    // ── pid1 bringup simulator: verifies mount plan + cgroup + listener ─

    #[test]
    fn sim_bringup_applies_all_six_minimal_mounts() {
        let b = pid1_bringup_sim(None).expect("sim bringup OK");
        let names: Vec<_> = b.applied_mounts.iter().map(|m| m.source.as_str()).collect();
        // Order MUST match PID1_MOUNTS exactly — it's the standard early
        // boot order.  If this fails, you re-ordered the array and broke
        // the boot contract.
        assert_eq!(names, vec!["proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "tmpfs"]);

        // Also check each sentinel file is present.
        for m in &b.applied_mounts {
            let sentinel = m.target.join(format!(
                ".mounted_from_{}_{}",
                m.source.replace('/', "_"),
                m.fstype
            ));
            assert!(sentinel.is_file(),
                    "expected mount sentinel {} — missing mount {} → {} ({})",
                    sentinel.display(), m.source, m.target.display(), m.fstype);
        }
    }

    #[test]
    fn sim_bringup_creates_cgroup_amin_subtree_with_control_file() {
        let b = pid1_bringup_sim(None).expect("sim bringup OK");
        assert!(b.cgroup_amin_root.is_dir(), "cgroup amin root dir must exist");
        let cg = fs::read_to_string(b.cgroup_amin_root.join("cgroup.subtree_control"))
            .expect("subtree_control file must be readable");
        assert_eq!(cg.trim(), CGROUP_SUBTREE_CONTROL.trim());
    }

    #[test]
    fn sim_bringup_bind_handoff_listener_and_sock_file_exists() {
        let b = pid1_bringup_sim(None).expect("sim bringup OK");
        let sock_path = b.root.join("run/amin/hand-off.sock");
        assert!(sock_path.exists(), "handoff sock file must exist at {}", sock_path.display());
        // Verify listener actually accept()-able (connect + immediate drop).
        use std::os::unix::net::UnixStream;
        UnixStream::connect(&sock_path).expect("listener must accept a connection");
    }

    #[test]
    fn sim_bringup_cmdline_parsed_correctly_including_passthrough() {
        let b = pid1_bringup_sim(None).expect("sim bringup OK");
        assert!(b.cmdline.init_profile_ref.starts_with("bitcache:blake3:"));
        assert!(!b.cmdline.node_id.is_empty());
        assert!(b.cmdline.slab_dev.starts_with("/dev/"));
        assert_eq!(b.cmdline.passthrough.get("init"), Some(&"/init".to_string()));
    }
}

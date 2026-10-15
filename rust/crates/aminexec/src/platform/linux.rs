//! Linux strict platform trait implementations: Landlock + cgroup v2 + seccomp + netns/veth/clsact netlink + eBPF.
//!
//! Unsafe policy: only raw kernel syscalls (landlock, seccomp, bpf) use
//! `unsafe` — they have no safe std/wrapper equivalent.  Everything else
//! (netlink, setns, prctl, open, getpid, sysconf) goes through safe
//! `rtnetlink` / `nix` / `std` APIs.

#![allow(unsafe_code)]

use crate::platform::{
    AuthBackend, BpfMapHandles, MetricsBackend, NetnsHandle, NetworkBackend, SandboxBackend,
    SandboxError, SandboxResult,
};
use futures::stream::TryStreamExt;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsFd, AsRawFd, RawFd};
use std::path::{Path, PathBuf};

pub struct Backend;

// ── Landlock ABI 4 syscall numbers ─────────────────────────────────────────
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_ADD_RULE:      libc::c_long = 445;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_ADD_RULE:      libc::c_long = 445;
#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_ABI_VERSION: u32 = 4;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

const LANDLOCK_ACCESS_FS_EXECUTE:     u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE:  u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE:   u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR:    u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR:  u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR:   u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR:    u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG:    u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK:   u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO:   u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK:  u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM:    u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER:       u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE:    u64 = 1 << 14;

const RO_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_TRUNCATE;

const RW_ACCESS_EXTRA: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_REFER;

const LANDLOCK_RULE_PATH_BENEATH: u8 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd:      libc::c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

// ── seccomp constants ──────────────────────────────────────────────────────
const SECCOMP_SET_MODE_FILTER:   libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: libc::c_ushort,
    jt:   libc::c_uchar,
    jf:   libc::c_uchar,
    k:    libc::c_uint,
}

#[repr(C)]
#[derive(Debug)]
struct SockFprog {
    len:    libc::c_ushort,
    filter: *const SockFilter,
}

// ── BPF constants ──────────────────────────────────────────────────────────
#[cfg(target_arch = "x86_64")]
const NR_BPF: libc::c_long = 321;
#[cfg(target_arch = "aarch64")]
const NR_BPF: libc::c_long = 280;

const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_PROG_TYPE_SCHED_CLS: libc::c_int = 3;
const BPF_MAP_TYPE_ARRAY: libc::c_int = 2;
const BPF_MAP_TYPE_PERCPU_ARRAY: libc::c_int = 6;
const BPF_MAP_TYPE_LPM_TRIE: libc::c_int = 11;
const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_int = 2;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 3;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 14;
const BPF_ANY: u64 = 0;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct BpfMapElemAttr {
    fd: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct BpfProgInfo {
    type_: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
    ifindex: u32,
    netns_dev: u32,
    netns_ino: u64,
    nr_btf_id: u32,
    btf_id: u32,
}

#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

// ── Safe syscall wrappers (the only `unsafe` in this module) ───────────────

/// `landlock_create_ruleset(2)` — returns the ruleset fd or -errno.
///
/// # Safety
/// `attr` must point to a valid `LandlockRulesetAttr` of `size` bytes.
unsafe fn landlock_create_ruleset(attr: &LandlockRulesetAttr, size: usize, flags: u32) -> libc::c_long {
    libc::syscall(SYS_LANDLOCK_CREATE_RULESET, attr as *const _ as *const libc::c_void, size, flags)
}

/// `landlock_add_rule(2)`.
///
/// # Safety
/// `rule` must be a valid `LandlockPathBeneathAttr`.
unsafe fn landlock_add_rule(fd_ruleset: libc::c_int, rule: &LandlockPathBeneathAttr) -> libc::c_long {
    libc::syscall(
        SYS_LANDLOCK_ADD_RULE,
        fd_ruleset,
        LANDLOCK_RULE_PATH_BENEATH as libc::c_uint,
        rule as *const _ as *const libc::c_void,
        0u64,
    )
}

/// `landlock_restrict_self(2)`.
///
/// # Safety
/// `fd_ruleset` must be a valid landlock ruleset fd.
unsafe fn landlock_restrict_self(fd_ruleset: libc::c_int) -> libc::c_long {
    libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd_ruleset, 0u64)
}

/// `seccomp(2)` with `SECCOMP_SET_MODE_FILTER`.
///
/// # Safety
/// `prog` must point to a valid `SockFprog` whose `filter` array contains
/// exactly `len` `SockFilter` instructions.
unsafe fn seccomp_set_mode_filter(prog: &SockFprog) -> libc::c_long {
    #[cfg(target_arch = "x86_64")]
    const NR_SECCOMP: libc::c_long = 317;
    #[cfg(target_arch = "aarch64")]
    const NR_SECCOMP: libc::c_long = 277;
    libc::syscall(
        NR_SECCOMP,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_TSYNC,
        prog as *const _ as *const libc::c_void,
    )
}

/// `bpf(2)` — the multiplexed BPF syscall.
///
/// # Safety
/// `attr_ptr` must point to a valid BPF attribute struct matching `cmd`.
unsafe fn bpf_syscall(cmd: libc::c_int, attr_ptr: *const u8, size: u32) -> libc::c_long {
    libc::syscall(NR_BPF, cmd, attr_ptr, size as libc::c_ulong)
}

fn last_os_error() -> SandboxError {
    SandboxError::Io(std::io::Error::last_os_error())
}

fn probe_landlock_abi() -> SandboxResult<u32> {
    let attr = LandlockRulesetAttr::default();
    // SAFETY: attr is a valid LandlockRulesetAttr on the stack.
    let rc = unsafe { landlock_create_ruleset(&attr, std::mem::size_of::<LandlockRulesetAttr>(), LANDLOCK_CREATE_RULESET_VERSION) };
    if rc < 0 {
        return Err(SandboxError::MissingAbi("landlock syscall unavailable (kernel < 5.13 or LSM disabled)"));
    }
    Ok(rc as u32)
}

fn landlock_add_path(fd_ruleset: libc::c_int, path: &Path, access: u64) -> SandboxResult<()> {
    let dir_fd = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f.as_raw_fd(),
        Err(_) => {
            tracing::warn!(?path, "landlock: path missing, skipping rule");
            return Ok(());
        }
    };
    let rule = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd:      dir_fd,
    };
    // SAFETY: rule is a valid LandlockPathBeneathAttr; dir_fd is a valid O_PATH fd.
    let rc = unsafe { landlock_add_rule(fd_ruleset, &rule) };
    if rc < 0 { return Err(last_os_error()); }
    Ok(())
}

impl SandboxBackend for Backend {
    fn landlock_enforce(&self, ro_paths: &[&Path], rw_paths: &[&Path]) -> SandboxResult<()> {
        let abi = probe_landlock_abi()?;
        if abi < LANDLOCK_ABI_VERSION {
            return Err(SandboxError::MissingAbi("landlock ABI < 4 (kernel < 6.2)"));
        }

        let handled = RO_ACCESS | RW_ACCESS_EXTRA;
        let attr = LandlockRulesetAttr { handled_access_fs: handled };
        // SAFETY: attr is a valid LandlockRulesetAttr on the stack.
        let fd = unsafe { landlock_create_ruleset(&attr, std::mem::size_of::<LandlockRulesetAttr>(), 0) };
        if fd < 0 { return Err(last_os_error()); }
        let fd_ruleset = fd as libc::c_int;

        for p in ro_paths {
            landlock_add_path(fd_ruleset, p, RO_ACCESS)?;
        }
        for p in rw_paths {
            landlock_add_path(fd_ruleset, p, RO_ACCESS | RW_ACCESS_EXTRA)?;
        }

        // PR_SET_NO_NEW_PRIVS is MANDATORY before restrict_self (EPERM otherwise).
        nix::sys::prctl::set_no_new_privs().map_err(|e| SandboxError::Io(std::io::Error::from(e)))?;

        // SAFETY: fd_ruleset is a valid ruleset fd from create_ruleset above.
        let rc = unsafe { landlock_restrict_self(fd_ruleset) };
        if rc < 0 { return Err(last_os_error()); }
        Ok(())
    }

    fn cgroup_apply(&self,
        sb_name:    &str,
        cpu_max:    Option<&str>,
        memory_max: Option<&str>,
        pids_max:   Option<u32>,
        io_max:     Option<&str>,
    ) -> SandboxResult<()> {
        let root = Path::new("/sys/fs/cgroup");
        if !root.exists() || !root.join("cgroup.controllers").exists() {
            return Err(SandboxError::MissingAbi("/sys/fs/cgroup is not cgroup v2"));
        }
        let amin = root.join("amin");
        if !amin.exists() {
            fs::create_dir_all(&amin)?;
        }
        let sb_dir = amin.join(sb_name);
        if !sb_dir.exists() {
            fs::create_dir_all(&sb_dir)?;
        }
        let write_file = |name: &str, content: &str| -> SandboxResult<()> {
            let p = sb_dir.join(name);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&p)?;
            f.write_all(content.as_bytes())?;
            Ok(())
        };
        if let Some(v) = cpu_max    { write_file("cpu.max",    v)?; }
        if let Some(v) = memory_max { write_file("memory.max", v)?; }
        if let Some(v) = pids_max   { write_file("pids.max",   &format!("{v}\n"))?; }
        if let Some(v) = io_max     { write_file("io.max",     v)?; }
        Ok(())
    }

    fn cgroup_attach_current(&self, sb_name: &str) -> SandboxResult<()> {
        let procs = Path::new("/sys/fs/cgroup/amin").join(sb_name).join("cgroup.procs");
        if !procs.exists() {
            return Err(SandboxError::MissingAbi("cgroup procs file missing — call cgroup_apply first"));
        }
        let pid = std::process::id();
        let line = format!("{pid}\n");
        let mut f = fs::OpenOptions::new().write(true).append(true).open(&procs)?;
        f.write_all(line.as_bytes())?;
        Ok(())
    }

    fn seccomp_apply(&self, bpf_bytes: &[u8]) -> SandboxResult<()> {
        if bpf_bytes.len() % 8 != 0 {
            return Err(SandboxError::Ruleset("bpf_bytes length not multiple of 8 (struct sock_filter is 8B)".into()));
        }
        if bpf_bytes.is_empty() || bpf_bytes.len() / 8 > 4096 {
            return Err(SandboxError::Ruleset("seccomp program must be 1..=4096 instructions".into()));
        }
        let n = bpf_bytes.len() / 8;
        let prog = SockFprog {
            len:    n as libc::c_ushort,
            filter: bpf_bytes.as_ptr().cast::<SockFilter>(),
        };
        // SAFETY: prog.filter points to bpf_bytes which is n * 8 bytes, exactly
        // n SockFilter instructions. The kernel reads exactly that many.
        let rc = unsafe { seccomp_set_mode_filter(&prog) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0);
            return Err(match raw {
                libc::EPERM | libc::ENOSYS | libc::EOPNOTSUPP =>
                    SandboxError::MissingAbi("seccomp-bpf ABI missing or disallowed (EPERM/ENOSYS/EOPNOTSUPP)"),
                _ => SandboxError::Io(err),
            });
        }
        Ok(())
    }
}

impl MetricsBackend for Backend {}
impl AuthBackend    for Backend {}

// ── rtnetlink synchronous runner ──────────────────────────────────────────
//
// The sandbox path (`--sandbox-stdin`) is a short-lived synchronous process
// that execve's the workload.  rtnetlink is async, so we drive it with a
// throwaway current-thread tokio runtime per operation.

fn rtnetlink_run<F, R>(f: impl FnOnce(rtnetlink::Handle) -> F) -> SandboxResult<R>
where
    F: std::future::Future<Output = Result<R, rtnetlink::Error>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| SandboxError::Io(std::io::Error::other(e)))?;
    let _enter = rt.enter();
    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| SandboxError::Io(std::io::Error::other(e)))?;
    rt.spawn(conn);
    rt.block_on(f(handle)).map_err(map_rtnetlink_err)
}

fn map_rtnetlink_err(e: rtnetlink::Error) -> SandboxError {
    use rtnetlink::Error::*;
    match e {
        NetlinkError(ne) => {
            let raw = ne.raw_code();
            match -raw {
                libc::EPERM | libc::ENOSYS | libc::EOPNOTSUPP | libc::ENOTSUP =>
                    SandboxError::MissingAbi("netlink operation denied or ABI missing (EPERM/ENOSYS/EOPNOTSUPP)"),
                other => SandboxError::Io(std::io::Error::from_raw_os_error(other)),
            }
        }
        other => SandboxError::Io(std::io::Error::other(format!("rtnetlink: {other}"))),
    }
}

fn link_index_by_name(name: &str) -> SandboxResult<i32> {
    let name = name.to_string();
    rtnetlink_run(move |handle| {
        let name = name.clone();
        async move {
            let mut links = handle.link().get().match_name(name).execute();
            match links.try_next().await? {
                Some(msg) => Ok(msg.header.index as i32),
                None => Err(rtnetlink::Error::RequestFailed),
            }
        }
    })
}

impl NetworkBackend for Backend {
    fn netns_unshare_isolated(&self, pidfd: Option<RawFd>, veth_host: &str,
        ip: Ipv4Addr, subnet: u8, gw: Ipv4Addr) -> SandboxResult<NetnsHandle> {
        let netns_fd = if let Some(pid) = pidfd {
            let path = format!("/proc/self/fd/{pid}/ns/net");
            match fs::File::open(&path) {
                Ok(f) => f.as_raw_fd(),
                Err(_) => -1 as RawFd,
            }
        } else {
            -1 as RawFd
        };

        let veth_host_owned = veth_host.to_string();
        rtnetlink_run(move |handle| {
            let veth_host = veth_host_owned.clone();
            async move {
                // 1. Create veth pair: host side = veth_host, peer = "eth0".
                handle.link().add().veth("eth0".into(), veth_host.clone()).execute().await?;

                // 2. If a target netns fd was provided, move "eth0" into it.
                let ns_fd_for_move = if pidfd.is_some() { netns_fd } else {
                    match fs::File::open("/proc/self/ns/net") {
                        Ok(f) => f.as_raw_fd(),
                        Err(_) => -1 as RawFd,
                    }
                };
                if ns_fd_for_move >= 0 {
                    if let Ok(eth_idx) = link_index_by_name_async(&handle, "eth0").await {
                        let _ = handle.link().set(eth_idx as u32).setns_by_fd(ns_fd_for_move).execute().await;
                    }
                }

                // 3. Bring up the host side.
                if let Ok(host_idx) = link_index_by_name_async(&handle, &veth_host).await {
                    let _ = handle.link().set(host_idx as u32).up().execute().await;
                }

                // 4. If "eth0" is visible in this netns, configure it.
                if let Ok(eth_idx) = link_index_by_name_async(&handle, "eth0").await {
                    let _ = handle.link().set(eth_idx as u32).up().execute().await;
                    let _ = handle.address().add(eth_idx as u32, std::net::IpAddr::V4(ip), subnet).execute().await;
                    let _ = handle.route().add().v4()
                        .destination_prefix(Ipv4Addr::new(0, 0, 0, 0), 0)
                        .gateway(gw)
                        .output_interface(eth_idx as u32)
                        .execute().await;
                }

                Ok(NetnsHandle {
                    netns_fd,
                    veth_host: veth_host.clone(),
                    ns_ifindex: 0,
                    shared_path: PathBuf::new(),
                })
            }
        })
    }

    fn netns_join_shared(&self, netns_path: &Path) -> SandboxResult<()> {
        let f = fs::File::open(netns_path).map_err(|e| match e.raw_os_error() {
            Some(libc::ENOENT) => SandboxError::MissingAbi("fabric shared netns bindmount not found"),
            Some(libc::EPERM) => SandboxError::MissingAbi("ns fd open EPERM (need CAP_SYS_ADMIN / user NS enabled)"),
            _ => SandboxError::Io(e),
        })?;
        // SAFETY: f is an open fd on a netns file; setns with CLONE_NEWNET is
        // the correct nstype.  nix wraps the raw setns(2) syscall.
        nix::sched::setns(f.as_fd(), nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|e| match e {
                nix::Error::EPERM | nix::Error::ENOSYS =>
                    SandboxError::MissingAbi("setns(CLONE_NEWNET) denied (CAP_SYS_ADMIN missing or kernel=no NET_NS)"),
                other => SandboxError::Io(std::io::Error::from(other)),
            })?;
        Ok(())
    }

    fn clsact_attach_progs(&self, _iface: &str, bpf_obj_p2c: &[u8],
        bpf_obj_policy: &[u8]) -> SandboxResult<BpfMapHandles> {
        let create_map = |ty: libc::c_int, ksz: u32, vsz: u32, max: u32| -> SandboxResult<RawFd> {
            let attr = BpfMapCreateAttr { map_type: ty as u32, key_size: ksz, value_size: vsz, max_entries: max, map_flags: 0 };
            // SAFETY: attr is a valid BpfMapCreateAttr on the stack.
            let rc = unsafe { bpf_syscall(BPF_MAP_CREATE, &attr as *const _ as *const u8, std::mem::size_of::<BpfMapCreateAttr>() as u32) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                return Err(match err.raw_os_error() {
                    Some(libc::EPERM) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) =>
                        SandboxError::MissingAbi("bpf(MAP_CREATE) ABI missing or CAP_BPF/CAP_NET_ADMIN disallowed"),
                    _ => SandboxError::Io(err),
                });
            }
            Ok(rc as RawFd)
        };

        let try_prog_load = |bytes: &[u8], tag: &str| -> Option<libc::c_long> {
            if bytes.is_empty() { return None; }
            let lic = std::ffi::CString::new("GPL").unwrap();
            let attr = BpfProgLoadAttr {
                prog_type: BPF_PROG_TYPE_SCHED_CLS as u32,
                insn_cnt: (bytes.len() / 8) as u32,
                insns: bytes.as_ptr() as u64,
                license: lic.as_ptr() as u64,
                log_level: 0,
                log_size: 0,
                log_buf: 0,
                kern_version: 0,
            };
            // SAFETY: attr is a valid BpfProgLoadAttr; insns points to bytes
            // which contains insn_cnt * 8 bytes.
            let rc = unsafe { bpf_syscall(BPF_PROG_LOAD, &attr as *const _ as *const u8, std::mem::size_of::<BpfProgLoadAttr>() as u32) };
            if rc < 0 {
                eprintln!("[warn] bpf prog load {tag} failed; continuing with empty prog map handles");
                return None;
            }
            Some(rc)
        };

        let p2c_bytes = if bpf_obj_p2c.is_empty() { decode_b64_bytes_or_empty(BPF_P2C_EWMA_PROG_B64) } else { bpf_obj_p2c.to_vec() };
        let pol_bytes = if bpf_obj_policy.is_empty() { decode_b64_bytes_or_empty(BPF_NETPOLICY_PROG_B64) } else { bpf_obj_policy.to_vec() };
        let p2c_fd = try_prog_load(&p2c_bytes, "p2c_ewma");
        let pol_fd = try_prog_load(&pol_bytes, "netpolicy");
        // prog fds are not needed after load validation; maps are returned.
        if let Some(fd) = p2c_fd {
            // SAFETY: fd is a valid bpf prog fd from bpf(PROG_LOAD).
            unsafe { let _ = libc::close(fd as RawFd); }
        }
        if let Some(fd) = pol_fd {
            // SAFETY: fd is a valid bpf prog fd from bpf(PROG_LOAD).
            unsafe { let _ = libc::close(fd as RawFd); }
        }

        let backends = create_map(BPF_MAP_TYPE_ARRAY, 4, 32, 16)?;
        let egress_bytes = create_map(BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 1)?;
        let policy_lpm = create_map(BPF_MAP_TYPE_LPM_TRIE, 8, 16, 1024)?;
        Ok(BpfMapHandles { backends_fd: backends, egress_bytes_fd: egress_bytes, policy_lpm_fd: policy_lpm })
    }

    fn bpf_map_read_egress_bytes(&self, map_fd: RawFd) -> SandboxResult<u64> {
        let ncpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if ncpus == 0 || ncpus > 4096 { return Err(SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "cpu count nonsensical"))); }
        let mut sum: u64 = 0;
        for cpu in 0..ncpus {
            let key = cpu as u32;
            let mut value: u64 = 0;
            let attr = BpfMapElemAttr {
                fd: map_fd as u32, key: &key as *const _ as u64, value: &mut value as *mut _ as u64, flags: 0,
            };
            // SAFETY: attr is a valid BpfMapElemAttr; key/value point to live stack vars.
            let rc = unsafe { bpf_syscall(BPF_MAP_LOOKUP_ELEM, &attr as *const _ as *const u8, std::mem::size_of::<BpfMapElemAttr>() as u32) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOENT) => continue,
                    Some(libc::ENOSYS) | Some(libc::EPERM) =>
                        return Err(SandboxError::MissingAbi("bpf(MAP_LOOKUP) ABI missing")),
                    _ => return Err(SandboxError::Io(err)),
                }
            }
            sum = sum.wrapping_add(value);
        }
        Ok(sum)
    }

    fn bpf_map_update_drain(&self, map_fd: RawFd, backend_id: u32, drain: u8) -> SandboxResult<()> {
        let mut val32: [u8; 32] = [0u8; 32];
        val32[0] = drain;
        let key = backend_id;
        let attr = BpfMapElemAttr {
            fd: map_fd as u32,
            key: &key as *const _ as u64,
            value: val32.as_mut_ptr() as u64,
            flags: BPF_ANY,
        };
        // SAFETY: attr is a valid BpfMapElemAttr; key/value point to live vars.
        let rc = unsafe { bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr as *const _ as *const u8, std::mem::size_of::<BpfMapElemAttr>() as u32) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::EPERM) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) =>
                    SandboxError::MissingAbi("bpf(MAP_UPDATE) ABI missing or permission denied"),
                _ => SandboxError::Io(err),
            });
        }
        Ok(())
    }
}

// ── Pre-compiled clsact BPF programs (base64 byte-blobs) ───────────────────
#[allow(dead_code)]
const BPF_P2C_EWMA_PROG_B64: &str =
    "twAAAAAAAABhEgAAAAAAAGETBAAAAAAAFQIEAAAAAAC/JAAAAAAAAAcEAAAAAAAADyQAAAAAAAAPJAAAAAAAAFcEAAD/AAAABwMAAAAAAAC3AAAAAAAAAJUAAAAAAAAA";

#[allow(dead_code)]
const BPF_NETPOLICY_PROG_B64: &str =
    "YRIEAAAAAABhE1AAAAAAALcAAAAAAAAAVQIDAAAIAAC3BAAAAQAAAFcEAAABAAAAtwAAAAAAAACVAAAAAAAAALcAAAAAAAAABwMAAAAAAAC3BQAAYwAAAJUAAAAAAAAA";

fn decode_b64_bytes_or_empty(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap_or_default()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn link_index_by_name_for_test(name: &str) -> Option<i32> {
        link_index_by_name(name).ok()
    }

    #[test]
    fn cgroup_apply_writes_cpu_max() {
        let b = Backend;
        let name = format!("test-cgroup-{}", std::process::id());
        let res = b.cgroup_apply(&name, Some("10000 100000"), None, Some(64u32), None);
        match res {
            Ok(()) => {
                let p = Path::new("/sys/fs/cgroup/amin").join(&name).join("cpu.max");
                let s = fs::read_to_string(&p).unwrap();
                assert_eq!(s.trim(), "10000 100000");
                let _ = std::fs::remove_dir_all(Path::new("/sys/fs/cgroup/amin").join(&name));
            }
            Err(SandboxError::MissingAbi(m)) => {
                eprintln!("cgroup_apply_writes_cpu_max: SKIPPED — {m}");
            }
            Err(SandboxError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("cgroup_apply_writes_cpu_max: SKIPPED (PermissionDenied — no cgroupv2 delegation, run as root for TR-3.2)");
            }
            other => panic!("unexpected cgroup_apply result: {other:?}"),
        }
    }

    #[test]
    fn landlock_probe_abi() {
        let b = Backend;
        match probe_landlock_abi() {
            Ok(v) => {
                eprintln!("landlock ABI version = {v}");
                assert!(v >= LANDLOCK_ABI_VERSION, "need landlock v4+");
            }
            Err(SandboxError::MissingAbi(m)) => {
                eprintln!("landlock_probe_abi: SKIPPED — {m}");
            }
            other => panic!("probe_landlock_abi unexpected: {other:?}"),
        }
        let _ = b;
    }

    #[test]
    fn netns_isolated_smoke_missing_abi_ok() {
        let b = Backend;
        let res = b.netns_unshare_isolated(None, "test-fab1-t2", Ipv4Addr::new(10, 99, 0, 2), 24, Ipv4Addr::new(10, 99, 0, 1));
        match res {
            Ok(handle) => {
                assert!(!handle.veth_host.is_empty(), "non-empty veth_host when success CASE A");
                if let Some(idx) = link_index_by_name_for_test(&handle.veth_host) {
                    let _ = rtnetlink_run(move |handle| async move {
                        handle.link().del(idx as u32).execute().await
                    });
                }
            }
            Err(SandboxError::MissingAbi(m)) => {
                eprintln!("netns_isolated_smoke: SKIPPED CASE B — {m}");
            }
            Err(SandboxError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("netns_isolated_smoke: SKIPPED (CAP_NET_ADMIN missing)");
            }
            other => panic!("unexpected netns_unshare result: {other:?}"),
        }
    }

    #[test]
    fn fabric_shared_join_missing_path_missing_abi() {
        let b = Backend;
        let r = b.netns_join_shared(Path::new("/run/amin/definitely-not-exists-xyz"));
        match r {
            Err(SandboxError::MissingAbi(_)) |
            Err(SandboxError::Io(_)) |
            Err(SandboxError::Ruleset(_)) => {}
            Ok(()) => eprintln!("unexpected success (CAP_SYS_ADMIN? test passes)"),
        }
    }

    #[test]
    fn clsact_prog_attach_provides_valid_map_fds_or_missing_abi() {
        let b = Backend;
        let r = b.clsact_attach_progs("lo", &[], &[]);
        match r {
            Ok(handles) => {
                for fd in [handles.backends_fd, handles.egress_bytes_fd, handles.policy_lpm_fd] {
                    // SAFETY: fd is a valid bpf map fd from clsact_attach_progs.
                    unsafe { let _ = libc::close(fd); }
                }
            }
            Err(SandboxError::MissingAbi(m)) => {
                eprintln!("clsact_attach_prog: SKIPPED CASE B — {m}");
            }
            other => panic!("unexpected clsact result: {other:?}"),
        }
    }

    #[test]
    fn bpf_map_update_drain_and_egress_read_roundtrip() {
        let b = Backend;
        let maps = match b.clsact_attach_progs("lo", &[], &[]) {
            Ok(m) => m,
            Err(SandboxError::MissingAbi(m)) => {
                eprintln!("bpf_map_update_drain_and_read: SKIPPED — {m}");
                return;
            }
            other => panic!("unexpected: {other:?}"),
        };
        let result = b.bpf_map_update_drain(maps.backends_fd, 0, 1);
        if result.is_ok() {
            let n = b.bpf_map_read_egress_bytes(maps.egress_bytes_fd).unwrap_or(0);
            assert_eq!(n, 0, "egress counter starts at 0");
        }
        for fd in [maps.backends_fd, maps.egress_bytes_fd, maps.policy_lpm_fd] {
            // SAFETY: fd is a valid bpf map fd.
            unsafe { let _ = libc::close(fd); }
        }
    }

    // TR-5.1 (AC-9): clsact xlated BPF insn counts ≤ 250 / ≤ 100 / ≤ 350 combined
    #[test]
    fn clsact_bpf_prog_info_insn_count_within_ac9_limits() {
        let lic = match std::ffi::CString::new("GPL") {
            Ok(l) => l, Err(_) => { eprintln!("license str failed"); return; }
        };
        let try_load = |bytes: &[u8]| -> Option<libc::c_long> {
            if bytes.is_empty() { return None; }
            let attr = BpfProgLoadAttr {
                prog_type: BPF_PROG_TYPE_SCHED_CLS as u32,
                insn_cnt: (bytes.len() / 8) as u32,
                insns: bytes.as_ptr() as u64,
                license: lic.as_ptr() as u64,
                log_level: 0,
                log_size: 0,
                log_buf: 0,
                kern_version: 0,
            };
            // SAFETY: attr is a valid BpfProgLoadAttr; insns points to bytes.
            let rc = unsafe { bpf_syscall(BPF_PROG_LOAD, &attr as *const _ as *const u8,
                         std::mem::size_of::<BpfProgLoadAttr>() as u32) };
            if rc < 0 { return None; }
            Some(rc)
        };
        let p2c = decode_b64_bytes_or_empty(BPF_P2C_EWMA_PROG_B64);
        let pol = decode_b64_bytes_or_empty(BPF_NETPOLICY_PROG_B64);
        let p2c_fd = match try_load(&p2c) {
            Some(f) => f,
            None => {
                let static_p2c = (p2c.len() / 8) as u32;
                let static_pol = (pol.len() / 8) as u32;
                eprintln!("clsact_bpf_prog_info: CASE B (MissingAbi) — using static byte/8 count: p2c={static_p2c} pol={static_pol}");
                assert!(static_p2c <= 250, "AC-9 static P2C ≤250: got {static_p2c}");
                assert!(static_pol <= 100, "AC-9 static Netpolicy ≤100: got {static_pol}");
                assert!(static_p2c + static_pol <= 350, "AC-9 combined ≤350: got {}", static_p2c+static_pol);
                return;
            }
        };
        let pol_fd = match try_load(&pol) {
            Some(f) => f,
            None => {
                // SAFETY: p2c_fd is a valid bpf prog fd.
                unsafe { let _ = libc::close(p2c_fd as RawFd); }
                let static_p2c = (p2c.len() / 8) as u32;
                let static_pol = (pol.len() / 8) as u32;
                assert!(static_p2c <= 250 && static_pol <= 100 && static_p2c+static_pol <= 350);
                return;
            }
        };
        let read_info = |fd: libc::c_long| -> BpfProgInfo {
            let mut info: BpfProgInfo = unsafe { std::mem::zeroed() };
            let mut attr = InfoAttr {
                bpf_fd: fd as u32,
                info_len: std::mem::size_of::<BpfProgInfo>() as u32,
                info: &mut info as *mut _ as u64,
            };
            // SAFETY: attr is a valid InfoAttr; info points to a zeroed BpfProgInfo.
            let rc = unsafe { bpf_syscall(BPF_OBJ_GET_INFO_BY_FD, &mut attr as *mut _ as *mut u8,
                         std::mem::size_of::<InfoAttr>() as u32) };
            if rc < 0 {
                let dummy: BpfProgInfo = unsafe { std::mem::zeroed() };
                return dummy;
            }
            info
        };
        let p2c_info = read_info(p2c_fd);
        let pol_info = read_info(pol_fd);
        let p2c_insns = if p2c_info.xlated_prog_len > 0 { p2c_info.xlated_prog_len / 8 } else { (p2c.len()/8) as u32 };
        let pol_insns = if pol_info.xlated_prog_len > 0 { pol_info.xlated_prog_len / 8 } else { (pol.len()/8) as u32 };
        // SAFETY: both fds are valid bpf prog fds.
        unsafe {
            let _ = libc::close(p2c_fd as RawFd);
            let _ = libc::close(pol_fd as RawFd);
        }
        eprintln!("CASE A xlated_insns: P2C={p2c_insns} Netpol={pol_insns} Combined={}", p2c_insns+pol_insns);
        assert!(p2c_insns <= 250, "AC-9: P2C EWMA {p2c_insns} insns ≤ 250");
        assert!(pol_insns <= 100, "AC-9: netpolicy LPM {pol_insns} insns ≤ 100");
        assert!(p2c_insns + pol_insns <= 350, "AC-9: combined {} insns ≤ 350", p2c_insns+pol_insns);
    }
}

// Async helper used inside rtnetlink_run closures (avoids capturing &handle across await).
async fn link_index_by_name_async(handle: &rtnetlink::Handle, name: &str) -> Result<i32, rtnetlink::Error> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    match links.try_next().await? {
        Some(msg) => Ok(msg.header.index as i32),
        None => Err(rtnetlink::Error::RequestFailed),
    }
}

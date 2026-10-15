#![allow(unsafe_code)]

//! `aminexec` CLI entry point.
//!
//! `aminexec` is the long-lived daemon that runs **on every Amin machine**
//! (metal, VM, iPhone, Android scanner) and speaks AWP/3 over the wire to
//! the scheduler.  It owns the sandbox backend and launches per-command
//! children under whatever policy the profile requires.
//!
//! On mobile targets this binary is embedded inside the host app:
//! - iOS: Swift Package Manager `.binaryTarget(name: "aminexec")` built via
//!   `cargo build --target aarch64-apple-ios-sim` + lipo fat archive
//! - Android: NDK `cargo-ndk` → `libaminexec.so` loaded via `System.loadLibrary`
//!
//! On Linux: static musl build (`cargo build --target x86_64-unknown-linux-musl`),
//! shipped as part of every Amin App bundle's `bin/` dir, setuid root only if
//! cgroup v2 controller delegation is active.
//!
//! Subcommands for Task 11 Sandbox IPC (invoked by the Perl dispatcher for
//! each <sandbox> block):
//!
//! `aminexec --sandbox-stdin` reads a 4-byte little-endian length N from
//! stdin, reads N bytes as a base64-expanded JSON sandbox manifest, applies
//! cgroup/landlock/seccomp in the correct kernel order, then execve's the
//! real workload.  This path is intentionally short-lived: each spawn gets
//! its own short-lived aminexec child.

use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aminexec::platform::{SandboxBackend, SandboxError, NetworkBackend};
use serde::Deserialize;
use std::net::Ipv4Addr;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // `--sandbox-stdin` is the Perl→Rust IPC contract used from
    // Amin::Command::Spawn.  It MUST run first (before tracing init — we
    // don't want tracing logs on the child's stderr stream that Perl waits
    // for error messages on).
    if args.len() >= 2 && args[1] == "--sandbox-stdin" {
        return sandbox_stdin_main();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), abi = aminexec::AMIN_EXEC_ABI, "aminexec starting");

    // Gate on PID == 1 (Linux-specific — on other platforms this is always
    // false, so we fall through to the normal userland backend path).
    #[cfg(target_os = "linux")]
    {
        let pid = std::process::id();
        if pid == 1 {
            return pid1_entry();
        }
    }

    // Normal userland path (app sandbox, CI, local dev, mobile embedded).
    let backend = aminexec::platform::default_backend();
    tracing::info!(?backend, "selected platform backend");
    Ok(())
}

#[derive(Debug, Deserialize, Default)]
struct NetManifest {
    #[serde(default)] mode: String,
    #[serde(default)] vpc: String,
    #[serde(default)] subnet: String,
    #[serde(default)] gateway: String,
    #[serde(default)] eth0_ip: String,
    #[serde(default)] veth_host: String,
    #[serde(default)] shared_netns_path: String,
}

#[derive(Debug, Deserialize)]
struct SandboxManifest {
    /// Unique cgroup sub-directory name under /sys/fs/cgroup/amin/.
    /// Typically `sb-<sha256hash of sandbox attrs>`.
    #[serde(default)]
    sb_name:     Option<String>,
    #[serde(default)]
    cpu_max:     Option<String>,
    #[serde(default)]
    memory_max:  Option<String>,
    #[serde(default)]
    memory_high: Option<String>,
    #[serde(default)]
    pids_max:    Option<u32>,
    #[serde(default)]
    io_max:      Option<String>,
    #[serde(default)]
    landlock_ro: Vec<String>,
    #[serde(default)]
    landlock_rw: Vec<String>,
    /// Base64-encoded seccomp bpf program (sock_filter array — 8 bytes/instruction).
    #[serde(default)]
    seccomp_bpf_base64: Option<String>,
    #[serde(default)]
    net:         Option<NetManifest>,
    argv:        Vec<String>,
    #[serde(default)]
    env:         HashMap<String, String>,
    #[serde(default)]
    cwd:         Option<String>,
}

fn sandbox_stdin_main() -> anyhow::Result<()> {
    // ---- Step 1: read 4-byte LE length prefix + JSON manifest --------------------
    let mut len_buf = [0u8; 4];
    match std::io::stdin().read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) => child_err_and_exit(1, &format!("sandbox_stdin: failed to read length prefix: {e}")),
    }
    let n = u32::from_le_bytes(len_buf) as usize;
    if n == 0 || n > 1024 * 1024 {
        child_err_and_exit(2, &format!("sandbox manifest size {n} out of range 1..1M"));
    }
    let mut json_buf = vec![0u8; n];
    match std::io::stdin().read_exact(&mut json_buf) {
        Ok(()) => {}
        Err(e) => child_err_and_exit(1, &format!("sandbox_stdin: failed to read {n}-byte manifest: {e}")),
    }
    let manifest: SandboxManifest = match serde_json::from_slice(&json_buf) {
        Ok(v) => v,
        Err(e) => child_err_and_exit(3, &format!("sandbox_stdin: manifest JSON parse error: {e}")),
    };
    if manifest.argv.is_empty() {
        child_err_and_exit(4, "sandbox manifest.argv is empty — nothing to exec");
    }

    // ---- Step 2: chdir if set -----------------------------------------------------
    if let Some(cwd) = &manifest.cwd {
        let p = Path::new(cwd);
        if let Err(e) = std::env::set_current_dir(p) {
            child_err_and_exit(5, &format!("chdir {cwd}: {e}"));
        }
    }

    // ---- Step 3: platform backend + all three setup calls in order ----------------
    #[cfg(target_os = "linux")]
    let backend = aminexec::platform::linux::Backend;
    #[cfg(target_os = "macos")]
    let backend = aminexec::platform::darwin::Backend;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let backend = aminexec::platform::posix::Backend;

    // cgroup first (we must attach current pid before landlock restricts /sys)
    if let Some(name) = manifest.sb_name.as_ref() {
        if let Err(e) = backend.cgroup_apply(
            name,
            manifest.cpu_max.as_deref(),
            manifest.memory_max.as_deref(),
            manifest.pids_max,
            manifest.io_max.as_deref(),
        ) {
            match e {
                SandboxError::MissingAbi(m) => {
                    child_err_and_exit(-4097i32, &format!("sandbox_missing_abi: {m}"));
                }
                other => {
                    let hint = match &other {
                        SandboxError::Io(io) => match io.raw_os_error() {
                            Some(libc::EACCES) | Some(libc::EPERM) =>
                                " (no cgroup v2 delegation for this uid; run as root or enable Delegate=yes)",
                            _ => "",
                        },
                        _ => "",
                    };
                    child_err_and_exit(6, &format!("cgroup_apply: {other}{hint}"));
                }
            }
        }
        if let Err(e) = backend.cgroup_attach_current(name) {
            child_err_and_exit(7, &format!("cgroup_attach_current: {e}"));
        }
    }

    // ---- Net step: netns / veth / addr / route (FR-NF-3 CORRECTED ORDER) ----
    // Must run BEFORE PR_SET_NO_NEW_PRIVS / landlock / seccomp because those
    // would otherwise deny the netlink / bpf / unshare syscalls used here.
    // On any MissingAbi/Io failure → rc=-4099 net_missing_abi with rollback.
    #[cfg(target_os = "linux")]
    {
        if let Some(net) = manifest.net.as_ref() {
            if net.mode != "host" {
                let nb: &dyn NetworkBackend = &backend;
                let result = if net.mode == "fabric" && !net.shared_netns_path.is_empty() {
                    nb.netns_join_shared(Path::new(&net.shared_netns_path))
                        .map(|_| None)
                } else {
                    let ip: Ipv4Addr = match net.eth0_ip.parse() {
                        Ok(v) => v,
                        Err(e) => child_err_and_exit(-4099i32,
                            &format!("net_missing_abi: invalid eth0_ip {:?}: {e}", net.eth0_ip)),
                    };
                    let gw: Ipv4Addr = match net.gateway.parse() {
                        Ok(v) => v,
                        Err(e) => child_err_and_exit(-4099i32,
                            &format!("net_missing_abi: invalid gateway {:?}: {e}", net.gateway)),
                    };
                    let subnet_bits: u8 = if net.subnet.contains('/') {
                        net.subnet.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(24)
                    } else { 24 };
                    nb.netns_unshare_isolated(None, &net.veth_host, ip, subnet_bits, gw)
                        .map(|h| Some(h))
                };
                if let Err(e) = result {
                    match e {
                        SandboxError::MissingAbi(m) => {
                            child_err_and_exit(-4099i32, &format!("net_missing_abi: {m}"));
                        }
                        other => {
                            child_err_and_exit(-4099i32, &format!("net_missing_abi: {other}"));
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Some(net) = manifest.net.as_ref() {
            if net.mode != "host" {
                child_err_and_exit(-4099i32,
                    "net_missing_abi: networking only supported on Linux");
            }
        }
    }

    // Always set PR_SET_NO_NEW_PRIVS=1 FIRST (before any landlock or
    // seccomp syscall).  SECCOMP_SET_MODE_FILTER requires NO_NEW_PRIVS set
    // when the caller lacks CAP_SYS_ADMIN.  landlock_enforce also does this
    // internally (Landlock v4 requires it before restrict_self), but doing it
    // here idempotently ensures correctness when seccomp-only sandboxes skip
    // the landlock_enforce call entirely (empty ro/rw lists).
    #[cfg(target_os = "linux")]
    {
        // PR_SET_NO_NEW_PRIVS=1 first (before landlock/seccomp).  nix wraps
        // prctl(2) safely; failure is fatal — unsandboxed fallback not permitted.
        if let Err(e) = nix::sys::prctl::set_no_new_privs() {
            child_err_and_exit(-4097i32,
                &format!("sandbox_missing_abi: prctl PR_SET_NO_NEW_PRIVS failed: {e}"));
        }
    }

    // landlock then seccomp (order fixed: seccomp must not accidentally block
    // landlock/prctl setup syscalls).
    let ro: Vec<PathBuf> = manifest.landlock_ro.iter().map(PathBuf::from).collect();
    let rw: Vec<PathBuf> = manifest.landlock_rw.iter().map(PathBuf::from).collect();
    let ro_slices: Vec<&Path> = ro.iter().map(|p| p.as_path()).collect();
    let rw_slices: Vec<&Path> = rw.iter().map(|p| p.as_path()).collect();
    if !ro_slices.is_empty() || !rw_slices.is_empty() {
        if let Err(e) = backend.landlock_enforce(&ro_slices, &rw_slices) {
            match e {
                SandboxError::MissingAbi(m) => {
                    child_err_and_exit(-4097i32, &format!("sandbox_missing_abi: {m}"));
                }
                other => child_err_and_exit(8, &format!("landlock_enforce: {other}")),
            }
        }
    }

    if let Some(b64) = manifest.seccomp_bpf_base64.as_ref() {
        use base64::Engine as _;
        let bytes = match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(b) => b,
            Err(e) => child_err_and_exit(9, &format!("seccomp b64 decode: {e}")),
        };
        if let Err(e) = backend.seccomp_apply(&bytes) {
            match e {
                SandboxError::MissingAbi(m) => {
                    child_err_and_exit(-4097i32, &format!("sandbox_missing_abi: {m}"));
                }
                other => child_err_and_exit(10, &format!("seccomp_apply: {other}")),
            }
        }
    }

    // ---- Step 4: set env ----------------------------------------------------------------
    for (k, v) in &manifest.env {
        std::env::set_var(k, v);
    }

    // ---- Step 5: execve the real workload ------------------------------------------------
    let argv_c: Result<Vec<CString>, _> = manifest.argv.iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect();
    let argv_c = match argv_c {
        Ok(v) => v,
        Err(e) => child_err_and_exit(11, &format!("argv null byte: {e}")),
    };
    let exe = &argv_c[0];
    // Build envp: inherit current env (set_var applied above) via std::env::vars_os.
    let envp_c: Result<Vec<CString>, _> = std::env::vars_os()
        .map(|(k, v)| {
            let mut line = Vec::new();
            line.extend_from_slice(k.to_string_lossy().as_bytes());
            line.push(b'=');
            line.extend_from_slice(v.to_string_lossy().as_bytes());
            CString::new(line)
        })
        .collect();
    let envp_c = match envp_c {
        Ok(v) => v,
        Err(e) => child_err_and_exit(12, &format!("env null byte: {e}")),
    };
    // exec vp: PATH-search like shells do when argv[0] lacks '/' — portable
    // via std CommandExt::exec (Apple libc has no execvpe binding; this
    // keeps the WORKLOAD RUNTIME path functional on macOS/FreeBSD while
    // the platform-specific enforcement backends stay Linux-only).
    {
        use std::os::unix::process::CommandExt;
        let exe_str = manifest.argv[0].as_str();
        let mut cmd = std::process::Command::new(exe_str);
        cmd.args(&manifest.argv[1..]);
        // env was already applied to this process via set_var above;
        // Command::exec inherits the current process environment.  It only
        // ever *returns* an error (success = process replaced).
        let e = cmd.exec();
        child_err_and_exit(13, &format!("execvp {:?}: {e}", manifest.argv[0]));
    }
    // unreachable — exec() never returns on success
    child_err_and_exit(13, "execvp: exec returned unexpectedly")
}

/// Emit 4-byte little-endian error code + NUL-terminated message to stderr,
/// then exit(code).  This matches the documented Perl→Rust error pipe contract.
fn child_err_and_exit(code: i32, msg: &str) -> ! {
    let _ = write_stderr_error(code, msg);
    std::process::exit(code);
}

fn write_stderr_error(code: i32, msg: &str) -> std::io::Result<()> {
    let mut stderr = std::io::stderr().lock();
    stderr.write_all(&(code as i32).to_le_bytes())?;
    stderr.write_all(msg.as_bytes())?;
    stderr.write_all(&[0u8])?;
    stderr.flush()
}

#[cfg(target_os = "linux")]
fn pid1_entry() -> anyhow::Result<()> {
    tracing::info!("running as PID 1 — executing Amin metal bringup");
    let bringup = aminexec::pid1::pid1_bringup()?;
    tracing::info!(
        node_id = %bringup.cmdline.node_id,
        init_profile = %bringup.cmdline.init_profile_ref,
        slab_dev = %bringup.cmdline.slab_dev.display(),
        mounts_applied = bringup.applied_mounts.len(),
        cg_root = %bringup.cgroup_amin_root.display(),
        "pid1 bringup complete"
    );
    // Future tasks (Task 9+): accept() on handoff_listener to grab mesh +
    // slab + seal fds from ainit, then exec the Perl SAX dispatcher on the
    // init profile document and run the workload.  For now we park the
    // listener in a local so drop doesn't close it mid-observation and
    // return cleanly.
    let _listener = bringup.handoff_listener;
    Ok(())
}

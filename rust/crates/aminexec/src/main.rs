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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), abi = aminexec::AMIN_EXEC_ABI, "aminexec starting");
    let backend = aminexec::platform::default_backend();
    tracing::info!(?backend, "selected platform backend");
    Ok(())
}

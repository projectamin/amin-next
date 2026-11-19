//! proxydump — emit the `<proxy:backend>` decisions for one profile + request.
//!
//! Support binary for the Perl↔Rust parity test (`t/73-proxy-parity.t`): it
//! runs the *same* routing logic [`amin_proxy`] exposes — the machine's
//! `Proxy::Route` filter over the shared `machine_spec.xml` — and prints one
//! canonical `<proxy:backend …/>` decision per line, in `to=` order. The Perl
//! side runs the `Amin::Proxy::Route` filter over the same profile and request,
//! and the two streams must match byte for byte (proxy-plan §7).
//!
//! ```text
//!   proxydump --profile FILE|- [--host HOST] [--path PATH] [--fingerprint]
//! ```
//!
//! With `--fingerprint`, it prints the profile's `X-Amin-Profile-SHA3` value
//! (one line) instead of the decision elements — the Perl↔Rust fingerprint
//! parity check (proxy-plan §7/§P5).
//!
//! Exit codes (stable — Perl `$? >> 8` matches them):
//!   0 OK (no match → no output) | 2 usage | 3 config error

use std::io::Read;
use std::process::ExitCode;

use clap::Parser;

use amin_proxy::{filters, ProxyConfig};

#[derive(Parser)]
#[command(name = "proxydump", version, about = "Amin 3 proxy decision dumper")]
struct Cli {
    /// Path to an `<amin:proxy>` profile, or `-` for stdin.
    #[arg(long)]
    profile: String,
    /// Request host (matched case-insensitively).
    #[arg(long, default_value = "")]
    host: String,
    /// Request path (prefix-matched; defaults to `/`).
    #[arg(long)]
    path: Option<String>,
    /// Print the profile's SHA3-256 fingerprint instead of decisions.
    #[arg(long)]
    fingerprint: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let xml = match read_profile(&cli.profile) {
        Ok(xml) => xml,
        Err(e) => {
            eprintln!("proxydump: {e}");
            return ExitCode::from(2);
        }
    };

    let cfg = match ProxyConfig::parse_xml(&xml).and_then(|c| c.compile()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("proxydump: {e}");
            return ExitCode::from(3);
        }
    };

    if cli.fingerprint {
        println!("{}", cfg.profile_sha3());
        return ExitCode::SUCCESS;
    }

    let path = cli.path.as_deref().unwrap_or("/");
    for line in filters::decisions(&cfg, &cli.host, path) {
        println!("{line}");
    }
    ExitCode::SUCCESS
}

fn read_profile(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("read stdin: {e}"))?;
        return Ok(s);
    }
    std::fs::read_to_string(path).map_err(|e| format!("open {path}: {e}"))
}

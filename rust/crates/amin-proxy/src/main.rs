//! amin-proxyd — the Rust proxy front (proxy-plan §8, P3).
//!
//! The Rust parity peer of `bin/amin proxy serve`: it parses the same
//! `<amin:proxy>` profile, matches with the same compiled vocabulary, and
//! produces the same `<proxy:backend>` decision — and the same upstream
//! request head — as the Perl front (proxy-plan §7).
//!
//! ```text
//!   amin-proxyd --profile FILE [--listen ADDR]
//! ```
//!
//! The listen address comes from `--listen` if given, else the profile's
//! `amin:listen`, else `127.0.0.1:8787`.
//!
//! Exit codes: 0 OK | 1 runtime error | 2 usage/profile I/O | 3 config error.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use amin_proxy::listener::Front;
use amin_proxy::ProxyConfig;

#[derive(Parser)]
#[command(name = "amin-proxyd", version, about = "Amin 3 L7 reverse proxy (Rust peer)")]
struct Cli {
    /// Path/URI to an `<amin:proxy>` profile. Supports file://, http(s)://,
    /// bitcache://, bc:// in addition to local paths.
    #[arg(long, short = 'u', alias = "uri")]
    profile: String,
    /// Listen address; overrides the profile's `amin:listen`.
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let xml = match read_profile(&cli.profile) {
        Ok(xml) => xml,
        Err(e) => {
            eprintln!("amin-proxyd: {e}");
            return ExitCode::from(2);
        }
    };

    let parsed = match ProxyConfig::parse_xml(&xml) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("amin-proxyd: {e}");
            return ExitCode::from(3);
        }
    };
    let listen = cli
        .listen
        .or_else(|| parsed.listen.clone())
        .unwrap_or_else(|| "127.0.0.1:8787".to_string());
    let compiled = match parsed.compile() {
        Ok(c) => c.with_source(&cli.profile),
        Err(e) => {
            eprintln!("amin-proxyd: {e}");
            return ExitCode::from(3);
        }
    };

    // TLS is on when `amin:tls` names a mode other than off/none; the mode v1
    // understands is `files`, which needs both PEM paths (§4.1/§5.5).
    let tls_mode = parsed.tls.as_deref().unwrap_or("").to_ascii_lowercase();
    let wants_tls = !matches!(tls_mode.as_str(), "" | "off" | "none" | "no");
    let front = if wants_tls {
        let (Some(cert), Some(key)) = (parsed.cert.as_deref(), parsed.key.as_deref()) else {
            eprintln!("amin-proxyd: tls: amin:cert and amin:key are both required for tls=\"{tls_mode}\"");
            return ExitCode::from(3);
        };
        match Front::with_tls_files(compiled, cert, key) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("amin-proxyd: tls: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        Front::new(compiled)
    };

    eprintln!("amin-proxyd: listening on {listen}");
    if let Err(e) = Arc::new(front).serve(&listen).await {
        eprintln!("amin-proxyd: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}


fn read_profile(path: &str) -> Result<String, String> {
    if path == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("read stdin: {e}"))?;
        return Ok(s);
    }
    if amin_machine::uri::is_uri(path) {
        let r = amin_machine::uri::resolve(path)?;
        return String::from_utf8(r.bytes).map_err(|e| format!("profile {path} is not utf-8: {e}"));
    }
    std::fs::read_to_string(path).map_err(|e| format!("open {path}: {e}"))
}

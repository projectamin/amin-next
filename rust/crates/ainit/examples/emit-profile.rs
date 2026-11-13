//! Host-side emitter for a node's local boot profile (BSAX).
//!
//! `ainit` reads the boot profile it finds on FRAMEBOOT as BSAX, so a
//! standalone (no-mesh) boot needs an `init-profile.bsax` to have a profile to
//! bring up.  This writes it with the same encoder ainit decodes with
//! (`ainit::bootstrap::encode_boot_profile`), so the two cannot drift.
//!
//! Run on the host, from the adistro profile's publish stage:
//!
//!     cargo run -q -p ainit --example emit-profile -- \
//!         --node-id sc7731g-vt10101 --slab-dev /dev/mmcblk0p27 \
//!         --out /path/to/init-profile.bsax

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (mut node_id, mut slab_dev, mut out) = (None, None, None);

    let mut i = 0;
    while i < argv.len() {
        let flag = argv[i].as_str();
        let value = argv
            .get(i + 1)
            .with_context(|| format!("{flag} needs a value"))?
            .clone();
        match flag {
            "--node-id" => node_id = Some(value),
            "--slab-dev" => slab_dev = Some(value),
            "--out" => out = Some(PathBuf::from(value)),
            other => bail!("unknown argument {other:?}"),
        }
        i += 2;
    }

    let node_id = node_id.context("--node-id is required")?;
    let slab_dev = slab_dev.context("--slab-dev is required")?;
    let out = out.context("--out is required")?;

    let bytes = ainit::bootstrap::encode_boot_profile(&node_id, &slab_dev);
    std::fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
    eprintln!(
        "emit-profile: {} ({} bytes) for node {node_id}, slab {slab_dev}",
        out.display(),
        bytes.len()
    );
    Ok(())
}

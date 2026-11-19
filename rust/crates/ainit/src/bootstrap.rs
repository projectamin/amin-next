//! Profile resolution — the one question `ainit` answers before handing over:
//! *where is the boot profile*.
//!
//! `ainit` does not care what the profile says.  Its whole job is to name the
//! document and hand it to phase 2 as a single argument:
//! `execve("/sbin/aminexec", ["aminexec", <profile>])`.  The same binary then
//! boots a phone, a desktop, or a racked server whose first boot was served a
//! ref by the `ToR` — only the ref differs.
//!
//! - **Served** — the `ToR`'s `BOOT_OFFER` ([`crate::boot_offer`]) left a
//!   `bitcache:`/`http(s)://` ref on the kernel cmdline; that ref is passed
//!   through untouched.
//! - **Standalone** — no mesh, no served ref: the profile is a local document
//!   on the slot's FRAMEBOOT and is passed as `local:<path>`.
//!
//! A `served` boot must never fall back to the local document: a locally
//! provisioned profile is only as strong as the FAT it sits on.  Local
//! resolution therefore happens only when the cmdline carries no served ref.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Kernel cmdline.  The frame's frameboot bind-mounts a copy of the boot
/// cmdline over this inside the slot, so it is the way a `ToR`'s served ref
/// reaches a kernel that never saw it.
pub const CMDLINE: &str = "/proc/cmdline";

/// What `ainit` exec's once the boot profile is resolved: phase 2.
pub const AMINEXEC: &str = "/sbin/aminexec";

/// Keys that mean a `ToR` `BOOT_OFFER` already decided this boot's profile.
/// Their presence disables local resolution.
pub const SERVED_KEYS: &[&str] = &["amin.bootstrap", "amin.init_profile_ref"];

/// Slot paths searched for the boot profile of a standalone boot, in order.
/// Both dialects are accepted: XML (the Perl runtime reads it directly) and
/// BSAX (the binary codec).  `/boot` is FRAMEBOOT once frameboot has
/// `switch_root`ed (C5's fstab); `/fb` is where the initramfs mounts it
/// before that.
pub const PROFILE_CANDIDATES: &[&str] = &[
    "/boot/init-profile.xml",
    "/boot/init-profile.bsax",
    "/fb/init-profile.xml",
    "/fb/init-profile.bsax",
    "/etc/amin/init-profile.xml",
    "/etc/amin/init-profile.bsax",
];

/// GPT name of the frame's boot FAT (the FRAMEBOOT partition).
pub const FRAME_BOOT_PARTNAME: &str = "fl-boot";

/// Where the frame's userland expects FRAMEBOOT mounted — C5's fstab line.
pub const FRAME_BOOT_MOUNTPOINT: &str = "/boot";

/// Resolve the profile this boot runs, as the ref phase 2 is handed.
///
/// The ref's scheme is what varies by machine: `local:` here, a served
/// `bitcache:`/`http(s)://` on a first-boot racked server.
pub fn resolve_profile_ref(cmdline: &str) -> Result<String> {
    if let Some(served) = served_ref(cmdline) {
        return Ok(served);
    }

    // Standalone: the profile lives on FRAMEBOOT, which frameboot unmounted
    // before `switch_root`, so mount it before looking.
    mount_frame_boot()?;
    for candidate in PROFILE_CANDIDATES {
        if Path::new(candidate).is_file() {
            return Ok(format!("local:{candidate}"));
        }
    }
    bail!(
        "no boot profile: none of {} exists and the cmdline carries no served ref",
        PROFILE_CANDIDATES.join(", ")
    )
}

/// The served ref on the cmdline, if a `ToR` put one there.
pub fn served_ref(cmdline: &str) -> Option<String> {
    cmdline.split_whitespace().find_map(|token| {
        let (key, value) = token.split_once('=')?;
        SERVED_KEYS.contains(&key).then(|| value.to_string())
    })
}

/// Mount FRAMEBOOT at [`FRAME_BOOT_MOUNTPOINT`] so a local profile is
/// reachable.  frameboot mounts it in the initramfs and unmounts it before
/// `switch_root` (the frame's other userspace re-mounts it the same way), and
/// this board has no udev, so the partition is found by its GPT name in
/// `/sys` and mounted by node.
pub fn mount_frame_boot() -> Result<()> {
    use std::ffi::CString;

    if mounted_at(FRAME_BOOT_MOUNTPOINT) {
        return Ok(());
    }
    let dev = find_partition(FRAME_BOOT_PARTNAME)
        .with_context(|| format!("no partition named {FRAME_BOOT_PARTNAME}"))?;
    fs::create_dir_all(FRAME_BOOT_MOUNTPOINT)
        .with_context(|| format!("creating {FRAME_BOOT_MOUNTPOINT}"))?;

    let source = CString::new(dev.as_os_str().as_encoded_bytes())?;
    let target = CString::new(FRAME_BOOT_MOUNTPOINT)?;
    let fstype = CString::new("vfat")?;
    let rc = unsafe {
        libc::mount(source.as_ptr(), target.as_ptr(), fstype.as_ptr(), 0, std::ptr::null())
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        bail!("mounting {} at {FRAME_BOOT_MOUNTPOINT} failed: {err}", dev.display());
    }
    Ok(())
}

/// Resolve a GPT partition name to its `/dev` node by reading the uevent the
/// kernel exports for each block device — the same scan the frame's shell
/// tooling makes.
fn find_partition(name: &str) -> Option<PathBuf> {
    let want = format!("PARTNAME={name}");
    for entry in fs::read_dir("/sys/class/block").ok()?.flatten() {
        let uevent = entry.path().join("uevent");
        let Ok(text) = fs::read_to_string(&uevent) else { continue };
        if !text.lines().any(|l| l == want) {
            continue;
        }
        if let Some(devname) = text.lines().find_map(|l| l.strip_prefix("DEVNAME=")) {
            return Some(PathBuf::from("/dev").join(devname));
        }
    }
    None
}

/// True when `target` is already a mount point.
fn mounted_at(target: &str) -> bool {
    fs::read_to_string("/proc/self/mounts")
        .map(|mounts| mounts.lines().any(|l| l.split_whitespace().nth(1) == Some(target)))
        .unwrap_or(false)
}

/// Hand over to phase 2, passing the resolved profile as its single argument.
/// Only returns on failure.
pub fn exec_aminexec(profile_ref: &str) -> Result<()> {
    use std::ffi::CString;
    let program = CString::new(AMINEXEC)?;
    let profile = CString::new(profile_ref)?;
    let argv: [*const libc::c_char; 3] =
        [program.as_ptr(), profile.as_ptr(), std::ptr::null()];
    unsafe { libc::execv(program.as_ptr(), argv.as_ptr()) };
    let err = std::io::Error::last_os_error();
    bail!("execv({AMINEXEC} {profile_ref}) failed: {err}")
}

/// Encode a node's local boot profile as BSAX — the binary dialect of the
/// document [`resolve_profile_ref`] hands to phase 2, written by the host-side
/// emitter (`examples/emit-profile.rs`) so producer and decoder cannot drift.
///
/// Stages 1..=4 carry the fields `ainit` executes on ([`crate::stage_decoder`]);
/// 5 and 6 are emitted empty so the closed-world decoder still sees what it
/// skips.  `node_id` goes on the stages that identify the metal (1, 4);
/// `slab_dev` on the ones that name storage (1, 3).
pub fn encode_boot_profile(node_id: &str, slab_dev: &str) -> Vec<u8> {
    use bsax::encode;
    use bsax::vocab::{self, ns_id::AMIN};
    use bytes::BytesMut;

    let mut buf = BytesMut::new();
    encode::write_magic(&mut buf);
    encode::write_start_doc(&mut buf);
    encode::write_start_elem(
        &mut buf,
        AMIN,
        vocab::by_name(b"profile").expect("profile in vocab"),
        &[] as &[(u32, &[u8])],
    );
    for (order, name, attrs) in [
        (
            1u32,
            "hwcheck",
            &[
                (b"node_id" as &[u8], node_id.as_bytes()),
                (b"slab_dev", slab_dev.as_bytes()),
            ][..],
        ),
        (2, "fw-update", &[][..]),
        (3, "storage-init", &[(b"slab_dev" as &[u8], slab_dev.as_bytes())][..]),
        (4, "mesh-join", &[(b"node_id" as &[u8], node_id.as_bytes())][..]),
        (5, "supervisor", &[][..]),
        (6, "workload-ready", &[][..]),
    ] {
        let mut pair: Vec<(u32, Vec<u8>)> = vec![
            (vocab::by_name(b"order").expect("order in vocab"), order.to_string().into_bytes()),
            (vocab::by_name(b"name").expect("name in vocab"), name.as_bytes().to_vec()),
        ];
        for (k, v) in attrs {
            pair.push((vocab::by_name(k).expect("attr in vocab"), v.to_vec()));
        }
        let borrowed: Vec<(u32, &[u8])> = pair.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"stage").expect("stage in vocab"), &borrowed);
        encode::write_end_elem(&mut buf);
    }
    encode::write_end_elem(&mut buf);
    encode::write_end_doc(&mut buf);
    buf.freeze().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_ref_is_passed_through_untouched() {
        assert_eq!(
            resolve_profile_ref("root=/dev/sda1 amin.bootstrap=bitcache:blake3:aa").unwrap(),
            "bitcache:blake3:aa"
        );
        assert_eq!(
            resolve_profile_ref("amin.init_profile_ref=https://tor/prof quiet").unwrap(),
            "https://tor/prof"
        );
    }

    #[test]
    fn served_ref_ignores_lookalike_keys() {
        // A key that merely *starts* the same way is not the key.
        assert_eq!(served_ref("amin.init_profile_refx=1"), None);
        assert_eq!(served_ref("console=tty1 frameboot wdt usbnet"), None);
    }

    #[test]
    fn local_resolution_prefers_xml_over_bsax() {
        let dir = tempfile::tempdir().unwrap();
        let xml = dir.path().join("init-profile.xml");
        let bsax = dir.path().join("init-profile.bsax");
        fs::write(&xml, b"<amin:profile/>").unwrap();
        fs::write(&bsax, b"AMINBSA1").unwrap();
        // Both dialects are listed; XML is searched first.
        let candidates: Vec<String> =
            PROFILE_CANDIDATES.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(candidates[0], "/boot/init-profile.xml");
        assert_eq!(candidates[1], "/boot/init-profile.bsax");
    }

    #[test]
    fn encoded_boot_profile_decodes_back_to_the_stages() {
        let bytes = encode_boot_profile("sc7731g-vt10101", "/dev/mmcblk0p27");
        let p = crate::stage_decoder::parse_init_profile_bsax(&bytes).unwrap();
        assert_eq!(p.stage_hwcheck.order, 1);
        assert_eq!(p.stage_hwcheck.node_id, "sc7731g-vt10101");
        assert_eq!(p.stage_storage.slab_dev, PathBuf::from("/dev/mmcblk0p27"));
        assert_eq!(p.stage_mesh_join.order, 4);
        assert!(p.skipped_elements > 0, "stages 5-6 must be skipped, not materialised");
    }
}

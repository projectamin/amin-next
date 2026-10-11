//! `ainit` binary — the first PID 1 the kernel executes from the netboot
//! initrd (`.cpio.zst` archive — the real `init` executable).
//!
//! The pipeline is implemented as a single data-driven sequence with
//! injectable I/O so the full end-to-end path is unit-testable without a
//! QEMU harness.  See `ainit::run_ainit_pipeline` in the library crate.
//!
//! Real-metal flow (on actual hardware / the QEMU netboot image):
//!
//! 1. `boot_offer::MeshHello` → broadcast on the boot VLAN.  Receive BOOT_OFFER
//!    from the ToR; verify with the baked-in mesh ML-DSA trust anchor.
//! 2. `cas_fetch::RsStripe::reassemble` the init-profile.xml.bsax Bitcache
//!    ref over 3 peer RS(3,2) stripes.
//! 3. `stage_decoder::parse_init_profile_bsax` stages 1..=4:
//!      • hwcheck, fw-update, storage-init, mesh-join
//! 4. Open the 3 mesh QUIC sockets + slab fd + seal-log fd.
//! 5. `fd_handoff::send_handoff` to `/run/amin/hand-off.sock` (bound by
//!    the aminexec PID-1 bringup that is about to run after `pivot_root`).
//! 6. `pivot_root(8)` into the Bitcache-backed amin rootfs;
//!    `execve("/sbin/aminexec")` → becomes the real long-lived PID 1.
//!
//! Under `cfg(test)` we never actually exec; pipeline just returns the
//! decoded stages and a report of what would have been shipped for the
//! fd handoff.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        let pid = unsafe { libc::getpid() };
        if pid != 1 {
            eprintln!(
                "ainit: WARNING: invoked as pid {pid}, not PID 1.  Running test-pipeline mode."
            );
            return match run_simulated_entrypoint() {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => { eprintln!("ainit sim-pipeline FAIL: {e:?}"); ExitCode::from(7) },
            };
        }
        // Real metal path.  All errors here = kernel panic / sysrq reboot,
        // since ainit has no stderr on the serial console in production
        // without a running getty.  Exit with a signal that the kernel
        // watchdog or BMC will catch and reboot the node.
        if let Err(e) = ainit::run_real_pid1_entrypoint() {
            eprintln!("ainit FATAL (will reboot): {e:?}");
            // Write a deterministic sentinel to /sysrq-trigger if present.
            let _ = std::fs::write("/proc/sysrq-trigger", b"b\n");
            return ExitCode::from(0x20);
        }
        return ExitCode::SUCCESS;
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ainit: unsupported target_os — only Linux metal netboot is supported");
        ExitCode::from(2)
    }
}

/// Non-Linux / non-PID-1 entrypoint for local dev smoke test.  Just runs
/// the full pipeline with mock I/O so `cargo run -p ainit` is useful and
/// prints a success line.
#[cfg(target_os = "linux")]
fn run_simulated_entrypoint() -> anyhow::Result<()> {
    use ainit::boot_offer::{BootOffer, MeshHello, TrustedAnchor};
    use ainit::cas_fetch::RsStripe;
    use ainit::stage_decoder::{self, ParsedInitProfile};
    use ainit::fd_handoff::{self, HandoffFds, HANDOFF_FD_COUNT};

    let tmp = tempfile::tempdir()?;
    let hello = MeshHello::new([0x11u8; 32], 1);
    let offer = BootOffer {
        node_id:               "sim-node".into(),
        init_profile_ref:      "bitcache:blake3:ffff1111".into(),
        aminexec_rootfs_ref:   "bitcache:blake3:aaaa1111".into(),
        slab_dev:              PathBuf::from("/dev/nvme0n1p2"),
        zcap_token_b64:        "zcap:mldsa87:SIM-TOKEN".into(),
        offer_ts_sec:          1_700_000_000,
        offer_signature_bytes: vec![0xAAu8; 128],
    };
    offer.verify(&hello, &TrustedAnchor::DevAcceptAll, 1_700_000_100)?;

    // Build a fake init-profile BSAX via encoder for end-to-end.
    let bsax_bytes = build_bsax_init_profile();
    let stripe = RsStripe::encode_mk(&bsax_bytes, 3, 2)?;
    let fetched = stripe.reassemble()?;
    assert_eq!(fetched.n_recovered, 0);
    assert_eq!(fetched.bytes, bsax_bytes);

    let profile: ParsedInitProfile = stage_decoder::parse_init_profile_bsax(&fetched.bytes)?;
    assert_eq!(profile.stage_hwcheck.order, 1);
    assert_eq!(profile.stage_mesh_join.order, 4);
    assert!(profile.skipped_elements > 0);

    // SCM handoff smoke (5 temp fds, no real network): bind sock + accept.
    let sock = tmp.path().join("sim-hand-off.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = std::os::unix::net::UnixListener::bind(&sock)?;
    let sender = std::os::unix::net::UnixStream::connect(&sock)?;
    let receiver = fd_handoff::accept_one(&listener)?;

    let (m1, _) = fd_handoff::make_unique_temp_fd(&tmp, 1)?;
    let (m2, _) = fd_handoff::make_unique_temp_fd(&tmp, 2)?;
    let (m3, _) = fd_handoff::make_unique_temp_fd(&tmp, 3)?;
    let (sl, _) = fd_handoff::make_unique_temp_fd(&tmp, 4)?;
    let (sc, _) = fd_handoff::make_unique_temp_fd(&tmp, 5)?;
    let send = HandoffFds { mesh_peer_1: m1, mesh_peer_2: m2, mesh_peer_3: m3, bitcache_slab: sl, seal_chain_append: sc };
    fd_handoff::send_handoff(&sender, &send)?;
    let recv = fd_handoff::recv_handoff(&receiver)?;
    let _ = recv; // drop order

    eprintln!(
        "ainit SIM-PIPELINE OK: profile stages=[hwcheck={},fw-update={},storage-init={},mesh-join={}] \
         skipped(closed-world)={} HandoffFds={HANDOFF_FD_COUNT}",
        profile.stage_hwcheck.order,   profile.stage_fw_update.order,
        profile.stage_storage.order,   profile.stage_mesh_join.order,
        profile.skipped_elements
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_bsax_init_profile() -> Vec<u8> {
    use bsax::encode;
    use bsax::vocab::{self, ns_id::AMIN};
    use bytes::BytesMut;
    let mut buf = BytesMut::new();
    encode::write_magic(&mut buf);
    encode::write_start_doc(&mut buf);
    encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"profile").unwrap(), &[] as &[(u8, &[u8])]);
    for (order, name, attrs) in [
        (1u32, "hwcheck",      &[(b"slab_dev" as &[u8], b"/dev/nvme0n1p2" as &[u8])][..]),
        (2,    "fw-update",    &[]),
        (3,    "storage-init", &[(b"slab_dev", b"/dev/nvme0n1p2")]),
        (4,    "mesh-join",    &[(b"node_id", b"sim-node")]),
        (5,    "supervisor",   &[]),
        (6,    "workload-ready",&[]),
    ] {
        let mut pair: Vec<(u8, Vec<u8>)> = vec![
            (vocab::by_name(b"order").unwrap(), order.to_string().into_bytes()),
            (vocab::by_name(b"name").unwrap(),  name.as_bytes().to_vec()),
        ];
        for (k, v) in attrs { pair.push((vocab::by_name(k).unwrap(), v.to_vec())); }
        let borrowed: Vec<(u8, &[u8])> = pair.iter().map(|(a, b)| (*a, b.as_slice())).collect();
        encode::write_start_elem(&mut buf, AMIN, vocab::by_name(b"stage").unwrap(), &borrowed);
        encode::write_end_elem(&mut buf);
    }
    encode::write_end_elem(&mut buf);
    encode::write_end_doc(&mut buf);
    buf.freeze().to_vec()
}

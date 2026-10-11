//! AWP/3 mesh HELLO / BOOT_OFFER — the *zero-touch metal bootstrap* handshake.
//!
//! On power-on:
//!
//! 1. ainit brings up the boot NIC (real metal code under `feature="metal"`;
//!    tests and CI mock this with byte buffers).
//! 2. ainit broadcasts a single [`MeshHello`] frame on the boot VLAN
//!    (link-local multicast; ToR switches running the Amin AWP/3 bootstrap
//!    agent respond with BOOT_OFFER for any node matching the cookie-cutter
//!    hardware fingerprint).
//! 3. ToR replies with a [`BootOffer`] containing:
//!      • zcap = ML-DSA-87-signed boot authority token for this node_id
//!      • init_profile_ref = Bitcache blake3 ref of the init-profile.xml.bsax
//!      • aminexec_rootfs_ref = Bitcache ref of the PID-1 rootfs blob
//!      • slab_dev = path of the slab block device for this cookie-cutter
//! 4. ainit calls [`BootOffer::verify`] with the mesh trust-anchor ML-DSA
//!    public key; FAIL → panic/sysrq reboot loop.  PASS → proceed to
//!    cas_fetch to pull the init-profile blob over N-peer RS stripes.
//!
//! For now we model the data structures + verification (pure data tests).
//! The actual NIC bring-up + multicast send is gated behind feature="metal"
//! because it needs raw netlink + ioctl that doesn't run in CI.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use blake3::Hash;

/// Default multicast group for zero-touch HELLO discovery on the boot VLAN.
/// (IPv6 link-local scope; every Amin ToR switch listens on this address for
/// the bootstrap service.)
pub const AWP3_BOOT_MCAST_V6: &[u8; 16] = b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x51";
pub const AWP3_BOOT_UDP_PORT: u16 = 4514;

/// ainit → ToR: "I'm a metal node, give me my boot ref."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshHello {
    /// blake3(fpga_stable_fingerprint_of_cookie_cutter_hardware)
    pub node_fingerprint: [u8; 32],
    /// monotonically increasing per-node boot counter (stored in the slab's
    /// header after last successful boot; helps the ToR serve the same
    /// init-profile ref on a reboot loop that the user *just* installed).
    pub boot_counter:      u64,
    /// wall-clock seconds (best-effort; used only for ToR audit logging).
    pub wall_ts_sec:       u64,
}

impl MeshHello {
    /// Build a `MeshHello` with the given fingerprint and boot_counter;
    /// wall_ts_sec = current unix time from SystemTime.
    pub fn new(fingerprint: [u8; 32], boot_counter: u64) -> Self {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Self { node_fingerprint: fingerprint, boot_counter, wall_ts_sec: secs }
    }

    /// Canonical bytes fed into the BOOT_OFFER signature — the ToR signs
    /// `blake3(HELLO_CANONICAL_BYTES || OFFER_CANONICAL_BYTES)`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 8);
        out.extend_from_slice(&self.node_fingerprint);
        out.extend_from_slice(&self.boot_counter.to_le_bytes());
        out.extend_from_slice(&self.wall_ts_sec.to_le_bytes());
        out
    }
}

/// ToR → ainit: signed response with all ainit needs to boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootOffer {
    /// Exact `node_id` that the kernel cmdline will carry (for audit /
    /// seal chain).  Usually equal to the MeshHello fingerprint as a hex
    /// string.
    pub node_id:               String,
    /// Bitcache blake3 ref of the init-profile.xml.bsax document we will
    /// feed the micro-decoder after CAS fetch.
    pub init_profile_ref:      String,
    /// Bitcache ref of the Amin rootfs (used after pivot_root to run
    /// aminexec PID 1).
    pub aminexec_rootfs_ref:   String,
    /// Block device path of the slab store — storage-init stage formats
    /// or opens this.
    pub slab_dev:              std::path::PathBuf,
    /// zcap token: ML-DSA-87 signature granting this node boot + mesh-join
    /// authority for scope {tier, zone, max-redundancy}.  Forwarded verbatim
    /// to the PID-1 cmdline's `amin.zcap=`.
    pub zcap_token_b64:        String,
    /// Walls-clock seconds at which this offer was minted — used to
    /// bound replay (ainit rejects offers older than 300 s or newer than
    /// +300 s from current clock if we can talk to a PTP grandmaster).
    pub offer_ts_sec:          u64,
    /// ML-DSA-87 signature over `blake3(hello_canon || offer_canon)`.
    pub offer_signature_bytes: Vec<u8>,
}

impl BootOffer {
    /// Canonical bytes combined with the sender's MeshHello for signature
    /// verification.  The ToR signs `blake3(hello.canonical() ||
    /// offer.canonical())` with its mesh root ML-DSA-87 key and writes it
    /// to [`BootOffer::offer_signature_bytes`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        extend_len_prefixed_utf8(&mut out, &self.node_id);
        extend_len_prefixed_utf8(&mut out, &self.init_profile_ref);
        extend_len_prefixed_utf8(&mut out, &self.aminexec_rootfs_ref);
        extend_len_prefixed_utf8(&mut out, self.slab_dev.to_str().unwrap_or(""));
        extend_len_prefixed_utf8(&mut out, &self.zcap_token_b64);
        out.extend_from_slice(&self.offer_ts_sec.to_le_bytes());
        out
    }

    /// Verify this boot offer against the mesh trust anchor public key.
    ///
    /// **Closed-world contract**: any failure (bad key format, sig mismatch,
    /// expired/too-new timestamp outside `[now-300, now+300]`) halts the
    /// boot deterministically — we return Err rather than trying another
    /// offer silently.
    ///
    /// Current implementation (bootstrapping) accepts a `TrustedAnchor` enum
    /// where:
    ///   • `DevAcceptAll` — CI / test-only mock: always OK.
    ///   • `MLDsa87(pubkey_bytes)` — calls the ml-dsa crate's verifier once
    ///     we integrate it (future phase).
    pub fn verify(&self, hello: &MeshHello, anchor: &TrustedAnchor, now_sec: u64) -> Result<()> {
        // Timestamp window: [now-300s, now+300s].  (On a true netboot with no
        // RTC the caller may override `now_sec` with 0 to skip the check.)
        if now_sec != 0 {
            let lo = now_sec.saturating_sub(300);
            let hi = now_sec.saturating_add(300);
            if self.offer_ts_sec < lo || self.offer_ts_sec > hi {
                bail!(
                    "BOOT_OFFER out of timestamp window: offer_ts={} valid=[{lo},{hi}]",
                    self.offer_ts_sec
                );
            }
        }
        match anchor {
            TrustedAnchor::DevAcceptAll => {}, // CI-only bypass.
            TrustedAnchor::MLDsa87(_pubkey) => {
                // TODO(Phase 2+): actually run ML-DSA-87 verifier here when
                // the ml-dsa crate is wired up.  For now we validate the
                // signed digest *shape* to make sure the offer format is
                // internally consistent.
                let digest = Self::compute_digest(hello, self);
                if digest.as_bytes().len() != 32 {
                    bail!("digest length invariant failed (blake3 should be 32 B)");
                }
                if self.offer_signature_bytes.len() < 32 {
                    bail!("BOOT_OFFER signature shorter than 32 B — likely forged");
                }
            },
        }
        if self.init_profile_ref.is_empty() {
            bail!("BOOT_OFFER missing init_profile_ref (refusal by ToR)");
        }
        if self.aminexec_rootfs_ref.is_empty() {
            bail!("BOOT_OFFER missing aminexec_rootfs_ref");
        }
        if self.zcap_token_b64.is_empty() {
            bail!("BOOT_OFFER missing zcap_token (node has no authority)");
        }
        Ok(())
    }

    /// Compute blake3(hello.canon || offer.canon).  In production this is
    /// the exact input to ML-DSA-87 sign/verify.  Exposed for tests that
    /// want to re-compute the digest deterministically.
    pub fn compute_digest(hello: &MeshHello, offer: &Self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&hello.canonical_bytes());
        hasher.update(&offer.canonical_bytes());
        hasher.finalize()
    }
}

fn extend_len_prefixed_utf8(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Mesh trust anchor used to verify BOOT_OFFER signatures.
#[derive(Debug, Clone)]
pub enum TrustedAnchor {
    /// **TEST-ONLY**: accept every offer unconditionally.  This MUST NOT be
    /// used outside CI/local development (feature="metal" builds panic if
    /// the caller tries to select this variant at runtime).
    DevAcceptAll,
    /// Real mesh root ML-DSA-87 public key.  Verifier is wired up in a
    /// future phase when the ml-dsa crate is added to ainit dependencies.
    MLDsa87(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hello() -> MeshHello {
        MeshHello::new([0xABu8; 32], 12)
    }

    fn dummy_offer(refuse: bool) -> BootOffer {
        let h = dummy_hello();
        let init_ref = if refuse { String::new() } else { "bitcache:blake3:abc".into() };
        let mut o = BootOffer {
            node_id:             "metal-blake3-abababab".into(),
            init_profile_ref:    init_ref,
            aminexec_rootfs_ref: "bitcache:blake3:fed".into(),
            slab_dev:            std::path::PathBuf::from("/dev/nvme0n1p2"),
            zcap_token_b64:      "zcap:mldsa87:BASE64HERE".into(),
            offer_ts_sec:        1_700_000_000,
            offer_signature_bytes: vec![0x55u8; 128],
        };
        o.offer_signature_bytes = BootOffer::compute_digest(&h, &o).as_bytes().to_vec();
        o
    }

    #[test]
    fn happy_verify_dev_anchor_ok() {
        let h = dummy_hello();
        let o = dummy_offer(false);
        o.verify(&h, &TrustedAnchor::DevAcceptAll, 1_700_000_100).unwrap();
    }

    #[test]
    fn timestamp_outside_window_rejected() {
        let h = dummy_hello();
        let o = dummy_offer(false);
        // offer = 1_700_000_000; now = 1_700_100_000 → 100_000 s past → reject.
        let err = o.verify(&h, &TrustedAnchor::DevAcceptAll, 1_700_100_000);
        assert!(err.is_err() && err.unwrap_err().to_string().contains("timestamp"));
    }

    #[test]
    fn mldsa_anchor_rejects_missing_init_ref_because_refuse_flag_uses_that_path() {
        let h = dummy_hello();
        let o = dummy_offer(true); // init_profile_ref = empty → refusal.
        let err = o.verify(&h, &TrustedAnchor::MLDsa87(vec![0u8; 32]), 1_700_000_000);
        assert!(err.is_err() && err.unwrap_err().to_string().contains("missing init_profile_ref"));
    }

    #[test]
    fn digest_is_deterministic_and_32_bytes() {
        let h = dummy_hello();
        let o = dummy_offer(false);
        let d1 = BootOffer::compute_digest(&h, &o);
        let d2 = BootOffer::compute_digest(&h, &o);
        assert_eq!(d1, d2);
        assert_eq!(d1.as_bytes().len(), 32);
    }

    #[test]
    fn hello_canonical_has_exact_32plus8plus8_layout() {
        let h = dummy_hello();
        let c = h.canonical_bytes();
        assert_eq!(c.len(), 48);
    }
}

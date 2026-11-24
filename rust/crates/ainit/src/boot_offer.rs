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
//! Trust is pushed from the existing ecosystem to the new node here: the
//! offer carries an authority-signed [`bitcache::nodecert::NodeCert`] that
//! certifies the hash of the key the node minted for itself
//! ([`crate::node_identity`]) and was named in its HELLO.
//!
//! Verification is real and fail-closed: ML-DSA-87 over a domain-separated
//! digest, certificate bound to this HELLO, no escape hatch in `metal` builds.
//!
//! The data structures + verification are pure (testable without hardware).
//! The actual NIC bring-up + multicast send is gated behind feature="metal"
//! because it needs raw netlink + ioctl that doesn't run in CI.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use bitcache::nodecert::NodeCert;
use blake3::Hash;

/// Default multicast group for zero-touch HELLO discovery on the boot VLAN.
/// (IPv6 link-local scope; every Amin ToR switch listens on this address for
/// the bootstrap service.)
pub const AWP3_BOOT_MCAST_V6: &[u8; 16] = b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x51";
pub const AWP3_BOOT_UDP_PORT: u16 = 4514;

/// Domain separation for the offer signature (never reusable as another
/// protocol's ML-DSA-87 message).
pub const OFFER_SIGN_DOMAIN: &[u8] = b"AMIN3-BOOT-OFFER-V1\n";

/// Length of [`MeshHello::canonical_bytes`]: 32 + 8 + 8 + 32.
pub const HELLO_CANON_LEN: usize = 80;

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
    /// `blake3(composite_vk)` of the identity key this node minted for this
    /// boot ([`crate::node_identity::NodeIdentity::vk_hash`]).  The offer's
    /// node certificate must certify exactly this hash.
    pub node_vk_hash:      [u8; 32],
}

impl MeshHello {
    /// Build a `MeshHello` with the given fingerprint and boot_counter;
    /// wall_ts_sec = current unix time from SystemTime.
    pub fn new(fingerprint: [u8; 32], boot_counter: u64, node_vk_hash: [u8; 32]) -> Self {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Self { node_fingerprint: fingerprint, boot_counter, wall_ts_sec: secs, node_vk_hash }
    }

    /// Canonical bytes fed into the BOOT_OFFER signature — the ToR signs
    /// `blake3(HELLO_CANONICAL_BYTES || OFFER_CANONICAL_BYTES)`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HELLO_CANON_LEN);
        out.extend_from_slice(&self.node_fingerprint);
        out.extend_from_slice(&self.boot_counter.to_le_bytes());
        out.extend_from_slice(&self.wall_ts_sec.to_le_bytes());
        out.extend_from_slice(&self.node_vk_hash);
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
    /// The authority's current log position when it minted this offer.  A
    /// netbooted node has no trustworthy clock; this is what its certificate
    /// validity is judged against.
    pub authority_pos:         u64,
    /// Bitcache ref (`bitcache:blake3:<64 hex>`) of a signed ledger join snapshot, or
    /// empty.  A node with no ledger yet adopts it instead of fetching history; it is
    /// covered by the offer signature, and the snapshot is itself signed by the same
    /// authority chain, so both the name and the content are bound to the trust root.
    pub ledger_snapshot_ref:   String,
    /// `NodeCert` (body ‖ ML-DSA-87 signature) certifying the node's identity
    /// key for this boot.  Required for every real anchor.
    pub node_cert:             Vec<u8>,
    /// ML-DSA-87 signature over `OFFER_SIGN_DOMAIN ‖ blake3(hello_canon ‖ offer_canon)`.
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
        out.extend_from_slice(&self.authority_pos.to_le_bytes());
        out.extend_from_slice(&(self.node_cert.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.node_cert);
        extend_len_prefixed_utf8(&mut out, &self.ledger_snapshot_ref);
        out
    }

    /// The exact message the authority signs for `hello`.
    pub fn signing_message(&self, hello: &MeshHello) -> Vec<u8> {
        let mut m = Vec::with_capacity(OFFER_SIGN_DOMAIN.len() + 32);
        m.extend_from_slice(OFFER_SIGN_DOMAIN);
        m.extend_from_slice(Self::compute_digest(hello, self).as_bytes());
        m
    }

    /// Authority side: sign this offer for `hello`.  Fill every other field
    /// (including `node_cert`) first — the signature covers them all.
    pub fn sign(&mut self, hello: &MeshHello, authority: &bitcache::Keypair) -> Result<()> {
        let sig = bitcache::mldsa87_sign(authority, &self.signing_message(hello))
            .map_err(|e| anyhow::anyhow!("sign BOOT_OFFER: {e}"))?;
        self.offer_signature_bytes = sig;
        Ok(())
    }

    /// Verify this boot offer against the mesh trust anchor.
    ///
    /// **Closed-world contract**: any failure halts the boot deterministically
    /// — we return Err rather than trying another offer silently.  Checks, in
    /// order:
    ///   1. timestamp window `[now-300, now+300]` (skipped when `now_sec == 0`,
    ///      i.e. no RTC; the certificate position check still applies);
    ///   2. `MLDsa87`: ML-DSA-87 signature over [`BootOffer::signing_message`];
    ///   3. `MLDsa87`: `node_cert` verifies under the same anchor, certifies
    ///      the key hash from this HELLO, this `node_id` and `boot_counter`,
    ///      and is valid at `authority_pos`;
    ///   4. the offer names a profile, a rootfs and a zcap.
    pub fn verify(&self, hello: &MeshHello, anchor: &TrustedAnchor, now_sec: u64) -> Result<()> {
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
            #[cfg(not(feature = "metal"))]
            TrustedAnchor::DevAcceptAll => {} // CI-only; does not exist in `metal` builds.
            TrustedAnchor::MLDsa87(vk) => {
                if vk.len() != bitcache::MLDSA87_VK_LEN {
                    bail!("trust anchor is not a {}-byte ML-DSA-87 key", bitcache::MLDSA87_VK_LEN);
                }
                if !bitcache::mldsa87_verify(vk, &self.signing_message(hello), &self.offer_signature_bytes) {
                    bail!("BOOT_OFFER signature invalid (ML-DSA-87)");
                }
                let cert = NodeCert::verify(&self.node_cert, vk)
                    .map_err(|e| anyhow::anyhow!("BOOT_OFFER node certificate rejected: {e:?}"))?;
                if cert.node_vk_hash != hello.node_vk_hash {
                    bail!("BOOT_OFFER node certificate certifies a different key than the HELLO's");
                }
                if cert.node_id != self.node_id {
                    bail!("BOOT_OFFER node certificate names node_id {:?}, offer names {:?}", cert.node_id, self.node_id);
                }
                if cert.boot_counter != hello.boot_counter {
                    bail!("BOOT_OFFER node certificate is for boot {}, HELLO is boot {}", cert.boot_counter, hello.boot_counter);
                }
                if !cert.valid_at(self.authority_pos) {
                    bail!("BOOT_OFFER node certificate not valid at authority position {}", self.authority_pos);
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
    /// **TEST-ONLY**: accept every offer unconditionally.  Compiled out of
    /// `metal` builds, so it cannot be selected on real hardware.
    #[cfg(not(feature = "metal"))]
    DevAcceptAll,
    /// The mesh root / authority ML-DSA-87 public key (2592 bytes).
    MLDsa87(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_identity::NodeIdentity;
    use rand::{rngs::StdRng, SeedableRng};

    struct World {
        authority: bitcache::Keypair,
        node: NodeIdentity,
        hello: MeshHello,
        offer: BootOffer,
    }

    fn world() -> World {
        let authority = bitcache::Keypair::generate(&mut StdRng::from_seed([5; 32]), "tor".into());
        let node = NodeIdentity::from_seeds(&[1; 32], &[2; 32]).unwrap();
        let hello = MeshHello::new([0xABu8; 32], 12, node.vk_hash());
        let cert = NodeCert {
            node_id: "metal-blake3-abababab".into(),
            node_vk_hash: node.vk_hash(),
            boot_counter: 12,
            scope_hash: [3; 32],
            valid_from_pos: 100,
            valid_to_pos: 200,
        };
        let mut offer = BootOffer {
            node_id:             "metal-blake3-abababab".into(),
            init_profile_ref:    "bitcache:blake3:abc".into(),
            aminexec_rootfs_ref: "bitcache:blake3:fed".into(),
            slab_dev:            std::path::PathBuf::from("/dev/nvme0n1p2"),
            zcap_token_b64:      "zcap:mldsa87:BASE64HERE".into(),
            offer_ts_sec:        1_700_000_000,
            authority_pos:       150,
            ledger_snapshot_ref: String::new(),
            node_cert:           cert.sign(&authority).unwrap(),
            offer_signature_bytes: Vec::new(),
        };
        offer.sign(&hello, &authority).unwrap();
        World { authority, node, hello, offer }
    }

    fn anchor(w: &World) -> TrustedAnchor {
        TrustedAnchor::MLDsa87(w.authority.verifying_key_bytes())
    }

    #[test]
    fn real_offer_verifies() {
        let w = world();
        w.offer.verify(&w.hello, &anchor(&w), 1_700_000_100).unwrap();
        // no RTC (now = 0) still verifies: certificate validity uses authority_pos
        w.offer.verify(&w.hello, &anchor(&w), 0).unwrap();
        let _ = &w.node;
    }

    #[test]
    fn dev_anchor_only_in_non_metal_builds() {
        let w = world();
        #[cfg(not(feature = "metal"))]
        w.offer.verify(&w.hello, &TrustedAnchor::DevAcceptAll, 1_700_000_100).unwrap();
        let _ = w;
    }

    #[test]
    fn forged_or_wrong_anchor_rejected() {
        let w = world();
        let other = bitcache::Keypair::generate(&mut StdRng::from_seed([6; 32]), "evil".into());
        let err = w.offer.verify(&w.hello, &TrustedAnchor::MLDsa87(other.verifying_key_bytes()), 0);
        assert!(err.unwrap_err().to_string().contains("signature invalid"));
        // a >=32-byte junk "signature" (what the old stub accepted) is rejected
        let mut forged = w.offer.clone();
        forged.offer_signature_bytes = vec![0x55; 4627];
        assert!(forged.verify(&w.hello, &anchor(&w), 0).is_err());
        forged.offer_signature_bytes = vec![0x55; 64];
        assert!(forged.verify(&w.hello, &anchor(&w), 0).is_err());
        // a short / malformed anchor is rejected, never "skipped"
        assert!(w.offer.verify(&w.hello, &TrustedAnchor::MLDsa87(vec![0u8; 32]), 0).is_err());
    }

    #[test]
    fn every_signed_field_is_bound() {
        let w = world();
        let a = anchor(&w);
        let mut o = w.offer.clone(); o.init_profile_ref.push('x');
        assert!(o.verify(&w.hello, &a, 0).is_err());
        let mut o = w.offer.clone(); o.aminexec_rootfs_ref.push('x');
        assert!(o.verify(&w.hello, &a, 0).is_err());
        let mut o = w.offer.clone(); o.zcap_token_b64.push('x');
        assert!(o.verify(&w.hello, &a, 0).is_err());
        let mut o = w.offer.clone(); o.slab_dev = "/dev/sda".into();
        assert!(o.verify(&w.hello, &a, 0).is_err());
        let mut o = w.offer.clone(); o.authority_pos += 1;
        assert!(o.verify(&w.hello, &a, 0).is_err());
        let mut o = w.offer.clone(); o.node_cert[30] ^= 1;
        assert!(o.verify(&w.hello, &a, 0).is_err());
        // replay against a different HELLO (other boot / other node key)
        let mut h = w.hello.clone(); h.boot_counter += 1;
        assert!(w.offer.verify(&h, &a, 0).is_err());
        let mut h = w.hello.clone(); h.node_vk_hash = [0xEE; 32];
        assert!(w.offer.verify(&h, &a, 0).is_err());
    }

    #[test]
    fn certificate_must_match_hello_node_and_position() {
        let w = world();
        let a = anchor(&w);
        let reissue = |mutate: &dyn Fn(&mut NodeCert), pos: u64| {
            let mut c = NodeCert {
                node_id: "metal-blake3-abababab".into(), node_vk_hash: w.node.vk_hash(),
                boot_counter: 12, scope_hash: [3; 32], valid_from_pos: 100, valid_to_pos: 200,
            };
            mutate(&mut c);
            let mut o = w.offer.clone();
            o.node_cert = c.sign(&w.authority).unwrap();
            o.authority_pos = pos;
            o.sign(&w.hello, &w.authority).unwrap();
            o.verify(&w.hello, &a, 0)
        };
        assert!(reissue(&|_| {}, 150).is_ok());
        assert!(reissue(&|c| c.node_vk_hash = [9; 32], 150).is_err(), "cert for another key");
        assert!(reissue(&|c| c.node_id = "someone-else".into(), 150).is_err(), "cert for another node");
        assert!(reissue(&|c| c.boot_counter = 11, 150).is_err(), "cert for another boot");
        assert!(reissue(&|_| {}, 99).is_err(), "before validity");
        assert!(reissue(&|_| {}, 201).is_err(), "after validity (expired)");
    }

    #[test]
    fn missing_cert_rejected() {
        let mut w = world();
        w.offer.node_cert.clear();
        w.offer.sign(&w.hello, &w.authority).unwrap();
        assert!(w.offer.verify(&w.hello, &anchor(&w), 0).is_err());
    }

    #[test]
    fn timestamp_outside_window_rejected() {
        let w = world();
        let err = w.offer.verify(&w.hello, &anchor(&w), 1_700_100_000);
        assert!(err.unwrap_err().to_string().contains("timestamp"));
    }

    #[test]
    fn refusal_when_tor_omits_profile() {
        let mut w = world();
        w.offer.init_profile_ref.clear();
        w.offer.sign(&w.hello, &w.authority).unwrap();
        let err = w.offer.verify(&w.hello, &anchor(&w), 0);
        assert!(err.unwrap_err().to_string().contains("missing init_profile_ref"));
    }

    #[test]
    fn digest_is_deterministic_and_hello_is_80_bytes() {
        let w = world();
        assert_eq!(w.hello.canonical_bytes().len(), HELLO_CANON_LEN);
        assert_eq!(
            BootOffer::compute_digest(&w.hello, &w.offer),
            BootOffer::compute_digest(&w.hello, &w.offer)
        );
    }
}

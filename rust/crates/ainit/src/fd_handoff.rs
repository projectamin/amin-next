//! SCM_RIGHTS file-descriptor handoff from ainit → PID-1-aminexec.
//!
//! After mesh-join (stage 4) completes, ainit has:
//!   • 3 AWP/3 QUIC sockets connected to 3 distinct mesh peers (for
//!     RS(3,2) stripe reconstruction of any Bitcache blob)
//!   • 1 slab fd = O_DIRECT opened slab file on `amin.slab_dev` with
//!     `flock(LOCK_EX)` exclusive write lock
//!   • 1 seal chain append fd = write-only fd open of the running seal
//!     log (blake3+ML-DSA-87 chain log appended to once per SAX event)
//!
//! Rather than re-open these in aminexec PID 1 (which would lose the LOCK_EX
//! state of the slab fd, the QUIC connected-state of the sockets, and any
//! kernel-side TLS/ML-KEM handshake state), we ship them over a local Unix
//! `SOCK_SEQPACKET` socket using the standard POSIX `SCM_RIGHTS` ancillary
//! data in a single `sendmsg` / `recvmsg` call.  The receiving side
//! (Task 9 PID 1) maps the 5 received fds to the correct slot indices and
//! closes its own fd handoff listener immediately after.
//!
//! File order on the wire (first 5 fds in cmsg, 1 byte marker payload):
//!
//! ```text
//! fd[0] — mesh peer #1 socket (AWP/3, already-connected QUIC)
//! fd[1] — mesh peer #2 socket
//! fd[2] — mesh peer #3 socket
//! fd[3] — bitcache slab fd (O_DIRECT | flock EX)
//! fd[4] — seal chain append fd
//! ```

use std::io::{self};
#[cfg(test)] use std::io::Write;
use std::mem;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};

/// Number of file descriptors in a single ainit → aminexec handoff.
/// MUST stay 5 unless the spec formally changes; ainit.h handoff receiver
/// asserts exact count and rejects otherwise.
pub const HANDOFF_FD_COUNT: usize = 5;

/// Labeled struct holding the 5 handoff file descriptors.  The receiving
/// side (aminexec PID 1) uses these by name.
#[derive(Debug)]
pub struct HandoffFds {
    /// AWP/3 connected QUIC socket to mesh peer #1 (RS stripe index 0).
    pub mesh_peer_1: OwnedFd,
    /// AWP/3 connected QUIC socket to mesh peer #2 (RS stripe index 1).
    pub mesh_peer_2: OwnedFd,
    /// AWP/3 connected QUIC socket to mesh peer #3 (RS stripe index 2).
    pub mesh_peer_3: OwnedFd,
    /// Bitcache slab file fd (LOCK_EX held, O_DIRECT, pre-positioned).
    pub bitcache_slab: OwnedFd,
    /// Append-only fd pointing at the seal chain log inside the slab.
    pub seal_chain_append: OwnedFd,
}

impl HandoffFds {
    /// Slice the 5 fds in order — used by [`send_handoff`].
    fn as_raw_array(&self) -> [RawFd; HANDOFF_FD_COUNT] {
        [
            self.mesh_peer_1.as_raw_fd(),
            self.mesh_peer_2.as_raw_fd(),
            self.mesh_peer_3.as_raw_fd(),
            self.bitcache_slab.as_raw_fd(),
            self.seal_chain_append.as_raw_fd(),
        ]
    }
}

/// ainit side: send [`HandoffFds` over a connected `UnixStream` (the
/// `SOCK_SEQPACKET`/`SOCK_STREAM`).  1 byte marker `b("H") payload
/// so the receiver can sanity-check the control-plane framing even with 0-length
/// payload sends.
pub fn send_handoff(stream: &UnixStream, fds: &HandoffFds) -> Result<()> {
    let fd_array = fds.as_raw_array();
    let cmsg_space = unsafe {
        libc::CMSG_SPACE(HANDOFF_FD_COUNT as u32 * mem::size_of::<RawFd>() as u32) as usize
    };
    let mut cmsg_buf = vec![0u8; cmsg_space];
    let msg_iov = libc::iovec {
        iov_base: b"H" as *const u8 as *mut libc::c_void,
        iov_len:  1,
    };
    unsafe {
        let cmsg = cmsg_buf.as_mut_ptr() as *mut libc::cmsghdr;
        (*cmsg).cmsg_len =
            libc::CMSG_LEN(HANDOFF_FD_COUNT as u32 * mem::size_of::<RawFd>() as u32) as _;
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type  = libc::SCM_RIGHTS;
        let data_ptr = libc::CMSG_DATA(cmsg) as *mut RawFd;
        std::ptr::copy_nonoverlapping(fd_array.as_ptr(), data_ptr, HANDOFF_FD_COUNT);
    }
    let msghdr = libc::msghdr {
        msg_name:       std::ptr::null_mut(),
        msg_namelen:    0,
        msg_iov:        &msg_iov as *const libc::iovec as *mut libc::iovec,
        msg_iovlen:     1,
        msg_control:    cmsg_buf.as_ptr() as *mut libc::c_void,
        // Darwin's msghdr declares msg_controllen as socklen_t (u32); Linux
        // declares it size_t (usize) — `as _` infers the correct field type.
        msg_controllen: cmsg_space as _,
        msg_flags:      0,
    };
    // SAFETY: all pointers are valid for the duration of the call.
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msghdr as *const libc::msghdr, 0) };
    if n < 0 {
        let e = io::Error::last_os_error();
        bail!("sendmsg SCM_RIGHTS failed: {e}");
    }
    Ok(())
}

/// aminexec PID 1 side: receive exactly [`HandoffFds` on a connected Unix stream.
/// Requires that exactly HANDOFF_FD_COUNT (5) FDs arrive; returns them as named
/// `OwnedFd`s so the caller owns them and they close on drop.
pub fn recv_handoff(stream: &UnixStream) -> Result<HandoffFds> {
    let cmsg_space = unsafe { libc::CMSG_SPACE(HANDOFF_FD_COUNT as u32 * mem::size_of::<RawFd>() as u32) as usize };
    let mut cmsg_buf = vec![0u8; cmsg_space.max(64)];
    let mut marker_buf = [0u8; 1];
    let mut msg_iov = libc::iovec {
        iov_base: marker_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len:  1,
    };
    let mut msghdr = libc::msghdr {
        msg_name:       std::ptr::null_mut(),
        msg_namelen:    0,
        msg_iov:        &mut msg_iov as *mut libc::iovec,
        msg_iovlen:     1,
        msg_control:    cmsg_buf.as_mut_ptr() as *mut libc::c_void,
        // See send_handoff: socklen_t on darwin, size_t on linux.
        msg_controllen: cmsg_buf.len() as _,
        msg_flags:      0,
    };
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msghdr as *mut libc::msghdr, 0) };
    if n < 0 {
        let e = io::Error::last_os_error();
        bail!("recvmsg SCM_RIGHTS failed: {e}");
    }
    if marker_buf[0] != b'H' {
        bail!("handshake mismatch: expected 'H' marker byte, got 0x{:02X}", marker_buf[0]);
    }

    // Walk cmsg chain and find SCM_RIGHTS block with exact count.
    let mut received: [Option<OwnedFd>; HANDOFF_FD_COUNT] = [None, None, None, None, None];
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let fdp = libc::CMSG_DATA(cmsg) as *const RawFd;
                let data_bytes = ((*cmsg).cmsg_len as usize)
                    .checked_sub(mem::size_of::<libc::cmsghdr>())
                    .unwrap_or(0);
                let n_fds = data_bytes / mem::size_of::<RawFd>();
                if n_fds != HANDOFF_FD_COUNT {
                    bail!("SCM_RIGHTS block carries {n_fds} fds, expected {HANDOFF_FD_COUNT}");
                }
                for (i, slot) in received.iter_mut().enumerate() {
                    let raw = std::ptr::read(fdp.add(i));
                    *slot = Some(OwnedFd::from_raw_fd(raw));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msghdr, cmsg);
        }
    }

    let Some(m1) = received[0].take() else { bail!("missing fd[0] mesh_peer_1 in handoff") };
    let Some(m2) = received[1].take() else { bail!("missing fd[1] mesh_peer_2 in handoff") };
    let Some(m3) = received[2].take() else { bail!("missing fd[2] mesh_peer_3 in handoff") };
    let Some(sl) = received[3].take() else { bail!("missing fd[3] bitcache_slab in handoff") };
    let Some(sc) = received[4].take() else { bail!("missing fd[4] seal_chain_append in handoff") };

    Ok(HandoffFds {
        mesh_peer_1:        m1,
        mesh_peer_2:        m2,
        mesh_peer_3:        m3,
        bitcache_slab:     sl,
        seal_chain_append:  sc,
    })
}

/// Accept a connection on `listener` (SOCK_SEQPACKET or SOCK_STREAM unix
/// listener), then run a round-trip assertion — used by tests to exercise
/// sendmsg/recvmsg inside one process.
pub fn accept_one(listener: &std::os::unix::net::UnixListener) -> io::Result<UnixStream> {
    let (s, _addr) = listener.accept()?;
    Ok(s)
}

/// Convenience: stat an fd and return the inode number — tests confirm each
/// received fd refers to the same underlying file/socket via inode match.
pub fn fd_inode(fd: RawFd) -> Result<u64> {
    // SAFETY: fstat on a valid fd is safe; the caller must have kept it open.
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    let rc = unsafe { libc::fstat(fd, &mut st as *mut libc::stat) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        bail!("fstat(fd={fd}) failed: {e}");
    }
    #[cfg(not(target_os = "linux"))]
    let ino = st.st_ino as u64;
    #[cfg(target_os = "linux")]
    let ino = st.st_ino;
    Ok(ino)
}

/// Helper to create a tempfile and immediately convert to `OwnedFd` with a
/// deterministic unique inode (because every tempfile gets its own inode).
pub fn make_unique_temp_fd(dir: &tempfile::TempDir, tag: u8) -> Result<(OwnedFd, u64)> {
    let path = dir.path().join(format!("fd-{tag}"));
    let f = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .create(false)
        .open(&path)
        .with_context(|| format!("create temp handoff fd at {}", path.display()))?;
    let ino = fd_inode(f.as_raw_fd())?;
    Ok((OwnedFd::from(f), ino))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tr_8_3_scm_rights_send_5_fds_inodes_match() {
        let tmp = tempfile::tempdir().unwrap();
        // Bind a unix socket in tmpdir; accept + connect.
        let sock = tmp.path().join("handoff-test.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let sender   = UnixStream::connect(&sock).unwrap();
        let receiver = accept_one(&listener).unwrap();

        // Make 5 uniquely-named tempfiles → 5 distinct inodes.
        let (fd1, i1) = make_unique_temp_fd(&tmp, 1).unwrap();
        let (fd2, i2) = make_unique_temp_fd(&tmp, 2).unwrap();
        let (fd3, i3) = make_unique_temp_fd(&tmp, 3).unwrap();
        let (fd4, i4) = make_unique_temp_fd(&tmp, 4).unwrap();
        let (fd5, i5) = make_unique_temp_fd(&tmp, 5).unwrap();
        let send = HandoffFds {
            mesh_peer_1:       fd1,
            mesh_peer_2:       fd2,
            mesh_peer_3:       fd3,
            bitcache_slab:    fd4,
            seal_chain_append:fd5,
        };
        send_handoff(&sender, &send).unwrap();

        let recv = recv_handoff(&receiver).unwrap();

        // Compare inodes on received fds match originals.
        assert_eq!(fd_inode(recv.mesh_peer_1.as_raw_fd()).unwrap(), i1);
        assert_eq!(fd_inode(recv.mesh_peer_2.as_raw_fd()).unwrap(), i2);
        assert_eq!(fd_inode(recv.mesh_peer_3.as_raw_fd()).unwrap(), i3);
        assert_eq!(fd_inode(recv.bitcache_slab.as_raw_fd()).unwrap(), i4);
        assert_eq!(fd_inode(recv.seal_chain_append.as_raw_fd()).unwrap(), i5);

        // All 5 inodes MUST be pairwise-distinct (sanity check that we didn't
        // dup a single fd 5 times).
        let set = std::collections::BTreeSet::from([i1, i2, i3, i4, i5]);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn recv_mismatched_marker_byte_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("handoff-bad.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let mut s1 = UnixStream::connect(&sock).unwrap();
        let s2 = accept_one(&listener).unwrap();

        // Write garbage (non-'H') then zero-length SCM.  The test verifies
        // the receiver rejects it cleanly instead of returning fds on corruption.
        s1.write_all(&[0x00]).unwrap();
        drop(s1);
        // Recv will either get a 0-length read or marker mismatch.  Either way,
        // recv_handoff MUST fail with a clear error (not UB / not panic).
        let err = recv_handoff(&s2);
        assert!(err.is_err());
    }
}

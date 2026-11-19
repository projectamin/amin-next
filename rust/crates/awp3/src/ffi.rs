//! The C ABI over the three AWP/3 entry points, for the Perl bridge.
//!
//! `Perl` never re-implements AWP/3 framing; `Amin::Net::AWP3` binds this
//! `cdylib` with `FFI::Platypus` and drives one [`Awp3Session`] per backend
//! connection (docs/proxy-plan.md §6).
//!
//! Every fallible entry point returns an `isize`: a non-negative value is the
//! number of bytes written to the output buffer, and a negative value is one of
//! the [`Awp3Error`] codes below.  Because every structure has a fixed size,
//! the caller sizes its output buffers from the `awp3_*_len` getters and no
//! length in/out parameter is needed.
//!
//! ```text
//!   -1 KeyMaterial   -2 Signature   -3 Aead        -4 Kem
//!   -5 Handshake     -6 Frame       -7 Closed      -8 BufferTooSmall
//!   -9 BadArgument
//! ```
//!
//! The handle is opaque and owned by Rust: it must be released with
//! [`awp3_free`].  It is not thread-safe; one handle per connection, driven
//! from one thread.

// `unsafe_code` is denied crate-wide and deliberately re-allowed only here, the
// one module that owns the raw C ABI.  Every `usize as isize` below is a wire
// length bounded by a small compile-time constant or a frame size, never a
// value that can approach `isize::MAX`.
#![allow(unsafe_code, clippy::cast_possible_wrap)]

use core::slice;

use rand::rngs::StdRng;
use rand::SeedableRng;
use x25519_dalek::StaticSecret;

use crate::framing::{self, Session, FRAME_OVERHEAD};
use crate::handshake::{
    self, Initiator, ResponderIdentity, BUNDLE_LEN, MSG1_LEN, MSG2_LEN,
};
use crate::sign::{CompositeSigningKey, COMPOSITE_SIG_LEN};
use crate::{Awp3Error, Result};

/// The lifecycle state of an opaque AWP/3 session handle.
enum State {
    /// A transient placeholder used only while moving another state out;
    /// never observed by callers.
    Empty,
    /// A responder before `msg1` arrives.
    ResponderWait(Box<ResponderIdentity>),
    /// An initiator before `msg2` arrives.
    InitiatorWait(Box<Initiator>),
    /// A live, handshaken session.
    Open(Box<Session>),
}

/// An opaque AWP/3 session, handed to Perl as `void *`.
pub struct Awp3Session {
    state: State,
}

fn errno(e: &Awp3Error) -> isize {
    match e {
        Awp3Error::KeyMaterial => -1,
        Awp3Error::Signature => -2,
        Awp3Error::Aead => -3,
        Awp3Error::Kem => -4,
        Awp3Error::Handshake => -5,
        Awp3Error::Frame => -6,
        Awp3Error::Closed => -7,
        Awp3Error::BufferTooSmall => -8,
        Awp3Error::BadArgument => -9,
    }
}

fn guard<F: FnOnce() -> Result<isize>>(f: F) -> isize {
    f().unwrap_or_else(|e| errno(&e))
}

/// # Safety
/// `p` must be valid for `len` readable bytes.
unsafe fn rslice<'a>(p: *const u8, len: usize) -> Result<&'a [u8]> {
    if p.is_null() {
        return Err(Awp3Error::BadArgument);
    }
    Ok(slice::from_raw_parts(p, len))
}

/// # Safety
/// `p` must be valid for `len` writable bytes.
unsafe fn wslice<'a>(p: *mut u8, len: usize) -> Result<&'a mut [u8]> {
    if p.is_null() {
        return Err(Awp3Error::BadArgument);
    }
    Ok(slice::from_raw_parts_mut(p, len))
}

/// # Safety
/// `h` must be a live pointer returned by one of the `*_new` constructors.
unsafe fn handle<'a>(h: *mut Awp3Session) -> Result<&'a mut Awp3Session> {
    if h.is_null() {
        return Err(Awp3Error::BadArgument);
    }
    Ok(&mut *h)
}

fn rng_from(seed: &[u8]) -> Result<StdRng> {
    let bytes: [u8; 32] = seed.try_into().map_err(|_| Awp3Error::BadArgument)?;
    Ok(StdRng::from_seed(bytes))
}

// ── Size getters ────────────────────────────────────────────────────────────

/// Length in bytes of a signed responder bundle.
#[no_mangle]
pub extern "C" fn awp3_bundle_len() -> usize {
    BUNDLE_LEN
}

/// Length in bytes of an initiator `msg1`.
#[no_mangle]
pub extern "C" fn awp3_msg1_len() -> usize {
    MSG1_LEN
}

/// Length in bytes of a responder `msg2`.
#[no_mangle]
pub extern "C" fn awp3_msg2_len() -> usize {
    MSG2_LEN
}

/// Length in bytes of a close receipt (a composite signature).
#[no_mangle]
pub extern "C" fn awp3_receipt_len() -> usize {
    COMPOSITE_SIG_LEN
}

/// Fixed per-frame overhead: header + nonce + AEAD tag.
#[no_mangle]
pub extern "C" fn awp3_frame_overhead() -> usize {
    FRAME_OVERHEAD
}

// ── Constructors ────────────────────────────────────────────────────────────

/// Create a responder (backend) session from a 32-byte seed and write its
/// [`awp3_bundle_len`]-byte public bundle to `bundle_out`.
///
/// Returns an opaque handle, or null on error.
///
/// # Safety
/// `seed` must point at 32 readable bytes; `bundle_out` at `awp3_bundle_len()`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn awp3_responder_new(
    seed: *const u8,
    bundle_out: *mut u8,
) -> *mut Awp3Session {
    let build = || -> Result<*mut Awp3Session> {
        let mut rng = rng_from(rslice(seed, 32)?)?;
        let identity = ResponderIdentity::generate(&mut rng);
        let bundle = identity.bundle()?;
        let out = wslice(bundle_out, BUNDLE_LEN)?;
        out.copy_from_slice(&bundle);
        Ok(Box::into_raw(Box::new(Awp3Session {
            state: State::ResponderWait(Box::new(identity)),
        })))
    };
    match build() {
        Ok(p) => p,
        Err(_) => core::ptr::null_mut(),
    }
}

/// Create an initiator (front) session from the responder's bundle and a
/// 32-byte seed for this peer's static identity.
///
/// Returns an opaque handle, or null on error.
///
/// # Safety
/// `bundle` must point at `awp3_bundle_len()` readable bytes; `seed` at 32.
#[no_mangle]
pub unsafe extern "C" fn awp3_client_new(
    bundle: *const u8,
    seed: *const u8,
) -> *mut Awp3Session {
    let build = || -> Result<*mut Awp3Session> {
        let bundle = rslice(bundle, BUNDLE_LEN)?;
        let mut rng = rng_from(rslice(seed, 32)?)?;
        let identity = CompositeSigningKey::generate(&mut rng);
        let identity_dh = StaticSecret::random_from_rng(&mut rng);
        let hs = handshake::handshake_initiator(bundle, &identity, &identity_dh, &mut rng)?;
        Ok(Box::into_raw(Box::new(Awp3Session {
            state: State::InitiatorWait(Box::new(hs)),
        })))
    };
    match build() {
        Ok(p) => p,
        Err(_) => core::ptr::null_mut(),
    }
}

// ── Handshake ───────────────────────────────────────────────────────────────

/// Write the initiator's `msg1` (of [`awp3_msg1_len`] bytes) to `out`.
///
/// # Safety
/// `h` must be an initiator handle from [`awp3_client_new`]; `out` must point
/// at `awp3_msg1_len()` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn awp3_client_msg1(h: *mut Awp3Session, out: *mut u8) -> isize {
    guard(|| {
        let s = handle(h)?;
        let State::InitiatorWait(hs) = &s.state else {
            return Err(Awp3Error::Handshake);
        };
        wslice(out, MSG1_LEN)?.copy_from_slice(hs.msg1());
        Ok(MSG1_LEN as isize)
    })
}

/// Consume the responder's `msg1` and write `msg2` (of [`awp3_msg2_len`] bytes)
/// to `out`, moving the handle into the live session state.
///
/// # Safety
/// `msg1` must point at `awp3_msg1_len()` readable bytes; `out` at
/// `awp3_msg2_len()` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn awp3_responder_accept(
    h: *mut Awp3Session,
    msg1: *const u8,
    out: *mut u8,
) -> isize {
    guard(|| {
        let s = handle(h)?;
        let State::ResponderWait(identity) = &s.state else {
            return Err(Awp3Error::Handshake);
        };
        let msg1 = rslice(msg1, MSG1_LEN)?;
        let mut rng = StdRng::from_entropy();
        let (session, msg2) = handshake::handshake_responder(identity, msg1, &mut rng)?;
        wslice(out, MSG2_LEN)?.copy_from_slice(&msg2);

        // Take the identity out by replacing the state wholesale.
        s.state = State::Open(Box::new(session));
        Ok(MSG2_LEN as isize)
    })
}

/// Consume the responder's `msg2`, completing the initiator handshake.
///
/// # Safety
/// `msg2` must point at `awp3_msg2_len()` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn awp3_client_finish(h: *mut Awp3Session, msg2: *const u8) -> isize {
    guard(|| {
        let s = handle(h)?;
        let State::InitiatorWait(_) = &s.state else {
            return Err(Awp3Error::Handshake);
        };
        let msg2 = rslice(msg2, MSG2_LEN)?;
        // Move the Initiator out so `finish` can consume it.
        let prev = core::mem::replace(&mut s.state, State::Empty);
        let State::InitiatorWait(hs) = prev else {
            return Err(Awp3Error::Handshake);
        };
        let session = hs.finish(msg2)?;
        s.state = State::Open(Box::new(session));
        Ok(0)
    })
}

// ── Frames ──────────────────────────────────────────────────────────────────

/// Seal one DATA frame carrying `pt_len` bytes of `pt` into `out`.
///
/// `out` must be at least `pt_len + awp3_frame_overhead()` bytes.  Returns the
/// frame length on success.
///
/// # Safety
/// Pointers must be valid for the documented lengths.
#[no_mangle]
pub unsafe extern "C" fn awp3_seal(
    h: *mut Awp3Session,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
) -> isize {
    guard(|| {
        let s = handle(h)?;
        let State::Open(session) = &mut s.state else {
            return Err(Awp3Error::Handshake);
        };
        let pt = rslice(pt, pt_len)?;
        let frame = framing::frame(session, pt)?;
        wslice(out, frame.len())?.copy_from_slice(&frame);
        Ok(frame.len() as isize)
    })
}

/// Open one frame of `fr_len` bytes into the plaintext buffer `out`.
///
/// `out` must be at least `fr_len - awp3_frame_overhead()` bytes.  Returns the
/// plaintext length on success.
///
/// # Safety
/// Pointers must be valid for the documented lengths.
#[no_mangle]
pub unsafe extern "C" fn awp3_open(
    h: *mut Awp3Session,
    fr: *const u8,
    fr_len: usize,
    out: *mut u8,
) -> isize {
    guard(|| {
        if fr_len < FRAME_OVERHEAD {
            return Err(Awp3Error::Frame);
        }
        let s = handle(h)?;
        let State::Open(session) = &mut s.state else {
            return Err(Awp3Error::Handshake);
        };
        let fr = rslice(fr, fr_len)?;
        // A CLOSE frame carries no payload but still ends the session.
        if fr[1] == framing::KIND_CLOSE {
            framing::open_close(session, fr)?;
            return Ok(0);
        }
        let pt = framing::unframe(session, fr)?;
        wslice(out, pt.len())?.copy_from_slice(&pt);
        Ok(pt.len() as isize)
    })
}

/// Seal the CLOSE frame into `frame_out` (`awp3_frame_overhead()` bytes) and the
/// signed receipt into `receipt_out` (`awp3_receipt_len()` bytes).
///
/// # Safety
/// Pointers must be valid for the documented lengths.
#[no_mangle]
pub unsafe extern "C" fn awp3_close(
    h: *mut Awp3Session,
    frame_out: *mut u8,
    receipt_out: *mut u8,
) -> isize {
    guard(|| {
        let s = handle(h)?;
        let State::Open(session) = &mut s.state else {
            return Err(Awp3Error::Handshake);
        };
        let out = framing::close(session)?;
        wslice(frame_out, out.frame.len())?.copy_from_slice(&out.frame);
        wslice(receipt_out, out.receipt.len())?.copy_from_slice(&out.receipt);
        Ok(out.frame.len() as isize)
    })
}

/// Release a session handle.  Passing null is a no-op.
///
/// # Safety
/// `h` must be a handle from a `*_new` constructor and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn awp3_free(h: *mut Awp3Session) {
    if !h.is_null() {
        drop(Box::from_raw(h));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Drive two sessions through the raw C ABI exactly as the Perl bridge will.
    #[test]
    fn abi_handshake_frame_and_close_round_trip() {
        unsafe {
            let mut bundle = vec![0u8; awp3_bundle_len()];
            let responder = awp3_responder_new([0x11u8; 32].as_ptr(), bundle.as_mut_ptr());
            assert!(!responder.is_null());
            let client = awp3_client_new(bundle.as_ptr(), [0x22u8; 32].as_ptr());
            assert!(!client.is_null());

            let mut msg1 = vec![0u8; awp3_msg1_len()];
            assert_eq!(awp3_client_msg1(client, msg1.as_mut_ptr()), MSG1_LEN as isize);

            let mut msg2 = vec![0u8; awp3_msg2_len()];
            assert_eq!(
                awp3_responder_accept(responder, msg1.as_ptr(), msg2.as_mut_ptr()),
                MSG2_LEN as isize
            );
            assert_eq!(awp3_client_finish(client, msg2.as_ptr()), 0);

            // client → responder
            let payload = b"hello amin";
            let mut frame = vec![0u8; payload.len() + awp3_frame_overhead()];
            let n = awp3_seal(client, payload.as_ptr(), payload.len(), frame.as_mut_ptr());
            assert_eq!(n, frame.len() as isize);
            let mut pt = vec![0u8; payload.len()];
            assert_eq!(
                awp3_open(responder, frame.as_ptr(), frame.len(), pt.as_mut_ptr()),
                payload.len() as isize
            );
            assert_eq!(&pt, payload);

            // responder → client
            let reply = b"world";
            let mut frame2 = vec![0u8; reply.len() + awp3_frame_overhead()];
            let n2 = awp3_seal(responder, reply.as_ptr(), reply.len(), frame2.as_mut_ptr());
            assert_eq!(n2, frame2.len() as isize);
            let mut pt2 = vec![0u8; reply.len()];
            assert_eq!(
                awp3_open(client, frame2.as_ptr(), frame2.len(), pt2.as_mut_ptr()),
                reply.len() as isize
            );
            assert_eq!(&pt2, reply);

            // Close: the client seals a CLOSE frame + receipt; the responder
            // opens the CLOSE frame (empty payload, returns 0).
            let mut cf = vec![0u8; awp3_frame_overhead()];
            let mut receipt = vec![0u8; awp3_receipt_len()];
            assert_eq!(
                awp3_close(client, cf.as_mut_ptr(), receipt.as_mut_ptr()),
                awp3_frame_overhead() as isize
            );
            let mut sink = [0u8; 0];
            assert_eq!(
                awp3_open(responder, cf.as_ptr(), cf.len(), sink.as_mut_ptr()),
                0
            );

            // A closed session refuses further frames.
            let mut f3 = vec![0u8; 1 + awp3_frame_overhead()];
            assert_eq!(awp3_seal(client, b"x".as_ptr(), 1, f3.as_mut_ptr()), -7);

            awp3_free(client);
            awp3_free(responder);
        }
    }

    #[test]
    fn abi_rejects_bad_arguments() {
        unsafe {
            assert!(awp3_client_new(core::ptr::null(), [0u8; 32].as_ptr()).is_null());
            assert_eq!(awp3_client_msg1(core::ptr::null_mut(), core::ptr::null_mut()), -9);
            awp3_free(core::ptr::null_mut()); // no-op, must not crash
        }
    }
}

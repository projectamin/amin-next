//! The compiled-profile fingerprint: the canonical bytes of a [`Compiled`]
//! profile and their SHA3-256 — the `X-Amin-Profile-SHA3` response header the
//! front stamps on everything it serves (proxy-plan §P5).
//!
//! The header lets a response be traced to *exactly* the profile that produced
//! it, so the Perl and Rust fronts must agree on the value byte for byte
//! (proxy-plan §7).  That rules out hashing the raw document (whitespace and
//! attribute order would leak in) as much as it rules out any DOM-shaped form.
//! What is hashed instead is the **compiled** profile — the frozen matcher both
//! fronts build — under a purpose-built, injective encoding:
//!
//! * every field is written `name <byte-len> <value>\n`, which is unambiguous
//!   with no escaping (the length delimits the value even if it holds spaces or
//!   newlines);
//! * maps are written in a fixed order — backends sorted by id, routes in
//!   compiled (most-specific-first) order — so the digest never depends on
//!   hash-iteration order;
//! * the config's *source path* is deliberately excluded: the fingerprint is a
//!   property of the profile's content, not of where it was read from.
//!
//! [`Amin::Proxy::Config`]: the Perl peer computes the same bytes.

use std::fmt::Write as _;

use sha3::{Digest, Sha3_256};

use crate::Compiled;

/// The canonical byte serialisation of a compiled profile.
///
/// Byte-identical to the Perl `Amin::Proxy::Config::canonical` for the same
/// profile (proxy-plan §7).
#[must_use]
pub fn canonical(c: &Compiled) -> String {
    let mut s = String::new();
    s.push_str("amin-proxy-profile/1\n");
    field(&mut s, "listen", c.listen.as_deref().unwrap_or(""));
    field(&mut s, "tls", c.tls.as_deref().unwrap_or(""));
    field(&mut s, "cert", c.cert.as_deref().unwrap_or(""));
    field(&mut s, "key", c.key.as_deref().unwrap_or(""));
    field(&mut s, "max-conns", c.max_conns.as_deref().unwrap_or(""));
    field(&mut s, "read-timeout", c.read_timeout.as_deref().unwrap_or(""));
    field(&mut s, "rate-limit", c.rate_limit.as_ref().map_or("", |r| r.spec.as_str()));

    // BTreeMap iterates in id order, matching Perl's `sort keys`.
    let _ = writeln!(s, "backend-count {}", c.backends.len());
    for b in c.backends.values() {
        let (ep_key, ep_val) = b.endpoint();
        field(&mut s, "id", &b.id);
        field(&mut s, "transport", &b.transport);
        field(&mut s, "endpoint", ep_key);
        field(&mut s, "endpoint-value", ep_val);
        field(&mut s, "hc", b.hc.as_deref().unwrap_or(""));
    }

    let _ = writeln!(s, "route-count {}", c.routes.len());
    for r in &c.routes {
        field(&mut s, "route-host", &r.host);
        field(&mut s, "route-path", &r.path);
        field(&mut s, "route-to", &r.to.join(","));
        field(&mut s, "route-policy", &r.policy);
        field(&mut s, "route-strip-prefix", if r.strip_prefix { "1" } else { "0" });
        field(&mut s, "route-ws", if r.ws { "1" } else { "0" });
        field(&mut s, "route-spec", r.spec.as_deref().unwrap_or(""));
    }
    s
}

/// SHA3-256 of [`canonical`], lowercase hex.
#[must_use]
pub fn sha3_256(c: &Compiled) -> String {
    let digest = Sha3_256::digest(canonical(c).as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Append one `name <byte-len> <value>\n` field.
fn field(out: &mut String, name: &str, value: &str) {
    let _ = writeln!(out, "{name} {} {value}", value.len());
}

//! HPACK's static Huffman code (RFC 7541 §5.2, Appendix B).
//!
//! The code is a canonical prefix code over 257 symbols: bytes `0..=255` plus
//! the end-of-string symbol (256).  It is fixed by the spec, so the whole code
//! is one table here; there is nothing to negotiate and nothing to configure.
//!
//! Decoding is the half that matters for a gateway — a client may Huffman-encode
//! any header — so it is strict: a code word may never exceed the 30-bit EOS
//! prefix, and the trailing padding must be the EOS prefix and shorter than one
//! byte (§5.2).  A malformed field is a connection error, never a silent
//! pass-through.

/// `(bit-length, code)` for every symbol, in symbol order; index 256 is EOS.
const CODES: [(u8, u32); 257] = [
    (13, 0x1ff8),
    (23, 0x007f_ffd8),
    (28, 0x0fff_ffe2),
    (28, 0x0fff_ffe3),
    (28, 0x0fff_ffe4),
    (28, 0x0fff_ffe5),
    (28, 0x0fff_ffe6),
    (28, 0x0fff_ffe7),
    (28, 0x0fff_ffe8),
    (24, 0x00ff_ffea),
    (30, 0x3fff_fffc),
    (28, 0x0fff_ffe9),
    (28, 0x0fff_ffea),
    (30, 0x3fff_fffd),
    (28, 0x0fff_ffeb),
    (28, 0x0fff_ffec),
    (28, 0x0fff_ffed),
    (28, 0x0fff_ffee),
    (28, 0x0fff_ffef),
    (28, 0x0fff_fff0),
    (28, 0x0fff_fff1),
    (28, 0x0fff_fff2),
    (30, 0x3fff_fffe),
    (28, 0x0fff_fff3),
    (28, 0x0fff_fff4),
    (28, 0x0fff_fff5),
    (28, 0x0fff_fff6),
    (28, 0x0fff_fff7),
    (28, 0x0fff_fff8),
    (28, 0x0fff_fff9),
    (28, 0x0fff_fffa),
    (28, 0x0fff_fffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0x0fff_fffc),
    (20, 0xfffe6),
    (22, 0x003f_ffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x003f_ffd3),
    (22, 0x003f_ffd4),
    (22, 0x003f_ffd5),
    (23, 0x007f_ffd9),
    (22, 0x003f_ffd6),
    (23, 0x007f_ffda),
    (23, 0x007f_ffdb),
    (23, 0x007f_ffdc),
    (23, 0x007f_ffdd),
    (23, 0x007f_ffde),
    (24, 0x00ff_ffeb),
    (23, 0x007f_ffdf),
    (24, 0x00ff_ffec),
    (24, 0x00ff_ffed),
    (22, 0x003f_ffd7),
    (23, 0x007f_ffe0),
    (24, 0x00ff_ffee),
    (23, 0x007f_ffe1),
    (23, 0x007f_ffe2),
    (23, 0x007f_ffe3),
    (23, 0x007f_ffe4),
    (21, 0x001f_ffdc),
    (22, 0x003f_ffd8),
    (23, 0x007f_ffe5),
    (22, 0x003f_ffd9),
    (23, 0x007f_ffe6),
    (23, 0x007f_ffe7),
    (24, 0x00ff_ffef),
    (22, 0x003f_ffda),
    (21, 0x001f_ffdd),
    (20, 0xfffe9),
    (22, 0x003f_ffdb),
    (22, 0x003f_ffdc),
    (23, 0x007f_ffe8),
    (23, 0x007f_ffe9),
    (21, 0x001f_ffde),
    (23, 0x007f_ffea),
    (22, 0x003f_ffdd),
    (22, 0x003f_ffde),
    (24, 0x00ff_fff0),
    (21, 0x001f_ffdf),
    (22, 0x003f_ffdf),
    (23, 0x007f_ffeb),
    (23, 0x007f_ffec),
    (21, 0x001f_ffe0),
    (21, 0x001f_ffe1),
    (22, 0x003f_ffe0),
    (21, 0x001f_ffe2),
    (23, 0x007f_ffed),
    (22, 0x003f_ffe1),
    (23, 0x007f_ffee),
    (23, 0x007f_ffef),
    (20, 0xfffea),
    (22, 0x003f_ffe2),
    (22, 0x003f_ffe3),
    (22, 0x003f_ffe4),
    (23, 0x007f_fff0),
    (22, 0x003f_ffe5),
    (22, 0x003f_ffe6),
    (23, 0x007f_fff1),
    (26, 0x03ff_ffe0),
    (26, 0x03ff_ffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x003f_ffe7),
    (23, 0x007f_fff2),
    (22, 0x003f_ffe8),
    (25, 0x01ff_ffec),
    (26, 0x03ff_ffe2),
    (26, 0x03ff_ffe3),
    (26, 0x03ff_ffe4),
    (27, 0x07ff_ffde),
    (27, 0x07ff_ffdf),
    (26, 0x03ff_ffe5),
    (24, 0x00ff_fff1),
    (25, 0x01ff_ffed),
    (19, 0x7fff2),
    (21, 0x001f_ffe3),
    (26, 0x03ff_ffe6),
    (27, 0x07ff_ffe0),
    (27, 0x07ff_ffe1),
    (26, 0x03ff_ffe7),
    (27, 0x07ff_ffe2),
    (24, 0x00ff_fff2),
    (21, 0x001f_ffe4),
    (21, 0x001f_ffe5),
    (26, 0x03ff_ffe8),
    (26, 0x03ff_ffe9),
    (28, 0x0fff_fffd),
    (27, 0x07ff_ffe3),
    (27, 0x07ff_ffe4),
    (27, 0x07ff_ffe5),
    (20, 0xfffec),
    (24, 0x00ff_fff3),
    (20, 0xfffed),
    (21, 0x001f_ffe6),
    (22, 0x003f_ffe9),
    (21, 0x001f_ffe7),
    (21, 0x001f_ffe8),
    (23, 0x007f_fff3),
    (22, 0x003f_ffea),
    (22, 0x003f_ffeb),
    (25, 0x01ff_ffee),
    (25, 0x01ff_ffef),
    (24, 0x00ff_fff4),
    (24, 0x00ff_fff5),
    (26, 0x03ff_ffea),
    (23, 0x007f_fff4),
    (26, 0x03ff_ffeb),
    (27, 0x07ff_ffe6),
    (26, 0x03ff_ffec),
    (26, 0x03ff_ffed),
    (27, 0x07ff_ffe7),
    (27, 0x07ff_ffe8),
    (27, 0x07ff_ffe9),
    (27, 0x07ff_ffea),
    (27, 0x07ff_ffeb),
    (28, 0x0fff_fffe),
    (27, 0x07ff_ffec),
    (27, 0x07ff_ffed),
    (27, 0x07ff_ffee),
    (27, 0x07ff_ffef),
    (27, 0x07ff_fff0),
    (26, 0x03ff_ffee),
    (30, 0x3fff_ffff),
];

/// The end-of-string symbol, whose 30-bit prefix is the only legal padding.
const EOS: u32 = 0x3fff_ffff;

/// Huffman-encode `input`, returning the packed bytes (no length prefix).
///
/// The result is only emitted when it is strictly shorter than `input`;
/// otherwise the caller should send the literal (HPACK §5.2 lets a sender
/// choose, and a longer Huffman field is pure waste).
#[must_use]
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        let (len, code) = CODES[b as usize];
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 {
        // Pad the final byte with the most-significant bits of the EOS prefix.
        // EOS is a 30-bit code (30 ones), so its top `pad` bits are `pad` ones.
        let pad = 8 - bits;
        acc = (acc << pad) | (u64::from(EOS) >> (30 - pad));
        out.push(acc as u8);
    }
    out
}

/// The number of bytes [`encode`] would produce for `input`.
#[must_use]
#[cfg(test)]
pub fn encoded_len(input: &[u8]) -> usize {
    let bits: usize = input.iter().map(|&b| usize::from(CODES[b as usize].0)).sum();
    bits.div_ceil(8)
}

/// Decode a Huffman field.
///
/// # Errors
/// Returns the reason a field is not a valid Huffman string: a code word that
/// cannot begin with the bits seen, an embedded EOS, or padding that is not the
/// EOS prefix.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(input.len());
    let mut code: u32 = 0;
    let mut len: u32 = 0;
    for &byte in input {
        for i in (0..8).rev() {
            let bit = u32::from((byte >> i) & 1);
            code = (code << 1) | bit;
            len += 1;
            if len > 30 {
                // No code word is longer than 30 bits; anything past that can
                // only be a run of EOS bits, which is illegal mid-string.
                return Err("huffman: code word exceeds 30 bits");
            }
            if let Some(sym) = lookup(len, code) {
                if sym == 256 {
                    return Err("huffman: embedded EOS");
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            }
        }
    }
    // Leftover bits must be a prefix of EOS (all ones) and shorter than a byte.
    if len > 7 {
        return Err("huffman: padding longer than 7 bits");
    }
    if len > 0 && code != (EOS >> (30 - len)) {
        return Err("huffman: invalid padding");
    }
    Ok(out)
}

/// The symbol whose code is exactly `len` bits of `code`, if any.
///
/// The code is fixed, so the reverse map is built once and reused; it is keyed
/// by `(bit-length, code)` because no two symbols share both.
fn lookup(len: u32, code: u32) -> Option<u16> {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static TABLE: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
    let t = TABLE.get_or_init(|| {
        CODES
            .iter()
            .enumerate()
            .map(|(sym, &(l, c))| ((l, c), sym as u16))
            .collect()
    });
    t.get(&(len as u8, code)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7541 Appendix C.4.1: "www.example.com" -> f1e3 c2e5 f23a 6ba0 ab90 f4ff.
    const WWW: &[u8] = b"www.example.com";
    const WWW_HUFF: &[u8] = &[
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    ];

    // RFC 7541 Appendix C.4.2: "no-cache".
    const NOCACHE_HUFF: &[u8] = &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
    // RFC 7541 Appendix C.4.3: "custom-key" / "custom-value".
    const CK_HUFF: &[u8] = &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
    const CV_HUFF: &[u8] = &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];

    #[test]
    fn rfc_vectors_encode() {
        assert_eq!(encode(WWW), WWW_HUFF);
        assert_eq!(encode(b"no-cache"), NOCACHE_HUFF);
        assert_eq!(encode(b"custom-key"), CK_HUFF);
        assert_eq!(encode(b"custom-value"), CV_HUFF);
    }

    #[test]
    fn rfc_vectors_decode() {
        assert_eq!(decode(WWW_HUFF).unwrap(), WWW);
        assert_eq!(decode(NOCACHE_HUFF).unwrap(), b"no-cache");
        assert_eq!(decode(CK_HUFF).unwrap(), b"custom-key");
        assert_eq!(decode(CV_HUFF).unwrap(), b"custom-value");
    }

    #[test]
    fn round_trips_every_byte() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
        let empty: &[u8] = b"";
        assert_eq!(encode(empty), Vec::<u8>::new());
        assert_eq!(decode(&[]).unwrap(), empty);
    }

    #[test]
    fn length_matches_encode() {
        for s in [&b""[..], b"a", WWW, b"custom-value", b"Content-Length"] {
            assert_eq!(encoded_len(s), encode(s).len());
        }
    }

    #[test]
    fn rejects_bad_padding_and_eos() {
        // A byte of all ones is 8 EOS prefix bits: too long to be padding.
        assert!(decode(&[0xff]).is_err());
        // Pad with zeros, which is not the EOS prefix.
        assert!(decode(&[0x00]).is_err());
    }
}

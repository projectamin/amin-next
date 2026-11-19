//! HPACK — HTTP/2 header compression (RFC 7541).
//!
//! A gateway needs both directions: it **decodes** the request header block the
//! client compressed and **encodes** the response header block the backend's
//! response becomes.  Both share one vocabulary — the 61-entry static table, a
//! FIFO dynamic table sized in octets, the integer and string primitives, and
//! the Huffman code in [`super::huffman`].
//!
//! The decoder is the strict half: an out-of-range index, a truncated block, a
//! dynamic-table size above what we advertised, or a malformed string is a
//! connection error (§2.3), never a silently dropped header — a proxy that
//! drops a header is a proxy that changes the message.
//!
//! The encoder deliberately never indexes: it emits exact static matches and
//! otherwise literals without indexing.  An encoder is free not to use the
//! dynamic table (§2.1), and responses here are one-shot, so there is nothing
//! to amortise — the win would be a per-connection table whose correctness we
//! would then have to prove for no gain.

use super::huffman;

/// A decoded header block: `(name, value)` byte pairs, in wire order.
pub(crate) type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// The HPACK static table (RFC 7541 Appendix A).  Entry *n* has index *n*;
/// index 0 is unused and reserved.
pub(crate) const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Per-entry overhead on the dynamic table size (RFC 7541 §4.1).
const ENTRY_OVERHEAD: usize = 32;

/// A decoding or encoding failure. Every variant is a connection error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum HpackError {
    /// The block ended in the middle of a representation.
    #[error("hpack: truncated block")]
    Truncated,
    /// An integer's continuation bytes never terminated.
    #[error("hpack: integer out of range")]
    IntOverflow,
    /// An index referred to no static or dynamic entry.
    #[error("hpack: bad index {0}")]
    BadIndex(usize),
    /// A Huffman string was malformed.
    #[error("hpack: malformed huffman string")]
    Huffman,
    /// A dynamic-table size update exceeded the advertised maximum.
    #[error("hpack: dynamic table size update above limit")]
    SizeUpdate,
}

/// A FIFO of `(name, value)` pairs, newest first, sized in octets (RFC 7541 §4).
#[derive(Debug, Default)]
pub(crate) struct DynamicTable {
    entries: std::collections::VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max: usize,
}

impl DynamicTable {
    /// A table with the given maximum size in octets.
    fn new(max: usize) -> Self {
        Self { entries: std::collections::VecDeque::new(), size: 0, max }
    }

    /// Set the maximum size, evicting from the oldest end as needed.
    fn resize(&mut self, max: usize) {
        self.max = max;
        self.evict();
    }

    /// Insert `(name, value)` at the newest end.
    fn insert(&mut self, name: &[u8], value: &[u8]) {
        let entry = name.len() + value.len() + ENTRY_OVERHEAD;
        // An entry larger than the table empties it and is not stored (§4.4).
        if entry > self.max {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.size += entry;
        self.entries.push_front((name.to_vec(), value.to_vec()));
        self.evict();
    }

    /// Drop oldest entries until the table fits its maximum.
    fn evict(&mut self) {
        while self.size > self.max {
            if let Some((n, v)) = self.entries.pop_back() {
                self.size -= n.len() + v.len() + ENTRY_OVERHEAD;
            } else {
                self.size = 0;
                break;
            }
        }
    }

    /// The entry at absolute index `i` (62-based, newest first).
    fn get(&self, i: usize) -> Option<&(Vec<u8>, Vec<u8>)> {
        self.entries.get(i - STATIC_TABLE.len() - 1)
    }

    /// The number of dynamic entries (so index bounds can be checked).
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Decode one integer with an `prefix`-bit prefix, starting at `pos`.
///
/// Returns the value and the position just past the last continuation byte.
fn decode_int(buf: &[u8], pos: usize, prefix: u32) -> Result<(u64, usize), HpackError> {
    let first = *buf.get(pos).ok_or(HpackError::Truncated)?;
    let mask = if prefix >= 8 { 0xff } else { (1u16 << prefix) - 1 };
    let mut value = u64::from(first) & u64::from(mask as u8);
    let mut i = pos + 1;
    if value < u64::from(mask as u8) {
        return Ok((value, i));
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(i).ok_or(HpackError::Truncated)?;
        i += 1;
        if shift > 56 {
            return Err(HpackError::IntOverflow);
        }
        value = value
            .checked_add(u64::from(b & 0x7f) << shift)
            .ok_or(HpackError::IntOverflow)?;
        if b & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
    }
}

/// Encode `value` with an `prefix`-bit prefix; `carry` supplies the bits above
/// the prefix (the representation's type discriminator).
fn encode_int(out: &mut Vec<u8>, value: u64, prefix: u32, carry: u8) {
    let mask = if prefix >= 8 { 0xff } else { (1u8 << prefix) - 1 };
    if value < u64::from(mask) {
        out.push(carry | value as u8);
        return;
    }
    out.push(carry | mask);
    let mut v = value - u64::from(mask);
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decode a length-prefixed string (Huffman if the high bit is set).
fn decode_str(buf: &[u8], pos: usize) -> Result<(Vec<u8>, usize), HpackError> {
    let huff = buf.get(pos).ok_or(HpackError::Truncated)? & 0x80 != 0;
    let (len, i) = decode_int(buf, pos, 7)?;
    let len = usize::try_from(len).map_err(|_| HpackError::IntOverflow)?;
    let end = i.checked_add(len).ok_or(HpackError::Truncated)?;
    let raw = buf.get(i..end).ok_or(HpackError::Truncated)?;
    let bytes = if huff {
        huffman::decode(raw).map_err(|_| HpackError::Huffman)?
    } else {
        raw.to_vec()
    };
    Ok((bytes, end))
}

/// Append a length-prefixed string, Huffman-coded only when that is shorter.
fn encode_str(out: &mut Vec<u8>, s: &[u8]) {
    let h = huffman::encode(s);
    if h.len() < s.len() {
        encode_int(out, h.len() as u64, 7, 0x80);
        out.extend_from_slice(&h);
    } else {
        encode_int(out, s.len() as u64, 7, 0x00);
        out.extend_from_slice(s);
    }
}

/// A stateful HPACK decoder: it owns the dynamic table shared across the
/// header blocks of one connection.
#[derive(Debug)]
pub(crate) struct Decoder {
    table: DynamicTable,
    limit: usize,
}

impl Decoder {
    /// A decoder whose dynamic table starts at `max` octets and may never
    /// exceed it (the `SETTINGS_HEADER_TABLE_SIZE` we advertised).
    pub(crate) fn new(max: usize) -> Self {
        Self { table: DynamicTable::new(max), limit: max }
    }

    /// Decode a complete header block into `(name, value)` byte pairs, in order.
    ///
    /// # Errors
    /// Any malformed representation, as [`HpackError`].
    pub(crate) fn decode(&mut self, block: &[u8]) -> Result<Fields, HpackError> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                // 6.1 Indexed Header Field.
                let (idx, next) = decode_int(block, pos, 7)?;
                pos = next;
                out.push(self.at(idx as usize)?);
            } else if b & 0xc0 == 0x40 {
                // 6.2.1 Literal with Incremental Indexing.
                let (name, value, next) = self.literal(block, pos, 6)?;
                self.table.insert(&name, &value);
                pos = next;
                out.push((name, value));
            } else if b & 0xe0 == 0x20 {
                // 6.3 Dynamic Table Size Update.
                let (size, next) = decode_int(block, pos, 5)?;
                pos = next;
                let size = usize::try_from(size).map_err(|_| HpackError::SizeUpdate)?;
                if size > self.limit {
                    return Err(HpackError::SizeUpdate);
                }
                self.table.resize(size);
            } else {
                // 6.2.2 Literal without Indexing / 6.2.3 Never Indexed.
                let (name, value, next) = self.literal(block, pos, 4)?;
                pos = next;
                out.push((name, value));
            }
        }
        Ok(out)
    }

    /// Decode a literal representation whose name may be indexed, returning the
    /// pair and the next position.
    fn literal(
        &self,
        block: &[u8],
        pos: usize,
        prefix: u32,
    ) -> Result<(Vec<u8>, Vec<u8>, usize), HpackError> {
        let (idx, mut i) = decode_int(block, pos, prefix)?;
        let name = if idx == 0 {
            let (n, next) = decode_str(block, i)?;
            i = next;
            n
        } else {
            self.at(idx as usize)?.0
        };
        let (value, next) = decode_str(block, i)?;
        Ok((name, value, next))
    }

    /// Resolve an absolute index to a `(name, value)` pair.
    fn at(&self, idx: usize) -> Result<(Vec<u8>, Vec<u8>), HpackError> {
        if idx == 0 {
            return Err(HpackError::BadIndex(0));
        }
        if idx <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[idx - 1];
            return Ok((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
        if idx <= STATIC_TABLE.len() + self.table.len() {
            return Ok(self.table.get(idx).cloned().unwrap_or_default());
        }
        Err(HpackError::BadIndex(idx))
    }
}

/// A stateless HPACK encoder for response header blocks.  It uses only the
/// static table and literals, so it can be reused across responses with no
/// shared state to keep in step — and it only ever emits final response heads.
#[derive(Debug, Default)]
pub(crate) struct Encoder;

impl Encoder {
    /// Encode `headers` (name, value) into a header block fragment.
    #[must_use]
    pub(crate) fn encode(&self, headers: &[(String, String)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(headers.len() * 16);
        for (name, value) in headers {
            // An exact static match is a single indexed byte.
            if let Some(i) = exact_static(name, value) {
                encode_int(&mut out, i as u64, 7, 0x80);
                continue;
            }
            // Otherwise a literal without indexing: an indexed name when the
            // static table has one, else a literal name; always a literal value.
            match static_name(name) {
                Some(i) => encode_int(&mut out, i as u64, 4, 0x00),
                None => {
                    encode_int(&mut out, 0, 4, 0x00);
                    encode_str(&mut out, name.as_bytes());
                }
            }
            encode_str(&mut out, value.as_bytes());
        }
        out
    }
}

/// The static index of an exact `(name, value)` match.
fn exact_static(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(n, v)| n == name && v == value)
        .map(|i| i + 1)
}

/// The first static index whose name matches (any value).
fn static_name(name: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(n, _)| n == name)
        .map(|i| i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn pairs(hs: &[(Vec<u8>, Vec<u8>)]) -> Vec<(String, String)> {
        hs.iter()
            .map(|(n, v)| {
                (
                    String::from_utf8(n.clone()).unwrap(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect()
    }

    // RFC 7541 Appendix C.3: three requests, no Huffman, dynamic table grows.
    #[test]
    fn rfc_c3_request_sequence() {
        let mut d = Decoder::new(4096);
        let first = d
            .decode(&hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"))
            .unwrap();
        assert_eq!(
            pairs(&first),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );

        let second = d
            .decode(&hex("8286 84be 5808 6e6f 2d63 6163 6865"))
            .unwrap();
        assert_eq!(
            pairs(&second),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
                ("cache-control".into(), "no-cache".into()),
            ]
        );

        let third = d
            .decode(&hex(
                "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
            ))
            .unwrap();
        assert_eq!(
            pairs(&third),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/index.html".into()),
                (":authority".into(), "www.example.com".into()),
                ("custom-key".into(), "custom-value".into()),
            ]
        );
    }

    // RFC 7541 Appendix C.4: the same requests with Huffman-coded values.
    #[test]
    fn rfc_c4_huffman_request_sequence() {
        let mut d = Decoder::new(4096);
        let first = d
            .decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"))
            .unwrap();
        assert_eq!(pairs(&first)[3], (":authority".into(), "www.example.com".into()));
        let second = d.decode(&hex("8286 84be 5886 a8eb 1064 9cbf")).unwrap();
        assert_eq!(pairs(&second)[4], ("cache-control".into(), "no-cache".into()));
        let third = d
            .decode(&hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"))
            .unwrap();
        assert_eq!(pairs(&third)[4], ("custom-key".into(), "custom-value".into()));
    }

    #[test]
    fn static_table_is_61_entries() {
        assert_eq!(STATIC_TABLE.len(), 61);
        assert_eq!(STATIC_TABLE[0], (":authority", ""));
        assert_eq!(STATIC_TABLE[60], ("www-authenticate", ""));
    }

    #[test]
    fn encoder_round_trips_through_decoder() {
        let headers = vec![
            (":status".to_string(), "200".to_string()),
            ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
            ("content-length".to_string(), "42".to_string()),
            ("date".to_string(), "Mon, 21 Oct 2013 20:13:21 GMT".to_string()),
            ("x-custom".to_string(), "some-value".to_string()),
        ];
        let block = Encoder.encode(&headers);
        // 200 is an exact static hit, so the first byte is the indexed form.
        assert_eq!(block[0], 0x88);
        let mut d = Decoder::new(4096);
        assert_eq!(pairs(&d.decode(&block).unwrap()), headers);
    }

    #[test]
    fn dynamic_table_evicts_oldest() {
        // Two 54-octet entries in a 100-octet table: the second evicts the first.
        let block = hex("400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65");
        let mut d = Decoder::new(100);
        d.decode(&block).unwrap();
        assert_eq!(d.table.len(), 1);
        d.decode(&block).unwrap();
        assert_eq!(d.table.len(), 1);
    }

    #[test]
    fn rejects_bad_index_and_size_update() {
        let mut d = Decoder::new(4096);
        assert_eq!(d.decode(&hex("80")), Err(HpackError::BadIndex(0)));
        assert_eq!(d.decode(&hex("ff00")), Err(HpackError::BadIndex(127)));
        // A size update above the advertised limit (0x3f + continuation).
        let mut d = Decoder::new(4096);
        assert!(matches!(d.decode(&hex("3f e2 1f")), Err(HpackError::SizeUpdate)));
    }

    #[test]
    fn int_round_trips_at_prefix_boundaries() {
        for (value, prefix) in [(0u64, 5u32), (30, 5), (31, 5), (1337, 7), (4096, 5)] {
            let mut out = Vec::new();
            encode_int(&mut out, value, prefix, 0);
            let (got, next) = decode_int(&out, 0, prefix).unwrap();
            assert_eq!(got, value);
            assert_eq!(next, out.len());
        }
    }
}

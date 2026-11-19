//! The form codec — the Rust form of `Amin::AXA::FormCodec`.
//!
//! The bundle declares the fragment; the codec only substitutes values
//! (`{placeholder}` → value). No policy, no domain knowledge: every byte
//! outside a substituted value comes from the fragment the bundle declared.
//! Encodings are not dialects (§4.2).
//!
//! Substituted values are XML-escaped on the way in, so
//! [`HtmlSerializer`](crate::serializer::HtmlSerializer) stays the single point
//! of *output* escaping while request data is inert.

use std::collections::HashMap;

/// The values a fragment's placeholders resolve against (request parameters
/// plus the reserved `sid`/`csrf`).
#[derive(Debug, Clone, Default)]
pub struct Values {
    map: HashMap<String, String>,
}

impl Values {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `key` to `value` (last write wins, like a flattened parameter list).
    pub fn set(&mut self, key: &str, value: &str) -> &mut Self {
        self.map.insert(key.to_string(), value.to_string());
        self
    }

    /// The value for `key`, or `""` when absent.
    #[must_use]
    pub fn get(&self, key: &str) -> &str {
        self.map.get(key).map_or("", String::as_str)
    }

    /// Whether `key` is present.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// Remove `key`, returning its value.
    pub fn take(&mut self, key: &str) -> Option<String> {
        self.map.remove(key)
    }

    /// Iterate keys.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(String::as_str)
    }
}

/// Substitute `{placeholder}` runs in `fragment` with escaped values.
///
/// A placeholder is `{key}` with `key` matching `[A-Za-z0-9_.\-]+`; a missing
/// key substitutes the empty string. Anything that is not a well-formed
/// placeholder is left byte-for-byte.
#[must_use]
pub fn inflate(fragment: &str, values: &Values) -> String {
    let bytes = fragment.as_bytes();
    let mut out = String::with_capacity(fragment.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let mut j = i + 1;
            while j < bytes.len() && is_key_byte(bytes[j]) {
                j += 1;
            }
            if j > i + 1 && j < bytes.len() && bytes[j] == b'}' {
                out.push_str(&escape_value(values.get(&fragment[i + 1..j])));
                i = j + 1;
                continue;
            }
        }
        // Copy one whole UTF-8 scalar (fragment bytes are valid UTF-8).
        let ch = fragment[i..].chars().next().expect("valid utf-8");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// `[A-Za-z0-9_.\-]` — the placeholder key alphabet.
fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-'
}

/// Escape the five XML specials for a fragment value (`< > & " '`).
///
/// Note this is the *five*-character form: the serializer escapes four, and
/// `'` is escaped only here, where the value becomes attribute content of the
/// app's own dialect.
#[must_use]
pub fn escape_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

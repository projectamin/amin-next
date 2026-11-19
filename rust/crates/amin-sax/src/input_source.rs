//! The parse source — the Rust form of `org.xml.sax.InputSource`.
//!
//! Java's `InputSource` can carry a byte stream, a character stream and an
//! encoding alongside the identifiers. This reader works on an in-memory
//! `&str`; a byte- or reader-backed source can be turned into one by the
//! caller (which owns its own decoder), so [`InputSource`] carries the two
//! identifiers plus the text.

/// A document source: optional public/system identifiers and the text to
/// parse (≈ `org.xml.sax.InputSource`).
///
/// ```
/// use amin_sax::InputSource;
/// let mut src = InputSource::with_text("<a/>");
/// src.set_system_id("file:///etc/amin/profile.xml");
/// assert_eq!(src.system_id(), Some("file:///etc/amin/profile.xml"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputSource {
    public_id: Option<String>,
    system_id: Option<String>,
    text: Option<String>,
}

impl InputSource {
    /// An empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A source holding `text`.
    #[must_use]
    pub fn with_text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            ..Self::default()
        }
    }

    /// Set the public identifier.
    pub fn set_public_id(&mut self, public_id: impl Into<String>) {
        self.public_id = Some(public_id.into());
    }

    /// Set the system identifier (a URI).
    pub fn set_system_id(&mut self, system_id: impl Into<String>) {
        self.system_id = Some(system_id.into());
    }

    /// Set the text to parse.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = Some(text.into());
    }

    /// The public identifier, if one was set.
    #[must_use]
    pub fn public_id(&self) -> Option<&str> {
        self.public_id.as_deref()
    }

    /// The system identifier, if one was set.
    #[must_use]
    pub fn system_id(&self) -> Option<&str> {
        self.system_id.as_deref()
    }

    /// The text to parse, if one was set.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }
}

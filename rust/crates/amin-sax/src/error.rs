//! SAX errors — the Rust form of `org.xml.sax.SAXException` and
//! `org.xml.sax.SAXParseException`.
//!
//! Java distinguishes a plain `SAXException` (any SAX failure, no position)
//! from a `SAXParseException` (a well-formedness error carrying a `Locator`).
//! [`SaxError`] keeps that split: [`SaxError::Parse`] carries a
//! [`ParseError`] kind plus the line/column, and the other variants are the
//! positionless cases.

/// A well-formedness violation the reader detected, without its position.
///
/// Position is attached by [`SaxError::Parse`]; keeping the kind separate
/// means a filter can match on *what* went wrong without matching the offset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Input ended in the middle of a construct.
    #[error("unexpected end of input in {0}")]
    UnexpectedEof(&'static str),
    /// Structurally invalid markup.
    #[error("malformed markup")]
    Malformed,
    /// A prefix was used without a matching `xmlns` declaration in scope.
    #[error("unbound namespace prefix '{0}'")]
    UnboundPrefix(String),
    /// An end tag did not match the currently open element.
    #[error("mismatched end tag: expected </{expected}>, found </{found}>")]
    MismatchedEnd {
        /// The open element's qualified name.
        expected: String,
        /// The name in the offending end tag.
        found: String,
    },
    /// A `&name;` reference that is not one of the predefined entities.
    #[error("unknown entity '&{0};'")]
    UnknownEntity(String),
    /// A `&#…;` reference whose body is not a valid code point.
    #[error("invalid numeric character reference '&#{0};'")]
    BadCharRef(String),
    /// The document ended with elements still open.
    #[error("unclosed element <{0}> at end of input")]
    UnclosedElement(String),
}

/// A fatal SAX failure (≈ `org.xml.sax.SAXException`).
///
/// The reader stops at the first error rather than attempting recovery.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SaxError {
    /// A positioned well-formedness error (≈ `SAXParseException`).
    #[error("{kind} at line {line}, column {column}")]
    Parse {
        /// What went wrong.
        kind: ParseError,
        /// 1-based line of the offending byte.
        line: usize,
        /// 1-based column (in characters) of the offending byte.
        column: usize,
    },
    /// A feature or property the reader does not recognise.
    #[error("feature or property '{0}' is not recognised")]
    NotRecognized(String),
    /// The source could not be read as text.
    #[error("cannot read source: {0}")]
    Io(String),
}

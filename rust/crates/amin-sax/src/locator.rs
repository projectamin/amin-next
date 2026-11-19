//! Document-position tracking — the Rust form of `org.xml.sax.Locator`.
//!
//! In Java the parser hands the application a single mutable `Locator` at the
//! start of the parse and updates it as it reads, so `locator.getLineNumber()`
//! always reflects *where the parser is now*. That is a live, shared handle,
//! which Rust models with `Rc` + interior mutability: the line and column are
//! [`Cell`]s so the reader can advance them through the shared handle while a
//! handler holds it.
//!
//! Parsing is single-threaded, so `Rc` (not `Arc`) is the right sharing
//! primitive; a `ContentHandler` that keeps the locator gets a live view, and
//! one that ignores it pays only a clone of the handle.

use std::cell::Cell;
use std::rc::Rc;

/// The parser's current position in the document (≈ `org.xml.sax.Locator`).
///
/// Created by the reader, handed to the handler through
/// [`ContentHandler::set_document_locator`](crate::ContentHandler::set_document_locator),
/// and updated in place as the reader advances.
#[derive(Debug, Default)]
pub struct Locator {
    public_id: String,
    system_id: String,
    line: Cell<usize>,
    column: Cell<usize>,
}

impl Locator {
    /// A locator for `system_id`, positioned at line 1, column 1.
    #[must_use]
    pub fn new(system_id: impl Into<String>) -> Self {
        Self {
            public_id: String::new(),
            system_id: system_id.into(),
            line: Cell::new(1),
            column: Cell::new(1),
        }
    }

    /// The public identifier of the entity, or `""` when there is none.
    #[must_use]
    pub fn public_id(&self) -> &str {
        &self.public_id
    }

    /// The system identifier (URI) of the entity, or `""` when there is none.
    #[must_use]
    pub fn system_id(&self) -> &str {
        &self.system_id
    }

    /// The 1-based line number of the current position.
    #[must_use]
    pub fn line(&self) -> usize {
        self.line.get()
    }

    /// The 1-based column (in characters) of the current position.
    #[must_use]
    pub fn column(&self) -> usize {
        self.column.get()
    }

    /// Set the public identifier. Call before the locator is shared.
    pub fn set_public_id(&mut self, id: impl Into<String>) {
        self.public_id = id.into();
    }

    /// Advance the shared position. Called by the reader only.
    pub(crate) fn set_position(&self, line: usize, column: usize) {
        self.line.set(line);
        self.column.set(column);
    }
}

/// A fresh shared locator for `system_id`.
pub(crate) fn shared(system_id: &str) -> Rc<Locator> {
    Rc::new(Locator::new(system_id))
}

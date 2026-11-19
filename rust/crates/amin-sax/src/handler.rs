//! The handler interfaces — the Rust form of `org.xml.sax.ContentHandler`,
//! `org.xml.sax.ErrorHandler` and `org.xml.sax.EntityResolver`.
//!
//! Only [`ContentHandler::start_element`] and [`ContentHandler::end_element`]
//! are required; every other event defaults to a no-op, so a filter implements
//! exactly the events it cares about — the same shape as `XML::SAX::Base` in
//! Perl and `org.xml.sax.helpers.DefaultHandler` in Java.

use std::rc::Rc;

use crate::attributes::Attributes;
use crate::error::SaxError;
use crate::locator::Locator;
use crate::InputSource;

/// The core event interface a filter implements and the reader drives
/// (≈ `org.xml.sax.ContentHandler`).
///
/// Event order for one element `E` with namespace declarations `D`:
///
/// ```text
/// set_document_locator           (once, before start_document)
/// start_document
/// [for each d in D] start_prefix_mapping(d)
/// start_element(E)
///   ... characters / processing_instruction / child elements ...
/// end_element(E)
/// [for each d in D, reversed] end_prefix_mapping(d)
/// end_document                   (once, after the root closes)
/// ```
pub trait ContentHandler {
    /// Receive the live document locator. SAX guarantees this is called at
    /// most once, before [`ContentHandler::start_document`]. The default
    /// ignores it.
    fn set_document_locator(&mut self, _locator: Rc<Locator>) {}

    /// Fired once before any element.
    fn start_document(&mut self) -> Result<(), SaxError> {
        Ok(())
    }

    /// Fired once after the root element closes.
    fn end_document(&mut self) -> Result<(), SaxError> {
        Ok(())
    }

    /// Fired before the element that declares `prefix` (`""` for the default
    /// namespace). Reported instead of an `xmlns` attribute.
    fn start_prefix_mapping(&mut self, _prefix: &str, _uri: &str) -> Result<(), SaxError> {
        Ok(())
    }

    /// Fired after the element that declared `prefix` closes.
    fn end_prefix_mapping(&mut self, _prefix: &str) -> Result<(), SaxError> {
        Ok(())
    }

    /// Fired for every element start (`uri`, `local_name`, `q_name`,
    /// attributes). For a self-closing `<e/>`, [`ContentHandler::end_element`]
    /// follows immediately.
    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError>;

    /// Fired for every element close.
    fn end_element(&mut self, uri: &str, local_name: &str, q_name: &str)
        -> Result<(), SaxError>;

    /// Fired for non-empty character data (entity-decoded). May be called
    /// more than once for one logical text run.
    fn characters(&mut self, _ch: &str) -> Result<(), SaxError> {
        Ok(())
    }

    /// Fired for whitespace known to be ignorable. This reader processes no
    /// DTD, so it never emits this event — whitespace is reported through
    /// [`ContentHandler::characters`], as a non-validating parser must.
    fn ignorable_whitespace(&mut self, _ch: &str) -> Result<(), SaxError> {
        Ok(())
    }

    /// Fired for `<?target data?>`.
    fn processing_instruction(&mut self, _target: &str, _data: &str) -> Result<(), SaxError> {
        Ok(())
    }

    /// Fired for an entity that was not expanded. This reader is
    /// closed-world: an unrecognised entity reference is a fatal
    /// [`SaxError`], so it never emits this event.
    fn skipped_entity(&mut self, _name: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

/// Receive warning, recoverable-error and fatal-error notifications
/// (≈ `org.xml.sax.ErrorHandler`).
///
/// The reader is fatal on the first well-formedness error: it calls
/// [`ErrorHandler::fatal_error`] and then stops. `warning` and `error` exist
/// for a filter that wraps the reader and reports them from the event stream.
pub trait ErrorHandler {
    /// A warning. Default: ignore.
    fn warning(&mut self, _e: &SaxError) -> Result<(), SaxError> {
        Ok(())
    }

    /// A recoverable error. Default: stop.
    fn error(&mut self, e: &SaxError) -> Result<(), SaxError> {
        Err(e.clone())
    }

    /// A fatal error. Default: stop.
    fn fatal_error(&mut self, e: &SaxError) -> Result<(), SaxError> {
        Err(e.clone())
    }
}

/// Resolve an external entity before the reader reads it
/// (≈ `org.xml.sax.EntityResolver`).
///
/// This reader does not resolve external entities (a DOCTYPE is skipped, not
/// processed), so it never calls this; the trait is present so a wrapper can
/// hold the same resolver contract as any other SAX reader.
pub trait EntityResolver {
    /// Return a replacement [`InputSource`] for (`public_id`, `system_id`), or
    /// `None` to let the reader use its own resolution.
    fn resolve_entity(&mut self, public_id: &str, system_id: &str) -> Option<InputSource>;
}

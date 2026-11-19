//! The reader and filter interfaces — the Rust form of
//! `org.xml.sax.XMLReader`, `org.xml.sax.XMLFilter` and
//! `org.xml.sax.helpers.XMLFilterImpl`.
//!
//! [`XMLReader`] is the driver interface: it owns the handler slots and
//! parses on demand. [`XMLFilter`] is a reader that sits in front of another
//! reader, forwarding (and optionally transforming) its event stream.
//! [`XMLFilterImpl`] is the no-op base filter a chain is built from.

use std::rc::Rc;

use crate::attributes::Attributes;
use crate::error::SaxError;
use crate::handler::{ContentHandler, EntityResolver, ErrorHandler};
use crate::input_source::InputSource;
use crate::locator::Locator;

/// The driver interface (≈ `org.xml.sax.XMLReader`).
///
/// A reader holds a content handler, an error handler and an entity resolver,
/// and parses a source on demand through [`XMLReader::parse`].
pub trait XMLReader {
    /// Install the handler that receives content events.
    fn set_content_handler(&mut self, handler: Box<dyn ContentHandler>);

    /// Install the handler that receives error notifications.
    fn set_error_handler(&mut self, handler: Box<dyn ErrorHandler>);

    /// Install the external-entity resolver.
    fn set_entity_resolver(&mut self, resolver: Box<dyn EntityResolver>);

    /// Parse `source`, driving the installed handlers.
    fn parse(&mut self, source: &InputSource) -> Result<(), SaxError>;
}

/// A reader that forwards another reader's events, optionally transforming
/// them (≈ `org.xml.sax.XMLFilter`).
///
/// A filter is itself an [`XMLReader`]; a chain is `parent → filter → app`.
pub trait XMLFilter: XMLReader {
    /// Install the parent reader whose events this filter forwards.
    fn set_parent(&mut self, parent: Box<dyn XMLReader>);

    /// The parent reader, if one is installed.
    fn get_parent(&self) -> Option<&dyn XMLReader>;
}

/// A pass-through filter base (≈ `org.xml.sax.helpers.XMLFilterImpl`).
///
/// Every [`ContentHandler`] event is forwarded unchanged to the installed
/// downstream handler; [`XMLReader::parse`] delegates to the installed
/// parent. Override any method in a wrapper to transform the stream.
#[derive(Default)]
pub struct XMLFilterImpl {
    content: Option<Box<dyn ContentHandler>>,
    error: Option<Box<dyn ErrorHandler>>,
    resolver: Option<Box<dyn EntityResolver>>,
    parent: Option<Box<dyn XMLReader>>,
}

impl XMLFilterImpl {
    /// A filter with no handlers and no parent.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The downstream content handler, for a subclass to drive directly.
    #[must_use]
    pub fn content_handler_mut(&mut self) -> Option<&mut (dyn ContentHandler + 'static)> {
        self.content.as_deref_mut()
    }
}

impl XMLReader for XMLFilterImpl {
    fn set_content_handler(&mut self, handler: Box<dyn ContentHandler>) {
        self.content = Some(handler);
    }

    fn set_error_handler(&mut self, handler: Box<dyn ErrorHandler>) {
        self.error = Some(handler);
    }

    fn set_entity_resolver(&mut self, resolver: Box<dyn EntityResolver>) {
        self.resolver = Some(resolver);
    }

    fn parse(&mut self, source: &InputSource) -> Result<(), SaxError> {
        match self.parent.as_mut() {
            Some(parent) => parent.parse(source),
            None => Err(SaxError::NotRecognized(
                "XMLFilterImpl has no parent reader".to_string(),
            )),
        }
    }
}

impl XMLFilter for XMLFilterImpl {
    fn set_parent(&mut self, parent: Box<dyn XMLReader>) {
        self.parent = Some(parent);
    }

    fn get_parent(&self) -> Option<&dyn XMLReader> {
        self.parent.as_deref()
    }
}

/// Forward a content event to the downstream handler, or do nothing when none
/// is installed.
fn forward(
    content: Option<&mut Box<dyn ContentHandler>>,
    f: impl FnOnce(&mut dyn ContentHandler) -> Result<(), SaxError>,
) -> Result<(), SaxError> {
    match content {
        Some(h) => f(h.as_mut()),
        None => Ok(()),
    }
}

impl ContentHandler for XMLFilterImpl {
    fn set_document_locator(&mut self, locator: Rc<Locator>) {
        if let Some(h) = self.content.as_mut() {
            h.set_document_locator(locator);
        }
    }

    fn start_document(&mut self) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| h.start_document())
    }

    fn end_document(&mut self) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| h.end_document())
    }

    fn start_prefix_mapping(&mut self, prefix: &str, uri: &str) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| h.start_prefix_mapping(prefix, uri))
    }

    fn end_prefix_mapping(&mut self, prefix: &str) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| h.end_prefix_mapping(prefix))
    }

    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| {
            h.start_element(uri, local_name, q_name, atts)
        })
    }

    fn end_element(&mut self, uri: &str, local_name: &str, q_name: &str) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| {
            h.end_element(uri, local_name, q_name)
        })
    }

    fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| h.characters(ch))
    }

    fn ignorable_whitespace(&mut self, ch: &str) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| h.ignorable_whitespace(ch))
    }

    fn processing_instruction(&mut self, target: &str, data: &str) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| {
            h.processing_instruction(target, data)
        })
    }

    fn skipped_entity(&mut self, name: &str) -> Result<(), SaxError> {
        forward(self.content.as_mut(), |h| h.skipped_entity(name))
    }
}

impl ErrorHandler for XMLFilterImpl {
    fn warning(&mut self, e: &SaxError) -> Result<(), SaxError> {
        match self.error.as_mut() {
            Some(h) => h.warning(e),
            None => Ok(()),
        }
    }

    fn error(&mut self, e: &SaxError) -> Result<(), SaxError> {
        match self.error.as_mut() {
            Some(h) => h.error(e),
            None => Err(e.clone()),
        }
    }

    fn fatal_error(&mut self, e: &SaxError) -> Result<(), SaxError> {
        match self.error.as_mut() {
            Some(h) => h.fatal_error(e),
            None => Err(e.clone()),
        }
    }
}

impl EntityResolver for XMLFilterImpl {
    fn resolve_entity(&mut self, public_id: &str, system_id: &str) -> Option<InputSource> {
        self.resolver
            .as_mut()
            .and_then(|r| r.resolve_entity(public_id, system_id))
    }
}

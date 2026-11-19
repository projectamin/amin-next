//! # amin-sax — a push-based (SAX) XML reader
//!
//! Amin's event pipeline is SAX: a parser drives a handler with
//! `start_document` / `start_element` / `characters` / `end_element` /
//! `end_document`, and filters mutate that event stream in flight. Perl gets
//! this from `XML::LibXML::SAX`. The Rust side has `bsax` for the *binary*
//! event wire, and needs a text-XML front end that produces the SAME event
//! shape so both languages drive one chain. This crate is that front end.
//!
//! There is no formal SAX specification; the canonical reference is Java's
//! [`org.xml.sax`][ref] package, and this crate is conformant with its event
//! and interface model:
//!
//! | `org.xml.sax`            | here                                    |
//! |--------------------------|-----------------------------------------|
//! | `ContentHandler`         | [`ContentHandler`]                      |
//! | `Attributes`/`AttributesImpl` | [`Attributes`] / [`AttributeList`] |
//! | `Locator`                | [`Locator`]                             |
//! | `ErrorHandler`           | [`ErrorHandler`]                        |
//! | `EntityResolver`         | [`EntityResolver`]                      |
//! | `InputSource`            | [`InputSource`]                         |
//! | `XMLReader`              | [`XMLReader`] / [`Reader`]              |
//! | `XMLFilter`/`XMLFilterImpl` | [`XMLFilter`] / [`XMLFilterImpl`]    |
//! | `SAXException`/`SAXParseException` | [`SaxError`] / [`ParseError`] |
//!
//! It is deliberately **not** a DOM builder: it never retains a tree, it calls
//! the handler as it scans, and it can therefore parse documents larger than
//! memory — the same property the Perl path relies on.
//!
//! Scope: well-formed, namespace-aware XML sufficient for Amin documents and
//! machine/proxy profiles — elements, attributes, `xmlns` / `xmlns:p`
//! declarations, comments, processing instructions, CDATA, the five predefined
//! entities and numeric character references. It does not implement DTD
//! validation, external entities, or mixed-content whitespace normalisation;
//! a DOCTYPE is skipped, not processed. Namespace declarations are delivered
//! as prefix-mapping events, not attributes (the SAX2 namespace model).
//!
//! ```
//! use amin_sax::{parse, Attributes, ContentHandler, SaxError};
//!
//! #[derive(Default)]
//! struct Names(Vec<String>);
//!
//! impl ContentHandler for Names {
//!     fn start_element(
//!         &mut self,
//!         _uri: &str,
//!         local: &str,
//!         _q: &str,
//!         _atts: &dyn Attributes,
//!     ) -> Result<(), SaxError> {
//!         self.0.push(local.to_string());
//!         Ok(())
//!     }
//!     fn end_element(&mut self, _uri: &str, _local: &str, _q: &str) -> Result<(), SaxError> {
//!         Ok(())
//!     }
//! }
//!
//! let mut names = Names::default();
//! parse("<a><b/><c/></a>", &mut names).unwrap();
//! assert_eq!(names.0, ["a", "b", "c"]);
//! ```
//!
//! [ref]: https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/org/xml/sax/package-summary.html

#![forbid(unsafe_code)]
#![warn(clippy::pedantic, missing_docs)]

pub mod attributes;
pub mod error;
pub mod handler;
pub mod input_source;
pub mod locator;
pub mod reader;
pub mod xml_filter;

pub use attributes::{Attribute, AttributeList, Attributes};
pub use error::{ParseError, SaxError};
pub use handler::{ContentHandler, EntityResolver, ErrorHandler};
pub use input_source::InputSource;
pub use locator::Locator;
pub use reader::{parse, Reader};
pub use xml_filter::{XMLFilter, XMLFilterImpl, XMLReader};

/// The reserved `xml` prefix namespace, pre-bound per the Namespaces in XML
/// specification.
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// The namespace of the namespace-declaration attributes themselves.
pub const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

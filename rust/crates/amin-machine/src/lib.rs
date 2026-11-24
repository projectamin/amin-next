//! # amin-machine — the Amin 3 filter machine (Rust peer of `Amin::Machine::Dispatcher`)
//!
//! Amin's architecture is one idea: a document is a SAX event stream, and every
//! feature is a *filter* composed into a chain by the **machine spec**. The
//! Perl side has done this for years in
//! [`Amin::Machine::Dispatcher`]; this crate is its Rust peer, so a Rust node
//! (embedded/mobile, no Perl) runs the *same* chain from the *same* shared
//! `machine_spec.xml` and stays interoperable with the Perl filters.
//!
//! `amin-proxy` is therefore not a standalone router: it is `amin` with the
//! `Proxy::Route` / `Proxy::RateLimit` filters registered into this machine
//! (proxy-plan §5.1 — "routing is a `begin` filter, not a second router").
//!
//! ## The model, mirrored from Perl
//!
//! * [`MachineSpec`] reads `machine_spec.xml` (path → `$AMIN_MACHINE_SPEC` →
//!   `/etc/amin/machine_spec.xml` → `$HOME/.amin/machine_spec.xml` → embedded)
//!   into a [`Spec`]: the filter declarations, the handler/log/generator
//!   classes and the `ui:` render dialects — parsed with SAX, never a DOM.
//! * [`build_chain`] composes the base graph from what must always be present
//!   (permanent filters, element-agnostic filters) and makes every remaining
//!   element-scoped spec filter a **candidate** of its position, gated by a
//!   [`LazyGate`] that splices it in only as its element flows past.
//! * [`Machine::run`] drives the source document through the chain with
//!   [`amin_sax`] — event by event, no tree, end to end.
//!
//! A filter is a [`Filter`]: an event handler that holds a `handler` link to
//! its downstream and forwards to it by default. Filters Amin carries in Rust
//! are declared to a [`Registry`] (the Rust form of `register`/`%FILTERS`);
//! a spec filter whose class is not registered is skipped, exactly as Perl
//! skips a class it cannot `require`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use amin_sax::{Attributes, Locator, SaxError};

pub mod chain;
mod bsax_front;
mod gate;
pub mod spec;
pub mod uri;

pub use chain::{build_chain, ChainContext, LateEnable, Machine};
pub use spec::{ClassAttrs, MachineSpec, Spec, SpecFilter, UiDialect};

/// One node in a composed filter chain: a filter behind shared interior
/// mutability, so a [`LazyGate`](gate::LazyGate) can splice a candidate in
/// mid-stream and un-splice it when its element closes.
pub type Node = Rc<RefCell<Box<dyn Filter>>>;

/// Wrap a filter as a chain [`Node`].
#[must_use]
pub fn node<F: Filter + 'static>(filter: F) -> Node {
    Rc::new(RefCell::new(Box::new(filter)))
}

/// The machine's log seam (≈ `Amin::Log::Standard`).
///
/// Only the surface the chain uses is modelled: a warning sink for filters
/// that deny a request, and the fail-fast latch. Once [`Log::halted`] is true,
/// [`Machine::run`] forwards every later event straight to the base handler —
/// no further filter or command executes (the 3.0 shape of amin-legacy's swap
/// to `Handler::Empty`).
pub trait Log {
    /// Record a warning.
    fn warn(&self, _msg: &str) {}
    /// Record an error.
    fn error(&self, _msg: &str) {}
    /// Whether the run has been aborted by a failed command.
    fn halted(&self) -> bool {
        false
    }
}

/// The construction context handed to a filter factory — the Rust form of the
/// keyword arguments `_build_chain` passes every filter (`Handler`, `Log`,
/// `Mode`, `Name`, `Element`, `Render`, `Proxy`) plus the spec's own declared
/// attributes as `cfg` (Perl's `_filter_cfg`).
pub struct FilterArgs {
    /// The downstream node this filter forwards to.
    pub handler: Option<Node>,
    /// The machine's log, if any.
    pub log: Option<Rc<dyn Log>>,
    /// The run mode (`render` / `run`).
    pub mode: String,
    /// The class-declared verb (`Name`); `None` for element-only filters.
    pub name: Option<String>,
    /// The element this filter binds to.
    pub element: Option<String>,
    /// The shared `ui:` render context, when a dialect serves the target.
    pub render: Option<Rc<dyn Any>>,
    /// The injected compiled context (for the proxy, the compiled profile).
    pub proxy: Option<Rc<dyn Any>>,
    /// Every non-structural attribute declared on the `<filter>`, verbatim.
    pub cfg: BTreeMap<String, String>,
}

/// A filter factory: builds one filter from its [`FilterArgs`].
pub type Constructor = Box<dyn Fn(FilterArgs) -> Box<dyn Filter>>;

/// One registry entry: the class's declared verb (≈ `sub name`) and its
/// factory.
struct Entry {
    verb: Option<String>,
    ctor: Constructor,
}

/// The set of filter classes this binary carries (the Rust form of
/// `Amin::Machine::Dispatcher::register` / `%FILTERS`).
///
/// A spec names a class; [`build_chain`] composes it only if the registry
/// holds it, otherwise the class is skipped — the same outcome as a Perl
/// `require` that fails. The declared `verb` is the class's `sub name`: `None`
/// means it has none (element-only binding), `Some("")` means it matches any
/// `name` attribute, `Some("x")` means it matches only `name="x"`. This is how
/// the machine knows a filter's verb without symbol-table reflection.
#[derive(Default)]
pub struct Registry {
    entries: BTreeMap<String, Entry>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a filter class. `verb` mirrors the Perl class's `sub name`.
    pub fn register(&mut self, class: impl Into<String>, verb: Option<&str>, ctor: Constructor) {
        self.entries.insert(
            class.into(),
            Entry {
                verb: verb.map(str::to_string),
                ctor,
            },
        );
    }

    /// Whether `class` is carried by this binary.
    #[must_use]
    pub fn has(&self, class: &str) -> bool {
        self.entries.contains_key(class)
    }

    /// The declared verb of `class`, or `None` when it has no `sub name`.
    #[must_use]
    pub fn verb(&self, class: &str) -> Option<String> {
        self.entries.get(class).and_then(|e| e.verb.clone())
    }

    /// The factory for `class`, if it is registered.
    #[must_use]
    pub fn constructor(&self, class: &str) -> Option<&Constructor> {
        self.entries.get(class).map(|e| &e.ctor)
    }

    /// Every registered class name, in sorted order.
    pub fn classes(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }
}

/// A machine filter (≈ a `XML::SAX::Base` subclass in the Perl chain).
///
/// Every event defaults to forwarding to [`Filter::handler`], so a filter that
/// only cares about one event implements exactly that one — the same shape as
/// `XML::SAX::Base` and `org.xml.sax.helpers.DefaultHandler`.
///
/// The method set is exactly the events [`amin_sax`] emits. Perl's
/// `processing_command` / `comment` do not exist here (the Rust reader does
/// not emit them); `processing_instruction` is deliberately absent — the
/// machine logs it and never forwards it into the chain (an escape hatch, not
/// part of the Amin contract).
pub trait Filter {
    /// The downstream node this filter forwards to (`None` = terminal).
    fn handler(&self) -> Option<Node>;

    /// Receive the document locator.
    fn set_document_locator(&mut self, locator: Rc<Locator>) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.set_document_locator(locator))
    }

    /// Fired once before any element.
    fn start_document(&mut self) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.start_document())
    }

    /// Fired once after the root element closes.
    fn end_document(&mut self) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.end_document())
    }

    /// Fired before the element that declares `prefix`.
    fn start_prefix_mapping(&mut self, prefix: &str, uri: &str) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.start_prefix_mapping(prefix, uri))
    }

    /// Fired after the element that declared `prefix` closes.
    fn end_prefix_mapping(&mut self, prefix: &str) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.end_prefix_mapping(prefix))
    }

    /// Fired for every element start.
    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        forward(self.handler(), |n| {
            n.start_element(uri, local_name, q_name, atts)
        })
    }

    /// Fired for every element close.
    fn end_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
    ) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.end_element(uri, local_name, q_name))
    }

    /// Fired for non-empty character data.
    fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.characters(ch))
    }

    /// Fired for whitespace known to be ignorable (never by this reader).
    fn ignorable_whitespace(&mut self, ch: &str) -> Result<(), SaxError> {
        forward(self.handler(), |n| n.ignorable_whitespace(ch))
    }
}

/// Implement [`Filter::handler`] for a struct whose `handler` field is a
/// `Option<Node>` — the two lines every filter would otherwise repeat.
#[macro_export]
macro_rules! filter_handler {
    () => {
        fn handler(&self) -> Option<$crate::Node> {
            self.handler.clone()
        }
    };
}

/// Forward one event to `next`, or no-op at the terminal.
fn forward(
    next: Option<Node>,
    f: impl FnOnce(&mut dyn Filter) -> Result<(), SaxError>,
) -> Result<(), SaxError> {
    if let Some(n) = next {
        let mut borrowed = n.borrow_mut();
        f(&mut **borrowed)?;
    }
    Ok(())
}

/// A spec filter's declared attributes ARE its configuration. The chain binds
/// the structural keys itself (position picks the region; element/name/target/
/// namespace/priority/window drive matching), so everything else declared on
/// the `<filter>` is handed to the factory — the Rust port of Perl's
/// `_filter_cfg` (proxy-plan §10.2).
#[must_use]
pub fn filter_cfg(meta: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    const STRUCTURAL: [&str; 7] = [
        "position",
        "element",
        "target",
        "name",
        "namespace",
        "priority",
        "window",
    ];
    meta.iter()
        .filter(|(k, _)| !STRUCTURAL.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The binding collision behind [`MachineError::Ambiguous`]: two candidates
/// bound the same `element` / `namespace` / `verb` / `target` at one priority.
#[derive(Debug)]
pub struct AmbiguousBinding {
    /// The bound element local name.
    pub element: String,
    /// The bound namespace (`*` when unbound).
    pub namespace: String,
    /// The bound verb (`*` when unbound).
    pub verb: String,
    /// The bound target (`*` when unbound).
    pub target: String,
    /// The shared priority.
    pub priority: i64,
    /// The first class bound to the key.
    pub first: String,
    /// The second class bound to the key.
    pub second: String,
}

/// A structural fault in the machine spec, or a fatal parse error.
#[derive(Debug, thiserror::Error)]
pub enum MachineError {
    /// Two element-scoped candidates bind the same thing at the same priority:
    /// a hard error, never a silent last-one-wins (see `LazyGate`). Boxed so a
    /// chain constructor's `Result` stays small on the happy path.
    #[error(
        "Amin: ambiguous element filters bound to <{}> (namespace={} verb={} target={}) \
         at equal priority {}: {} vs {}",
        .0.element, .0.namespace, .0.verb, .0.target, .0.priority, .0.first, .0.second
    )]
    Ambiguous(Box<AmbiguousBinding>),
    /// The source document (or a spec) was not well-formed XML.
    #[error(transparent)]
    Sax(#[from] SaxError),
}

/// Re-export so downstream crates can name the set without a path to
/// `BTreeSet`.
pub type ClassSet = BTreeSet<String>;

//! # amin-axa — the AXA render path, in Rust (proxy-plan §8 P4)
//!
//! The Perl AXA origin server (`Amin::AXA::HTTP` core over `Amin::AXA::Serve`)
//! reads a request, inflates
//! the fragment the app declared for its path, and drives that fragment
//! through the machine's SAX chain: a **middle** app filter (`Amin::Example::Shop`)
//! emits the canonical `ui:` IR, a **late** projection fleet turns each `ui:`
//! element into real `html:` XHTML events, and `Amin::Handler::HTML` serialises
//! and escapes them. This crate is that same path, ported, so the two
//! implementations render **byte-identical** pages — the project's Perl↔Rust
//! parity rule applied to the render path (its proxy analogue is `amin-proxy`).
//!
//! The port keeps the shape of the original, deliberately:
//!
//! | Perl                              | here                        |
//! |-----------------------------------|-----------------------------|
//! | `Amin::Handler::HTML`             | [`serializer::HtmlSerializer`] |
//! | `Amin::UI::Target::HTML`          | [`ui_target::HtmlTarget`]   |
//! | `Amin::Filter::UI::Guard`         | the spec's `vocab` band (`bsax::vocab::Vocab`) — not repeated in the target |
//! | `Amin::Example::Shop`             | [`shop::Shop`]              |
//! | `Amin::AXA::FormCodec`            | [`formcodec::inflate`]      |
//! | `Amin::AXA::App`                  | [`app::App`]                |
//! | `Amin::AXA::Store` / `::Session`  | [`store`] / [`session`]     |
//! | `Amin::AXA::HTTP` / `::Serve`     | [`adaptor`] (request framing) + [`render`] |
//!
//! The chain here is specialised to the app surface (one `ui:`-emitting filter
//! and the HTML projection fleet) rather than composed from a spec file — the
//! always-present machine filters are byte-neutral for an app document, so the
//! events that reach the serializer are exactly the ones modelled here. The
//! `ui:` subtree still rides alongside its projection (additive), which is what
//! keeps intermediate character data dropped and leaf text flushed at close —
//! see [`render::Renderer`].
//!
//! ```
//! use amin_axa::{render_fragment, Values};
//!
//! // The fragment an app declares, placeholders intact.
//! let frag = r#"<shop:request route="catalog" sid="{sid}" csrf="{csrf}"/>"#;
//! let mut vals = Values::new();
//! vals.set("sid", "0").set("csrf", "0");
//! let html = render_fragment(frag, &vals, &[], &mut Default::default()).unwrap();
//! assert!(html.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod acme;
pub mod adaptor;
pub mod app;
pub mod formcodec;
pub mod render;
pub mod serializer;
pub mod session;
pub mod shop;
pub mod store;
pub mod ui_target;

pub use acme::AcmeKey;
pub use app::App;
pub use formcodec::{inflate, escape_value};
pub use render::{render_fragment, Page, RenderError, Values};
pub use serializer::HtmlSerializer;
pub use session::Session;
pub use store::{Record, Store};
pub use ui_target::HtmlTarget;

/// Core Amin namespace (the `amin:` prefix).
pub const AMIN_NS: &str = "http://projectamin.org/ns/2026/";
/// The canonical `ui:` IR namespace.
pub const UI_NS: &str = "http://projectamin.org/ns/ui/1";
/// The XHTML namespace the HTML target emits into.
pub const XHTML_NS: &str = "http://www.w3.org/1999/xhtml";
/// The shop example's own namespace — the filter contract of `Amin::Example::Shop`.
pub const SHOP_NS: &str = "urn:projectamin:example:shop";
/// The AXA app declaration namespace (`axa:`).
pub const AXA_NS: &str = "http://projectamin.org/ns/axa/1";
/// Maximum request body the adapter will parse (256 KiB — M2 acceptance).
pub const BODY_CAP: usize = 262_144;

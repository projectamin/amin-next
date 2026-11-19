//! Chain composition and the run driver — the Rust peer of
//! `Amin::Machine::Dispatcher::_build_chain` and `run`.

use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use amin_sax::{Attributes, ContentHandler, Locator, SaxError};
use bsax::vocab::Vocab;

use crate::gate::LazyGate;
use crate::spec::{Spec, SpecFilter};
use crate::{filter_cfg, Filter, FilterArgs, Log, MachineError, Node, Registry};

/// Which optional `late` regions are active for a run (the Perl
/// `late_filters_enable`). All default on.
#[derive(Debug, Clone, Copy)]
pub struct LateEnable {
    /// Compose `::Map::` late filters.
    pub map: bool,
    /// Compose `::UI::` late filters.
    pub ui: bool,
    /// Compose `::AI::Graph` late filters.
    pub ai: bool,
}

impl Default for LateEnable {
    fn default() -> Self {
        Self {
            map: true,
            ui: true,
            ai: true,
        }
    }
}

/// The canonical region order: `end → late → middle → begin → permanent`.
/// The last composed is outermost, so `permanent` ends up outermost overall —
/// the trust boundary sees events first (TR-2.1).
const POSITIONS: [&str; 5] = ["end", "late", "middle", "begin", "permanent"];

/// The ambient context every composed node shares: the class registry, the
/// log, the run mode and render target, the shared `render`/`proxy` handles and
/// the `late`-region switches.
///
/// Bundling them keeps each constructor's signature about *what it composes*
/// rather than the setup threaded through every filter — the Rust form of the
/// keyword arguments `_build_chain` passes each filter.
pub struct ChainContext {
    /// The filter classes this binary carries.
    pub registry: Rc<Registry>,
    /// The machine's log, if any.
    pub log: Option<Rc<dyn Log>>,
    /// The run mode (`render` / `run`).
    pub mode: String,
    /// The render target (`ui_os`).
    pub ui_os: String,
    /// The shared `ui:` render context, when a dialect serves the target.
    pub render: Option<Rc<dyn Any>>,
    /// The injected compiled context (for the proxy, the compiled profile).
    pub proxy: Option<Rc<dyn Any>>,
    /// Which optional `late` regions compose.
    pub late_enable: LateEnable,
}

impl ChainContext {
    /// A context over `registry` for a run in `mode` on render target `ui_os`,
    /// with every `late` region enabled and no injected render/proxy handle.
    #[must_use]
    pub fn new(registry: Rc<Registry>, mode: impl Into<String>, ui_os: impl Into<String>) -> Self {
        Self {
            registry,
            log: None,
            mode: mode.into(),
            ui_os: ui_os.into(),
            render: None,
            proxy: None,
            late_enable: LateEnable::default(),
        }
    }
}

/// Compose the base chain graph over `base`, from the spec, exactly as the Perl
/// `_build_chain` does:
///
/// * element-scoped, non-permanent spec filters become **candidates** of their
///   position (only if the registry carries the class), and the position gets a
///   [`LazyGate`];
/// * permanent and element-agnostic filters are composed statically;
/// * within each position the statics are pushed in reverse, so the
///   first-listed is the outermost of that region;
/// * each gate is inserted *before* its region's statics, so it sits at the
///   region's innermost boundary.
pub fn build_chain(base: Node, ctx: &ChainContext, spec: &Spec) -> Result<Node, MachineError> {
    let mut head = base;

    // The shared `ui:` render context is a declared contract fact
    // (`<ui-dialect target= class=>`), not a class-name rule. Rust carries no
    // `ui:` dialect implementations today, so a target yields no render, and
    // since every `ui:` element filter is target-scoped, no splicing happens
    // and the subtree passes through untouched — the neutral outcome the spec
    // intends for `tty`.
    let render = ctx.render.clone();

    let mut by_p: BTreeMap<String, Vec<SpecFilter>> = BTreeMap::new();
    let mut cands_by_p: BTreeMap<String, Vec<SpecFilter>> = BTreeMap::new();
    for f in &spec.filters {
        let position = f
            .meta
            .get("position")
            .cloned()
            .unwrap_or_else(|| "middle".to_string());
        let element_scoped = f.meta.get("element").is_some_and(|el| !el.is_empty());
        if element_scoped && position != "permanent" {
            // A candidate class the registry cannot build was never in the
            // static chain either — skip it, as Perl skips an un-`require`-able
            // class.
            if ctx.registry.has(&f.class) {
                cands_by_p.entry(position).or_default().push(f.clone());
            }
        } else {
            by_p.entry(position).or_default().push(f.clone());
        }
    }

    for position in POSITIONS {
        if let Some(candidates) = cands_by_p.get(position) {
            let gate = LazyGate::new(head.clone(), ctx, candidates.clone())?;
            head = Rc::new(RefCell::new(Box::new(gate)));
        }

        if let Some(filters) = by_p.get(position) {
            for f in filters.iter().rev() {
                if position == "late" && late_disabled(f, &ctx.ui_os, &ctx.late_enable) {
                    continue;
                }
                let Some(ctor) = ctx.registry.constructor(&f.class) else {
                    continue;
                };
                let args = FilterArgs {
                    handler: Some(head.clone()),
                    log: ctx.log.clone(),
                    mode: ctx.mode.clone(),
                    name: f.meta.get("name").cloned(),
                    element: f.meta.get("element").cloned(),
                    render: render.clone(),
                    proxy: ctx.proxy.clone(),
                    cfg: filter_cfg(&f.meta),
                };
                head = Rc::new(RefCell::new(ctor(args)));
            }
        }
    }

    Ok(head)
}

/// The `late` region's mode/target gates: a `late` filter is composed only
/// when its mode is enabled and, if target-scoped, its target is the run's.
fn late_disabled(f: &SpecFilter, ui_os: &str, late_enable: &LateEnable) -> bool {
    let class = &f.class;
    let target = f.meta.get("target").map_or("", String::as_str);
    (class.contains("::Map::") && !late_enable.map)
        || (class.contains("::AI::Graph") && !late_enable.ai)
        || (class.contains("::UI::") && !late_enable.ui)
        || (!target.is_empty() && target != ui_os)
}

/// The machine: a parsed [`Spec`] and the means to run a document through its
/// composed chain (≈ `Amin::Machine::Dispatcher`).
pub struct Machine {
    spec: Spec,
}

impl Machine {
    /// A machine over `spec`.
    #[must_use]
    pub fn new(spec: Spec) -> Self {
        Self { spec }
    }

    /// The machine's spec.
    #[must_use]
    pub fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Compose the chain over `base` and drive `source` through it.
    ///
    /// `base` is the terminal handler — for the proxy, the decision collector.
    /// The caller keeps its own handle to whatever `base` writes into and
    /// inspects it after the run; the composed chain owns copies of the nodes
    /// it wraps, so the returned chain is dropped at the end.
    ///
    /// `ctx` carries the registry, log, mode, render target and the injected
    /// compiled context, downcast by the filters that consume it (the same
    /// channel that injects `Render` in Perl).
    pub fn run(
        &self,
        base: Node,
        source: &str,
        ctx: &ChainContext,
    ) -> Result<(), MachineError> {
        let mut driver = self.driver(base, ctx)?;
        amin_sax::parse(source, &mut driver)?;
        Ok(())
    }

    /// Compose the chain over `base` and drive `source` through it, *sniffing*
    /// the dialect — the Rust peer of Perl's `Amin->parse`.
    ///
    /// A document whose first non-whitespace byte (within 64) is `<` is XML and
    /// takes [`Machine::run`]; anything else is BSAX and is decoded through the
    /// [`bsax_front`](crate::bsax_front), resolving the spec-declared vocabulary
    /// band ([`Spec::vocab`]).  The two branches drive the *same* chain, so a
    /// BSAX document and its XML twin produce identical events — the property
    /// that keeps the auto-detected transport from becoming a parser
    /// differential.
    pub fn run_bytes(
        &self,
        base: Node,
        source: &[u8],
        ctx: &ChainContext,
    ) -> Result<(), MachineError> {
        if crate::bsax_front::is_xml(source) {
            let text = std::str::from_utf8(source)
                .map_err(|_| SaxError::NotRecognized("document is not UTF-8 XML".to_string()))?;
            return self.run(base, text, ctx);
        }
        let mut driver = self.driver(base, ctx)?;
        crate::bsax_front::drive(source, Vocab::from_names(&self.spec.vocab), &mut driver)?;
        Ok(())
    }

    /// Compose the chain over `base` and build the run driver — the shared
    /// prologue of [`Machine::run`] and [`Machine::run_bytes`].
    fn driver(&self, base: Node, ctx: &ChainContext) -> Result<Driver, MachineError> {
        let head = build_chain(base.clone(), ctx, &self.spec)?;
        Ok(Driver {
            head,
            base,
            log: ctx.log.clone(),
            drained: false,
        })
    }
}

/// Drives a parsed document into the chain, with the fail-fast latch: once the
/// log is halted, every later event goes straight to the base handler.
struct Driver {
    head: Node,
    base: Node,
    log: Option<Rc<dyn Log>>,
    drained: bool,
}

impl Driver {
    fn halted(&self) -> bool {
        self.log.as_ref().is_some_and(|l| l.halted())
    }

    /// Dispatch one chain event, honouring the fail-fast latch.
    fn emit(
        &mut self,
        f: impl FnOnce(&mut dyn Filter) -> Result<(), SaxError>,
    ) -> Result<(), SaxError> {
        if self.halted() {
            if !self.drained {
                self.drained = true;
                if let Some(log) = &self.log {
                    log.error(
                        "[halt] run aborted at the first failed command; \
                         later elements are not processed",
                    );
                }
            }
            let mut base = self.base.borrow_mut();
            return f(&mut **base);
        }
        let mut head = self.head.borrow_mut();
        f(&mut **head)
    }
}

impl ContentHandler for Driver {
    fn set_document_locator(&mut self, locator: Rc<Locator>) {
        // Delivered once, before start_document; always into the chain. The
        // reader offers no way to surface a locator fault, so it is dropped.
        let _ = self.head.borrow_mut().set_document_locator(locator);
    }

    fn start_document(&mut self) -> Result<(), SaxError> {
        self.emit(|n| n.start_document())
    }

    fn end_document(&mut self) -> Result<(), SaxError> {
        self.emit(|n| n.end_document())
    }

    fn start_prefix_mapping(&mut self, prefix: &str, uri: &str) -> Result<(), SaxError> {
        self.head
            .borrow_mut()
            .start_prefix_mapping(prefix, uri)
    }

    fn end_prefix_mapping(&mut self, prefix: &str) -> Result<(), SaxError> {
        self.head.borrow_mut().end_prefix_mapping(prefix)
    }

    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        self.emit(|n| n.start_element(uri, local_name, q_name, atts))
    }

    fn end_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
    ) -> Result<(), SaxError> {
        self.emit(|n| n.end_element(uri, local_name, q_name))
    }

    fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
        self.emit(|n| n.characters(ch))
    }

    fn ignorable_whitespace(&mut self, ch: &str) -> Result<(), SaxError> {
        self.emit(|n| n.ignorable_whitespace(ch))
    }

    fn processing_instruction(&mut self, target: &str, data: &str) -> Result<(), SaxError> {
        // Never forwarded into the chain: a PI carries arbitrary target/data
        // outside the closed-world vocabulary — an escape hatch. Record the
        // attempt only (proxy-plan, bsax "escape hatches are not a trust
        // boundary").
        if let Some(log) = &self.log {
            log.warn(&format!(
                "ignored processing instruction (target '{target}', {} B of data): \
                 not part of the Amin contract",
                data.len()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node;
    use crate::spec::SpecFilter;
    use crate::Constructor;
    use std::cell::RefCell as StdRefCell;

    /// A filter that records the class it was built from and then forwards.
    struct Recorder {
        handler: Option<Node>,
        tag: String,
        sink: Rc<StdRefCell<Vec<String>>>,
    }

    impl Filter for Recorder {
        crate::filter_handler!();

        fn start_element(
            &mut self,
            uri: &str,
            local_name: &str,
            q_name: &str,
            atts: &dyn Attributes,
        ) -> Result<(), SaxError> {
            self.sink.borrow_mut().push(self.tag.clone());
            if let Some(h) = self.handler.clone() {
                return h.borrow_mut().start_element(uri, local_name, q_name, atts);
            }
            Ok(())
        }
    }

    fn recorder(
        class: &str,
        sink: &Rc<StdRefCell<Vec<String>>>,
    ) -> Constructor {
        let class = class.to_string();
        let sink = sink.clone();
        Box::new(move |args: FilterArgs| {
            Box::new(Recorder {
                handler: args.handler,
                tag: class.clone(),
                sink: sink.clone(),
            })
        })
    }

    struct Terminal {
        handler: Option<Node>,
        sink: Rc<StdRefCell<Vec<String>>>,
    }

    impl Filter for Terminal {
        crate::filter_handler!();

        fn start_element(
            &mut self,
            _uri: &str,
            _local_name: &str,
            _q_name: &str,
            _atts: &dyn Attributes,
        ) -> Result<(), SaxError> {
            self.sink.borrow_mut().push("terminal".to_string());
            Ok(())
        }
    }

    fn filter(class: &str, meta: &[(&str, &str)]) -> SpecFilter {
        SpecFilter {
            class: class.to_string(),
            meta: meta
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// A `run`-mode, `tty`-target context over `reg` (no log, no proxy).
    fn ctx(reg: &Rc<Registry>) -> ChainContext {
        ChainContext::new(reg.clone(), "run", "tty")
    }

    const NS: &str = "http://projectamin.org/ns/2026/";

    #[test]
    fn statics_compose_in_reverse_so_first_listed_is_outermost() {
        let sink = Rc::new(StdRefCell::new(Vec::new()));
        let mut reg = Registry::new();
        reg.register("T::A", None, recorder("T::A", &sink));
        reg.register("T::B", None, recorder("T::B", &sink));
        let reg = Rc::new(reg);

        let spec = Spec {
            filters: vec![
                filter("T::A", &[("position", "begin")]),
                filter("T::B", &[("position", "begin")]),
            ],
            ..Spec::default()
        };
        let terminal = node(Terminal {
            handler: None,
            sink: sink.clone(),
        });
        let head = build_chain(terminal, &ctx(&reg), &spec).unwrap();

        let empty = amin_sax::AttributeList::new();
        head.borrow_mut()
            .start_element(NS, "request", "amin:request", &empty)
            .unwrap();
        assert_eq!(*sink.borrow(), vec!["T::A", "T::B", "terminal"]);
    }

    #[test]
    fn element_scoped_candidate_splices_only_on_its_element() {
        let sink = Rc::new(StdRefCell::new(Vec::new()));
        let mut reg = Registry::new();
        reg.register("T::Route", Some(""), recorder("T::Route", &sink));
        let reg = Rc::new(reg);

        let spec = Spec {
            filters: vec![filter(
                "T::Route",
                &[("position", "begin"), ("element", "request"), ("namespace", NS)],
            )],
            ..Spec::default()
        };
        let terminal = node(Terminal {
            handler: None,
            sink: sink.clone(),
        });
        let head = build_chain(terminal, &ctx(&reg), &spec).unwrap();

        let empty = amin_sax::AttributeList::new();
        // A different element does not trigger the candidate.
        head.borrow_mut()
            .start_element(NS, "other", "amin:other", &empty)
            .unwrap();
        assert_eq!(*sink.borrow(), vec!["terminal"]);

        // The bound element splices the candidate in, above the terminal.
        sink.borrow_mut().clear();
        head.borrow_mut()
            .start_element(NS, "request", "amin:request", &empty)
            .unwrap();
        assert_eq!(*sink.borrow(), vec!["T::Route", "terminal"]);
    }

    #[test]
    fn ambiguous_candidates_are_a_hard_error() {
        let sink = Rc::new(StdRefCell::new(Vec::new()));
        let mut reg = Registry::new();
        reg.register("T::One", None, recorder("T::One", &sink));
        reg.register("T::Two", None, recorder("T::Two", &sink));
        let reg = Rc::new(reg);

        let spec = Spec {
            filters: vec![
                filter("T::One", &[("position", "begin"), ("element", "request")]),
                filter("T::Two", &[("position", "begin"), ("element", "request")]),
            ],
            ..Spec::default()
        };
        let terminal = node(Terminal {
            handler: None,
            sink: sink.clone(),
        });
        let err = match build_chain(terminal, &ctx(&reg), &spec) {
            Ok(_) => panic!("expected an ambiguous binding error"),
            Err(e) => e,
        };
        assert!(matches!(err, MachineError::Ambiguous(_)), "got {err:?}");
    }

    #[test]
    fn machine_runs_a_document_end_to_end() {
        let sink = Rc::new(StdRefCell::new(Vec::new()));
        let mut reg = Registry::new();
        reg.register("T::Route", Some(""), recorder("T::Route", &sink));
        let reg = Rc::new(reg);

        let spec = Spec {
            filters: vec![filter(
                "T::Route",
                &[("position", "begin"), ("element", "request")],
            )],
            ..Spec::default()
        };
        let terminal = node(Terminal {
            handler: None,
            sink: sink.clone(),
        });
        let machine = Machine::new(spec);
        machine
            .run(
                terminal,
                &format!(
                    "<amin:profile xmlns:amin=\"{NS}\"><amin:request/></amin:profile>"
                ),
                &ctx(&reg),
            )
            .unwrap();
        // The base terminal sees every element (the wrapper `profile` and the
        // `request`); the candidate splices in above it for `request` only.
        assert_eq!(
            *sink.borrow(),
            vec!["terminal", "T::Route", "terminal"]
        );
    }

    #[test]
    fn run_bytes_sniffs_and_drives_the_same_chain_as_run() {
        use bsax::encode;
        use bsax::vocab::ns_id::AMIN;

        let sink = Rc::new(StdRefCell::new(Vec::new()));
        let mut reg = Registry::new();
        reg.register("T::Route", Some(""), recorder("T::Route", &sink));
        let reg = Rc::new(reg);

        // The element-scoped filter declares `request`; the parser harvest
        // (tested in `spec`) would populate `vocab` with exactly that name, so
        // it is set here verbatim.
        let spec = Spec {
            filters: vec![filter(
                "T::Route",
                &[("position", "begin"), ("element", "request")],
            )],
            vocab: vec!["request".to_string()],
            ..Spec::default()
        };
        let machine = Machine::new(spec);

        let xml = format!("<amin:profile xmlns:amin=\"{NS}\"><amin:request/></amin:profile>");
        let terminal = node(Terminal {
            handler: None,
            sink: sink.clone(),
        });
        machine.run(terminal, &xml, &ctx(&reg)).unwrap();
        let from_xml = sink.borrow().clone();

        // The identical document on the BSAX wire: `profile` is a core NAME_ID
        // (0); `request` rides the spec band the front resolves via the spec.
        let vocab = Vocab::from_names(&machine.spec().vocab);
        let profile = vocab.name_id(b"profile").unwrap();
        let request = vocab.name_id(b"request").unwrap();
        let no_attrs: &[(u32, &[u8])] = &[];
        let mut out = vec![];
        encode::write_magic(&mut out);
        encode::write_start_doc(&mut out);
        encode::write_start_elem(&mut out, AMIN, profile, no_attrs);
        encode::write_start_elem(&mut out, AMIN, request, no_attrs);
        encode::write_end_elem(&mut out);
        encode::write_end_elem(&mut out);
        encode::write_end_doc(&mut out);

        sink.borrow_mut().clear();
        let terminal = node(Terminal {
            handler: None,
            sink: sink.clone(),
        });
        machine.run_bytes(terminal, &out, &ctx(&reg)).unwrap();
        let from_bsax = sink.borrow().clone();

        // The dialect is sniffed, never configured, and both branches drive the
        // SAME chain: the auto-detected transport is not a parser differential.
        assert_eq!(from_bsax, from_xml);
        assert_eq!(from_xml, vec!["terminal", "T::Route", "terminal"]);
    }
}

//! `LazyGate` — the mid-stream splice (Rust peer of
//! `Amin::Machine::Dispatcher::_LazyGate`).
//!
//! The machine spec declares every filter a machine *supports*; only some of
//! them belong in a given document's chain. An element-scoped, non-permanent
//! filter becomes a **candidate** of its position, and the position gets a gate
//! that splices the candidate into the event chain as its element's
//! `start_element` flows through, then un-splices it after the matching
//! `end_element`. No pre-scan, no DOM: the profile itself is the decision
//! signal.
//!
//! The gate deliberately forwards events directly to its current child rather
//! than through a cached dispatcher, because a splice swaps that child
//! mid-stream — the exact hazard the Perl gate documents for
//! `XML::SAX::Base`'s cached paths.

use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use amin_sax::{Attributes, SaxError};

use crate::spec::SpecFilter;
use crate::{
    filter_cfg, AmbiguousBinding, ChainContext, Filter, FilterArgs, Log, MachineError, Node,
    Registry,
};

/// One currently-spliced candidate.
struct Active {
    /// The spliced instance's chain node.
    node: Node,
    /// The gate depth recorded at splice time (post-increment).
    depth: usize,
    /// The candidate's class, for the one-live-instance-per-candidate rule.
    class: String,
    /// Whether this candidate claims the whole document
    /// (`window="document"`), staying spliced until `end_document`.
    doc: bool,
}

/// A gate that splices element-scoped candidates into the chain on demand.
pub(crate) struct LazyGate {
    handler: Option<Node>,
    base_child: Option<Node>,
    log: Option<Rc<dyn Log>>,
    mode: String,
    target: String,
    render: Option<Rc<dyn Any>>,
    proxy: Option<Rc<dyn Any>>,
    registry: Rc<Registry>,
    candidates: Vec<SpecFilter>,
    active: Vec<Active>,
    depth: usize,
}

impl LazyGate {
    /// Build a gate over `handler`, ordering its candidates and rejecting
    /// ambiguous bindings.
    pub(crate) fn new(
        handler: Node,
        ctx: &ChainContext,
        mut candidates: Vec<SpecFilter>,
    ) -> Result<Self, MachineError> {
        order_candidates(&mut candidates, &ctx.registry)?;
        Ok(Self {
            base_child: Some(handler.clone()),
            handler: Some(handler),
            log: ctx.log.clone(),
            mode: ctx.mode.clone(),
            target: ctx.ui_os.clone(),
            render: ctx.render.clone(),
            proxy: ctx.proxy.clone(),
            registry: ctx.registry.clone(),
            candidates,
            active: Vec::new(),
            depth: 0,
        })
    }

    /// The render target this gate serves: an explicit target, else
    /// `$AMIN_OSTYPE`, else `""` (platform-neutral — a target-scoped candidate
    /// then never matches).
    fn effective_target(&self) -> String {
        if !self.target.is_empty() {
            return self.target.clone();
        }
        std::env::var("AMIN_OSTYPE").unwrap_or_default()
    }
}

/// A candidate's declared attribute, or `""`.
fn meta<'a>(f: &'a SpecFilter, key: &str) -> &'a str {
    f.meta.get(key).map_or("", String::as_str)
}

/// A candidate's numeric priority (unparsable/absent = 0, as Perl numifies).
fn priority(f: &SpecFilter) -> i64 {
    meta(f, "priority").trim().parse().unwrap_or(0)
}

/// Order candidates by priority (desc) then class (asc), and refuse two
/// candidates that bind the same thing at the same priority.
///
/// Order == priority: the first match wins, so an app overrides a built-in by
/// raising its priority (axa-plan §4.3). Equal priorities cannot decide a
/// match, so an ambiguous binding is a hard error, never a silent
/// last-one-wins.
fn order_candidates(
    candidates: &mut [SpecFilter],
    registry: &Registry,
) -> Result<(), MachineError> {
    candidates.sort_by(|a, b| priority(b).cmp(&priority(a)).then(a.class.cmp(&b.class)));

    let mut seen: BTreeMap<String, (i64, String)> = BTreeMap::new();
    for c in candidates.iter() {
        let verb = registry.verb(&c.class).unwrap_or_default();
        let key = format!(
            "{}\0{}\0{}\0{}",
            meta(c, "element"),
            meta(c, "namespace"),
            verb,
            meta(c, "target")
        );
        let pri = priority(c);
        if let Some((prior_pri, who)) = seen.get(&key) {
            if *prior_pri == pri {
                return Err(MachineError::Ambiguous(Box::new(AmbiguousBinding {
                    element: meta(c, "element").to_string(),
                    namespace: meta(c, "namespace").to_string(),
                    verb,
                    target: meta(c, "target").to_string(),
                    priority: pri,
                    first: who.clone(),
                    second: c.class.clone(),
                })));
            }
        }
        seen.insert(key, (pri, c.class.clone()));
    }
    Ok(())
}

impl Filter for LazyGate {
    fn handler(&self) -> Option<Node> {
        self.handler.clone()
    }

    fn start_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        let ln = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        self.depth += 1;

        if !ln.is_empty() {
            if let Some(index) = self.match_candidate(ln, uri, atts) {
                if self.splice(index, uri, local_name, q_name, atts)? {
                    return Ok(());
                }
            }
        }

        if let Some(child) = self.handler.clone() {
            return child.borrow_mut().start_element(uri, local_name, q_name, atts);
        }
        Ok(())
    }

    fn end_element(
        &mut self,
        uri: &str,
        local_name: &str,
        q_name: &str,
    ) -> Result<(), SaxError> {
        // The instance sees its own close first, then it un-splices.
        let ret = if let Some(child) = self.handler.clone() {
            child.borrow_mut().end_element(uri, local_name, q_name)
        } else {
            Ok(())
        };

        let ln = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        if ln.is_empty() {
            return ret;
        }
        self.depth = self.depth.saturating_sub(1);
        let should_pop = self
            .active
            .last()
            .is_some_and(|top| !top.doc && top.depth == self.depth + 1);
        if should_pop {
            if let Some(top) = self.active.pop() {
                self.handler = top.node.borrow().handler();
            }
        }
        ret
    }

    fn end_document(&mut self) -> Result<(), SaxError> {
        // Document-window candidates un-splice at the end of the document.
        let ret = if let Some(child) = self.handler.clone() {
            child.borrow_mut().end_document()
        } else {
            Ok(())
        };
        self.active.clear();
        self.handler = self.base_child.clone();
        ret
    }
}

impl LazyGate {
    /// The index of the first candidate this element triggers, if any.
    fn match_candidate(&self, ln: &str, uri: &str, atts: &dyn Attributes) -> Option<usize> {
        let name_attr = atts.value_of_local("name");
        let effective_target = self.effective_target();
        for (i, c) in self.candidates.iter().enumerate() {
            if meta(c, "element") != ln {
                continue;
            }
            let cns = meta(c, "namespace");
            if !cns.is_empty() && cns != uri {
                continue;
            }
            let ct = meta(c, "target");
            if !ct.is_empty() && ct != effective_target {
                continue;
            }
            // Verb matching mirrors the static chain: a class with a non-empty
            // verb requires a matching `name` attribute; a class with no verb
            // (or an empty one) is element-only.
            if let Some(verb) = self.registry.verb(&c.class) {
                if !verb.is_empty() {
                    match name_attr {
                        Some(n) if !n.is_empty() && n == verb => {}
                        _ => continue,
                    }
                }
            }
            // One live instance per candidate: a nested same-key element is
            // still inside the active instance's capture scope.
            if self.active.iter().any(|a| a.class == c.class) {
                continue;
            }
            return Some(i);
        }
        None
    }

    /// Splice candidate `index` in as the current child and forward the
    /// triggering event to it. Returns `false` if it could not be built (the
    /// class has no factory), so the caller forwards to the existing child.
    fn splice(
        &mut self,
        index: usize,
        uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<bool, SaxError> {
        let candidate = self.candidates[index].clone();
        let doc = meta(&candidate, "window") == "document";
        let registry = self.registry.clone();
        let Some(ctor) = registry.constructor(&candidate.class) else {
            return Ok(false);
        };
        let Some(rest) = self.handler.clone() else {
            return Ok(false);
        };

        let args = FilterArgs {
            handler: Some(rest),
            log: self.log.clone(),
            mode: self.mode.clone(),
            name: candidate.meta.get("name").cloned(),
            element: candidate.meta.get("element").cloned(),
            render: self.render.clone(),
            proxy: self.proxy.clone(),
            cfg: filter_cfg(&candidate.meta),
        };
        let node: Node = Rc::new(RefCell::new(ctor(args)));
        self.handler = Some(node.clone());
        self.active.push(Active {
            node: node.clone(),
            depth: self.depth,
            class: candidate.class.clone(),
            doc,
        });
        node.borrow_mut()
            .start_element(uri, local_name, q_name, atts)?;
        Ok(true)
    }
}

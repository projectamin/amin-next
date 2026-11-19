//! Reading `machine_spec.xml` — the Rust peer of `Amin::Machine::MachineSpec`.
//!
//! The spec is the machine's contract: which filters exist, where they sit,
//! what they bind to, and which handler/log/generator and `ui:` dialects serve
//! a run. It is XML, so it is read with the machine's own SAX reader — never a
//! DOM (machine-spec-is-a-stream, same as every other Amin document).
//!
//! On an unreadable or malformed spec the machine degrades to "no allowlist,
//! no filters", exactly as the Perl `_parse` degrade path does, rather than
//! failing a boot on a host whose spec is absent.

use std::collections::{BTreeMap, BTreeSet};

use amin_sax::{Attributes, ContentHandler, SaxError};

/// One `<filter>` declaration: its class and every non-structural attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFilter {
    /// The filter class name (Perl package name, e.g. `Amin::Proxy::Route`).
    pub class: String,
    /// The declared attributes, minus `class`/`name` (the class is the source
    /// of truth for a filter's verb, so the spec's `name=` is not kept).
    pub meta: BTreeMap<String, String>,
}

/// A `<handler>` / `<log>` / `<generator>` declaration: its class and attrs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassAttrs {
    /// The class name.
    pub class: String,
    /// The declared attributes, minus `class`/`name`.
    pub attrs: BTreeMap<String, String>,
}

/// A `<ui-dialect target= class=>` row: which render class serves a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiDialect {
    /// The render class for this target.
    pub class: String,
}

/// The parsed machine spec (the Rust form of `MachineSpec->spec`).
#[derive(Debug, Default, Clone)]
pub struct Spec {
    /// The classes the spec declares. `None` = no allowlist (every registered
    /// class is allowed); `Some` = only these — the Rust form of the Perl
    /// `allowed` hash, with `undef` modelled as `None`.
    pub allowed: Option<BTreeSet<String>>,
    /// The `<filter>` declarations, in document order.
    pub filters: Vec<SpecFilter>,
    /// The `<handler>` declaration.
    pub handler: Option<ClassAttrs>,
    /// The `<log>` declaration.
    pub log: Option<ClassAttrs>,
    /// The `<generator>` declaration.
    pub generator: Option<ClassAttrs>,
    /// The `<name>` of the machine.
    pub name: Option<String>,
    /// `target => ui-dialect`.
    pub ui_dialects: BTreeMap<String, UiDialect>,
    /// Raw spec-declared BSAX vocabulary band LocalNames, in document order —
    /// every element-scoped `<filter element=…>` plus any explicit
    /// `<vocab><name>…</name></vocab>`. Unfiltered here: the codec drops core
    /// names and assigns band NAME_IDs (`band_start()`, …) itself, exactly as
    /// the Perl `MachineSpec->spec->{vocab}` does. This makes a spec a dynamic
    /// property of the vocabulary, so an external filter's element travels the
    /// BSAX wire with no core edit.
    pub vocab: Vec<String>,
}

impl Spec {
    /// The degraded spec: no allowlist, no filters (Perl's `_parse` degrade).
    #[must_use]
    pub fn degrade() -> Self {
        Self::default()
    }
}

/// The bundled spec, shared with Perl — the single source of truth. Embedded
/// at compile time so a Rust node carries its contract even with no filesystem
/// copy (`perl-lib/Amin/Machine/machine_spec.xml`).
const EMBEDDED_SPEC: &str = include_str!("../../../../perl-lib/Amin/Machine/machine_spec.xml");

/// Locate and parse the machine spec (≈ `Amin::Machine::MachineSpec`).
#[derive(Debug, Default)]
pub struct MachineSpec {
    path: Option<String>,
}

impl MachineSpec {
    /// A spec resolved from the default candidate list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A spec resolved from `path` first, the default list thereafter.
    #[must_use]
    pub fn with_path(path: impl Into<String>) -> Self {
        Self {
            path: Some(path.into()),
        }
    }

    /// Read and parse the spec.
    #[must_use]
    pub fn spec(&self) -> Spec {
        match self.load_xml() {
            Some(xml) if !xml.is_empty() => parse_spec(&xml),
            _ => Spec::degrade(),
        }
    }

    /// The first readable candidate, or the embedded spec. Order mirrors the
    /// Perl `_candidates`: explicit path, `$AMIN_MACHINE_SPEC`,
    /// `/etc/amin/machine_spec.xml`, `$HOME/.amin/machine_spec.xml`, bundled.
    fn load_xml(&self) -> Option<String> {
        let mut candidates: Vec<String> = Vec::new();
        if let Some(p) = &self.path {
            candidates.push(p.clone());
        }
        if let Ok(p) = std::env::var("AMIN_MACHINE_SPEC") {
            if !p.is_empty() {
                candidates.push(p);
            }
        }
        candidates.push("/etc/amin/machine_spec.xml".to_string());
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                candidates.push(format!("{home}/.amin/machine_spec.xml"));
            }
        }
        for candidate in candidates {
            if let Ok(contents) = std::fs::read_to_string(&candidate) {
                if !contents.is_empty() {
                    return Some(contents);
                }
            }
        }
        Some(EMBEDDED_SPEC.to_string())
    }
}

/// Parse spec XML into a [`Spec`]; degrade on any parse fault.
fn parse_spec(xml: &str) -> Spec {
    let mut collector = SpecCollector::default();
    if amin_sax::parse(xml, &mut collector).is_err() {
        return Spec::degrade();
    }
    let mut allowed = BTreeSet::new();
    for f in &collector.filters {
        allowed.insert(f.class.clone());
    }
    Spec {
        allowed: if allowed.is_empty() { None } else { Some(allowed) },
        filters: collector.filters,
        handler: collector.handler,
        log: collector.log,
        generator: collector.generator,
        name: collector.name,
        ui_dialects: collector.ui_dialects,
        vocab: collector.vocab_names,
    }
}

/// Normalise one element's attributes to `LocalName => Value` — all the spec
/// ever reads (≈ `MachineSpec::Collector::_surface`).
fn surface(atts: &dyn Attributes) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for i in 0..atts.length() {
        let local = atts.local_name(i);
        let name = if local.is_empty() {
            atts.q_name(i)
        } else {
            local
        };
        if !name.is_empty() {
            out.insert(name.to_string(), atts.value(i).to_string());
        }
    }
    out
}

/// A SAX collector for the machine spec itself (≈ `MachineSpec::Collector`).
#[derive(Default)]
struct SpecCollector {
    filters: Vec<SpecFilter>,
    ui_dialects: BTreeMap<String, UiDialect>,
    handler: Option<ClassAttrs>,
    log: Option<ClassAttrs>,
    generator: Option<ClassAttrs>,
    name: Option<String>,
    in_name: bool,
    name_text: String,
    /// The BSAX dynamic vocabulary band (see [`Spec::vocab`]) — raw names in
    /// document order, first-seen wins, core names dropped by the codec.
    vocab_names: Vec<String>,
    in_vocab: bool,
    capturing_vname: bool,
    vname_text: String,
}

impl SpecCollector {
    fn class_attrs(a: &BTreeMap<String, String>) -> Option<ClassAttrs> {
        let class = a.get("class").or_else(|| a.get("name"))?;
        if class.is_empty() {
            return None;
        }
        let attrs = a
            .iter()
            .filter(|(k, _)| k.as_str() != "class" && k.as_str() != "name")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Some(ClassAttrs {
            class: class.clone(),
            attrs,
        })
    }
}

impl ContentHandler for SpecCollector {
    fn start_element(
        &mut self,
        _uri: &str,
        local_name: &str,
        q_name: &str,
        atts: &dyn Attributes,
    ) -> Result<(), SaxError> {
        let name = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        if name.is_empty() {
            return Ok(());
        }
        // Inside <vocab>, only <name> children matter: each contributes one
        // spec-declared LocalName to the BSAX dynamic vocabulary band.
        // Returning early stops <vocab><name> being mistaken for the machine
        // <name>.
        if self.in_vocab {
            if name == "name" {
                self.capturing_vname = true;
                self.vname_text.clear();
            }
            return Ok(());
        }
        if name == "vocab" {
            self.in_vocab = true;
            return Ok(());
        }
        let a = surface(atts);
        match name {
            "filter" => {
                if let Some(class) = a.get("class").or_else(|| a.get("name")) {
                    if !class.is_empty() {
                        let meta = a
                            .iter()
                            .filter(|(k, _)| k.as_str() != "class" && k.as_str() != "name")
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        self.filters.push(SpecFilter {
                            class: class.clone(),
                            meta,
                        });
                        // An element-scoped filter declares a LocalName the
                        // machine's BSAX vocabulary must cover — harvested in
                        // document order (first-seen wins).
                        if let Some(el) = a.get("element") {
                            if !el.is_empty() {
                                self.vocab_names.push(el.clone());
                            }
                        }
                    }
                }
            }
            "ui-dialect" => {
                let target = a.get("target");
                let class = a.get("class").or_else(|| a.get("name"));
                if let (Some(t), Some(c)) = (target, class) {
                    if !t.is_empty() && !c.is_empty() {
                        self.ui_dialects
                            .insert(t.clone(), UiDialect { class: c.clone() });
                    }
                }
            }
            "handler" => {
                if self.handler.is_none() {
                    self.handler = Self::class_attrs(&a);
                }
            }
            "log" => {
                if self.log.is_none() {
                    self.log = Self::class_attrs(&a);
                }
            }
            "generator" => {
                if self.generator.is_none() {
                    self.generator = Self::class_attrs(&a);
                }
            }
            "name" if self.name.is_none() => {
                self.in_name = true;
                self.name_text.clear();
            }
            _ => {}
        }
        Ok(())
    }

    fn end_element(
        &mut self,
        _uri: &str,
        local_name: &str,
        q_name: &str,
    ) -> Result<(), SaxError> {
        let name = if local_name.is_empty() {
            q_name
        } else {
            local_name
        };
        if self.capturing_vname && name == "name" {
            self.capturing_vname = false;
            let trimmed = self.vname_text.trim();
            if !trimmed.is_empty() {
                self.vocab_names.push(trimmed.to_string());
            }
            return Ok(());
        }
        if name == "vocab" {
            self.in_vocab = false;
            return Ok(());
        }
        if name == "name" && self.in_name {
            self.in_name = false;
            let trimmed = self.name_text.trim();
            if !trimmed.is_empty() {
                self.name = Some(trimmed.to_string());
            }
        }
        Ok(())
    }

    fn characters(&mut self, ch: &str) -> Result<(), SaxError> {
        if self.in_name {
            self.name_text.push_str(ch);
        }
        if self.capturing_vname {
            self.vname_text.push_str(ch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_spec_parses_and_declares_the_proxy_filters() {
        let spec = MachineSpec::new().spec();
        let classes: Vec<&str> = spec.filters.iter().map(|f| f.class.as_str()).collect();
        assert!(classes.contains(&"Amin::Proxy::Route"), "Route missing");
        assert!(
            classes.contains(&"Amin::Proxy::RateLimit"),
            "RateLimit missing"
        );

        let route = spec
            .filters
            .iter()
            .find(|f| f.class == "Amin::Proxy::Route")
            .unwrap();
        assert_eq!(route.meta.get("position").map(String::as_str), Some("begin"));
        assert_eq!(route.meta.get("element").map(String::as_str), Some("request"));
        assert_eq!(
            route.meta.get("namespace").map(String::as_str),
            Some("http://projectamin.org/ns/2026/")
        );

        // RateLimit is element-agnostic: no `element` key at all.
        let rl = spec
            .filters
            .iter()
            .find(|f| f.class == "Amin::Proxy::RateLimit")
            .unwrap();
        assert_eq!(rl.meta.get("position").map(String::as_str), Some("begin"));
        assert!(!rl.meta.contains_key("element"));
    }

    #[test]
    fn embedded_spec_carries_the_command_fleet_and_ui_dialects() {
        let spec = MachineSpec::new().spec();
        let commands = spec
            .filters
            .iter()
            .filter(|f| f.class.starts_with("Amin::Command::"))
            .count();
        assert!(commands > 100, "expected the full command fleet, got {commands}");
        assert!(spec.ui_dialects.contains_key("ios"), "ui: ios dialect missing");
        assert_eq!(spec.name.as_deref(), Some("Amin::Machine::Dispatcher"));
    }

    #[test]
    fn malformed_spec_degrades_quietly() {
        assert_eq!(parse_spec("<machine><filter").allowed, None);
        assert!(parse_spec("not xml at all").filters.is_empty());
    }

    // The BSAX dynamic vocabulary band is a property of the spec: element-scoped
    // filters and an explicit <vocab> block both contribute LocalNames, in
    // document order, and the machine <name> is never mistaken for a band name
    // (mirrors Amin::Machine::MachineSpec::Collector->{vocab_names}).
    #[test]
    fn spec_vocab_band_harvests_element_filters_and_vocab_block() {
        let xml = r#"
            <machine>
              <name>Test::Machine</name>
              <filter class="Amin::Proxy::Route" element="request"/>
              <filter class="Amin::Proxy::RateLimit"/>
              <filter class="Amin::Acme::Challenge" element="acme-challenge"/>
              <vocab>
                <name>frob</name>
                <name>  widget  </name>
              </vocab>
            </machine>
        "#;
        let spec = parse_spec(xml);
        assert_eq!(spec.name.as_deref(), Some("Test::Machine"));
        assert_eq!(
            spec.vocab,
            vec![
                "request".to_string(),
                "acme-challenge".to_string(),
                "frob".to_string(),
                "widget".to_string(),
            ]
        );
    }

    // The bundled spec has no <vocab> block, so its band is exactly the
    // element-scoped filters in document order (mostly core `command`).
    #[test]
    fn embedded_spec_band_is_element_scoped_filters_only() {
        let spec = MachineSpec::new().spec();
        let expected: Vec<String> = spec
            .filters
            .iter()
            .filter_map(|f| f.meta.get("element").cloned())
            .filter(|e| !e.is_empty())
            .collect();
        assert_eq!(spec.vocab, expected);
        assert!(!spec.vocab.is_empty());
    }
}

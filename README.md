# Amin

> The Cloud Stripper platform — a unified, SAX-streamed, PQ-safe edge+datacenter control plane that treats XML pipelines, native OS isolation, and binary wire protocols as first-class citizens.

Amin is a *profile execution fabric*, not a config manager, not a PaaS, not a templating engine.  The same profile that builds a custom Linux image, configures a switch port, provisions a host, and renders the admin console's topology view is one XML document processed by one SAX filter graph — and the output of that graph is itself valid SAX, so you can feed it right back in and the fabric will still enforce every contract and trust boundary.

This is the project's defining characteristic.  Everything else follows from it.

- **SAX-first, always.**  Profiles enter Amin as a stream of SAX events.  Every filter in the graph sees every event, and every filter may rewrite or suppress those events before the next stage sees them.  No DOM.  No intermediate trees.  Stream in → filter graph → stream out.
- **Late filters for UI, topology, and network plan output.**  The same profile that provisions a rack can also render a SwiftUI view tree, a network topology SVG, or a switch configuration diff — because those stages run *late* in the SAX chain and only emit their respective events when enabled.
- **BSAX: Binary SAX.**  XML-text-compatible binary encoding with exact SAX event-model parity.  50–75% smaller on the wire; zero-copy decode.  Rust reference implementation in `rust/crates/bsax`; generator and handler classes in `perl-lib/Amin/Generator/BSAX.pm` and `perl-lib/Amin/Handler/BSAX.pm`.
- **AWP/3 PQ-safe wire protocol.**  ML-KEM-768 + X25519 hybrid key exchange over a Noise_XKems-style framed transport.  QUIC transport is optional behind a feature flag.
- **Native OS isolation, not WASM.**  Sandboxing uses the host's native primitive: Linux Landlock + cgroups v2 + seccomp on recent kernels, FreeBSD Jails, iOS App Sandbox, Android SELinux.  POSIX fallback for oddball hosts.
- **Post-Quantum signatures (ML-DSA) for apps and filters.**  Every `.amina` bundle is composite-signed before it reaches production; verification is mandatory *before* the dispatcher even parses the profile.  AI-authored filter contributions carry their own detached signatures and must re-pass the same contract gate as human-authored ones.

---

## Quick Start

Amin's toolchain is managed by [`mise`](https://mise.jdx.dev/).  Installing dependencies is one command:

```bash
cd amin
mise install
```

`mise install` installs the pinned toolchain (Perl 5.38, Rust 1.80, Cargo-binstall, jq) and, on first entry to the directory, the `hooks.enter` handler triggers `mise run bootstrap` — which:

1. Pulls the latest stable CPAN deps listed in [`cpanfile`](./cpanfile) into `./local/` using the mise-managed `cpanm` shim;
2. Installs develop/test Perl dists (Test2, Carton, Perl::Tidy, …);
3. Writes a Carton snapshot at `./cpanfile.snapshot` so a future `carton install --deployment` replays the exact same versions;
4. Fetches the Rust workspace dependencies.

To force a re-run after editing `cpanfile`:

```bash
rm -rf local && mise run bootstrap
```

Then verify the CLI with the bundled example:

```bash
./bin/amin app examples/apps/shop-ui                            # render, full SAX chain
./bin/amin --stream dryrun examples/apps/shop-ui/profile.xml    # streaming dry-run
./bin/amin map examples/apps/shop-ui/map+ui.xml --out=svg       # topology → SVG
./bin/amin ui  examples/apps/shop-ui/map+ui.xml --os=ios        # UI → SwiftUI events
```

Run the test suite:

```bash
mise run test
```

---

## Architecture

```
profile.xml ──SAX──▶ Amin::Machine::Dispatcher ──begin/middle/late filters──▶ Handler (XML / BSAX)
                         │                                            │
                         │  Amin::Cond::OS                            ├─ Amin::Filter::Map::Topology (late)
                         │  Amin::Command::{Build,Exec,Mkdir,Echo,…}  ├─ Amin::Filter::UI::SwiftUIView (late)
                         │  Amin::Elt (IPC::Run harness)              │
                         └────── BSAX ⇄ XML roundtrip ────────────────┘
                             (Generator / Handler under perl-lib/Amin/)
```

The dispatcher in [`Amin::Machine::Dispatcher`](./perl-lib/Amin/Machine/Dispatcher.pm) builds the filter chain at startup based on `position` tags: `begin → middle → late → permanent → end`.  The `ui` and `map` stages are late-only filters that the CLI toggles independently (`amin map …`, `amin ui …`, `amin render …`).

OS and platform branches (`<amin:linux>`, `<amin:freebsd>`, `<amin:ios>`, …) are SAX event-level rewrites in [`Amin::Cond::OS`](./perl-lib/Amin/Cond/OS.pm) at the head of the chain, so downstream filters never see events destined for a different host.

### The core loop: output → input → re-verify, always

Because Amin's output is itself a valid SAX event stream (XML or BSAX), you can pipe the result of a render pass straight back in:

```
profile.xml ──(render)──▶ rendered.xml ──(diff + patch filter)──▶ patched.xml ──(verify + sign)──▶ deploy
```

Contracts, signatures, and trust boundaries are enforced on *every* pass, not just the first.  A filter (human or AI) that mutates a profile does not bypass verification simply because the input was "already approved."

---

## Repository Layout

| Path | What it is |
|---|---|
| [`bin/amin`](./bin/amin) | CLI entry point.  Auto-rexecs into the mise-managed Perl and stitches `./perl-lib` + `./local/lib/perl5` onto `@INC`. |
| [`perl-lib/Amin.pm`](./perl-lib/Amin.pm) | Public façade: `Amin->new(Mode => …, Handler => …, Log => …)->parse($xml)`. |
| [`perl-lib/Amin/Machine/`](./perl-lib/Amin/Machine/) | SAX filter chain and dispatch — the *machine*. |
| [`perl-lib/Amin/Command/`](./perl-lib/Amin/Command/) | Command handlers: `Build`, `Exec`, `Mkdir`, `Echo`, `Remove`, …  Each subclasses [`Amin::Elt`](./perl-lib/Amin/Elt.pm), which drives the `IPC::Run` harness. |
| [`perl-lib/Amin/Cond/`](./perl-lib/Amin/Cond/) | Condition rewrites.  `OS` today; network topology, tier, region, and feature-gate conditionals next. |
| [`perl-lib/Amin/Filter/Map/`](./perl-lib/Amin/Filter/Map/) | Late filter for network-topology and adminlist map rendering. |
| [`perl-lib/Amin/Filter/UI/`](./perl-lib/Amin/Filter/UI/) | Late filter for mobile / desktop UI view-tree rendering (SwiftUI today; Jetpack Compose next). |
| [`perl-lib/Amin/Generator/BSAX.pm`](./perl-lib/Amin/Generator/BSAX.pm) + [`perl-lib/Amin/Handler/BSAX.pm`](./perl-lib/Amin/Handler/BSAX.pm) | Binary SAX codec; 1:1 vocab parity with `rust/crates/bsax/src/vocab.rs`. |
| [`perl-lib/Amin/Util/`](./perl-lib/Amin/Util/) | Shared helpers (Fold/allow-lists, provenance tags, …). |
| [`rust/crates/awp3/`](./rust/crates/awp3/) | **A**min **W**ire **P**rotocol v3 — PQ-safe framed transport. |
| [`rust/crates/aminexec/`](./rust/crates/aminexec/) | Per-process sandbox, cgroup v2 metrics, platform impls for Linux / FreeBSD / iOS / Android. |
| [`rust/crates/bsax/`](./rust/crates/bsax/) | Rust Binary SAX codec; `no_std` compatible; `std` feature adds `bytes`. |
| [`examples/apps/shop-ui/`](./examples/apps/shop-ui/) | Reference app bundle. |
| [`docs/app-bundle-contract.md`](./docs/app-bundle-contract.md) | Full `.amina` bundle spec, including AI-assisted authoring tiers. |
| [`t/`](./t/) | Perl integration tests.  Run with `prove -r t/` or `mise run test`. |
| [`.mise.toml`](./.mise.toml) | Toolchain, env vars, tasks, auto-bootstrap hooks. |
| [`cpanfile`](./cpanfile) | Runtime CPAN requirements — intentionally **unpinned** (latest stable); `cpanfile.snapshot` is the reproducibility lock. |

---

## Usecases (outline)

### 1. Custom Linux image builds as first-class deploy inputs

Custom kernel, custom `userland`, custom signing key, per-build reproducibility — a profile is the build plan, the test plan, and the deploy plan in one document.  `<amin:command name="build">` runs the kernel/configroot/pkg tree; `<amin:result>` emits a signed manifest; the same manifest feeds back as a `<amin:require kind="manifest" sha3-512="…">` gate on the next deploy pass.  No separate build repo; no separate artifact DSL; build output flows into the machine the same way every other profile fragment does.

### 2. Network management, switch config, and topology as SAX events

Rack, spine, leaf, port, vlan, sflow, mirror — all first-class SAX elements.  The *same* profile that provisions hosts also produces a topology map (`amin map`), a switch-config diff, and a signed change-request.  Because output is re-parsable SAX, a rollback is literally: save the emitted config-set, feed it back in with the inverse patch filter, re-sign, re-deploy.  Contracts (e.g. "port-eth0 must never carry vlan-4095 untagged") are enforced on the *rollback output* exactly as on the forward pass.

### 3. Bare-metal service deploys (Linux / FreeBSD / POSIX edge)

`aminexec` launches each process inside Landlock + seccomp + cgroup v2 on Linux ≥ 6.2, or Jails on FreeBSD.  No containerd, no shim, no pause container, no runtime class to babysit.  The dispatcher writes the same `<amin:result kind=success rc=0 pid=… duration=… cgroup_cpu=… cgroup_mem=…>` SAX events for a 128-core Ampere node as for a Raspberry Pi Zero, so aggregation sees one shape instead of seven.

### 4. Mobile and desktop UI view trees from the *same* profile

Late `ui:` filters render SwiftUI (and next, Jetpack Compose) view trees from the service profile's identity, schedule, storage, and observability blocks.  The admin console UI, the on-device settings panel, and the deploy plan all pull from the same source of truth — and when a filter mutates the schedule, the UI tree emitted on the next pass is automatically consistent, because contracts ("sla.99pct_latency_ms must be a positive integer") run against the *mutated* output before it even reaches the UI stage.

### 5. Output is parsable, mutable, and feeds back in — with contracts and trust boundaries intact

This is Amin's most compelling attribute.

1. **Parsable.**  Output is always a SAX event stream (XML text or BSAX).  Every tool that reads SAX — including the dispatcher itself — can read the result of a prior Amin run.  No schema registry, no separate log format, no telemetry translation layer.
2. **Mutable.**  Any filter (human-authored, AI-authored, or generated from a diff tool) can insert, rewrite, or suppress events in the stream.  Patches are explicit SAX-level transforms, not opaque blobs.
3. **Enforceable on re-entry.**  Every time the stream re-enters the dispatcher, the machine runs the full contract gate again: signature verification, sandbox tiers, provenance allow-lists, cross-NS integrity checks, and user-specified invariants.  A filter that removes a `<amin:require>` is *itself* rejected by the next pass if that violates a higher-priority contract.  The result: Amin can ingest its own outputs, permit arbitrary mutation by downstream tools and agents, and still hold the line on what gets executed.

### 6. AI / LLM filter pipelines with verifiable source and ownership

AI- and LLM-authored filters are *just filters*: they plug into the same `begin/middle/late` positions and produce the same SAX events a human would.  But Amin does not treat them as equivalent to human code on trust alone.

- **AI output is always marked.**  Every event an AI filter emits carries a `provenance.author_kind=ai` tag and a `provenance.filter_id=<filter sha3>` back-reference.  Provenance tags survive round-trips through BSAX and through `feed-back-in` passes.
- **AI output is always gated.**  AI-authored fragments are **Tier 0** (see [app-bundle-contract.md § AI-Assisted Authoring](./docs/app-bundle-contract.md)) and cannot reach a `prod` stage until ≥ 1 human signature promotes them to Tier 2.
- **Source and ownership are verifiable end-to-end.**  Composite ML-DSA signatures, filter-level checksums embedded in each emitted event, and the re-entry contract gate together mean you can answer, for any SAX event reaching production: *who (or what) wrote it, which filter produced it, who promoted it, and which prior Amin runs signed it into its current form*.
- **AI filters run inside the same sandbox boundary.**  An LLM-backed filter that executes subprocesses (e.g. to summarise a diff or perform a lookup) runs under the same `aminexec` Landlock policy as every other command — and its stdout/stderr is captured as `<amin:result>` SAX events, so you can feed *its own output* back into a downstream verification filter.

### 7. PQ-verified deployments end-to-end

Every `.amina` bundle is composite-signed with ML-DSA.  Every cross-control-plane message runs over AWP/3's ML-KEM-768 + X25519 hybrid handshake.  Regulated workloads (PCI, HIPAA, FedRAMP) land in defaults that don't require a separate "migrate off RSA" backlog item.

---

## Path Forward

**Short-term:**
- ✅ SAX dispatcher + filter chain + OS conditionals
- ✅ Built-in command handlers: `build`, `exec`, `mkdir`, `echo`, `remove`
- ✅ Perl integration test suite, 11 tests under `t/`
- ✅ BSAX codec (Perl + Rust reference implementations)
- 🔲 *Wire `aminexec` in as the exec backend* — command handlers currently use `IPC::Run` from `Amin::Elt`; swapping to `aminexec` brings cgroup metrics + Landlock enforcement into every command result block.
- 🔲 *ML-DSA composite signing + `aminsig` CLI* — prototype in sibling repo; integrate into `bin/amin sign|verify`.
- 🔲 *`amin app scaffold --from-prompt`* — Tier 0 LLM skeleton generator; output must be human-signed before deploy.
- 🔲 *Asymmetric cost attribution* — cgroup v2 CPU/memory × negotiated unit prices → `billing.owner` invoice lines.

**Medium-term:**
- Network-management filter family: switch config, vlan plans, sflow/mirror, rack-topology output with verification contracts.
- Custom Linux image build pipeline as a first-class filter pack (`amin build image …`).
- Android Jetpack Compose late `ui:` filter, parallel to SwiftUIView.
- Sandbox tier enforcement: `prod` apps → `linux-strict` Landlock; `staging` → `posix-minimal`; mismatch is a hard reject before parse.
- QUIC transport for AWP/3 via the `quic` feature flag.
- Provenance byte-identity guarantee: same inputs → byte-identical `provenance.xml` pre-signature, across control planes.

**Long-term:**
- End-to-end E2EE inter-node verification fabric, replacing TLS hop-by-hop.
- SAX-level hardware / embedded profiles: the same graph model drives `amin device flash …` over CMSIS-DAP / UART / SWD.
- Control-plane federation with asymmetric cost attribution per partner org: your processes run on my metal; you get the invoice, automatically, from cgroup counters.

---

## Conventions & Principles

- **Modern Perl 5.38+ everywhere.**  `use v5.38; use experimental 'signatures';` is the default.  `Class::Tiny` for object plumbing.  No Moose, no Moo.
- **SAX pipeline purity.**  If a filter aggregates events, it buffers *locally*; filters must not reach across the graph.  This rule is what lets us swap the `Writer` handler for `BSAX`, or toggle late filters from a single CLI flag.
- **UI and map logic in late filters, never in the data source.**  `profile.xml` describes *what is true*; how it gets drawn on iOS, Android, or an SVG topology graph is downstream.
- **Native OS isolation over WASM.**  The platform already ships strong, well-audited primitives; wrapping them in a second sandbox adds a second attack surface.
- **Unpinned CPAN, pinned by snapshot.**  `cpanfile` has no version pins so `mise run bootstrap` picks up security fixes immediately; when a set of versions is good, commit `cpanfile.snapshot` and use `carton install --deployment` for CI and production machines.
- **Integration tests, not 3rd-party re-tests.**  `t/` tests contracts the Amin namespace owns; it does not re-test `XML::LibXML` or `Class::Tiny`.
- **Re-entry is a first-class operation.**  Any new output shape, new filter, or new wire format that cannot round-trip through the dispatcher *and still pass contracts* is a bug, not a feature.

---

## FAQ

**Why XML / SAX instead of JSON / YAML / Protocol Buffers?**  Because SAX is the only data model where an arbitrary number of filters can rewrite, suppress, and emit events in a single pass without ever materialising a tree.  JSON and protobuf each force a parse-tree; BSAX preserves SAX semantics *and* gets the compact binary wire format back.

**Why not a YAML / Helm / Terraform-style templating language?**  Because a SAX filter can perform any transformation a template can, with a strict event contract, and without learning a third language.  Need to insert `<amin:command name="echo">…</amin:command>` after every `mkdir`?  That's a 20-line `begin` filter.  Template engine not required.

**Why Perl for the dispatcher and Rust for the exec / wire stack?**  Perl still has the best SAX ecosystem on the planet, plus 30 years of production-safe process handling.  Rust is the only language that lets us ship Landlock + cgroup v2 + iOS FFI + Android JNI out of a single crate workspace with no runtime overhead.  The pipeline is deliberately language-agnostic at the wire boundary: feed a BSAX stream from Perl, Rust, Swift, Kotlin, or anything that can write 8-bit bytes, and the machine treats it identically.

**Why treat AI filters as regular filters instead of hiding them behind a special CLI?**  Because the trust boundary is the contract gate, not the author's species.  Marking AI output (`provenance.author_kind=ai`, filter sha3 back-reference) and enforcing the Tier-0-to-Tier-2 promotion path on re-entry is enough to audit every event AI tools touch, while letting AI filters produce exactly the same SAX events a human would — which is exactly what makes the round-trip and contract-enforcement story work uniformly for *all* mutations.

## License

BSD-2-Clause.  See individual crates under `rust/` for workspace-level declarations.

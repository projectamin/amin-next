# AXA — HTML UI layer for Amin

Status: plan / not implemented.
Scope: make `examples/apps/shop-ui` a real web application whose every
interaction is a genuine Amin profile round-trip.

---

## 1. Did AXA exist in `amin-legacy`?

**No — there is no reference to AXA anywhere in `../amin-legacy`.**

Evidence gathered (repo at `projectamin/amin-legacy`, `master`, 490 commits):

| Check | Result |
|---|---|
| `grep -rin axa` over the working tree | 0 hits |
| `git log --all -S"axa" -i` (pickaxe) | 0 hits |
| Every blob in `git rev-list --objects --all` (490 commits), case-insensitive substring | 0 hits |
| Commit messages (`git log --all -i --grep=axa`) | 0 hits |
| Branches | only `origin/master` |

The blob sweep used a *substring* match, so it would also have caught
`Axapta`, `taxable`, or a path like `lib/Amin/Axa/`. Nothing.

The only HTML-adjacent code in the legacy tree is `lib/Amin/SAXP.pm` (in the
sibling `amin-legacy` checkout, so deliberately not linked — it is outside
this workspace), a fork of `Pod::SAX` that turns **POD documentation into
SAX events** (markup → SAX). Its
`%HTML_Escapes` table is POD's `E<...>` entity table, not a page renderer.
`HTML::Tagset` / `HTML::HeadParser` in `Makefile.PL` and `INSTALL` are
transitive deps of that POD parser. There is no web layer, no template
engine, no CGI, no HTML output path.

On GitHub, `projectamin` has 8 public repos — `amin-next`, `samin`, `amin`,
`adistro`, `kamin`, `camin`, `bitcache`, `amin-legacy` — none named or
described as AXA. Combined with the clean history, the reasonable
conclusion is that AXA lived in an archive/private tree that was never
pushed. Recovering it needs the original tarball (or Bryan), not the
repos. Worth noting: AXA is the exact **inverse** of `SAXP.pm` — SAXP took
markup in and emitted SAX; AXA takes SAX out and emits markup.

---

## 2. What exists in Amin 3.0 today

The seams AXA needs are already there, but the render side is stubbed:

- `bin/amin` accepts `--os=html` and validates it
  ([bin/amin:119](../bin/amin)), but `Amin->new` stores `ui_os` and
  `Amin::parse` never forwards it to the Dispatcher
  ([perl-lib/Amin.pm:21](../perl-lib/Amin.pm)). The value is dead.
- `--out=svg|dot|xml` is likewise parsed and validated, and `map_out` is
  never passed to `Amin::Filter::Map::Topology`. `amin map … --out=svg`
  returns **XML**, not SVG.
- `Amin::Filter::UI::SwiftUIView` is an identity normalizer: `_map_view()`
  re-emits the same `ui:*` element with re-prefixed attributes. It does
  not generate SwiftUI, let alone HTML.
- `Amin::Filter::Map::Topology` accumulates nodes/regions/edges in memory
  and emits `map:node` events; nothing serializes them to SVG/DOT.
- There is no HTTP server, no PSGI/Plack, no template engine anywhere in
  the tree or `cpanfile`.

So: `amin ui --os=html` today prints the `ui:` tree as XML. The layer is
absent, and the CLI hook for it is already reserved.

---

## 3. The model: profile in, profile out

AXA is **not** a second framework beside Amin. It is a notation and a set
of filters. An HTTP request is just another way a profile enters the
dispatcher; an HTTP response is just a profile leaving it. The app sends
its own profile, and the filters installed for that app interpret it.

```
transport — interchangeable; only the codec differs
  stdin/file  ·  POST /_axa  ·  mesh peer  ·  queue / mail ingest
                             │  a profile, in the app's own dialect
                             ▼
   Dispatcher ── one chain, whichever transport fed it ───────────────
     permanent ═ outermost; machine-installed, never app-declared ═
               Auth::ZCap      verify token → principal + claims
               Auth::Policy    element → declaring filter → permissions
               audit / provenance
     begin : Session · routing (app filters)
     middle: Auth::Egress · app filters · Amin::Command::*
     late  : Amin::AXA::Element::*   one filter per ui: element,
             spliced lazily by element name
             Amin::Filter::Map::Topology (admin views, unchanged)
     end   : billing / provenance (unchanged)
                             │
                             ▼
              response profile (still valid SAX; XML or BSAX)
                             │  Content-Type: text/html (fragment + swap)
                             ▼
              transport writes it back (socket, stdout, peer, …)
```

The response profile is the source of truth. `--out=xml` returns it as a
profile, `--out=bsax` returns the binary codec, `--out=html` runs the late
HTML filter. Same document, same contracts, three renderings. Debugging a
page is `curl`-ing the profile — no separate server-side template state.

Notice what is *above* and *below* the dispatcher. Above it, only a codec.
Below it, nothing transport-aware. Swap the transport and not one filter
changes, because the authorization decision (§5) lives in `permanent`,
where neither a transport nor an app bundle can displace it.

This preserves the project's five invariants: SAX-first, late filters for
UI, output is re-parsable, contracts run on every pass, AI-authored
filters stay gated.

---

## 4. Design decisions

### 4.1 Filters do the work; the server is dumb plumbing

`Amin::AXA::PSGI` should be < 150 lines: read body → feed dispatcher →
write status/headers/body. It does not know what a shop is, what an
action is, or who may do what. Routing, cart logic, and rendering are
filters at declared positions, registered through `machine_spec.xml` like
every other filter — and the [app bundle contract](app-bundle-contract.md)
already reserves a `machine_spec.xml` for exactly this: the app's own
filter list. (That file is not wired up today; merging it with the
machine's spec is M1's job.) Authorization is in `permanent` (§5). No
request expander, no special request path, no separate MVC stack, no
second router.

### 4.2 The wire carries a profile; only filters have effects

The app sends its own profile, in its own dialect, and app filters
interpret it. There is no server-side step that reads an action name and
manufactures a document, because the app already knows how to say what it
wants — that is the point of one dialect for every transport.

An earlier draft of this plan made it a hard rule that a client must never
send a profile containing `amin:` elements. That rule defended the wrong
thing. A profile is data: on its own it does nothing. The only vocabulary
with effects is `amin:` — `exec`, `spawn`, `net`, … — and it is checked by
filters the operator installed, not by anything the sender supplies. So
`amin:exec` over HTTP is exactly as powerful as `amin:exec` on stdin,
which is the property we want (§5.1); a transport that refused it would be
*adding* a policy the CLI does not have.

What must not be conflated: **filters are code, profiles are data.** An
app bundle does ship code (`filters/`, signed, Tier 0→2 gated), and
installing that bundle is the trust decision. Afterwards the app's filters
are trusted to interpret the app's profile — but no profile, however it
arrives, can make the machine load a new filter or define a new action.
"Send your own profile" never means "send your own code".

The no-JS form path is the one place a body is not already a document:
`FormCodec` turns `axa.action` + `axa.param.*` into the app's own declared
fragment. It has no policy and no domain knowledge, and it cannot emit
anything the bundle does not already contain. **Encodings are not
dialects.**

### 4.3 One filter per element, not one renderer

There is no monolithic `Render::HTML`. **Each `ui:` element is a filter**
at `late`, element-scoped, declared in `machine_spec.xml`:

```xml
<filter class="Amin::AXA::Element::Button" position="late"
        element="button" namespace="http://projectamin.org/ns/ui/1" />
```

`_LazyGate` already splices element-scoped candidates when the element's
`start_element` arrives and un-splices on its close. That is exactly the
composition mechanism this needs, and it keeps rendering event-by-event:
no DOM, no recursion into a tree, no central switch statement over a
closed set of elements.

Each filter does three things: validate its attributes, emit the opening
`html:*` events in `http://www.w3.org/1999/xhtml`, and forward the
children. It emits the closing events on `end_element`. Children are
rendered by their own filters as the stream flows through them, so
`ui:card` never needs to know what a `ui:button` is.

Consequences:

- **A new UI element is a new filter.** `ui:product-card` in an app
  profile is a filter in the app's `filters/`, signed and loaded like any
  other. No core change, no registry fork.
- **An app can override a built-in element** by registering a filter for
  the same element/namespace with a higher `priority` meta. The
  dispatcher picks the first match; equal priorities are an error, not
  last-one-wins. `priority` needs adding to the candidate sort in
  `_LazyGate`.
- **AI-authored element filters** go through the existing Tier 0 → Tier 2
  gate; nothing HTML-specific is trusted differently.
- **The page skeleton is a filter too** (`Amin::AXA::Element::Document`
  on `ui:app`) — doctype, `<html>`, `<head>`, asset links — not a special
  case in the handler.
- **`Amin::Handler::HTML` stays a dumb serializer:** void elements,
  attribute escaping, and dropping non-`html:` events (debug mode keeps
  them in an HTML comment).

Test surface is per element: one filter plus a recording handler. No
server, no fixtures, no full document needed.

### 4.4 Binding stays deliberately small

`{@id}`, `{.}`, `{text()}`, `{count(path)}`, and pre-resolved `{cond ?
a : b}`. Each element filter resolves its own bindings against the
*response* profile as it emits. Unknown expressions are a hard error
(fail closed), not silently empty. No loops over arbitrary XPath, no Perl eval, no template
language — the README's "not a templating engine" claim is a feature.

### 4.5 HTML never comes from strings

All text and attributes are escaped by the writer. Raw markup is not
available to `ui:` authors. An explicit `ui:html` escape hatch, if ever
added, requires a signed filter and is off by default.

### 4.6 Full page on GET, fragment on action

`<axa:target selector="#cart" swap="innerHTML">` wraps the changed region
in the response. The renderer emits `data-axa-target` / `data-axa-swap`,
and a ~30-line `axa.js` does the fetch + swap. Forms degrade: without JS
they post normally and receive a full page. No client-side state, no
hydration, no build step.

### 4.7 Sessions and state

Cookie carries an opaque session id + CSRF token, both signed. State lives
behind `Amin::AXA::Store` (get/set/delete keyed by session): in-memory
adapter for the demo, Bitcache or SQLite adapter later. No PII in the
cookie. Checkout carries an idempotency key so double-submits return the
same order.

A session is **bound to a principal**: the store record keeps the ZCap
verifying key and tenant that created it, and each request must present a
token that verifies to that same key. A cookie on its own is never a
principal — it only selects which store record to attach to the principal
the token proves (§5.3).

### 4.8 Server: persistent process, streaming out, spec read once

Measured on this checkout (mise perl 5.38.2, 7.2 KB `map+ui.xml`, the
291-filter stock spec, 200-iteration averages):

| Stage | Cost |
| --- | --- |
| process load (`Dispatcher` + `Writer` + `Log`) | 29.5 ms, once per process |
| `XML::LibXML::SAX` parse of the document | 0.45 ms/req |
| `MachineSpec->new->spec` (re-reads `machine_spec.xml`) | 1.93 ms/req |
| `_build_chain` | 2.26 ms/req |
| full warm `Dispatcher->run` | 9.33 ms/req |
| `./bin/amin ui … --os=tty` end to end | ~150 ms |

Two facts follow, and both dwarf the transport question. The
per-invocation CLI model costs ~16× a warm request, so a persistent worker
is the entire win. And **45% of a warm request is spec resolution + chain
construction, not rendering.** At 9.33 ms of application work per request,
the gap between the fastest and slowest PSGI server — Gazelle vs Starman on
a *hello-world* is 0.009 ms vs 0.03 ms of request handling — is ~0.2% of a
request. No server choice pays for itself before those two rows do.

So the server is fixed by design, not by benchmark: **read the spec once at
startup and keep it for the lifetime of the process**, stream the response
out, and spend the per-request budget on the document rather than on the
machinery. Concretely, at boot:

1. `Amin::Machine::MachineSpec->new->spec` — one parse, 1.93 ms, kept
   forever. `run` already accepts a pre-resolved `machine_spec => \%spec`
   ([Dispatcher.pm:39-51](../perl-lib/Amin/Machine/Dispatcher.pm#L39-L51));
   the adapter never passes a path again.
2. Register `Amin::Auth::ZCap`'s trust anchors (`@TRUST_ANCHORS` is
   register-only and therefore process-scoped by design —
   [ZCap.pm:34-40](../perl-lib/Amin/Auth/ZCap.pm#L34-L40)).
3. One warm-up chain build, which is what loads all 291 filter classes
   (the `require` inside `_build_chain`). After that, `->new` per filter is
   the only cost left.

That turns 9.33 ms into ~7.40 ms with no behavioural change at all. The
remaining 2.26 ms is a *fresh chain instance per request* — see §4.9 for why
that is currently mandatory, and for the reset protocol that would retire
it (a further ~24%).

**Streaming is the default, not an option.** `Amin::Handler::Writer`
already has an `fh` + `autoflush` path (`_push` prints and flushes when
`fh` is set), so incremental output exists; what does not exist yet is an
adapter writer that skips the `buf` accumulation. The streaming design has
one sharp edge, and it is the same one PSGI already encodes:

- PSGI's `psgi.streaming` is a SHOULD, not a MUST, and the spec fixes status
  and headers at the moment the responder is called. There is no revising
  them after the first body byte.
- `Writer` pushes the XML declaration at `start_document` — *before* any
  filter has authenticated anything. So the adapter cannot simply forward
  bytes from the first event.

The resolution is a **status latch**: the adapter holds the first bytes (the
XML declaration and root open tag — a few dozen) and does not call the
responder until it can name a status. The decision arrives early, because
ZCap checks the token at the first child of `root` and suppresses the rest of
the document on failure. So: on an `amin:status` with a negative rc before
any body content → that rc maps to the HTTP status and the body is the error
rendering; otherwise → 200, release the latch, and stream everything after.
What the latch cannot do is change status for a failure that occurs *after*
the commit point — a `permissions` violation on a deep element (§5.4) — and
that is honest: such a failure rides in the body, as `amin:status` already
specifies. A full-page GET can render it as an error page; a fragment swap
can swap the fragment. That is what the streaming contract costs, and it is
paid in the body, not in the status line.

The adapter must check `$env->{'psgi.streaming'}` and fall back to buffering
when the server does not advertise it — the same code path, with the latch
released at `end_document`.

`plackup`/Starman behind nginx, one worker per core. Never a `bin/amin`
subprocess or fork-per-request: that is the 29.5 ms load, every page. For the
alternatives and why they do not win: Mojolicious/Hypnotoad buys a different
framework rather than a faster SAX pipeline (`Mojo::Server::PSGI` consumes a
PSGI app, so it stays inside this design); nginx + FastCGI removes a socket
hop but adds `FCGI`, whose 0.44–0.82 series is reported to carry
CVE-2025-40907, and still needs `fastcgi_buffering off` to pass streams;
mod_perl2's current release is 2.0.13 from October 2023 and HTTP/2 under its
prefork MPM is poor; Twiggy and Feersum become the interesting choice only
when the event loop itself is the point (backpressure across many idle
streams), not because streaming alone requires them.

`Plack::Runner` for `amin axa serve`. Tests use `Plack::Test` (no sockets,
deterministic) plus one loopback smoke test. Add `Plack` to `cpanfile`.

### 4.9 Request isolation in a long-lived process

A fresh `Dispatcher` per request is necessary but not sufficient. The
isolation question is *what may outlive a document*, and it has four
answers — three of which are already correct in the codebase and one that is
not.**Safe to keep for the process lifetime.** The parsed spec (`$spec->{filters}`
is an array of `{class, meta}` hashes, read-only after parse) and the
read-only memoized caches — `MachineSpec`, `SwiftUIView`'s `%known`,
`Bitcache`, `ToolPaths`, `AI::Embed`, `UCC::Instruments`, `ZCap`'s `$cv`,
`Discovery::Mesh`'s `$MOCK` — all of which are `state`-initialized constants
or frozen hashes.

**Mutable globals that must be sealed before serving.** Two registries look
process-scoped but are not read-only, and both would silently change the
behaviour of every request after them:

- `%FILTERS` is **not** frozen at `INIT` — only `%RUNTIME_ALLOWED` is
  ([Dispatcher.pm:18-23](../perl-lib/Amin/Machine/Dispatcher.pm#L18-L23)):
  `register` pushes to `%FILTERS{$pos}` unconditionally, and `_build_chain`
  merges runtime registrations into the spec
  ([Dispatcher.pm:318](../perl-lib/Amin/Machine/Dispatcher.pm#L318)). So in a
  long-lived process, a late `register()` from an app bundle or a test
  helper would alter the chain that every *subsequent* request builds. The
  adapter asserts the registry is sealed before it accepts its first
  request, and the CLI's `--with-begin` / `--with-middle` / `--with-late` /
  `--with-end` flags become boot-time-only.
- `@TRUST_ANCHORS` is not push-only — `clear_trust_anchors` exists
  ([ZCap.pm:48](../perl-lib/Amin/Auth/ZCap.pm#L48)). Rotation is legitimate,
  but it happens at boot or between requests, never mid-document.

**Must be per-request.** Every filter's traversal state: `ZCap`'s
`{_stack,_suppress,_tier_set,_zone_set,_netpol_set,_zcap,_element_seq,
_first_root_stage_seen,_tenant_injected,_enforce_check_done,
_doc_zcap_error_rc,_doc_error_status_emitted,_vpc_open}`, `_LazyGate`'s
`{active,Handler,depth}`, and `Writer`'s `{buf,stack,depth}`. This is why
§4.8's step 3 warms classes rather than caching instances: the chain is
stateful, so it is rebuilt per request today.

**The landmine: `Class::Tiny` ref defaults are one shared reference per
class.** A non-CODE default is assigned by reference on first read —
`$_[0]{$name} = $default` — so every instance of a class shares the one
arrayref. Verified, not inferred:

```
request 1 after 3 unclosed     stack depth: 3  LEFTOVER
request 2 before any event     stack depth: 3  LEFTOVER
```

That is two `Amin::Handler::BSAX` instances; the second starts with the
first's nesting because `stack => []` is a non-CODE default and the handler
calls the accessor (`$self->stack`, [BSAX.pm:159](../perl-lib/Amin/Handler/BSAX.pm#L159),
[BSAX.pm:163](../perl-lib/Amin/Handler/BSAX.pm#L163)). It is latent today
only because one process handles one document.

The rest of the codebase dodges this by accident: `SwiftUIView`, `Topology`,
`Generator::BSAX`, `Bitcache` and `Elt` all declare the same kind of ref
default but read their fields by direct hash access (`$self->{stack}`), which
autovivifies fresh and leaves the declared default as dead code. The fix is
to make the house rule explicit — **ref defaults are always `sub { [] }` /
`sub { {} }`** — and `Amin::Handler::Writer` already sets that pattern
(`stack => sub { [] }`). One-line change per class, and a test that instantiates
each spec filter twice and asserts the refs are distinct.

**The deep issue: scope is a package global, not per-instance.**
`Amin::Auth::ZCap`'s `$CURRENT_SCOPE`
([ZCap.pm:493](../perl-lib/Amin/Auth/ZCap.pm#L493)), `Amin::Sandbox`'s and
`Amin::Net::Fabric`'s equivalents are file-scoped `my` variables exposed by
class methods, and at least ten modules read them that way — `AI::Gate`,
`AI::Embed`, `AI::Memory`, `Schedule::Placement`, `Billing::CgroupV2`,
`Command::Exec`, `Command::Spawn`. Fresh instances cannot fix this: it is a
global channel. In a long-lived process, a document that is suppressed
mid-way leaves the previous document's tenant, sandbox and net scope in
place for the next one.

The plan's answer is layered, smallest first:

1. **Clear at document boundaries.** ZCap's `start_document`/`end_document`
   reset all three scopes. That is a few lines and it makes one-process-one-
   document sound today.
2. **Assert, do not hope.** A test that runs a token-bearing document
   immediately followed by a tokenless one, and asserts the second sees
   `undef` scopes — the shape `t/16` and `t/22` already use for the
   clear-on-end contract.
3. **The correct long-term shape: an explicit request context.** §5.5's
   `Auth::Egress` already needs "how does the gate get the verified scope" —
   and the answer is the same object: a per-request context passed down the
   chain, which retires `$CURRENT_SCOPE`, `stash_for_spawn` and the class-
   method accessors in one move. That is a core change, so it is staged
   after the adapter, not in it.

Until (3) lands, (1) plus fresh instances per request is what the adapter
can rely on — and it is exactly the property the M2 isolation test pins.

---

## 5. Transport is not the trust boundary

The intent is that Amin does the same things over every transport: a
profile on stdin, a POST from a browser, a mesh peer, a queue or mail
ingest. Only the codec differs. So there is exactly **one** authorization
path — the `permanent` region — and it is the same path regardless of who
delivered the bytes.

### 5.1 One chain, every transport

`Amin::Auth::ZCap` is element-agnostic (no `element=` attribute), so
[`_build_chain`](../perl-lib/Amin/Machine/Dispatcher.pm) places it in the
*base* graph rather than in the lazy candidates. It is therefore present
for `Dispatcher->run`, for event-fed dispatchers, and thus for every
adapter that exists or will exist. That is the property to protect: a
transport adapter must never be able to assemble a dispatcher without it,
and must never implement a second, weaker check beside it.

Parity becomes a test rather than a promise: the same profile fed through
`amin render`, `amin axa run`, `POST /_axa`, and an in-process mesh peer
must produce byte-identical response profiles.

### 5.2 `permanent` is outermost, and only the machine writes it

`_build_chain` wraps positions in the order `end → late → middle → begin →
permanent`, so **`permanent` ends up outermost overall** — the code says it
outright: *"permanent ends up outermost overall (trust boundary sees events
first — TR-2.1)"*. Within a position the loop wraps in `reverse`, so the
first-listed filter is that position's outermost — verified by building a
chain from a two-entry `permanent` spec in both orders: the head comes
back as whichever class was listed first.

And `permanent` is **empty** in the stock spec (291 filters, none of them
permanent). The region exists, it is outermost, and nothing is in it —
which is precisely why the trust boundary today sits one region too deep,
at `begin`.

Two invariants follow. Neither is enforced today.

1. **Anything that must run before app filters has to be `permanent`.** A
   `begin` filter is outside `middle` and `late`, but it is not outside
   another `begin` filter — and app filters may be declared at `begin`
   (routing is one). Merged order within a position depends on spec order
   and on the runtime `%FILTERS` merge, so a trust filter placed at `begin`
   can end up *inside* app code.
2. **No app bundle may declare a `permanent` filter.** `_build_chain` merges
   whatever the resolved spec contains; nothing today distinguishes the
   machine's spec from a bundle's, so `<filter position="permanent">` in an
   app would put app code outside the trust boundary. Refuse the bundle at
   load — do not silently skip the entry.

The merge itself must be machine-first: the resolved chain is the
machine's `permanent` entries in their declared order, then the bundle's
entries at `begin`/`middle`/`late`/`end`, and `allowed` is the union of
both. A bundle cannot remove, reorder, or shadow a machine filter, and a
duplicate class is a load error. Today there is no merge at all —
`--machine-spec` selects one file — so M1 introduces it.

Both get tests (`t/54-axa-permanent.t`; the permanent/begin *ordering*
property is already covered by `t/19-dispatch-perm-order.t`, so `t/54` is
about the merge, not about re-proving order): `_build_chain` from the stock spec
returns `Amin::Auth::ZCap` as its head node, and a spec containing an
app-declared `permanent` entry fails to load.

### 5.3 ZCap moves into `permanent`

`Amin::Auth::ZCap` is registered at `begin` today, which makes it the
outermost *begin* filter — and inside every permanent one. Worse, a future
app filter declared at `begin` and merged ahead of it would sit outside the
trust boundary: silently, with every existing test still green. Ordering is
not untested — `t/19-dispatch-perm-order.t` proves `permanent` sees events
that a `begin` filter drops (TR-2.1) — but what the suite pins is *ZCap's
position inside `begin`*, not that nothing can be merged ahead of it:
`t/27-zcap-position-and-tenant.t` asserts `begin[]` holds exactly 7 entries
with `Amin::Auth::ZCap` at index 0. That test encodes today's design, so
this change **retargets** it rather than deleting it — ZCap must be the
first-listed `permanent` filter and the head of the resolved chain, and
`begin[]` drops to 6. The assertion gets stronger, not weaker: it moves from
the spec file's line order to `_build_chain`'s actual output.

The fix is a registration move, not a rewrite:

```xml
<filter class="Amin::Auth::ZCap"   position="permanent" />
<filter class="Amin::Auth::Policy" position="permanent" />
```

ZCap needs no code change. It is element-agnostic, `permanent` is not
subject to the `late` enable flags, and its behaviour — verify
`<amin:zcap token=…>`, inject `<amin:tenant>`, suppress the document on
failure, scope-check the six machine command localnames — is unchanged.
What it gains is a guarantee instead of a convention: because no app may
declare `permanent` (§5.2), spec merge order can no longer put app code
outside it, and it is the first thing every event reaches on every
transport.

One thing to watch: `current_scope_attrs` exposes a package-level
`$CURRENT_SCOPE`, which is file-scoped state rather than per-instance.
"One dispatcher per request" (§4.9) is what keeps that correct, and it is
also why an adapter must not interleave two documents in one process.

### 5.4 Permissions are declared per filter, enforced once

Each filter states what its element requires, in its own spec entry:

```xml
<filter class="Amin::AXA::App::CartAdd" position="middle"
        element="cart-add" namespace="urn:example:shop"
        permissions="shop.cart.add" />
<filter class="Amin::AXA::Element::Card" position="late"
        element="card" namespace="http://projectamin.org/ns/ui/1"
        permissions="" />
```

`permissions=""` is explicit: presentation only, no authority needed. A
filter claiming a non-`ui:` element and omitting `permissions` is a
**load-time error** — fail closed, not "unchecked by default". Nothing in
the parser has to change for this: `MachineSpec` already copies every
non-`class`/`name` filter attribute verbatim into `meta`
([MachineSpec.pm:93-99](../perl-lib/Amin/Machine/MachineSpec.pm#L93-L99)),
so `permissions` reaches the chain builder today and only `Auth::Policy`
has to interpret it.

That is the per-filter half: the *requirement* lives beside the code that
acts on the element, so it cannot be forgotten in one place while
remembered in another, and a reviewer reads it at the point of effect. The
*enforcement* is not per-filter: `Amin::Auth::Policy` receives the compiled
`element → required permissions` map (keyed by Clark name, `{ns}local`) when the
chain is built and checks every `start_element` before it reaches the
filter that claims the element.
Distributed checks give N chances to forget one; one permanent gate gives
one.

Rules:

- `permissions` is a **requirement, never a grant**. An app cannot widen its own
  permissions by shipping an `axa.xml`; only the issuer can.
- A requirement is not satisfied by a neighbouring grant: a filter claiming
  `shop.cart.add` is refused for a principal holding only
  `shop.cart.remove`. No fallback, no prefix guessing beyond one trailing
  `*` per grant.
- Denial uses the same `amin:status` with `RC_SCOPE_VIOLATION` (`-5121`)
  the `spawn`/`exec` checks already emit, and the existing subtree
  suppression applies, so a denied element cannot half-execute.
- Grants live in the signed token scope, exactly as tiers and zones do.
  Adding `action:` entries changes the scope-hash input and the domain tag
  from `amin.zcap.v1` to `amin.zcap.v2`; a v1 token still verifies but
  grants **no** app elements. Fail toward read-only, never toward
  everything. This touches
  [`Amin::Test::ZCapSign`](../perl-lib/Amin/Test/ZCapSign.pm) and the
  task-13 spec.
- Anonymous is a distinct principal with an explicit grant set
  (`action:public.*`), never "unchecked".
- `ui:` needs no grant: it renders an already-authorized response (§5.7).

### 5.5 Emitted events cross a gate too

`Auth::Policy` checks the document as it arrives. Filters also emit, and
what they emit never passes through `permanent` again. Events travel
inward and only inward — each filter's `Handler` is the next inner node —
so direction decides whether that matters.

- A filter at `late` or `end` can never reach the command filters at
  `middle`; it can only produce presentation. `Topology` emitting
  `map:node` is harmless and needs no gate.
- A filter at `permanent` or `begin` emits straight into `middle`, where
  `Amin::Command::*` lives — past `ZCap` and `Policy`, which have already
  seen the document and will not see this. The plan puts routing at
  `begin`, so that is one app filter away from minting an unchecked
  `amin:exec`.

So the second gate sits at the **outer edge of `middle`**: first-listed
static filter of that region, which `_build_chain` places above the
element-scoped command candidates. `Amin::Auth::Egress` checks any `amin:`
element it sees against the verified scope and forwards everything else
untouched. Document-borne commands are then checked twice and emitted ones
for the first time; the check is idempotent, so the second pass costs
nothing and closes the gap without a second policy.

This is the flip side of §5.4: a `permissions` requirement guards *entry*, `Egress` guards
*synthesis*. Both are needed once filters may rewrite a profile, and
neither is transport-specific.

Tests: a `begin` filter that emits `amin:exec` from a tokenless document
yields `-5121` and runs nothing; and a document with UI and map content
renders unchanged, so the gate takes no false positive on the presentation
path. How `Egress` gets the verified scope — a scope-only `ZCap`
instantiation, or a shared request context — is an M1 decision.

### 5.6 What transports *do* own

Nothing about authorization. Transport concerns stay in the adapter, and
each one denies a *browser* attack rather than granting a permission:

| Concern | Owner | Why it is not authorization |
|---|---|---|
| CSRF token, `Origin` / `Sec-Fetch-Site`, `SameSite` | HTTP adapter | stops another site using an ambient cookie; a CLI has no cookie |
| Body cap, `Content-Type`, method, path | HTTP adapter | framing, not permission |
| Rate limit, listener TLS | adapter / listener | availability and transport integrity |
| Replay window (`ts`, idempotency key) | codec + `Amin::AXA::Store` | one rule for every transport |
| **Which elements this principal may cause to run** | **`Auth::ZCap` + `Auth::Policy`, both `permanent`** | transport-independent by construction |

`Amin::AXA::PSGI` must contain no `if $element eq …`, no role table, no
allow-list. An authorization decision appearing in the adapter is a bug by
definition: the identical profile over stdin would bypass it.

### 5.7 Rendering is scoped identically

A GET renders the same chain under the same principal, so a catalogue page
cannot display data that the action following it would refuse to act on.
There is no "public page, privileged action" split: if a page needs a
token, the GET carries one. `ui:` needs no grant of its own — it is
presentation over an already-authorized response. The one rule is that a
binding may not reach outside the profile being rendered (§4.4's
allow-list), so a widget cannot pull in a document the principal was never
shown.

---

## 6. Work breakdown

### M0 — Element filter pack (no server, no actions)

Files:
- `perl-lib/Amin/AXA/Element/Base.pm` — attribute validation, `html:*`
  event helpers, escaping contract.
- `perl-lib/Amin/AXA/Element/{Document,Text,Badge,Button,Link,List,Row,
  Column,VStack,HStack,Card,Image,Form,Input,Table,Alert,Progress}.pm`
  — one filter per element used by `map+ui.xml`.
- `perl-lib/Amin/Handler/HTML.pm` — serializer (void elements, doctype,
  attribute escaping).
- `bin/amin` — forward `ui_os` to the Dispatcher; `--os=html` enables the
  element pack; `--os=tty` (today's default, `bin/amin:45`) keeps today's
  behaviour. `--os` accepts only `ios|android|html|tty` (`bin/amin:119`) —
  `--os=xml` exits 25. The byte-identical regression baseline is therefore
  `--os=tty`, and `--out=xml` is a different flag (the map renderer's output
  format, `bin/amin:116`), which is why it must not be confused with the UI
  serializer's target.
- `perl-lib/Amin/Machine/machine_spec.xml` — register each element filter
  at `late`, namespace `http://projectamin.org/ns/ui/1`,
  `permissions=""`.
- `t/49-axa-elements.t`.

Acceptance:
- `./bin/amin ui examples/apps/shop-ui/map+ui.xml --os=html` emits
  `<!DOCTYPE html>`, one `<html lang>`, no `ui:` elements, and parses as
  XHTML/HTML5.
- Each filter is testable alone: feed one `<ui:button>` event, assert the
  emitted `html:*` events; no server, no whole document.
- A `<ui:text>` containing `<script>alert(1)</script>` renders escaped.
- **Extensibility:** a temp bundle that adds `<ui:product-card>` plus a
  `ProductCard` filter renders correctly without touching core.
- **Override:** an app filter for `ui:text` with higher `priority` wins;
  duplicate priority is a hard error.
- `--os=tty` output is byte-identical to today's, byte for byte — the
  regression check runs the CLI, not the dispatcher, so attribute-order
  drift cannot hide in it. (Baseline today: 5,963 bytes for
  `map+ui.xml`.) Note `--os=html` is *already* accepted and today emits a
  profile with `ui:` elements intact and no doctype, differing from
  `--os=tty` only in attribute order — so "`--os=html` is unchanged" is not
  a property that exists to preserve.
- Existing `t/10-app-shop-ui.t` still passes.

### M1 — Profile in, profile out (no HTTP)

Files:
- `perl-lib/Amin/AXA/App.pm` — load a bundle: its profile, its
  `machine_spec.xml` filter declarations (refusing `permanent`), its
  declared actions.
- `perl-lib/Amin/Auth/Policy.pm` — the permanent gate: compiled
  `element → required permissions` map, per-element check, `-5121` on deny.
- `perl-lib/Amin/AXA/FormCodec.pm` — form encoding → the app's own
  declared fragment. No policy, no domain knowledge (§4.2).
- `perl-lib/Amin/Handler/BSAX.pm`, `Filter/UI/SwiftUIView.pm`,
  `Filter/Map/Topology.pm`, `Generator/BSAX.pm`, `Filter/Storage/Bitcache.pm`,
  `Elt.pm` — **ref-valued `Class::Tiny` defaults become `sub { [] }` /
  `sub { {} }`** (§4.9). `Amin::Handler::Writer` already does this; the rest
  are latent because they read by direct hash access. Required before a
  process may serve two documents.
- `perl-lib/Amin/AXA/Response.pm` — response profile → status + body.
- `bin/amin` — `amin axa run <app> <profile.xml> --out=html`, plus
  `--form axa.action=cart.add --form axa.param.sku=sku-1`.
- `t/50-axa-profile-loop.t`.

Acceptance:
- A profile and the equivalent form encoding produce a byte-identical
  response profile: encodings are not dialects (§4.2).
- The same profile through `amin axa run` and through
  `Amin::Mesh::Transport::InProcess` yields a byte-identical response
  profile (§5.1).
- `<amin:exec>` in a profile is denied with `-5121` for a principal that
  lacks it and permitted for one that holds it — the *same* rule on stdin
  and over HTTP, not a transport-specific refusal (§4.2).
- A denied element leaves no trace in the store: the store is byte-identical
  before and after (§5.4).
- An app bundle declaring a `permanent` filter is refused at load (§5.2).
- Machine-first merge: a bundle spec that omits, reorders, or redefines
  `Auth::ZCap` still yields ZCap as the chain head; a duplicate filter
  class is a load error (§5.2).
- `_build_chain` returns `Amin::Auth::ZCap` as its head for the stock spec
  (§5.3).
- A filter claiming a non-`ui:` element without `permissions` is a load error
  (§5.4).
- A `begin` filter that emits `amin:exec` from a tokenless document
  yields `-5121` and runs nothing (§5.5).
- Two sequential actions observe the same cart via the store.
- **Isolation (§4.9):** a token-bearing document run immediately after a
  tokenless one observes `undef` scopes — `ZCap`, `Sandbox` and
  `Net::Fabric` all reset at document boundaries. This is asserted over two
  documents in one process, because that is the case the CLI cannot catch.
- **Ref defaults are per-instance (§4.9):** a test instantiates every filter
  class in the stock spec twice and asserts no two instances share a
  reference-valued default. (This fails on `Amin::Handler::BSAX` today.)

### M2 — HTTP

Files:
- `perl-lib/Amin/AXA/PSGI.pm` — the adapter.
- `perl-lib/Amin/AXA/Session.pm` — cookie → session record, adapter-side;
  carries the CSRF token as transport hygiene, not as authorization (§5.6).
- `bin/amin` — `amin axa serve <app> --listen 127.0.0.1:8787`.
- `cpanfile` — `Plack`.
- `t/51-axa-http.t` (Plack::Test), `t/52-axa-http-smoke.t` (loopback).

Acceptance:
- `GET /` → 200 `text/html`, correct body, no `ui:` leakage.
- `POST /_axa` with the app's own profile, or its form encoding, → 200
  fragment with `data-axa-target`.
- Bad CSRF → 403; unknown action → 422; wrong method → 405; unknown path
  → 404.
- Request body cap (256 KiB) and `application/vnd.amin+xml` content-type
  enforced.
- Unknown `Origin` on a mutating request → 403.
- A profile permitted for a principal over stdin returns the *same*
  response profile over HTTP — the adapter adds no gate of its own (§5.6).
- The adapter's only rejections are the hygiene ones above: no cookie, no
  `Origin` check, and no rate limit apply to a CLI principal.
- Loopback smoke test asserts the listener answers and the process is the
  one we started.
- **Streaming is real (§4.8):** the first body byte is flushed before the
  document ends — asserted against a deliberately slow generator, not by
  inspecting the code — and the response is byte-identical to the buffered
  rendering.
- **`psgi.streaming` fallback (§4.8):** with the key absent from `$env`, the
  adapter buffers and returns the same status and body.
- **Status latch (§4.8):** an invalid token yields its mapped HTTP status
  (not 200-then-error), and the latch holds back no more than the XML
  declaration plus the root open tag before committing.
- **Isolation under a long-lived process (§4.9):** two documents served
  through one process produce byte-identical output to the same two
  documents run through two fresh processes, in both orders — the second
  document must not see the first's nesting, scope, or buffer.
- **Warm-request budget (§4.8):** `machine_spec.xml` is parsed once at boot,
  not per request — asserted, not assumed (a counter on spec resolution, or
  the injected-spec path). A request that re-reads the spec file is a bug.

### M3 — Shop demo becomes a real app

Files under `examples/apps/shop-ui/`:
- `axa.xml` — the app's own profile dialect: routes, actions, page
  definitions.
- `machine_spec.xml` — the bundle's filter declarations, one `permissions` per
  element it claims (§5.4).
- `data/catalog.xml` — products as SAX (name, price, stock, image).
- `data/orders.xml` — order records for the demo store.
- `filters/` — app business filters if declarative actions are not enough
  (Type P, signed).
- `web/` — `axa.js`, `shop.css` (hashed, served from `files/`).
- `t/53-axa-shop-flow.t`.

Pages: catalogue → product → cart → checkout → confirmation, plus a
`/admin/map` page reusing the existing topology filter.

Actions: `cart.add`, `cart.set_qty`, `cart.remove`, `checkout.place`,
`catalog.search`.

Acceptance:
- Full flow test: browse → add → set qty → remove → add → checkout →
  order id; stock decrements once; replayed idempotency key returns the
  same order.
- Empty cart checkout → error page, no order emitted.
- `<axa:order>` events feed `Amin::UCC::Sales` so an invoice is emitted
  for the same action (ties the demo to the existing billing filters).
- The same `axa.xml` still runs through `amin render` and produces a
  valid profile — no web-only dialect.

### M4 — Hardening and proof

- Escaping audit (text, attribute, URL, JS context).
- The *declared* action set comes from the signed profile: an unsigned
  filter cannot add an action name or claim an app element. (The *grant*
  set is the token's, never a file in the app — §5.4.)
- ZCap v2 grants end to end: issuer mints, `Auth::Policy` enforces,
  `-5121` on overreach, and an app cannot widen its own permissions
  (§5.4).
- Policy coverage: every spec filter that claims an element has an explicit
  `permissions` (possibly empty), asserted over the resolved chain rather than
  only the stock spec.
- No app-declared `permanent` filter: a bundle that ships one is refused at
  load (§5.2).
- Principal binding on sessions: a stolen cookie without the matching
  token is anonymous, not the victim.
- Session rotation on checkout; rate limit per IP; body caps.
- Response header carries the profile hash (`X-Amin-Profile-SHA3`) so a
  page can be traced to the exact profile + filter chain that produced it.
- `docs/axa.md` user guide; example in README.
- Bench, with the §4.8 baseline recorded alongside it: catalogue page with
  1,000 products renders in < 50 ms warm, and the p50 warm request for the
  7.2 KB `map+ui.xml` stays under 12 ms (9.33 ms measured on the dev box),
  with spec resolution not repeated per request.
- Streaming is only claimed after the §4.8 status problem is answered for
  real: either the responder is delayed until the status is fixed, or the
  buffered path is the documented one. "No full-document buffering" is not
  a goal on its own — today's `Writer` buffers, and a page whose status is
  decided by a `-5121` late in the document cannot be streamed without
  choosing one of the three answers.

Rough effort: M0 1–2 d, M1 2–3 d, M2 ~2 d, M3 4–6 d, M4 ~3 d. A credible
demo is M0–M3; M4 is what makes it safe to expose.

---

## 7. What not to build

- **No second router.** Routing is a begin filter over `axa:route` events.
- **No monolithic renderer.** No `Render::HTML` that switches over every
  element; that would make the element set closed and the layer
  unextendable.
- **No DOM.** The whole point is that the page is assembled event by
  event, like every other Amin output.
- **No template language.** Binding is a small allow-list; everything
  else is a filter.
- **No client framework.** One fetch helper and progressive enhancement.
- **No privileged vocabulary outside `amin:`.** App namespaces describe
  intent; effects come from `amin:` and from filters acting on their own
  elements, and both are checked in `permanent` (§5.2).
- **No transport-specific authorization.** No role table in the HTTP
  adapter, no "web-only" element list, no second check beside
  `Auth::ZCap`/`Auth::Policy`. One principal, one decision, one place (§5).
- **No app-declared `permanent` filter.** That space belongs to the machine
  (§5.2).
- **No parallel config.** The app's actions live in the same signed
  profile that deploys it.

---

## 8. Open questions

1. Is "AXA" the name of the whole layer (`Amin::AXA::*`) or just the
   element/render side? Recommendation: whole layer, with the element
   pack under `Amin::AXA::Element::*`.
2. Business logic: declarative `axa:` actions vs. Type P app filters?
   Recommendation: AXA ships session/cart/CSRF primitives; anything
   domain-specific is an app filter under `filters/`.
3. Demo persistence: in-memory behind `Amin::AXA::Store` (fastest) or
   straight to Bitcache? Recommendation: memory now, Bitcache adapter in
   M4.
4. Wire format: XML first, or BSAX for the profile endpoint? Recommendation:
   XML now; BSAX behind a flag once M2 is green — it is the best demo of
   the codec (same profile, 50–75% smaller).
5. Do you want `amin axa serve` in `bin/amin`, or a separate
   `bin/amin-axa`? Recommendation: subcommand, so the CLI stays one entry
   point.
6. ZCap v2: extend the scope hash in place (v1 tokens stop verifying) or
   keep v1 verification and treat v1 as read-only? Recommendation: second
   option — no silent widening on redeploy.
7. Grant syntax: flat strings (`action:shop.*`) or a structured `<grant>`
   list inside the token? Recommendation: flat strings, because the scope
   hash already canonicalises flat length-prefixed arrays.
8. Should `Auth::Policy` be one filter or a family (`Policy::RBAC`,
   `Policy::Capability`) so an app with an existing auth system can plug
   into `permanent` without editing core? Recommendation: one gate with a
   pluggable *grant source*; a policy-table adapter is a small class, a
   second gate is not.
9. Does a rendered page ever need a *read* grant, or is "renders only what
   the response profile exposed" sufficient? Recommendation: sufficient —
   revisit only if a binding can reach a namespace the principal has no
   grant on.

---

## Appendix A — what an element filter looks like

Illustrative; the exact `Base` API is M0's job.

Profile side:

```xml
<ui:button action="cart.add" product="sku-1" class="primary">
  Add to cart
</ui:button>
```

Filter side (`perl-lib/Amin/AXA/Element/Button.pm`, ~30 lines):

```perl
package Amin::AXA::Element::Button;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AXA::Element::Base';

sub start_element ($self, $e) {
    my %a = $self->attrs($e);            # resolves {...} bindings, rejects unknown keys
    my $action = delete $a{action};
    return $self->forward($e) unless defined $action;

    $self->html(form => { method => 'post', action => '/_axa',
                          class  => 'axa-form' });
    $self->html(input => { type => 'hidden', name => 'axa.action',
                           value => $action });
    $self->html(input => { type => 'hidden', name => "axa.param.$_",
                           value => $a{$_} }) for sort keys %a;
    $self->html(button => { type  => 'submit',
                            class => 'axa-button primary' });
    $self->{wrapped} = 1;                # children (the label) stream through
}

sub end_element ($self, $e) {
    $self->html_close('button') if delete $self->{wrapped};
    $self->html_close('form');
    $self->forward_end($e);
}

1;
```

Two things worth noticing:

1. The button becomes a real `<form>`, so the action works with **no
   JavaScript at all**. The action name and its parameters post as ordinary
   form fields; JS only upgrades it to a fragment swap.
2. The element packs no knowledge of carts. It turns a declared action
   into an HTTP submission — a form encoding, which `FormCodec` lowers to
   the app's own fragment. `Auth::Policy` in `permanent` decides whether
   this principal may run the element that handles it.

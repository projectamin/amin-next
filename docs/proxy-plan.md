# PROXY — an L7 reverse proxy inside Amin

Status: plan / not implemented.
Scope: an HTTP/1.1 front whose routing, authorization, header policy and
**backend selection** are declared in the profile and executed as SAX filters,
served by a non-blocking adapter (`amin proxy serve`) — plus a Rust peer
implementation sharing the *same contract*, byte-for-byte, the way `bsax` and
ZCap already do.

The shape this targets: **one Amin proxy in front of many Amin backends**, where
a route answers a single question — *where does this profile go?* — and the
config itself is a content-addressed Bitcache ref, so it replicates across hosts
by hash rather than by copy (§5.13).

---

## 1. Why

`axa-plan.md:318` places the web layer **behind** nginx on purpose. That is a
statement about the origin server, and it is still right for AXA: nginx
terminates TLS and the origin only ever sees authenticated requests. It is
*not* a statement about ingress in general. What nginx is doing there —
host/path routing, backend balancing, TLS termination, header rewriting — is
exactly the class of work Amin already models as data + filters, and it is the
last hop that stays outside the framework's one-chain/one-trust-boundary
property. Anything nginx does in front of an Amin origin is a second,
transport-specific policy surface that a `curl` on stdin does not share.

This plan closes that gap for the HTTP edge, natively, without weakening
`§5 Transport is not the trust boundary` (axa-plan.md:428). It is *not* a
general-purpose HTTP proxy bolted onto Amin: the things behind it are Amin
backends, and the artifact it moves is the **profile**. The proxy itself is
authority-free: it dispatches, pumps, and preserves the caller's authority for
the backend to verify as if the connection were direct.

---

## 2. What exists today

Three pieces are relevant, and one is missing.

| Piece | File | What it does |
|---|---|---|
| L4 load balancer | [Net/Fabric.pm](../perl-lib/Amin/Net/Fabric.pm) | `<lb vip= backends= policy="p2c_ewma" hc= backend_drain=>` — eBPF clsact, longest-prefix, delta-before-syscall. **L4 only.** |
| L7 origin adapter | [AXA/HTTP.pm](../perl-lib/Amin/AXA/HTTP.pm) + [AXA/Serve.pm](../perl-lib/Amin/AXA/Serve.pm) | read body → feed chain → status latch → stream response, over `Amin::Net::Loop`. |
| HTTP serve | [bin/amin:128-167](../bin/amin#L128-L167) | `axa serve`, `Amin::Net::Loop` pre-forked by `--workers` (4), `read-timeout` (2 s), `keepalive_timeout` (5 s). |
| Orchestration | [machine_spec.xml:7](../perl-lib/Amin/Machine/machine_spec.xml#L7), [Auth/ZCap.pm](../perl-lib/Amin/Auth/ZCap.pm) | chain build; ZCap at `begin` today. |
| Content-addressed config | [Bitcache/Reference.pm](../perl-lib/Amin/Bitcache/Reference.pm) | `bitcache://blake3/<hash>` ref: parse → `bctool get` → `bctool verify`, fail-closed. One resolver shared by `MachineSpec`, the proxy config and route specs (§5.13). |

What is **absent**, and confirmed by search over `perl-lib/`:

- **No TLS server.** `IO::Socket::SSL`/`Net::SSLeay` are dependencies
  ([cpanfile:42-43](../cpanfile#L42-L43)) but only as an HTTPS *client* for
  inference hops; nothing terminates.
- **No Perl AWP/3 client.** [Mesh/Transport/InProcess.pm](../perl-lib/Amin/Mesh/Transport/InProcess.pm)
  is a fork-based test double. The Rust [`awp3` crate](../rust/crates/awp3/src/lib.rs)
  is a 28-line skeleton — `VERSION`, `DEFAULT_PORT`, and a doc comment naming
  `frame` / `handshake_initiator` / `handshake_responder` that are **not
  implemented**. There is no binary and no binding.

---

## 3. The model: a front + a vocabulary + filters

Not a new daemon with its own config format — the same shape AXA already is
(a transport adapter plus a notation plus filters), with the origin server
replaced by a set of backends:

```
client ──TLS──▶ listener ──▶ request profile ──▶ Dispatcher chain ──▶ dispatch
                (epoll)        <amin:request>   permanent: ZCap/Policy        │
                              + <amin:backend>×N  begin:  Proxy::Route        │
                              + <amin:route>×N    middle: Proxy::Backend       ▼
                                                                   selected Amin backend
                                                          awp3 (mesh) | http (interop)
              ◀──── backend response profile / bytes (status latch) ─────────────┘
```

Above the dispatcher: a codec. Below it: nothing transport-aware. The
authorization decision lives in `permanent`, where neither a transport nor a
route table can displace it (axa-plan.md:450-463). Swap the adapter and not one
filter changes.

The asymmetry against AXA is that the response comes from a **backend**, not
from render filters. So the chain produces an *authorization decision + a
backend selection + header directives*, and the adapter pumps bytes. For an
`awp3` backend the front forwards the `<amin:request>` profile and streams the
backend's response back — the front is a **profile pump**. `http` backends are
the explicit interop case, where a conventional request/response is spoken
instead. The chain never buffers a body either way.

Each `<amin:route>` may also name an optional machine spec. That spec is not
loaded per request. Instead the route owns a warm Amin **provider**: a long-lived
object created on first use (or boot warm-up) that resolves the route's machine
spec, seals registrations, and holds immutable routing/runtime context for that
route. Each request still gets a **fresh Dispatcher instance** built from that
warm provider, because filter traversal state remains per-document
(`axa-plan.md:363-369`).

---

## 4. The contract (configuration as contract)

Nothing lives in an env var or a side file. One container, two declared tables,
one per-request element, and one adapter-facing decision event — all in the
profile.

### 4.1 Config — `<amin:proxy>`, `<amin:backend>`, `<amin:route>`

```xml
<!-- the document itself may be a local path or a Bitcache ref, on the CLI:
     amin proxy serve bitcache://blake3/3f…c1?signer=edge&ts=…&sig=…&vk=… -->
<amin:proxy amin:listen="0.0.0.0:8443" amin:tls="files"
            amin:cert="/etc/amin/tls/fullchain.pem"
            amin:key="/etc/amin/tls/privkey.pem"
            amin:max-conns="4096" amin:read-timeout="30">

  <!-- where a profile can go -->
  <amin:backend amin:id="shop-a" amin:peer="shop-a.mesh" amin:transport="awp3"
                amin:hc="tcp_ack_3rst=auto_drain"/>
  <amin:backend amin:id="shop-b" amin:peer="shop-b.mesh" amin:transport="awp3"/>
  <amin:backend amin:id="legacy" amin:addr="10.0.0.20:80" amin:transport="http"/>

  <!-- where *this* profile goes -->
  <amin:route amin:host="shop.example" amin:path="/api/" amin:to="shop-a,shop-b"
              amin:policy="p2c_ewma"
              amin:spec="bitcache://blake3/9a…c4?signer=edge&ts=…&sig=…&vk=…"
              amin:ws="on"/>
  <amin:route amin:host="legacy.example" amin:to="legacy"/>
  <amin:route amin:host="*" amin:to="shop-a"/>
</amin:proxy>
```

**`<amin:backend>`** — the destination, declared once and reusable:

- `id` — referenced by routes.
- `peer` (mesh identity) *or* `addr` (`host:port`) — exactly one.
- `transport` — `awp3` (an Amin backend, §6) or `http` (interop).
- `hc` — TCP-level health check, same grammar as `<lb>`.

**`<amin:route>`** — pure dispatch, the answer to "where does this profile go":

- `host` — exact, `*.suffix` wildcard, or `*`. Longest wins.
- `path` — prefix, longest wins (regex is *not* in v1; `axa-plan.md:79` already
  ships exact-path for AXA).
- `to` — a comma-separated list of **backend ids**. Not addresses.
- `spec` — optional route-local machine spec to resolve once and keep warm as
  that route's Amin provider; a local path, or a `bitcache://blake3/<hash>`
  ref (same grammar and signature verification as `bc_uri`, §5.13).
- `policy` — reuses the `Net::Fabric` `<lb>` vocabulary so there is one
  balancing implementation, not two.
- `strip-prefix`, `ws` — route-level directives (and nothing else; §5.9).

A route's backends must share one `transport`; mixing is rejected at profile
validation, so the balancer stays transport-blind.

The `<amin:proxy>` document is itself resolvable from Bitcache: `amin proxy
serve <ref>` accepts a local path or a signed `bitcache://` ref exactly like a
machine spec, so the deployed config and every route-local spec share one
content-addressed, signature-verified source (§5.13).

### 4.2 Per request — `<amin:request>`

Synthesized by the adapter after it parses the request line and headers, and fed
into the same chain:

```xml
<amin:request amin:host="shop.example" amin:method="GET"
              amin:path="/api/v1/items" amin:scheme="https"
              amin:sni="shop.example" amin:client="203.0.113.7"/>
```

### 4.3 Decision — `<proxy:backend>`

Emitted by the routing filter, consumed by the adapter (never by a filter
downstream — it is adapter-facing, like `amin:status` is):

```xml
<proxy:backend amin:id="shop-a" amin:transport="awp3" amin:peer="shop-a.mesh"
               amin:policy="p2c_ewma" amin:strip-prefix="false" amin:ws="on"/>
```

A route whose `to=` names several backends (`to="shop-a,shop-b"`) emits **one
`<proxy:backend>` per candidate, in declared order** — the router picks the set,
the balancer (§5.4) chooses among them. Each element carries the *route's*
policy, so the adapter needs nothing else.

---

## 5. Design decisions

### 5.1 Routing is a `begin` filter, not a second router

`axa-plan.md:854` is explicit: *"No second router. Routing is a begin filter
over `axa:route` events."* PROXY obeys it. `Amin::Proxy::Route` is a `begin`
candidate bound to `element="request"`, so it is a `_LazyGate` candidate — it
splices in when the first `<amin:request>` arrives and un-splices on close,
exactly like the `ui:` element fleet. It owns no table: the compiled matcher
(§5.3) is injected, not streamed.

### 5.2 Route selection lands **below** auth automatically

`_build_chain` places each region's lazy gate *below* that region's static
members, "so begin-region candidates splice in BELOW the auth/HW filters rather
than ahead of them (TR-2.1)" ([Dispatcher.pm:479-496](../perl-lib/Amin/Machine/Dispatcher.pm#L479-L496)).
Because `Proxy::Route` is a candidate and ZCap is a static `begin` filter,
**authorization always precedes route selection** with no ordering convention to
get wrong. When ZCap moves to `permanent` (axa-plan.md:492-527) the property
only strengthens.

### 5.3 Routes compile once into warm providers; requests still get fresh dispatchers

The tables are declared in the profile (single source of truth). At boot the
adapter loads the config **once** — `Amin::Proxy::Config->load` parses
`<amin:backend>` and `<amin:route>` into compiled route records and freezes them
(sorted most-specific-first; a request never re-sorts or re-parses). The filter
never sees the tables: the frozen matcher is injected into `Proxy::Route` as
`Proxy`, the same channel that injects `Render`. Each record names a warm Amin
**provider** for that route: resolved machine spec, sealed registry, compiled
matcher, and any route-local backend/runtime handles. That provider is reused
across requests.

Per request the chain is still rebuilt — it is stateful, so a fresh
`Dispatcher` is mandatory (axa-plan.md:363-369) — but it is rebuilt **from the
warm provider**, not from scratch. The frozen matcher/provider handle is
injected into the fresh filter, the same channel that injects `Render`
([Dispatcher.pm:515-520](../perl-lib/Amin/Machine/Dispatcher.pm#L515-L520)).

Rejected: re-emitting the tables into every request stream (a redundant
per-request data flow, which the project opposes). Rejected: routing inside the
adapter (`App.pm`-style lookup) — a second router, failing 5.1.

### 5.4 The listener is a dedicated epoll loop on core `IO::Poll`

`Amin::Net::Loop`: one process, `IO::Poll` (epoll on Linux), non-blocking
accept/read/write, bounded per-connection buffers so a slow reader applies
backpressure instead of growing memory. No CPAN dependency — `IO::Poll` is core.
Multicore is N processes each with its own loop sharing the listen socket via
`SO_REUSEPORT` (`--workers`), chosen deliberately rather than inherited from
Starman's prefork. **This loop exists** — [Net/Loop.pm](../perl-lib/Amin/Net/Loop.pm),
built for the AXA origin (`Amin::AXA::Serve`) and reused by the proxy as-is.

Why not Starman: it is correct but it pins a worker per backend round-trip. A
proxy's whole job is multiplexing many partially-idle client↔backend pairs —
the exact case `axa-plan.md:328` names.

### 5.5 TLS is terminated in-process

`IO::Socket::SSL` (already a dependency) wraps the accepted socket; cert/key
come from the profile (§4.1). Full L7 visibility — required for path routing and
header rewrite. SNI selects among multiple `<amin:proxy>` cert blocks. ACME is
**not** a proxy concern: it is an app-level machine filter (RFC 8555 HTTP-01),
composed in the app bundle's own `machine_spec.xml`, so the proxy only ever
sees an already-provisioned cert/key (§4.1).

### 5.6 Transport is a property of the backend: `awp3` or `http`

- `awp3` — an Amin backend. The front forwards the `<amin:request>` profile as
  AWP/3 frames (§6); the backend runs its chain and returns a response
  profile/bytes, decoded back to the client.
- `http` — a non-Amin origin. A conventional origin-form request is sent; the
  response status line commits the client status.

Transport never appears on a route, only on a backend, so a route is purely
"which backends" and the balancer carries no transport logic.

### 5.7 Streaming and the status latch

The [`HTTP.pm`](../perl-lib/Amin/AXA/HTTP.pm) latch carries over, with one
difference: the first committed status comes from the **backend**, not from an
`amin:status` — the upstream status line for an `http` backend, or the
backend's response status for an `awp3` backend. The adapter holds the client
status line until (a) the chain has authorized the request (ZCap's decision
lands early — it checks the first child of `root` and suppresses on failure),
and (b) the backend's first response bytes have arrived. A `-5121` from a
`permanent` filter becomes an HTTP 4xx, never a 200-then-error. Bodies stream
both directions without buffering; `amin:status` on a failure after commit
rides in the body, exactly as axa-plan.md:296-312 specifies.

### 5.8 WebSocket and `Upgrade`

`amin:ws="on"` on a route: on a `101` from the backend, the adapter stops being
an HTTP proxy and becomes a bidirectional byte splice between the two sockets in
the loop until either closes. Hop-by-hop headers are handled by 5.9.

### 5.9 Header policy — small and closed

The adapter (not a filter) strips hop-by-hop headers (`Connection`,
`Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Proxy-*`),
appends `X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host`, and
rewrites `Host` to the selected backend. v1 adds no `proxy_set_header`
mini-language; anything beyond this table is a filter that emits
`<proxy:backend>` with directives, or it is not built. Header policy must
**never** strip the caller authority material the backend re-authorizes against
(§5.12).

### 5.10 When it touches the fabric, delta-before-syscall still holds

If a backend is realized inside a `<net>` scope (listener in a netns, backend
via a veth), every kernel mutation emits its synthetic sibling event **before**
the syscall, matching [Net/Fabric.pm](../perl-lib/Amin/Net/Fabric.pm) and
`t/24`. The proxy does not get a private path to the kernel.

### 5.11 One chain, every transport

A profile over `amin proxy`'s listener is authorized by the identical chain that
authorizes it on stdin. Parity is a test, not a promise (axa-plan.md:445-448):
the same profile fed through `amin render` and through the proxy listener must
produce byte-identical decision profiles.

### 5.12 The front is authority-free; backends remain the trust boundary

The front parses, routes, and pumps. It does **not** mint, widen, or replace
authority. Every Amin backend independently verifies the caller authority on the
profile it receives and applies its own closed-world policy as if the
connection were direct. A misrouted or compromised front therefore cannot
bypass a backend's policy.

Consequences:

- The front forwards the caller's own authority material on the backend hop and
  preserves whatever headers/profile elements the backend needs in order to
  verify it. The backend verifies the signature, not the front's word.
- AWP/3 authenticates the **front** as a peer (§6); being authenticated is not
  being authorized. Closed-world still applies at the backend.
- A route can narrow scope, never widen it: it may only select among backends
  whose policy already admits the client's authority.

### 5.13 The config is content-addressed: hosts replicate by hash

A proxy that only reads a local file cannot be deployed to N hosts without N
copies drifting. So the proxy config is **Bitcache-addressable**, using the
scheme and verification that `MachineSpec` already implements for `bc_uri`,
now shared through the one resolver
([Bitcache/Reference.pm](../perl-lib/Amin/Bitcache/Reference.pm)):

```
bitcache://blake3/<64-hex-content-hash>?signer=<name>&ts=<unix>&sig=<…>&vk=<…>
```

Two things are addressable, and nothing else:

- the `<amin:proxy>` document itself — the `amin proxy serve <ref>` argument
  (§4.1);
- each `<amin:route amin:spec=>` — the route's warm provider spec.

Identity is the **content hash**; the signed ref is the deploy artifact. A host
needs nothing but the ref: it fetches the blob (`bctool get --slab --hash`),
verifies the signature (`bctool verify`, trust anchor by `sha256(signer)`), and
runs it. Two hosts given the same ref run byte-identical config by construction
— the hash *is* the version, so drift is not possible and a per-host edit is a
different hash.

Rules, matching the fail-closed posture of `MachineSpec`:

- **Fail closed.** A `bitcache://` ref that fails verification refuses to start;
  there is no "unsigned local fallback" for an addressed config. (A local
  *path* is still the explicit unaddressed case for development.)
- **Resolve at boot, not per request.** The ref is fetched and verified once,
  when the warm providers are built (§5.3); the request path never touches the
  slab.
- **Replicate by pushing the hash, not the file.** Shipping a new config is
  pushing one blob to each slab (or letting a host pull it from a peer over the
  same mesh AWP/3 uses) and handing over the new ref. The transport is the
  existing Bitcache/mesh distribution — there is no second config channel.

Reload is the natural consequence: a new config is a new hash, so a host detects
the announced ref, fetches and verifies it, builds the new warm providers
underneath, and swaps atomically — in-flight requests drain on the old providers
and new connections land on the new ones. No restart, no partial config.

One implementation, not two: the parse → `bctool get` → `bctool verify` logic
used to be private to `MachineSpec`. It now lives in one resolver,
**`Amin::Bitcache::Reference`**, that `MachineSpec`, the proxy config loader and
route specs all call. It sits with the rest of the Bitcache family
([Filter/Storage/Bitcache.pm](../perl-lib/Amin/Filter/Storage/Bitcache.pm),
[Command/Bitcache.pm](../perl-lib/Amin/Command/Bitcache.pm)) — deliberately
**not** under `Amin::Content`, which is the unrelated `amin:document`
generation base ([Content.pm](../perl-lib/Amin/Content.pm)). Rejected: a second
fetcher in `Proxy::Config` (a redundant data path the project opposes), and a
hand-rolled hash check outside `bctool` (PQ signature verification lives in one
place, as §7 requires).

---

## 6. AWP/3 — the transport to Amin backends

The contract is already written down in [awp3/src/lib.rs](../rust/crates/awp3/src/lib.rs);
it is not yet implemented. This section is that contract, restated as the build
target so the Perl bridge and the Rust core agree.

- **Key exchange**: hybrid post-quantum every handshake — Noise_XKems with
  ML-KEM-768 + X25519.
- **Authentication**: hybrid — ML-DSA-65 + ed25519 composite signatures on every
  handshake transcript and every `.aminsig` artifact.
- **AEAD per frame**: ASCON-128a.
- **Frame hashes**: BLAKE3 rolling — each frame id chained into the next, an
  append-only Merkle log terminating at the session-close signature and written
  to the audit log as a receipt.
- **Framing only**: no HTTP, no WebSockets, no middleware chain. Frames carry
  raw byte payloads exactly as the SAX pipeline emits them.
- `VERSION = 0x03`, `DEFAULT_PORT = 4514`.

Three public entry points only: `frame`, `handshake_initiator`,
`handshake_responder`.

On the backend hop the front forwards the `<amin:request>` profile and the
caller authority material (§5.12) as frames; the backend runs its own chain and
returns a response profile/bytes. AWP/3 authenticates the front as a peer; it
does not authorize the request.

**Perl bridge.** The crate builds a `cdylib` exposing a C ABI over those three
entry points; Perl binds it with `FFI::Platypus` (new dependency). Rejected: a
per-connection subprocess bridge (the `InProcess` shape) — too heavy per backend
connection — and a hand-written AWP/3 in Perl (PQ crypto belongs in one
implementation). The cdylib is built static, matching the project's static-link
rule for OpenSSL/libblake3/liboqs.

---

## 7. Perl ↔ Rust parity

Same discipline that keeps BSAX and ZCap consistent across languages:

- **One codec.** Both sides use the existing BSAX implementation
  ([perl: Generator/BSAX.pm](../perl-lib/Amin/Generator/BSAX.pm),
  [rust: crates/bsax](../rust/crates/bsax)). No new wire format.
- **One contract.** The vocabulary in §4 is the interface; both sides parse and
  emit it identically.
- **Parity tests, byte-for-byte.** One profile → the Perl routing filter and the
  Rust routing filter → **byte-identical** `<proxy:backend>` profiles. One
  AWP/3 handshake → Perl-derived and Rust-derived frames match, in the shape
  `t/29` already uses to cross-verify ML-DSA-87 sign/verify.
- **`awp3` is the single source of truth** for the mesh wire format; the Perl
  side never re-implements framing, only drives the cdylib.

---

## 8. Work breakdown

### P0 — Vocabulary + routing (no sockets, both languages)

Files:
- `perl-lib/Amin/Bitcache/Reference.pm` — extract the `bc_uri` parse → `bctool
  get` → `bctool verify` logic out of `MachineSpec` into one resolver;
  `MachineSpec` is refactored onto it. Fail-closed on a bad signature.
- `perl-lib/Amin/Proxy/Config.pm` — resolve the config/document ref (path or
  `bitcache://`, §5.13) through the resolver; parse `<amin:proxy>`/
  `<amin:backend>`/`<amin:route>`; compile route providers; validate (one
  transport per route, exactly one of `peer`/`addr` per backend); freeze them.
- `perl-lib/Amin/Proxy/Route.pm` — the `begin`, `element="request"` filter;
  matches `<amin:request>`, emits one `<proxy:backend>` per candidate backend.
- `perl-lib/Amin/Machine/machine_spec.xml` — register `Proxy::Route`.
- `rust/crates/amin-proxy` — serde types for §4 (no sockets yet).
- `t/65-proxy-vocabulary.t`, `t/72-bitcache-reference.t`.

Acceptance:
- Host/path/wildcard longest-match picks the declared route; `*` catches.
- `to=` resolves to declared backend ids; an undeclared id and a mixed-transport
  route both fail validation.
- `Proxy::Route` splices below `begin` statics (5.2), asserted the way
  `t/19`/`t/27` assert position.
- The compiled table is injected, not re-streamed (5.3): a counter on the
  matcher/provider proves one compile/init per boot, not one per request.
- A `bitcache://` config/route spec resolves to the same bytes `MachineSpec`
  gets for the same ref, and a ref with a bad signature fails to load (§5.13).
- Perl and Rust produce byte-identical `<proxy:backend>` for one profile.

### P1 — Perl listener + HTTP/1.1 backend

Files:
- `perl-lib/Amin/Net/Loop.pm` — `IO::Poll` event loop, non-blocking sockets,
  bounded buffers, `SO_REUSEPORT` workers.
- `perl-lib/Amin/Proxy/HTTP.pm` — the adapter: TLS accept, request parse →
  `<amin:request>`, run the chain, on `<proxy:backend>` connect + stream, status
  latch, hop-by-hop headers, WebSocket splice.
- `perl-lib/Amin/Proxy/Backend.pm` — resolve/connect/pool/health; reuses the
  `Net::Fabric` `p2c_ewma` math.
- `bin/amin` — `proxy serve <ref> [--listen …] [--workers N]`, where `<ref>` is
  a local path or a signed `bitcache://` ref (§5.13).
- `t/66-proxy-http.t` (against a local origin), `t/67-proxy-loop.t`.

Acceptance:
- `GET`/`POST` proxy to a local origin backend; bodies stream both directions
  without buffering; a slow client applies backpressure (asserted, not
  inspected).
- TLS termination with a test cert; `https://` client works.
- A `-5121` from a permanent filter yields a 4xx, not a 200.
- WebSocket echo through the proxy succeeds past `101`.
- Hop-by-hop headers are stripped; `X-Forwarded-For` is appended; the caller
  authority material survives the hop (§5.12).
- Two requests through one loop process equal two fresh single-request processes
  (isolation, axa-plan.md:778-781), even when they reuse one warm route
  provider.

### P2 — AWP/3 (Rust core + Perl bridge), `awp3` backends

Files:
- `rust/crates/awp3/src/lib.rs` — implement `frame`, `handshake_initiator`,
  `handshake_responder` per §6.
- `rust/crates/awp3/Cargo.toml` — `crate-type = ["cdylib", "rlib"]`; C ABI shim.
- `perl-lib/Amin/Net/AWP3.pm` — `FFI::Platypus` binding.
- `cpanfile` — add `FFI::Platypus`.
- `.mise.toml` — build `awp3` cdylib in the bootstrap task.
- `t/68-awp3-frames.t`, `t/69-awp3-perl-bridge.t`.

Acceptance:
- Handshake completes between two `awp3` instances; hybrid KEM tuple and
  composite signature verified (cross-verified against the Rust signer, `t/29`
  shape).
- Frames are BLAKE3-chained and terminate at a signed session-close receipt.
- Perl and Rust derive byte-identical frames from one transcript.
- An `awp3` backend receives the forwarded profile and **re-authorizes** it
  (§5.12): a profile whose ZCap the backend's policy rejects is refused even
  though the front selected it.

### P3 — Rust proxy (parity peer)

Files:
- `rust/crates/amin-proxy/src/{main,listener,http,route,backend}.rs` — tokio
  listener, `rustls` termination, hyper-class HTTP/1.1, the same routing filter
  logic reused from P0.
- `t/70-proxy-parity.t` — one profile through the Perl listener and the Rust
  listener → byte-identical decision profiles.

### P4 — Rust AXA parity (the "pure Rust alongside Perl" end goal)

Files:
- `rust/crates/amin-axa` — the AXA adapter + element filters in Rust,
  reusing `crates/bsax`.
- `bin/amin-axa` or an `amin axa serve --impl=rust` flag.
- `t/71-axa-parity.t` — the same `axa.xml` app renders byte-identically under
  both implementations.

### P5 — Hardening

- ACME / cert rotation; per-IP rate limit; connection pooling + keepalive to
  backends; HTTP/2 inbound; `X-Amin-Profile-SHA3` on proxied responses;
  `docs/proxy.md` user guide.

Ordering note: P0→P1→P2 is the Perl spine. P3/P4 are the Rust track and can
start as soon as P0's contract is frozen, because they consume the same
vocabulary.

---

## 9. What not to build

- **No second router.** Routing is a `begin` filter over `amin:route` events.
  (§5.1)
- **No addresses on routes.** A route names backends; a backend owns its
  address, peer identity and transport. (§4.1)
- **No transport on a route.** One transport per route, enforced at validation.
  (§5.6)
- **No DOM / no full-body buffering.** The request profile is synthesized
  element-by-element; the body streams. (§5.7)
- **No `proxy_set_header` mini-language.** A closed header table plus filters.
  (§5.9)
- **No transport-specific authorization.** No allow-list in the adapter; the
  decision is `permanent`'s — and the backend's, independently. (axa-plan.md:617-632)
- **No backend trust shortcut.** A peer authenticated by AWP/3 is authenticated,
  not authorized; the backend still runs closed-world on the caller's
  authority. (§5.12)
- **No per-request table re-emission.** Compiled once. (§5.3)
- **No new wire format.** BSAX profiles and AWP/3 frames, both already specified.
- **No hand-written AWP/3 in Perl.** One implementation, bound by FFI. (§6)
- **No parallel config.** Backends and routes live in the signed profile that
  deploys the front.
- **No second fetcher, no second config channel.** The config and route specs
  resolve through the one Bitcache resolver (`bctool get`/`verify`); there is no
  separate distribution mechanism for proxy config. (§5.13)

---

## 10. Open questions

1. **Naming.** `Amin::Proxy::*` vs `Amin::Net::Proxy::*`? Recommendation:
   `Amin::Proxy::*` for the L7 layer, `Amin::Net::Loop` for the substrate (which
   `<lb>` may also want).
2. **Filter-injection channel.** Inject the warm route provider via a spec
   attribute through `_filter_cfg`, or via a shared context like `Render`?
   Recommendation: a shared context — it matches `Render`, and spec attributes
   are per-machine-spec while backend/route providers are per-profile.
3. **ZCap ordering dependency.** Do we block P1 on the axa-plan.md:492-527
   ZCap→`permanent` move, or ship with ZCap at `begin` (still below routing,
   §5.2)? Recommendation: ship at `begin`; the candidate ordering already gives
   the property.
4. **Route-local machine spec reference.** Do we spell `amin:spec=` as a path /
   `bitcache://` ref only, or also allow an indirection id that resolves inside
   the profile? Recommendation: path / ref only in v1, because the one Bitcache
   resolver (§5.13) already knows how to resolve them.
5. **Config reload trigger.** How does a running host learn a new config hash —
   restart with a new ref, a mesh AWP/3 announce, or a poll? Recommendation:
   start-time ref resolution in v1; the AWP/3 announce and atomic provider swap
   (§5.13) land with P2, since the mesh transport is being built there anyway.
6. **`awp3` C ABI surface.** Raw bytes + lengths, or an opaque session handle
   with `poll`-driven IO? Recommendation: session handle plus explicit `poll_*`,
   so the Rust core owns its framing state and the Perl loop stays a byte pump.
7. **Connection pooling ownership.** In the adapter, or on the warm route
   provider as a backend/runtime concern? Recommendation: the provider owns pool
   handles, but the adapter owns sockets and poll registration, so the
   transport boundary still stays in adapter code.
8. **`<lb>` convergence.** Should `<lb>` (L4) and `<amin:backend>` (L7) share one
   health/policy implementation, or converge into one element with a `layer=`
   attribute? Recommendation: one health/policy implementation, two declarations
   — the layers have genuinely different keys (VIP vs host+path) and `<lb>`
   predates this.

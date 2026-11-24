# Amin ledger

A tamper-evident, replicable, quantum-safe log of audited events, built on Bitcache. It is
what makes a cgroup bill, a settlement, an AI tool call or a boot *uncontestable*: each is an
entry in a Merkle log whose head is signed by a key that chains to the same authority that
admitted the node at boot.

It is deliberately small. There is no consensus protocol and no mining. Each node owns one
log; trust comes from signatures and Merkle proofs; independent logs are tied together by
exchanging signed checkpoints.

## 1. Layers

```
 Perl (Amin::Filter::Ledger, Amin::Crypto::Verify)     verify + hand events to bctool
      │  FFI (libbitcache.so)             │  exec
      ▼                                   ▼
 ┌──────────────────────────── bitcache (Rust) ─────────────────────────────┐
 │ entry      typed event, per-actor hash chain                              │
 │ tlog       Merkle tree, RFC 9162 proofs, frontier (O(log n) state)        │
 │ ledger     durable log in a pinned slab; seal / join / compact            │
 │ checkpoint signed (origin,size,root) + witness cosignatures + CertCache   │
 │ snapshot   join state: frontier + heads + accepted-receipt state          │
 │ mesh       observe peers, fault proofs, receipts, witness review          │
 │ accepted / policy   bounded replay guard · tiered witness quorum          │
 │ iot        leaf reports, gateway batches, leaf receipts                   │
 │ nodecert / trust / signer   authority → node key chain, ML-DSA-87         │
 └───────────────────────────────────────────────────────────────────────────┘
      ▲
 ainit (netboot PID 1): BOOT_OFFER → verify → open_for_boot → record_boot
```

**One implementation, two languages.** Perl never encodes or interprets ledger bytes itself.
Every verifier (`ckpt`, `snapshot`, `receipt`, `iot leaf`, `iot report`, `zcap`, `instrument`)
is the Rust code, exposed over a C ABI and bound with FFI::Platypus. Shared golden vectors
(`t/data/trust-golden-v1.tsv`) are checked from Rust through the ABI and from Perl, so the two
cannot drift. Writing events goes through the `bctool` binary.

## 2. Trust chain

```
authority  ML-DSA-87 key   (the BOOT_OFFER anchor)
   └─ signs NodeCert { node_id, node_vk_hash, boot_counter, scope_hash, valid_from_pos, valid_to_pos }
        └─ node key  composite ML-DSA-65 ‖ Ed25519   (both halves must verify)
             └─ signs Checkpoint { origin = node_id, size, root }
                  └─ optional witnesses: ML-DSA-87 cosignatures over the same body
```

* A node may only sign checkpoints whose `origin` equals its certified `node_id`.
* Validity is judged against an *authority log position* (`pos`), not wall-clock time: a
  netbooted node has no trustworthy clock. The BOOT_OFFER carries `authority_pos`.
* Several authorities can be trusted at once (`verify_any`), which is how separate meshes
  under different roots verify each other. A mesh that trusts only its own root refuses the
  other's checkpoints.
* Witnesses are an explicit roster; a quorum counts *distinct* roster members.

## 3. Data model

### Entry
`kind, actor, subject, seq, prev, auth, ts, attrs` (attrs sorted, strict canonical decode).
Domain-separated id (`AMIN3-LEDGER-ENTRY-ID-V1`). Each **actor** is its own hash chain
(`seq` dense from 1, `prev` = id of the actor's previous entry) inside the single global log, so
`append_drafts` assigns `seq`/`prev` itself and a caller can neither skip nor fork a chain.
`auth` points at what authorised the event (the signed offer digest for `boot`, the payer's
entry id for `transfer.in`, a checkpoint hash for observations).

Kinds in use: `boot`, billing/settlement events, `transfer.out`, `transfer.in`, `ledger.state`,
`ledger.anchor`, `ledger.peer`, `ledger.fault`, `iot.batch`. Opaque (untyped) entries are
tolerated in the log but are not chained.

### Log
Merkle tree over entries: `leaf = H(0x00‖entry)`, `node = H(0x01‖l‖r)`, BLAKE3. Inclusion and
consistency proofs follow RFC 9162. The tree stores levels sparsely, so it can be rebuilt from a
**frontier** (the O(log n) hashes that fold to the root) without the leaves.

### Storage
`<path>` is a Bitcache slab holding every entry, content-addressed and pinned (the refcount
sentinel `PINNED`), so slab GC can never evict history. Sidecars:

| file | content |
|---|---|
| `<path>.ledger` | 32-byte header (`AMIN3REF` + index of first ref) then 32-byte entry refs |
| `<path>.base` | the join/compaction snapshot this ledger resumes from, if any |
| `<path>.seal` | the most recent sealed state, waiting for a signed checkpoint |

Commit order is entry → pin → ref (fsync). A crash can strand unreferenced garbage, never a
reference to a missing entry; a torn final ref is dropped on open. On open the tree is rebuilt
from the entries, which are re-hashed on read, so an edited ref file shows up as a different
root and fails consistency against any checkpoint that was signed earlier.

## 4. Joining without history

```
 seal   → append a `ledger.state` entry that commits  heads_root  and  accepted_root
 sign   → node signs a checkpoint of exactly that size/root
 export → Snapshot { checkpoint, frontier, heads, accepted, state_entry, inclusion proof }
 join   → verify checkpoint chain + cross-checks, adopt frontier/heads/accepted; no history
```

A snapshot is O(log n + actors + payers) and independent of history length. `Snapshot::verify`
checks: the signed checkpoint; that the frontier folds to its root; that the state entry is the
checkpoint's last leaf (inclusion proof); that `heads` and `accepted` hash to the roots the state
entry commits; and that the state entry continues its actor's chain. A joined node continues
exactly like a full node: identical seq/prev, identical roots going forward.

**Validating backwards without history.** Any older checkpoint, and any old entry, can be
checked from the current head with an O(log n) consistency or inclusion proof (≤ 2·⌈log₂ n⌉
hashes). Whoever archived the old entries serves the proof; the verifier needs none of the
history.

**Compaction (rolling window).** `Ledger::compact(checkpoint)` adopts the node's *own* sealed
and signed state as its new base and drops everything before it. Local state becomes the
frontier plus entries since the seal. Crash order is new snapshot → rewrite refs → unpin, and
every intermediate state reopens correctly (leading refs before the base are skipped). Dropped
history stays provable by an archive.

## 5. Meshes that fall off and on the internet

Every node keeps its own log and signs its own checkpoints, so nothing needs the network to
keep working. Continuity comes from recording what other logs have said.

* **Observation.** `ledger.anchor` (report up to a parent) and `ledger.peer` (two meshes pass
  roots) record another origin's signed checkpoint. Each origin gets its own chain, and a new
  checkpoint must *extend* the last one recorded (consistency proof). A pruned ledger supplies
  the previous observation entry, which must hash to its committed chain head.
* **Equivocation.** Two signed roots for one size is a self-contained proof of forking. It is
  recorded as a signed `ledger.fault` and that origin is refused afterwards. An inconsistent
  extension *without* a provable fork returns `Inconsistent` and writes nothing: a relay could
  otherwise frame an honest origin with a bad proof.
* **Receipts.** `Receipt = entry + inclusion proof + signed checkpoint`. Verifiable with no
  network. Offline payment: the payer's `transfer.out` receipt is handed over; the payee
  verifies it and records `transfer.in` (`auth` = payer entry id).
* **Replay guard.** A receipt is named `(origin, payer actor, seq)`. Per name the receiver keeps
  a floor plus at most 64 accepted seqs: a seq below the floor is refused as *stale*, a seq in
  the set as a *replay*. State is bounded, exact for what it admits, and committed in the
  snapshot as `accepted_root`, so a node that joined from a snapshot still refuses old
  receipts. The price: a very old out-of-order receipt must be re-issued by the payer.
* **Witness policy.** A witness cosigns an origin's checkpoint only if it extends the last one
  that witness recorded (or is the same checkpoint again). Fork, older, or inconsistent ⇒ no
  cosignature, so conflicting histories can never both reach a quorum of honest witnesses.
  What a witness has seen is itself ledger entries, so witnesses are auditable.
* **Quorum scales with value.** `QuorumPolicy { base, tiers: [(amount ≥, witnesses)] }`; the
  highest matching tier wins and an unreadable amount takes the strictest tier. Small payments
  need only the payer's signature; large ones need witnesses. The quorum applied is recorded
  on the `transfer.in` (`witnesses` attr).

Without a witness quorum there is a window (until the next reconnect) in which a payer's
double-spend is *detectable* but not *prevented*. The tiers let you choose where that risk is
acceptable.

## 6. Boot integration

```
ToR ── BOOT_OFFER (signed: …, authority_pos, ledger_snapshot_ref, node_cert) ──▶ ainit
ainit: BootOffer::verify → open_for_boot → record_boot
```

* `open_for_boot`: no snapshot ref ⇒ open normally. Ledger already has state (a reboot) ⇒ keep
  it; a node never swaps history underneath itself. Empty ledger + ref ⇒ fetch, require
  `blake3(bytes) == ref`, verify against the authority at `authority_pos`, then join. Any
  failure aborts the boot rather than starting unanchored.
* `record_boot` writes a `boot` entry under the node's own actor, `auth` = the digest the
  authority signed, so the first link of the audit chain points at the exact capability that
  admitted the boot. The ref is covered by the offer signature, and the snapshot is itself
  signed by the authority chain.
* In the `ainit` simulation entrypoint no fetcher is wired yet (the offer there carries no ref).

## 7. IoT profile

Constrained devices should not run a ledger, hold a post-quantum key or sign anything.

```
 sensor ──53-byte report, keyed-BLAKE3 tag──▶ gateway ──one iot.batch entry──▶ ledger ──signed checkpoint
```

* **Report** (`MAX 316 B`): `ver ‖ leaf ‖ ctr ‖ payload ‖ 16-byte tag`. Per-leaf key =
  `derive_key("AMIN3-IOT-LEAFKEY-V1", master ‖ leaf)`, so the gateway holds one secret. Work on
  the sensor is a single keyed hash (~140 ns on a desktop core).
* **Gateway** verifies tag and a strictly increasing per-leaf counter, then commits a whole
  batch with one entry: `iot.batch { n, reports_root, counters_root }`. The log grows with
  batches, not sensors; `heads` stays at one actor per gateway; one fsync and one PQ signature
  per epoch.
* **Leaf receipt** = report → batch root (O(log batch)) → `iot.batch` entry → signed checkpoint.
  Offline-verifiable, also from Perl.
* **Counters.** A replacement gateway restores counters from any copy and proves them with
  `counters_root` from the latest batch entry (`restore_checked`, `--counters-root`). They are
  not in the snapshot because they grow with the fleet.
* **Slim receipts.** The node certificate (~4.7 KB) can be omitted; see §8.
* **Limit.** The tag is symmetric, so only the gateway can check it. The log proves the
  gateway committed that it received the report, not that the sensor signed it.

Rough sizes and costs (release build on a desktop, *not* a microcontroller):

| item | value |
|---|---|
| report | 53 B (16 B payload) |
| leaf receipt | ~10.6 KB full, ~5.9 KB slim |
| signed checkpoint | ~10.2 KB |
| snapshot to join | ~10.8 KB |
| gateway ingest | ~2 µs / report |
| checkpoint sign / receipt verify | ~0.5 ms / ~0.65 ms |

The receipt size is dominated by the post-quantum signatures and certificate. Receipts are for
gateways and archives; only the 53-byte report crosses a LoRa/BLE link.

## 8. Slim checkpoints and the certificate cache

`checkpoint::slim(wire)` removes the certificate. A slim checkpoint verifies only through
`CertCache`:

* entries are admitted only after the certificate verifies under that authority key, keyed by
  `(authority hash, node key hash)`; a checkpoint cannot add its own;
* a hit still re-checks validity at `pos`, `node_id == origin`, the key hash and the node
  signature; a miss fails closed (`UnknownKid`); the cache is bounded;
* the C ABI and Perl have no cache, so plain `verify` never accepts a slim wire (golden vectors
  pin this). `bctool --cert-cache FILE` re-verifies every stored certificate on load.

## 9. Quantum safety

| purpose | primitive |
|---|---|
| authority, witnesses, certificates, offers | ML-DSA-87 (FIPS 204) |
| node checkpoints | ML-DSA-65 ‖ Ed25519, both must verify |
| hashing, Merkle tree, ids, IoT tag | BLAKE3 with domain separation |
| IoT report key | 256-bit symmetric, 128-bit tag |

There is no RSA, ECDSA or Ed25519-only path. An optional future external timestamp anchor
(e.g. OpenTimestamps/Bitcoin) would be a hash commitment with a classical dependency.

## 10. Wire formats

| artifact | magic |
|---|---|
| checkpoint body | `AMIN3-TLOG-CKPT-V1\n` (cosig domain `…COSIG-V1\n`) |
| snapshot | `AMIN3-SNAPSHOT-V2\n` |
| receipt | `AMIN3-RECEIPT-V1\n` |
| leaf receipt | `AMIN3-IOT-LEAF-RECEIPT-V1\n` |
| entry / entry id | `AMIN3-LEDGER-ENTRY-V1\n` / `…ENTRY-ID-V1\n` |
| refs file header | `AMIN3REF` |

Layouts are documented at the top of `checkpoint.rs`, `snapshot.rs`, `receipt.rs` and `iot.rs`.
Return codes over FFI: `0` OK, `-1` format, `-2` unknown key, `-3` bad signature or proof,
`-4` not valid at position, `-5` quorum, `-9` bad argument.

## 11. bctool

| area | commands |
|---|---|
| identity | `nodecert-issue` |
| log | `tlog-append`, `tlog-head`, `tlog-prove`, `tlog-consistency`, `tlog-checkpoint`, `tlog-verify-*` |
| events | `ledger-append`, `ledger-show`, `ledger-verify`, `ledger-seal`, `ledger-join`, `ledger-compact` |
| snapshots | `snapshot-export`, `snapshot-verify` |
| mesh | `ckpt-observe` (`--cosign-sk` makes a witness), `ckpt-last`, `ckpt-attach` |
| receipts | `receipt-make`, `receipt-verify`, `receipt-accept` (`--quorum-tier`), `receipt-slim` |
| IoT | `iot-report`, `iot-ingest`, `iot-receipt`, `iot-verify`, `iot-slim` |

Arguments named `--checkpoint`, `--cert`, `--receipt` and the like accept a file path (raw
bytes) **or** inline base64.

Perl entry points: `Amin::Filter::Ledger` routes `amin:billing`, `ucc:settlement` and
`ledger:event` to `ledger-append` in batches and dies if events cannot be recorded (set
`AMIN_LEDGER_SLAB`); `Amin::Crypto::Verify` exposes the verifiers and the IoT report helpers.

## 12. Known limits

* **Double-spend while fully offline** is prevented only with a witness quorum; otherwise it is
  detected at the next contact.
* **Certificate position policy.** Offline observers judge a certificate at the position the
  origin last knew; both positions are recorded but not enforced, and revocation is unresolved.
* **Snapshot size** grows with the number of actors and payers (flat lists). Very large actor
  sets would want a sparse Merkle commitment.
* **Replay window** refuses receipts older than the last 64 accepted from the same payer actor.
* **Per-sensor non-repudiation** is not provided (symmetric tags); a hash-based key per leaf
  would add it.
* **Writer process.** `bctool ledger-append` reopens the ledger per call. For a busy node use
  `bctool ledger-stream` (or `stream => 1` / `AMIN_LEDGER_STREAM=1` on `Amin::Filter::Ledger`):
  one process, requests end with a `.` line. It holds the slab lock while open, so close it
  before another process opens the same ledger.
* **Compaction crash** is covered by an unpin-intent file written before the new base; the next
  open unpins what the intent lists (never anything still retained) and removes it.
* **Instrument replay.** The signed instrument message (`amin.ucc.art3.v2`) carries a per-maker
  `seq`; `Amin::UCC::Instruments` accepts only a seq above the maker's last accepted one, after the
  signature verifies. The high-water mark is per process unless `AMIN_INSTRUMENT_STATE` names a file.
* **Snapshot fetch.** `ainit` reads the snapshot named by the offer from `AMIN_SNAPSHOT_SLAB`
  (a mesh-replicated slab); hash and signature are checked before use, absence fails closed.
  Fetching over the network is the replication layer's job, not `ainit`'s.
* **Checkpoint gossip** (`bitcache::gossip`): a node advertises its latest signed checkpoint as a
  slab object in `hot_refs[3]`; peers fetch, verify and observe it. Gossip carries no proof, so a
  checkpoint that does not extend the recorded one comes back `NeedProof` and the origin must be
  challenged. Nothing in `aminexec` publishes or polls yet; the library and `Mesh.pm` accessor exist.
* **Producers.** cgroup egress/disk metering already flows through `amin:billing`. `ucc:event`
  is recorded as `ucc.event`; `Amin::Ledger::Event` emits authorisation (`authz.grant|deny`) and AI
  tool-call (`ai.tool_call`) events. Calling it from the ZCap check and the AI tool dispatcher is
  not wired.

## 13. Tests

* `cargo test -p bitcache -p ainit -p awp3` — unit and scenario tests (three phones offline,
  fork detection, witness gating, snapshot join, compaction crash, 20k-report gateway, boot join).
* `AMIN_REGEN_GOLDEN=1 cargo test -p bitcache --test golden` regenerates the shared vectors.
* `prove -I perl-lib t/80-trust-golden.t t/81-ledger-filter.t` — Perl against the same vectors,
  and the audited-event filter.

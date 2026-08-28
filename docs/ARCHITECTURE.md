# Architecture

GOOIR is a semantic compiler substrate, not an application framework,
workflow engine, plugin daemon, or agent orchestrator. It represents semantic
values and typed ways to derive other values. It stops before effectful
execution.

## The object graph

```text
Fact --Capability--> Candidate Fact
```

A capability may have several named input and output ports, including distinct
ports with the same value kind. Planning therefore operates over typed
hyperedges, not over a list of verbs or a source/target pair.

There is only one edge kind. Lift, analysis, bridge, projection, lowering,
generation, and semantic validation describe what a capability means in its
own ecosystem; they are not parallel kernel mechanisms.

## Three semantic levels

```text
DialectId
  an independently governed, versioned vocabulary family

ValueKindId
  one exact named type within that dialect

Fact
  one content-identified value of that exact kind
```

Requests, messages, receipts, scopes, and faults do not each become dialects
when one authority governs them as a vocabulary. Conversely, unrelated
authorities do not become one dialect merely because a workflow composes them.

A fact identity covers its exact value kind, payload, and preserved semantic
extensions. It does not silently absorb provenance, implementation choice,
conformance, or host policy. Those are evidence about the value.

## Five kernel concepts

### Fact

An immutable semantic value. Unknown extension data survives serialization.
Malformed, ambiguous, unverified, or incompatible inputs are rejected or
retained as explicit uncertainty; absence is never upgraded into safety.

### Capability

An exact, versioned promise over named typed ports. It declares the default
conformance obligation. It is not code, a transport, a worker, or a lease.

### Provider

One implementation claiming to satisfy a capability. Provider identity and
implementation digest are distinct from the capability. Multiple providers
remain alternatives until a caller links one explicitly.

### Plan

A provider-neutral composition of capability steps followed by an explicit
linked invocation. Installing a package can add offers; it cannot silently
select an implementation.

### Admission

The evidence plane that distinguishes proposed output, exact provider
authority, independent conformance, and local policy. A host may explicitly
authorize one complete measured provider offer, or require an independently
produced assessment. A provider cannot grant itself either authority, and a
passing suite does not bypass the admitting host's policy.

## Packages

`org.gooi.package/v1` packages bind exact content-addressed resources,
dependencies, capability declarations, provider offers, conformance offers,
and exports. Installation produces immutable locks and rejects coordinate or
content substitution.

Packages describe what is available. Selection belongs to planning. Launch
authority belongs to a host.

## Product façade

`gooir-derive` is the 0.1 composition door over that finite substrate. A
request names either a value-kind query or one exact capability output,
admitted fact-authority references, and either an explicit complete selection
or the conservative `UniqueOnly` policy. An exact output remains the graph
root even when its value kind is already available initially; this prevents a
portable artifact carrier such as `ContentSet` from erasing generator intent.
Route, offer, named-input, and authority-basis choices are fixed before the
first host effect. Every offer not directly authorized by the local policy
also fixes a suite and independent attester.

Every accepted request ends in one remedy-preserving answer:

- `Produced`: the target and every materialized output are admitted authority
  records, never bare provider claims;
- `Blocked`: semantic routes exist but lack an implementation or, for an offer
  without direct provider authority, an available independent attester;
- `Unreachable`: no declared semantic route reaches the target;
- `Refused`: the request, selection, ambiguity, or local policy forbids the
  attempt; or
- `Failed`: one exact selection was attempted but did not yield an admitted
  target.

This façade selects and validates neutral documents. It does not add a runtime
or move launch, transport, retry, or recovery policy into the semantic graph.

`gooir-derive::CompilerDriver` is the ergonomic in-memory entry over that same
façade. It stages source-observation admission and uses conservative complete
selection so downstream hosts do not reconstruct plans, offers, named input
bindings, invocations, or authority records. `compile_output` names a semantic
terminal without fixing its provider or dependency route. It adds no
serialized compile protocol.

## Execution boundary

The substrate may emit and validate neutral documents such as:

- a linked invocation;
- a candidate;
- an independent conformance assessment; and
- an admission decision and authority record.

Independent assessment is one admission basis, not a universal second
implementation. An exact `CapabilityOffer` explicitly listed in the host's
default-deny policy may instead be admitted through provider authority. This
still validates exact inputs, invocation/result/candidate correlation, named
outputs, content identities, and atomic admission. Installation, package
ownership, or a provider's own claim never populates that policy list.

An external host owns:

- credentials and secret transport;
- process or network launch;
- deadlines, cancellation, and resource limits;
- leases, fencing, retries, and idempotency;
- durable journals and crash recovery;
- implementation selection policy; and
- target-specific authority.

The host is not modeled recursively as another semantic dialect merely because
its state can be serialized. Host facts may be lifted into an ecosystem when a
real consumer needs their meaning, but that does not move host machinery into
the kernel.

The optional bounded local stdio host is one concrete `DerivationHost`, not a
universal runtime. It dispatches provider artifacts only by exact installed
`OfferId` to `PackageRegistry::offer_artifact` copied bytes. Attesters are
explicit complete `ConformanceAuthority` bindings to copied package resources
with the same digest. Artifacts run from private temporary paths with no
arguments, environment, or `PATH` lookup under mandatory positive byte and
deadline bounds; timeout kills and reaps the child. The child retains the
caller's ordinary OS authority, so this is not a sandbox, credential boundary,
daemon lifecycle, or durable host.

`gooir-toolchain` is optional host SDK support before that execution boundary.
It turns explicit final external artifacts and exact package recipes into a
create-only deployment image, then independently reloads the image through the
ordinary package loader. Provider resources become package offers only through
their measured bytes. Attester resources remain exact host bindings in a
separate toolchain lock and never become semantic implementation offers. A
loaded toolchain supplies inventory; it does not select, execute, attest, admit,
or materialize a product artifact. Loading is bounded both per package and over
the complete image. Create-only publication returns an explicit committed
report, including uncertain parent-directory synchronization after the atomic
commit rather than a retryable-looking error.

## Admitted artifact publication boundary

`gooir-artifact-sdk` is optional host support after semantic derivation and
admission. It defines one offer-free portable content-set contract so unrelated
external generators can converge on paths and bytes without moving target
meaning into GOOIR. A private-constructor `Admitted<T>` resolves only an exact
fact-and-authority pair through `AdmissionLedger`; an unadmitted candidate has
no publication path.

The local publisher owns filesystem policy, not semantics. It operates on one
dedicated managed directory, with an owner-fenced canonical manifest and
read-only check/diff. Missing output may be created. Changed output may be
replaced only when the existing complete tree still matches its manifest.
Unmanaged, wrong-owner, drifted, ambiguous, unsupported-extension, and symlink
states fail closed.

macOS and Linux publication uses a cooperative lock on the caller-controlled
immediate parent plus atomic no-replace rename or directory exchange. This
coordinates SDK publishers; it does not defend a parent controlled by a
malicious non-cooperating process. After an atomic commit, sync and retired-tree
cleanup uncertainty are returned as receipt data rather than ordinary errors.
The SDK makes no cross-filesystem or universal power-loss durability claim.

This boundary adds no `Backend`, `Materialize`, lowering/lifting, or lens edge.
Generation remains an ordinary capability. Concrete target contracts and
providers remain external packages.

## Reference managed-build composition

The generic CLI demonstrates, but does not hide, the complete public Rust SDK
path:

```text
InstalledToolchain
  -> LocalStdioHost
  -> CompilerDriver::compile_output(exact capability, exact output port)
  -> Admitted<ContentSet>::resolve(the same driver's ledger)
  -> LocalPublisher
```

`CompilerDriver` chooses the authority basis fixed by policy. Directly
accepted exact offers require no attester resource. Every other selected offer
still requires an available independent attester accepted by the same policy.

Raw source paths enter only as one caller-authorized `ContentSet` observation.
The CLI preserves their portable paths and binary bytes, records a documented
raw-file SHA-256 evidence kind, and requires a complete explicit observation
authority accepted by the admission policy. It neither parses domain syntax
nor claims that the named observer artifact executed. The exact output is
preflighted as `ContentSet` before provider execution, and only a `Produced`
answer can reach publication.

This reference path is intentionally a command composition rather than a new
host or build protocol. Backend repositories supply provider and attester
packages for installed toolchains, not per-dialect CLIs. Product hosts may call
the same public crates with a different `DerivationHost` or effect policy.

## Extension direction

```text
domain contract/package
          |
          v
GOOIR public protocols and planning
          |
          v
external host policy and execution
```

The dependency direction is one-way. Domain ecosystems consume GOOIR. Fleetd
or another orchestrator may host provider attempts. Neither becomes a kernel
concept, and GOOIR never imports their vocabulary.

## Compatibility and support status

The identity, capability, package, planning, and authority protocols are the
architectural center. `gooir-derive::{DerivationRequest, Answer}` is the 0.1
host-facing product façade over them. `gooir-provider::neutral` is the
established 0.1 typed authoring surface for package-backed providers over the
neutral v1 invocation and result documents. It validates exact provider
binding and named-port shape but does not launch code, measure the selected
artifact, or establish trust. Independent data-model and native HTTP/Axum
consumers exercise single- and multi-input providers, semantic inability,
artifact production, and neutral framing.
`gooir-provider::attester` is the matching narrow authoring surface over the
versioned neutral assessment request. The executing host, not the attester,
still binds the complete authority to measured artifact bytes.
The older
`gooir-capability::{CapabilityRegistry, DerivationRequest, Answer}`, the
top-level in-process provider helpers, and `org.gooi.plugin/v2` are
compatibility surfaces, not universal execution protocols. Their presence does
not authorize a second runtime inside GOOIR.

`gooir-wasip1-command-runtime` is a reusable host library. It is not semantic
meaning and it does not make WASI the required provider backend.

`gooir-toolchain` is likewise reusable host support, not a backend registry or
target SDK. Backend is an ecosystem role played by an ordinary provider. The
toolchain SDK only removes repeated deployment measurement and binding
machinery from those external ecosystems.

## Proven consumers

The data-model ecosystem proves deterministic lifting/lowering, exact package
installation, recoverable external execution, and the neutral provider SDK in
its authored-data-model provider. The native HTTP/Axum ecosystem proves named
three-input lowering through a Rust-source-tree endpoint. It does not yet
prove `ContentSet` generation or managed materialization. Those deterministic
compiler paths may use explicit exact provider authority rather than
handwritten shadow attesters. Independent assessment remains available when
their host does not directly authorize an offer.
The Fleetd direct-conversation ecosystem proves a stateful capability with two
independent clients, a credential-free child command boundary, an independent
attester, owner-fenced attempts, crash recovery, and deterministic terminal
replay.

Those proofs are deliberately downstream. Their source and evidence live in
their own repositories so the kernel cannot grow by copying the next
consumer's nouns into itself.

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

The evidence plane that distinguishes proposed output, independent
conformance, and local policy. A provider cannot attest itself into truth, and
a passing suite does not bypass the admitting host's policy.

## Packages

`org.gooi.package/v1` packages bind exact content-addressed resources,
dependencies, capability declarations, provider offers, conformance offers,
and exports. Installation produces immutable locks and rejects coordinate or
content substitution.

Packages describe what is available. Selection belongs to planning. Launch
authority belongs to a host.

## Product façade

`gooir-derive` is the 0.1 composition door over that finite substrate. A
request names an exact target, admitted fact-authority references, and either
an explicit complete selection or the conservative `UniqueOnly` policy. Route,
offer, named-input, suite, and independent-attester choices are fixed before
the first host effect.

Every accepted request ends in one remedy-preserving answer:

- `Produced`: the target and every materialized output are admitted authority
  records, never bare provider claims;
- `Blocked`: semantic routes exist but lack an implementation or available
  independent attester;
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
bindings, invocations, or authority records. It adds no serialized compile
protocol.

## Execution boundary

The substrate may emit and validate neutral documents such as:

- a linked invocation;
- a candidate;
- an independent conformance assessment; and
- an admission decision and authority record.

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

`gooir-file-tree-v1` is an optional artifact dialect on the semantic side of
this boundary. A `FileTree` fact describes bounded, content-addressed virtual
files at portable relative paths. It has no absolute destination, filesystem
handle, overwrite or deletion policy, permission bits, write status, or
materialization receipt. A producer reaches it through an ordinary declared
capability and it acquires authority through the existing independent
conformance and admission path. A product host may materialize only an exact
admitted fact under its own explicit local policy. That host operation is not
a semantic capability, and the compiler driver does not perform it.

`gooir-file-tree-materializer` is one optional local implementation of that
host operation. Its public authority gate accepts an `AdmissionLedger` plus one
exact `AdmittedFactRef` and performs resolution internally; a caller cannot
substitute a publicly assembled `ResolvedFact`. It revalidates the complete
authority and FileTree payload and refuses unknown extensions anywhere in the
reference, authority chain, fact, tree, or file rather than assuming they are
irrelevant.
Mandatory host limits bound files, directories, per-file bytes, and total
bytes. Mandatory policy fixes ordinary Unix file and directory modes and, in
this first version, supports only atomic refusal of every existing destination.

The local implementation creates a private random staging directory beside the
destination, traverses it only through retained no-follow descriptors, writes
and synchronizes exact files, then publishes the complete tree with atomic
no-replace rename. After that commit point it returns a receipt even if syncing
the parent directory fails; the receipt marks durability uncertain so a caller
does not retry under the false assumption that no effect occurred. The receipt
is non-constructible in-process host evidence, not a stable semantic protocol.
Crashes may still leave a private staging directory or a published tree without
a returned receipt; durable reconciliation belongs to a later product host.

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

The file-tree contract is narrow optional support, not a new kernel concept or
a generic effect model. Target-specific artifact dialects may remain richer;
an explicit capability can project one into the generic file-tree kind when
its information is sufficient.

The matching local materializer is also optional support. Neither
`CompilerDriver` nor the semantic planner depends on it. A product build driver
may compose them by explicitly resolving the produced authority and then
calling the host-side `FileTreeMaterializer` seam.

`gooir-wasip1-command-runtime` is a reusable host library. It is not semantic
meaning and it does not make WASI the required provider backend.

## Proven consumers

The data-model ecosystem proves deterministic lifting/lowering, independent
conformance, exact package installation, recoverable external execution, and
the neutral provider SDK in its authored-data-model provider. Its remaining
legacy providers stay on the compatibility helper. The native HTTP/Axum
ecosystem proves named three-input lowering followed by artifact generation,
offer-free package planning, typed inability, and exact neutral provider
document handling; its binaries expose the SDK's stdio entry point.
The Fleetd direct-conversation ecosystem proves a stateful capability with two
independent clients, a credential-free child command boundary, an independent
attester, owner-fenced attempts, crash recovery, and deterministic terminal
replay.

Those proofs are deliberately downstream. Their source and evidence live in
their own repositories so the kernel cannot grow by copying the next
consumer's nouns into itself.

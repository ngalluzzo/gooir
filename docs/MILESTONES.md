# Milestones

## Established

- Exact dialect, value-kind, fact, capability, provider, package, invocation,
  candidate, conformance, and admission identities.
- Named typed capability ports, including repeated value kinds in distinct
  roles and conservative extension preservation.
- Content-bound package dependencies, resources, offers, exports, installed
  locks, and provider-neutral planning.
- Exact capability/output planning and derivation goals, including generators
  whose initial and terminal values share one portable artifact kind.
- Explicit implementation linking and substitution-resistant invocation
  identity.
- Exact provider authority and independent conformance as disjoint,
  default-deny contextual admission bases.
- One bounded 0.1 derivation façade with exact complete selection and five
  remedy-preserving terminal answers.
- One reusable compiler driver that atomically admits source observations,
  retains their exact references across several requests, exposes named
  admitted outputs, and delegates the complete multi-hop
  plan/link/invoke/authorize-or-assess/admit spine to the façade.
- One bounded local stdio host over exact copied offer and attester resources,
  with explicit byte/deadline bounds and kill-plus-reap timeout behavior.
- A neutral v1 attester assessment-request and authoring seam.
- Neutral graph diagnostics and explicitly loaded package manifests.
- A bounded WASI command runtime usable by external hosts.
- One deterministic data-model ecosystem extracted as a downstream consumer.
- One stateful Fleetd direct-conversation proof ecosystem extracted as a
  downstream consumer.
- A neutral v1 provider-authoring SDK exercised independently by the
  authored-data-model provider and the native HTTP-to-Axum-to-Rust ecosystem.
- Exact multi-capability provider dispatch for serving several implementations
  from one executable without discovery, fallback, or per-capability mains.
- A host-owned toolchain-image SDK for measuring final external provider and
  attester resources, deriving exact offers and bindings, atomically staging a
  create-only image, and independently reloading its package inventory.
- An optional admitted-artifact SDK with an offer-free portable content-set
  contract, exact ledger gate, read-only check/diff, owner-fenced create or
  atomic clean replacement, canonical manifest, and uncertainty-aware receipt.
- One generic managed-build CLI and public SDK composition from explicit raw
  source paths through an exact installed capability output, exact provider
  authority or independent conformance, admission, and repeated `ContentSet`
  publication.

## Current boundary

GOOIR 0.1 presents one product door over the finite substrate. Ecosystems can
publish exact packages; hosts can ask one derivation question, fix a complete
route/offer/input/attester selection, execute it through their own effect
boundary, and receive `Produced`, `Blocked`, `Unreachable`, `Refused`, or
`Failed` without changing the kernel.

The established 0.1 provider-authoring surface reduces neutral v1 providers to
one typed function over named inputs and outputs while retaining exact binding,
conservative extension handling, and protocol framing. The data-model and
native HTTP/Axum ecosystems exercise materially different provider shapes.
Artifact measurement, execution policy, provider qualification, conformance,
and admission remain host concerns and are not implied by SDK stability. An
installed offer becomes direct authority only when the host's default-deny
policy explicitly names that complete measured offer; all other offers still
require accepted independent conformance.

The local `gooir compile` composition is intentionally narrower than a general
execution platform. It loads only explicit packages, source observations,
policy, attester bindings, target, and resource limits; it produces the
existing derivation answer without target-specific materialization or a new
stable receipt protocol. Its child artifacts retain caller OS authority and
receive no arguments or environment. Durable execution, credentials, retries,
deployment, and sandboxing remain external-host concerns.

External backend repositories remain independently governed. GOOIR supplies
their neutral provider/attester authoring seams and the shared host machinery
for building an exact installed toolchain image; it does not ship their target
profiles, lowerings, generators, conventions, or artifact semantics.
Those repositories ship ordinary provider and attester packages rather than
per-dialect GOOIR CLIs. The generic `gooir build` command is one reference host
over the same public Rust SDK composition available to other hosts.

Those repositories may converge on `ContentSet` as their final admitted bytes
and reuse the managed local publisher. This is host machinery after admission,
not backend discovery or a new semantic edge. The first publisher is scoped to
dedicated directories on supported macOS/Linux local filesystems. It uses
cooperative parent locking, refuses unmanaged or drifted state, and reports
post-commit synchronization and cleanup uncertainty without implying a
portable durability guarantee.

Proposed Decision 0046 defines the next product gate: source-tree observation
and managed snapshots, minimal application and bridge contracts, the external
TypeSpec frontend, a separately authorized locked workspace preset, complete
artifact backends, and one real Fleetd vertical slice with no manual assembly.
This work must not add another kernel compiler surface, universal IR, or
backend abstraction; the reusable derivation and provider SDKs are sufficient.
The legacy in-process CLI derivation path remains only as an isolated migration
bridge and is not part of the 0.1 host contract.

The first read-only prerequisite is now present in the artifact SDK: bounded
recursive source capture and verified clean managed-output snapshot recovery.
They remain authority-neutral host I/O; preset, frontend, bridge, backend, and
Fleetd proof work stays external or above the kernel as Decision 0046 requires.

The repository split in GOOIR-0033 is itself an acceptance gate: GOOIR must
continue to compile and test while both extracted ecosystems compile and test
solely as downstream users of its public crates.

## Deliberately not standardized

- task, issue, workflow, conversation, message, agent-session, data-model, UI,
  and Fleetd vocabularies;
- a universal provider transport or daemon lifecycle;
- host retry, lease, recovery, credential, or deployment policy;
- a generic effect dialect;
- registry federation or ecosystem governance; and
- compatibility for superseded research probes.

These are not omissions to fill preemptively. They are boundaries to revisit
only when independent consumers demonstrate recurring semantics.

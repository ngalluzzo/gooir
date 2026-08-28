# Milestones

## Established

- Exact dialect, value-kind, fact, capability, provider, package, invocation,
  candidate, conformance, and admission identities.
- Named typed capability ports, including repeated value kinds in distinct
  roles and conservative extension preservation.
- Content-bound package dependencies, resources, offers, exports, installed
  locks, and provider-neutral planning.
- Explicit implementation linking and substitution-resistant invocation
  identity.
- Independent conformance separated from contextual host admission.
- One bounded 0.1 derivation façade with exact complete selection and five
  remedy-preserving terminal answers.
- One thin compiler driver that admits source observations and delegates the
  complete multi-hop plan/link/invoke/assess/admit spine to that façade.
- One bounded local stdio host over exact copied offer and attester resources,
  with explicit byte/deadline bounds and kill-plus-reap timeout behavior.
- A neutral v1 attester assessment-request and authoring seam.
- Neutral graph diagnostics and explicitly loaded package manifests.
- A bounded WASI command runtime usable by external hosts.
- A separately versioned, bounded, content-addressed virtual file-tree
  artifact contract with portable path and collision rules; the contract
  itself carries no filesystem authority.
- A bounded local file-tree materializer that requires exact admitted
  authority, rejects unknown semantic extensions and existing destinations,
  and atomically publishes a synchronized same-parent staging tree.
- One deterministic data-model ecosystem extracted as a downstream consumer.
- One stateful Fleetd direct-conversation proof ecosystem extracted as a
  downstream consumer.
- A neutral v1 provider-authoring SDK exercised independently by the
  authored-data-model provider and the native HTTP-to-Axum-to-Rust ecosystem.

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
Artifact measurement, execution policy, conformance, and admission remain host
concerns and are not implied by SDK stability.

The optional file-tree dialect standardizes only an artifact value shared by
independent consumers. It does not widen `CompilerDriver`: destination choice,
write policy, materialization, receipts, and product build orchestration remain
outside the semantic driver. A future product build driver must resolve an
exact admitted file-tree authority before invoking any host materializer.

The first local materializer supplies that authority gate and a
non-constructible host receipt. It intentionally supports only no-replace
publication with mandatory limits and modes. It does not give the compiler
driver filesystem authority, define overwrite or deletion policy, serialize a
universal receipt, or recover an interrupted build.

The local `gooir compile` composition is intentionally narrower than a general
execution platform. It loads only explicit packages, source observations,
policy, attester bindings, target, and resource limits; it produces the
existing derivation answer without target-specific materialization or a new
stable receipt protocol. Its child artifacts retain caller OS authority and
receive no arguments or environment. Durable execution, credentials, retries,
deployment, and sandboxing remain external-host concerns.

The next meaningful semantic work should be driven by another real consumer
encountering a specific missing protocol property, not by adding speculative
dialects or a generic effect runtime. The legacy in-process CLI derivation path
remains only as an isolated migration bridge and is not part of the 0.1 host
contract.

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

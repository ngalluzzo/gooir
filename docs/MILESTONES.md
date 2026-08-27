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
- Neutral graph diagnostics and explicitly loaded pack manifests.
- A bounded WASI command runtime usable by external hosts.
- One deterministic data-model ecosystem extracted as a downstream consumer.
- One stateful Fleetd direct-conversation proof ecosystem extracted as a
  downstream consumer.

## Current boundary

GOOIR is complete enough for ecosystems to publish contracts and for hosts to
link, execute, attest, and admit them without changing the kernel. The next
meaningful work should be driven by a second real consumer encountering a
specific missing protocol property, not by adding speculative dialects or a
generic effect runtime.

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

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
- Neutral graph diagnostics and explicitly loaded package manifests.
- A bounded WASI command runtime usable by external hosts.
- One deterministic data-model ecosystem extracted as a downstream consumer.
- One stateful Fleetd direct-conversation proof ecosystem extracted as a
  downstream consumer.

## Current boundary

GOOIR 0.1 presents one product door over the finite substrate. Ecosystems can
publish exact packages; hosts can ask one derivation question, fix a complete
route/offer/input/attester selection, execute it through their own effect
boundary, and receive `Produced`, `Blocked`, `Unreachable`, `Refused`, or
`Failed` without changing the kernel.

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

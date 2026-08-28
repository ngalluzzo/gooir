# 0045 — Exact provider authority is a valid admission basis

Status: accepted

## Context

Decision 0012 correctly required independent conformance before admitting
untrusted Fleetd and agent-produced candidates. Decision 0017 correctly added
a separate local policy so that any merely different attester could not mint
authority. Decision 0034 then generalized that one threat model into a
requirement that every provider candidate have a separately deployed
independent attester.

That generalization is wrong for an exact implementation that the admitting
host has already qualified and chosen to trust. `CapabilityOffer` already
binds the capability, implementation identity, measured artifact digest, and
content-derived offer identity. `AdmissionPolicy` already names the local
decision authority. Requiring another executable in this case does not create
a new authority; it forces backend ecosystems to reproduce the provider's
semantics in a shadow implementation.

Installation remains availability, not trust. Determinism, a package
declaration, a signature, shared source ownership, or provider-supplied
evidence cannot authorize an offer automatically.

## Decision

An admission policy may explicitly accept complete exact `CapabilityOffer`
values. A candidate from such an offer can pass through a provider-authorized
admission path without a per-candidate independent assessment.

```text
exact installed offer + explicit local provider authority
  -> invoke
  -> validate result and candidate structure
  -> apply local policy
  -> atomically admit every output

all other offers
  -> invoke
  -> independently assess
  -> apply local policy
  -> atomically admit every output
```

The provider-authorized path retains exact input-authority resolution,
invocation and result correlation, named output validation, content identity,
local decision records, atomic multi-output admission, and complete derivation
provenance. Its authority record explicitly says that the local policy
authorized the selected provider offer and contains no assessment.

The allow-list is default empty. It contains full `CapabilityOffer` values,
not implementation names, capability names, packages, or artifact digests in
isolation. Packages cannot populate it. A host must make the decision from
outside the package being authorized.

When a policy both directly accepts an offer and accepts an independent
attester applicable to it, direct provider authority takes precedence. Adding
an exact offer to the provider allow-list is therefore an intentional choice
to omit per-candidate assessment, never an availability-dependent fallback.

For every offer not directly accepted, the requirements from Decisions 0012
and 0017 remain unchanged: the attester must differ by both implementation and
artifact digest, its assessment must bind the exact candidate, it must pass,
and the local policy must accept its complete authority.

## Qualification and target-native tools

GOOIR does not add a generic qualification protocol. A host can qualify an
exact provider artifact through code review, conformance corpora, an official
parser or compiler, database execution and introspection, reproducible builds,
or another authority appropriate to the target. The resulting host decision
is represented by the exact offer in its admission policy.

For untrusted generation, an independent attester should use authoritative
target tooling and semantic comparison where available. It should not become
a second generator merely to reconstruct the expected bytes.

Direct provider authority says only that this host accepts semantic output
from those exact implementation bytes. It does not prove determinism,
correctness, hermeticity, or safety. Execution isolation and runtime closure
measurement remain host responsibilities.

## Compatibility

`accepted_provider_offers` is omitted when empty, and constructors retain the
existing admission-policy v1 protocol and identity. A nonempty provider
allow-list requires admission-policy v2. That protocol split is mandatory
because v1 flattened arbitrary extension keys: interpreting a legacy
`accepted_provider_offers` extension as authority would fail open. New readers
reject that field under v1; older readers reject v2. Existing policy JSON,
policy identities, independently assessed decisions, authority records, and
snapshots therefore retain their existing representation. New
provider-authorized decisions and authority records use new disjoint enum
variants. Older readers reject those variants rather than treating them as
assessed facts, which fails closed.

Capability declarations, package manifests, provider protocol, planning
documents, toolchain locks, and `DerivationHost` do not change. The existing
default conformance suite remains the suite selected when independent
assessment is required; directly authorized execution does not run it.

## Consequences

- Deterministic parsers, lifts, lowerings, and generators no longer require a
  handwritten shadow attester solely to become usable.
- Untrusted and agent-produced output retains the strict independent membrane.
- One route may mix provider-authorized and independently assessed steps.
- A toolchain may contain zero attesters when every selected offer is directly
  accepted by the host policy.
- Installed but unauthorized offers still cannot produce admitted facts.
- Provider-authorized provenance is distinguishable from independently
  assessed provenance at every admitted output.

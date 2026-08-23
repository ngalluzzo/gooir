# 0002 — Evidence trust is contextual

Status: accepted for externally lifted claims

## Decision

A serialized claim cannot declare itself trusted. `Verified` records only that an
attester reported successful verification. `SemanticResolver` receives an
explicit trust policy, whose default admits no conformance attestations.

Each conformance attestation carries exact opaque identifiers for:

- the attester authority;
- the conformance suite and version;
- the digest of the adapter, bridge, or implementation exercised;
- the digest of an immutable result document.

The result document is expected to bind the attester, suite, subject, outcome,
and execution metadata. Before admitting the exact tuple, the host is
responsible for validating its authenticity, the attester's authority, and the
referenced artifact. This slice models auditable admission, not cryptographic
proof or a global authority registry.

Multiple claims for the same exact contract remain ambiguous before trust is
considered. A trusted claim never silently overrides a conflicting claim.
Contract-version bridges preserve evidence and cannot mint trust.

## Rationale

Trusting any `Verified + digest` record permits trait laundering: an adapter can
assert its own safety and cause generic analyzers to produce false confidence.
Trusting an authority or suite name alone has the same flaw because no admitted
result identity is required.

Exact contextual admission gives the first externally lifted analyses a
default-deny boundary while keeping authority governance, signature algorithms,
and semantic meaning outside the microkernel.

## Consequences

- Existing test fixtures must explicitly construct a trust policy.
- Loaded graphs with self-reported verified evidence resolve as unknown unless
  the active host admits their exact attestations.
- A later package may verify signed result envelopes and construct policies; it
  need not change the core evidence transport or analyzer contract.
- Revocation, trust delegation, quorum rules, and cryptographic envelope formats
  remain follow-up work.

## Acceptance evidence

The resolver tests cover default denial, exact admission, all attestation fields,
conflicting admitted claims, and rejection of a bridge that changes evidence.
The retry-safety integration tests demonstrate that a valid contract-version
bridge preserves rather than creates trust.

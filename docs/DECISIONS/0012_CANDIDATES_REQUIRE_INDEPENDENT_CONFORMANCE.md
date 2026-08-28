# Decision 0012: candidates require independent conformance

> Decision 0045 narrows this universal requirement to candidates whose exact
> provider offer is not directly authorized by the admitting host's policy.
> The independent-conformance rule below remains unchanged for untrusted and
> agent-produced output.

## Context

GOOIR can bind a missing typed capability to exact input facts, and Fleetd can
carry that request through one durable, owner-fenced harness attempt. A harness
terminal response is execution evidence, not semantic output. Accepting JSON
that merely names the requested fact type would let provider prose, malformed
output, or self-attested tests enter the semantic graph as truth.

## Decision

The return path has three distinct records:

1. The orchestrator-owned attempt preserves terminal execution evidence.
2. A strict lift extracts a provider-neutral `CapabilityCandidate` containing
   the exact request identity, semantic provider and implementation digest,
   exact proposed output set, and an opaque digest of the attempt evidence.
3. An independently identified conformance provider runs the exact suite named
   by the request and emits a content-addressed result with named checks.

Candidate and conformance-result identities are RFC 8785 canonical JSON hashed
with SHA-256. Candidate extraction establishes shape and binding only. It does
not establish that payloads mean what their fact types promise.

The conformance provider must differ from the generating provider in both exact
provider identity and implementation digest. A suite mismatch, empty check set,
or verifier execution failure fails closed. Failed checks produce an exact
result with no admitted facts. Passed checks construct facts whose derivations
bind the input fact identities, request, candidate, generating implementation,
and conformance result.

## Consequences

- ACP, OpenCode, Fleetd leases, and session epochs remain outside semantic fact
  meaning; the candidate carries only an opaque attempt reference.
- An agent cannot promote its own statement that tests passed.
- Raw attempts can be re-lifted deterministically as extraction improves.
- Conformance suites remain product- or dialect-specific providers; the
  generic capability crate learns no UI, workflow, Fleetd, or web semantics.
- Passing conformance is evidence rather than universal trust. A consuming host
  still applies its contextual admission policy.

The cross-repository fixture is deliberately a transport-only mock. GOOIR and
Fleetd agree on its candidate identity, the named suite rejects it, and no fact
is admitted. This demonstrates the trust boundary before the real runnable-web
suite exists.

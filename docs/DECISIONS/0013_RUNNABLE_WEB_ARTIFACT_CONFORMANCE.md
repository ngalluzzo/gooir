# Decision 0013: Runnable web artifacts are exact revisions with verifier-owned behavior checks

## Status

Accepted for the Fleetd dogfood slice.

## Context

The generic candidate/admission waist can prove that a proposed output is
bound to an exact request and durable attempt, but it intentionally cannot know
what makes a Fleetd web surface runnable. Accepting a producer-authored test
report would collapse extraction and trust back into one agent claim.

The first real slice also needs to preserve the neutral-waist thesis. The web
implementation should consume the already-derived target IR rather than copy
its fields, actions, and HTTP bindings into an unrelated UI specification.

## Decision

`fleetd-capability-pack` owns the versioned
`dev.fleetd.conformance.runnable_web_surface@0.1.0` contract. A candidate
payload contains only:

- the exact schema identity;
- an operator-trusted Fleetd repository authority and full Git revision;
- the exact input target-fact identity;
- the fixed `/operator/` entrypoint; and
- the exact four-file served-asset manifest with media types and SHA-256
  digests.

The generating provider cannot choose the repository evaluated by the suite.
The operator supplies the trusted repository root to the verifier, and the
candidate authority must equal its canonical identity.

The verifier clones and checks out the exact proposed revision, requires a
pristine checkout, verifies every manifest digest, then writes a
verifier-owned integration test into that temporary checkout. That test starts
the candidate Fleetd router with real durable state and checks:

- the operator entrypoint and restrictive browser security policy;
- the accessible surface anchors required by this suite version;
- exact equality between `/operator/contract.json` and the request's bound web
  target IR;
- operator authentication on the target API; and
- the real requeue and abandon state transitions.

The emitted contract asset is the semantic link between target IR and runtime
UI. The JavaScript adapter may render it, but it may not replace or reinterpret
it with another hand-written API contract.

## Consequences

- Candidate-authored tests remain useful development feedback but are not
  admission evidence.
- Git revision plus asset digests make the evaluated artifact reconstructible.
- The suite is product-specific and separately versioned; `gooir-core` and the
  generic capability crate gain no web or Fleetd concepts.
- Running candidate code remains an effectful verification step. A later
  hardening milestone should execute conformance inside a resource- and
  filesystem-bounded runner without changing the artifact or admission waist.
- Browser interaction can be added as another independently identified check
  without changing provider output shape.

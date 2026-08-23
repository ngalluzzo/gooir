# Milestones

## GOOIR-000 — Kernel boundary invariants

- Opaque unknown dialect data round-trips losslessly.
- An analysis depends on exact semantic contracts, not source dialect names.
- Any two inputs resolving to the same contract graph produce the same normalized result, regardless of native representation.
- Unknown, unverified, or ambiguous claims degrade to unknown.
- A contract-version change is rejected until an explicit bridge exists.

## GOOIR-001 — Lift Buzz event surface

Lift event-kind declarations, SDK builders, CLI commands, relay handlers, feed/UI classifications, and relevant tests from a pinned Buzz revision and feature configuration.

Run a contract-based surface-completeness analysis. Findings identify the missing edge, exact searched scope, lifter versions, and source provenance.

## GOOIR-002 — Lift Buzz workflow transitions

Represent actions, suspension, approval, resumption, and terminal outcomes. Detect a path that can suspend but cannot reach a successful terminal outcome under the lifted scope.

## GOOIR-003 — Close and re-observe one finding

Have the Buzz agent team implement one verified missing edge. Re-lift and show that the target diagnostic disappeared, no other diagnostics regressed, tests pass, and the observed semantic graph changed only in the intended subgraph.

## GOOIR-004 — Import a non-Buzz authority

Lift one mature external semantic model such as Prisma DMMF or Smithy, bridge a narrow subset into shared contracts, analyze it, and delegate generation/execution back to the authoritative toolchain.

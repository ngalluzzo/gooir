# Milestones

## GOOIR-000 — Kernel boundary invariants

Status: merged at `f4eb97a453af9c6c4204cdc74c2f6ed5dad7720d` after independent exact-commit review.

- Opaque unknown dialect data round-trips losslessly.
- An analysis depends on exact semantic contracts, not source dialect names.
- Any two inputs resolving to the same contract graph produce the same normalized result, regardless of native representation.
- Unknown, unverified, or ambiguous claims degrade to unknown.
- A contract-version change is rejected until an explicit bridge exists.

## GOOIR-001 — Lift Buzz event surface

Status: active on `gooir-001-buzz-event-surface`, pinned to Buzz tag `desktop-v0.5.18` at commit `39f8b46935736334cdd7045a4e4b5d7eb1a33888`.

Lift event-kind declarations, SDK builders, CLI commands, relay handlers, feed/UI classifications, and relevant tests from a pinned Buzz revision and feature configuration.

Run a contract-based surface-completeness analysis. Findings identify the missing edge, exact searched scope, lifter versions, and source provenance.

The checked-in relation snapshot is a staging oracle for contract and analyzer development. GOOIR-001 closes only after coverage-witnessed lifters reproduce it from the pinned source; hand-authored rows cannot establish trusted product findings.

Current source-derived analysis projects the protocol, relay, and CLI native lifts through an exact, default-deny local admission policy. It reports six admitted relay-ingest contradictions and one exhaustive CLI command-surface gap. The six SDK-constructor requirements and runtime-dispatch requirement remain unknown until their own coverage-witnessed lifters land.

## GOOIR-002 — Lift Buzz workflow transitions

Represent actions, suspension, approval, resumption, and terminal outcomes. Detect a path that can suspend but cannot reach a successful terminal outcome under the lifted scope.

## GOOIR-003 — Close and re-observe one finding

Have the Buzz agent team implement one verified missing edge. Re-lift and show that the target diagnostic disappeared, no other diagnostics regressed, tests pass, and the observed semantic graph changed only in the intended subgraph.

## GOOIR-004 — Import a non-Buzz authority

Lift one mature external semantic model such as Prisma DMMF or Smithy, bridge a narrow subset into shared contracts, analyze it, and delegate generation/execution back to the authoritative toolchain.

## Experimental — Capability-planned Fleetd dogfood

Status: first in-process derivation and providerless need implemented on
`gooir-capability-planner-v0`.

The generic registry reconstructs the existing Fleetd multi-dialect pipeline
from exact typed capability edges and executes the web and terminal targets
with full fact derivation provenance. A declared but unimplemented runnable-web
edge becomes a machine-readable capability need. GOOIR binds that need to an
exact input fact and Fleetd carries it through an owner-fenced provider
attempt. The generic return path now works: Fleetd strictly extracts an exact
candidate, both repositories agree on its content identity, and GOOIR admits
facts only through a separately identified matching conformance provider.

The transport-only cross-repository fixture still intentionally fails the
named runnable-web suite and therefore admits no facts. The real
`dev.fleetd.conformance.runnable_web_surface@0.1.0` provider now defines an
exact artifact manifest, checks out the proposed Fleetd revision from an
operator-trusted repository, verifies its assets, and injects a verifier-owned
black-box test.

The first complete product loop now passes. A deterministic brownfield
provider projected Fleetd revision `98c73ba08c47eff77769c12f142442cdebb29ace`
through a durable Fleetd attempt. Candidate
`sha256:42d157fcec55a6385630a1b11130b40f4ec05cb4ef625a63ebba6d6df4236fcf`
passed independent conformance, produced admitted artifact fact
`sha256:5591961e7692ce6429464bf1b04abf04a44b95afb720a765d26871949f418a56`,
and re-planned to zero steps and zero needs. The next orchestration boundary is
an explicit structured result channel for tool-using ACP agents; progress prose
must remain evidence without being conflated with the final provider result.

## Experimental — Ecosystem-derived interaction activation

Status: provisional v0 contract and recurrence falsifier implemented on
`gooir-ui-ecosystem-correction-v0`.

GOOIR now pins 17 full runtime, conformance, materializer, and library source
documents plus five licenses from exact React, Vue, Ink, shadcn/ui, and Mantine
revisions. Source-specific AST projections over React DOM and Vue runtime-dom
independently recur on one narrow positive meaning: a bound activation invokes
its registered handler. Ink demonstrates the same route across a terminal host
but shares the React lineage; shadcn and Mantine are also React participants.
None of those three inflates the independent-authority count.

The provisional contract deliberately excludes component trees, buttons,
clicks, keys, labels, availability, state transitions, and effect cardinality.
The recurrence suite preserves all measured host differences in namespaced
native extensions, carries incomplete dependency closure and unexecuted test
suites as typed disjoint limits, and rejects a missing binding, stimulus,
assertion, runtime invocation, source digest, or parser pin as unknown.

The next gate is a same-application behavioral realization: semantic
activation through actual target revisions and authoritative builds, followed
by verifier-owned browser or PTY stimulus and a lift of only the observed
handler-dispatch subset. That proof, not source-shape code generation, earns
the first lowering capability.

## Experimental — Production representation-boundary probe

Status: native corpus and negative generic result implemented on
`gooir-ui-ecosystem-correction-v0`.

Six current production products plus one historical production corroborator
reject `Screen`, `Document`, and a universal component tree as GOOIR semantic
contracts. The pinned corpus contains native route, composition,
guarded-alternative, host-document, terminal, and stdout mechanisms. Its
Babel/Vue-compiler inventory records syntax only, without treating provider
behavior as projected or syntax as visibility and product meaning.

The web subset retains a provider-backed navigation binding as a separate
candidate. Gemini CLI and the historical TypeScript Codex CLI retain an
agent-session/activity candidate, while Shopify CLI falsifies any inference
from Ink itself. Neither candidate is admitted here. The next proof must bring
the appropriate authoritative route providers or an independent current
product/runtime lineage, then observe a real build under verifier-owned state.

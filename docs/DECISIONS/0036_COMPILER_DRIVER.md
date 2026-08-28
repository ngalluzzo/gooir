# 0036 — Compiler driver and bounded local stdio host

> Decision 0043 adds exact capability/output goals and
> `CompilerDriver::compile_output`. The value-kind `compile` path and all host,
> admission, and execution boundaries below remain unchanged.

Status: accepted first corrective composition

## Context

Decision 0034 already implemented the complete GOOIR 0.1 derivation spine:
package-backed planning, conservative complete selection, explicit linking,
external host invocation, independent assessment, and contextual admission.
Its public façade was exact but left every downstream product to admit source
observations, construct the façade inventory, and coordinate a request.

The generic CLI exposed planning while its only executable command used the
legacy `CapabilityRegistry`. Provider-side neutral stdio authoring existed, but
there was no equivalent generic assessment request or attester authoring seam.
The downstream Fleetd direct-conversation attester demonstrated the missing
shape with a closed request containing the invocation, result, candidate, and
host-measured attester digest. That domain-specific request is evidence, not a
protocol for GOOIR to import.

## Decision

`gooir-derive::CompilerDriver` is the default in-memory compiler-driver entry.
It is thin composition over `DerivationFacade`, not another planner or compile
protocol. A caller supplies one exact package registry, admission policy,
attester inventory, `DerivationHost`, finite limits, target, and source
observations. The driver stages source admission through `AdmissionLedger`,
uses `DerivationRequest::unique_only`, and returns the existing five-variant
`Answer`.

The driver never synthesizes offers or authority records. Offers are only the
content-bound values already derived by package loading. Complete selection,
named input binding, and invocation construction remain inside the façade and
`SemanticPlanner::link_invocation`. Source and derived authority records remain
products of `AdmissionLedger`.

`gooir-derive::LocalStdioHost` is one bounded concrete host for the CLI:

- provider dispatch resolves the invocation's exact `OfferId` through
  `PackageRegistry::offer_artifact` and executes only those loader-owned copied
  bytes;
- an attester binding pairs one complete `ConformanceAuthority` with one exact
  resource in an explicitly installed package, and construction refuses a
  copied resource digest different from the authority artifact digest;
- each artifact is written into a private temporary directory and executed by
  that exact path with no arguments, environment, source-package path, or
  `PATH` lookup;
- stdin, stdout, stderr, and elapsed time each require an explicit positive
  bound; and
- timeout kills and then waits for the child before returning, so no timed-out
  child is abandoned or left unreaped.

The local host freezes a clone of the installed registry. It rechecks the exact
offer or attester binding at dispatch. A provider result and attester
assessment remain untrusted until the existing derivation membrane validates
and admits them.

`gooir-capability::assessment` defines
`org.gooi.authority.assessment-request/v1`; `gooir-provider::attester`
reexports it as part of the authoring seam. The closed request carries the exact
invocation, result, candidate, and host-selected complete conformance
authority. `Attester` binds authoring code to one exact suite and implementation
identity, validates the complete request and independence before semantic
checks run, constructs `ConformanceAssessment`, and supplies `assess_json`,
`serve_once`, and `serve_stdio`. The artifact cannot self-measure its own final
digest; the local host's resource binding establishes that coordinate.

`gooir compile` composes these pieces. It loads only explicitly named package
directories in dependency order, source-observation documents, one admission
policy, attester-binding documents, a target, and the four required resource
limits. It performs no executable scanning and no target-specific
materialization. Its JSON form is the existing derivation `Answer`; this
decision does not promise a new stable compile receipt protocol.

## Scope and tradeoffs

The local stdio host is credential-free, single-request, local execution. It
does not supply process arguments or environment, resolve interpreters through
`PATH`, persist a ledger, retry an attempt, recover after a crash, materialize a
target file, or define deployment and enrollment. Selected children retain the
caller's filesystem, network, and other OS authority. Explicit package loading
and content binding make selection exact; they do not make the child sandboxed.

Those constraints keep this corrective slice coherent. A product needing
credentials, isolation, durable execution, or recovery implements
`DerivationHost` and reuses `CompilerDriver`; it does not widen this adapter or
change the semantic graph.

The legacy `gooir derive --pack ... --plugin ...` path remains visibly legacy.
It is not silently reinterpreted as package-v1 execution and is not removed in
this change.

## Acceptance evidence

- A real two-hop test executes two exact copied offer artifacts, passes each
  candidate through an exact copied independent attester, admits the first
  output, and proves the second invocation links that admitted authority.
- Driver tests retain `Produced`, `Blocked`, `Unreachable`, `Refused`, and
  `Failed` with distinct remedies.
- Attester tests prove closed request decoding, identity checks before semantic
  work, exact assessment construction, and stream framing.
- Local-host tests enforce all three byte directions and prove the timeout path
  kills and reaps the child.

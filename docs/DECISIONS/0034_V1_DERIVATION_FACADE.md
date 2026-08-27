# 0034 — A v1 derivation façade over the finite substrate

Status: accepted

## Context

Decision 0030 found a durable product requirement: one derivation question
needs one typed answer whose variants preserve different remedies. Its
`DerivationRequest`, `Answer`, `FactInstance`, `DerivationPlan`, and
`ExecutionReport` were unversioned experimental Rust shapes, not a stable wire
protocol. That decision is recovered product intent, not a request to restore
its old serialization or its direct in-process execution path.

[0031](0031_MINIMAL_SEMANTIC_SUBSTRATE.md) subsequently established the
architecture that a real answer must compose:

```text
Fact + exact authority
  -> PackageRegistry
  -> SemanticPlanner
  -> explicit route, implementation, and attester selection
  -> exact linked invocation
  -> external host
  -> neutral result and candidate
  -> independent conformance
  -> contextual admission
```

[0033](0033_SUBTRACT_AND_EXTRACT.md) made that dependency direction physical.
GOOIR now contains a neutral semantic substrate and narrow host support; domain
contracts and product hosts are downstream consumers. The recovered stateful
Fleetd proof from Decision 0032 demonstrated the same membrane with two client
offers, an independent attester, exact linked invocations, and a
crash-recoverable external host. That proof is evidence for this composition,
not a Fleetd dependency or a universal host protocol.

The current compatibility `DerivationRequest` and `Answer` still sit over
`FactInstance`, `CapabilityRegistry`, and direct in-process providers. They do
not expose exact admitted inputs, named-port linking, complete implementation
alternatives, external-host execution, or the authority records that make a
produced `Fact` usable. Removing the façade entirely would leave every product
caller to reconstruct the same outcome taxonomy. Promoting the compatibility
path would create a second runtime beside the finite substrate.

## Decision

GOOIR retains the product names `DerivationRequest` and `Answer`, but defines
their v1 meaning as a host-facing façade over the existing public substrate.
The façade is composition code, not another semantic level and not an
execution host.

One façade instance is constructed from an exact validated `PackageRegistry`
snapshot, a `SemanticPlanner` created from that snapshot with explicit limits,
an `AdmissionLedger`, a fixed `AdmissionPolicy`, a bounded host attester
inventory, and an external-host adapter. The registry and planning-scope
digest remain fixed for one answer. Installing more ecosystem material creates
a new scope; it cannot change a request already being answered.

“v1” names the behavioral contract in this decision. No compatibility with
the derived serde shape from Decision 0030 is implied. If the façade becomes a
portable document, it must receive an explicit protocol identity, canonical
encoding rules, bounds, and unknown-extension rules of its own; public Rust
types alone do not establish a wire protocol.

### Request

A v1 `DerivationRequest` logically contains:

- one exact target `ValueKindId`;
- a bounded collection of admitted inputs, each pairing one validated `Fact`
  with the exact `AuthorityRecord` selected for it; and
- one selection directive: `Explicit` or `UniqueOnly`.

The façade resolves every input as the exact `(FactId, AuthorityRecordId)` pair
in its contextual `AdmissionLedger` before planning. A bare fact, a record for
a different fact, an unknown record, or an authority record that does not
validate is not an admitted input.

Several inputs may have the same `ValueKindId`. Named ports and exact fact and
authority identities disambiguate their roles. Repeating the same exact
fact-authority pair in the request is invalid, but repeated value kinds are not
refused merely for being repeated.

An explicit selection fixes the complete finite derivation before the first
host effect. It names:

- the provider-neutral semantic route and its terminal output port;
- every named input binding, from either a request input or an earlier route
  output;
- the exact installed `OfferId` for every capability step; and
- the exact conformance suite and independent attester authority for every
  step.

The selected route is a bounded, finite dependency graph. Each step is linked
only when its exact admitted inputs exist, but all route, offer, suite, and
attester choices are fixed before execution begins. The linker uses
`SemanticPlanner::link_invocation`; it never manufactures an invocation by
copying fields around that validation boundary.

`UniqueOnly` is deliberately conservative. It considers complete selections,
not just semantic paths. A complete selection fixes the route, terminal port,
every named fact-authority binding, every offer, and every independent
attester. For conformance it considers only each capability's declared default
suite; a suite override requires `Explicit`. `UniqueOnly` proceeds if and only
if exactly one complete, available, policy-eligible selection exists. Zero
complete selections is classified according to the outcome rules below. More
than one is `Refused` as ambiguous, even if every alternative would probably
produce the same fact.

Canonical ordering exists only to make alternatives reproducible. It never
breaks a tie. The façade must not choose the first provider, lowest identity,
package order, registry iteration order, or an undocumented default.

### Semantic routes and needs

A semantic route is a provider-neutral, finite named-port derivation from the
request's initial value kinds to one exact target output port. Route existence
depends only on capability declarations. Offers, host launch support,
attesters, and admission policy do not make an unreachable target reachable.
Like `SemanticPlan`, a v1 route is a bounded graph slice rather than a walk: it
does not repeat a capability merely to traverse a cycle again.

A step is available only when it has at least one installed implementation
offer and that offer can be paired with an available attester for the selected
suite whose implementation identity and artifact digest are independent of
the provider. An implementation declaration is not an attester, and a suite
declaration is not proof that an attester can run.

The external host supplies a bounded, exact attester availability inventory.
That inventory is host machinery, not package meaning and not another set of
semantic graph edges.

Needs remain attached to the bounded AND/OR blockage graph. The analysis names
every target-producing alternative, every capability node, each missing
implementation, and each named input whose producer alternatives are blocked.
It shares common nodes rather than exhaustively enumerating a potentially
exponential set of routes. A flat summary may be derived for display, but it
is not the authority for why a target remains blocked.

An attester that is available but rejected by local admission policy is not a
missing attester. That is an admission-policy refusal.

### The five outcomes

`answer` returns one `Answer`, not `Result<Answer, _>`. Façade construction may
fail before a request is accepted if its registry snapshot, planner bounds,
host adapter, admission ledger, policy, or attester inventory is invalid. Once
a valid façade accepts a request, every terminal request outcome is one of the
following five variants.

#### Produced

`Produced` means the requested target is admitted, not merely returned by a
provider or passed by an attester.

Its payload contains:

- an exact `AdmittedFactRef` identifying the selected target; and
- a canonical, nonempty collection of `AdmittedFact` values, each containing
  a complete `Fact` and its complete, exact `AuthorityRecord`.

The collection contains the target pair and every route output materialized
and admitted while answering the request, including an idempotently existing
record encountered on replay. Every pair must validate, its record must name
that fact, and its reference must resolve in the façade's ledger at return.
Candidates, passing assessments, provider success, or policy decisions without
authority records can never appear as `Produced`.

If an admitted request input already has the target value kind, no semantic
step is required. An explicit selection may choose that exact input. Under
`UniqueOnly`, exactly one such exact input is produced without calling the
host; several eligible target inputs are an ambiguous selection and are
refused.

#### Blocked

`Blocked` means at least one semantic route exists, and every semantic route
lacks at least one required installed implementation or available independent
attester. No provider or attester is launched.

Its payload contains the exact semantic plan and planning-scope identities plus
the bounded AND/OR blockage analysis. Every retained target alternative is
connected through named input dependencies to the missing implementation or
attestation needs that prevent it from executing. `Blocked` is invalid if the
offer- and attester-aware graph can reach the target.

Multiple installed offers, multiple eligible attesters, invalid selection, or
policy rejection are not blockage. They are selection or policy questions and
therefore become `Refused` when no unambiguous eligible selection remains.

#### Unreachable

`Unreachable` means no declared semantic route derives the target value kind
from the request's initial value kinds, even if implementation and attestation
availability are ignored. It retains the target, canonical initial value-kind
set, planning-scope digest, and exact unreachable planning diagnostic. It has
no provider or attester needs because there is no capability route to staff.

#### Refused

`Refused` means execution is not authorized for the request as presented. Its
reason is exactly one of:

- `InvalidRequest`: malformed or unresolvable facts or authority records,
  duplicate exact inputs, unsupported extensions, invalid bounds, or another
  request invariant;
- `InvalidSelection`: an explicit route, port binding, offer, suite, attester,
  or target is absent, incomplete, incompatible, not independent, or outside
  the exact planning scope;
- `AmbiguousSelection`: `UniqueOnly` found more than one complete eligible
  selection, or the supplied selection did not resolve to one exact choice;
  or
- `AdmissionPolicy`: an otherwise available choice is ineligible under the
  fixed local policy, or a valid passing assessment is withheld by that policy.

Ambiguity retains the exact alternative selection identities rather than only
a count. A post-assessment policy refusal retains the exact admission decision.
Pre-execution refusals make zero external-host calls. `Refused` never reports
an unadmitted candidate as a fact the caller may use.

#### Failed

`Failed` means one exact selection had been fixed and progress through linking,
an external attempt, result validation, assessment, or admission machinery did
not produce an admitted target. It covers:

- failure to link the already selected step against the fixed inventory;
- external-host launch, transport, timeout, cancellation, recovery, or
  protocol failure;
- a valid provider `Unable` result;
- malformed, uncorrelated, substituted, or output-invalid provider results;
- candidate-construction failure;
- attester launch or assessment-document validation failure;
- a valid `Failed` or `Indeterminate` conformance assessment; and
- admission ledger or authority-record validation failure other than a
  deliberate policy refusal.

The failure retains the selected route and exact failing stage plus every
validated invocation, result, assessment, evidence reference, and already
admitted fact-authority pair available before that stage. It does not convert
an uncertain host outcome into a semantic inability, retry the attempt on its
own, or claim the requested target was produced. Retry, replay, parking, and
recovery remain external-host policy.

### Execution and authority flow

For each selected step the façade:

1. resolves each named input's exact fact-authority pair;
2. explicitly links the selected installed offer, named inputs, and suite into
   one `CapabilityInvocation`;
3. gives that neutral invocation to the external host;
4. validates the returned `CapabilityResult` against the invocation;
5. constructs the untrusted `CapabilityCandidate` only from a valid produced
   result;
6. asks the external host to run the exact selected independent attester;
7. validates the `ConformanceAssessment`; and
8. applies the fixed `AdmissionPolicy` through `AdmissionLedger`, retaining
   the resulting authority records before a later step may link them.

Admission of a multi-output candidate remains atomic. A later step may consume
only the exact admitted output and authority record selected for its named
input port. The same semantic `Fact` produced by different implementations may
therefore retain one `FactId` and several exact authority records without the
façade silently choosing among them.

### External-host membrane

The façade does not launch provider or attester code. Its external-host
interface accepts exact neutral invocation or assessment inputs and returns
bounded neutral results, assessments, failures, and opaque evidence
references.

Credentials, endpoints, process and container state, deadlines, cancellation,
leases, fencing, retries, idempotency permissions, sessions, deployment locks,
journals, crash recovery, and target authority remain outside
`DerivationRequest`, `Answer`, `Fact`, `SemanticPlan`, and
`CapabilityInvocation`. A product envelope may own those fields around the
façade call; the semantic answer does not restate them.

The host is not recursively represented as dialects, facts, capabilities, or
providers merely because its state is serializable. A separately governed
host observation may be lifted as an ordinary ecosystem fact when an
independent consumer needs its meaning. That does not move the host machinery
or this façade into the semantic graph.

### Representation boundary

The façade preserves the three semantic levels from Decision 0031:

```text
DialectId     vocabulary authority
ValueKindId   one exact named type in that vocabulary
Fact          one content-identified value of that exact kind
```

It does not alias, flatten, or replace these levels with a single “type” or
“dialect” coordinate, and it does not restore `FactInstance` as the product
currency. Provenance, selection, conformance, admission, and host state remain
authority or machinery about a fact; they do not change the fact's semantic
identity.

## Consequences

- Products regain one door with five stable remedy classes while the kernel
  remains finite.
- `DerivationRequest` and `Answer` become a composition surface over `Fact`,
  package planning, explicit linking, neutral protocols, and authority records;
  they do not become shortcuts around those layers.
- The legacy `CapabilityRegistry`/`FactInstance` execution façade is a
  migration source only. Its Rust and serde shapes receive no compatibility
  promise from v1.
- A caller that wants automatic choice must supply an explicit policy in a
  later decision. v1 supplies only exact explicit choice and conservative
  `UniqueOnly`.
- Availability reporting grows from a flat provider list into route-specific
  implementation and attestation needs.
- `Produced` is larger than a bare fact because usable semantic output must
  carry exact authority. Equal facts may legitimately appear with different
  authority records.
- Host implementations remain free to use processes, WASI, HTTP, Fleetd, or a
  future transport without changing the façade's semantic contract.
- No domain package is installed implicitly, and no downstream vocabulary or
  host becomes a GOOIR dependency.

## Rejected alternatives

### Restore Decision 0030's exact Rust and serde shapes

Those shapes predated explicit `DialectId`/`ValueKindId`/`Fact` separation,
named ports, package offers, linked invocations, and the authority ledger.
Treating them as wire compatibility would preserve the defects recovered by
Decision 0031.

### Expose only the substrate primitives

The primitives must remain independently usable, but making every product
invent its own terminal taxonomy would recreate the original “answer at the
door” defect and produce incompatible meanings for blocked, unreachable,
refused, and failed.

### Choose the first or highest-ranked provider

Registry, package, lexical, or iteration order is not authority to select an
implementation. An implicit ranking would also erase observable alternatives
and make package installation change behavior without an explicit decision.

### Flatten all non-production into one error

Missing implementation work, an absent semantic route, caller or policy
refusal, and a failed selected attempt have different owners and remedies.
Collapsing them would make safe automation impossible.

### Return a fact without its authority record

A fact's stable semantic identity deliberately omits provenance and trust.
Returning only the fact would force callers either to guess an authority or to
treat provider output as admitted.

### Put selection, execution, or attestation into `SemanticPlanner`

Planning is a provider-neutral graph operation. Adding effects or local trust
policy would make plans depend on one host and would reintroduce a hidden
runtime inside the substrate.

### Model the façade and host recursively as graph content

Serializability is not semantic authority. Recursively representing loading,
selection, credentials, attempts, recovery, or admission as ordinary
capabilities would reopen the unbounded trusted graph rejected by Decision
0031.

## Acceptance criteria

An implementation of this decision is accepted only when automated tests
establish all of the following:

1. `Produced` is impossible before admission and every returned fact-authority
   pair validates and resolves by its exact reference in the resulting ledger.
2. An already admitted target returns `Produced` without a host call; two
   eligible exact target inputs under `UniqueOnly` return
   `Refused::AmbiguousSelection`.
3. `Blocked` is returned only when semantic routes exist and the bounded
   AND/OR blockage graph accounts for every target alternative. Two routes
   missing different resources retain distinct producer alternatives and need
   nodes without requiring exhaustive route enumeration.
4. A route with an available implementation and independent attester can never
   be reported `Blocked`, even when another route has needs.
5. `Unreachable` depends only on declared capability reachability and remains
   unchanged when offers or attesters are added or removed.
6. Reordering packages, capabilities, offers, attesters, inputs, or map entries
   does not change an answer or selection identity.
7. `UniqueOnly` executes exactly one complete eligible selection and refuses
   two or more while retaining their identities. No perturbation that changes
   iteration order can change which provider runs.
8. `Explicit` rejects a missing or partial route, wrong named-port binding,
   absent or substituted offer, unsupported suite, non-independent attester,
   changed planning scope, and unknown selection extension before host launch.
9. Two named ports with the same `ValueKindId` can bind exact inputs; the
   compatibility façade's duplicate-kind refusal is not reproduced.
10. Changing the selected offer, attester, input authority record, suite, or
    output port changes the appropriate linked invocation or selection
    identity and cannot reuse a prior result.
11. The external host receives only exact neutral invocation and assessment
    inputs. Request and answer envelopes contain no credential, endpoint,
    process, lease, retry, session, journal, deployment, or recovery fields
    outside opaque semantic payloads and evidence references.
12. A provider `Unable`, host failure, malformed or uncorrelated result, wrong
    output port or kind, invalid candidate, failed or indeterminate assessment,
    and malformed assessment each return `Failed` and never `Produced`.
13. A passing valid assessment withheld only because its exact authority is
    not accepted returns `Refused::AdmissionPolicy` with the exact decision;
    provider and attester are not rerun.
14. Multi-output admission is atomic, later steps link only admitted exact
    pairs, and a later failure reports earlier admitted pairs without claiming
    the target was produced.
15. Unknown fact and protocol extensions survive every required round trip;
    an unsupported extension that affects linking or selection fails closed
    before an effect.
16. The implementation adds no domain vocabulary, implicit package, provider
    transport, process launcher, credential path, or host lifecycle to the
    semantic kernel.
17. `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
    warnings`, and `cargo test --workspace` pass for the exact reviewed commit.

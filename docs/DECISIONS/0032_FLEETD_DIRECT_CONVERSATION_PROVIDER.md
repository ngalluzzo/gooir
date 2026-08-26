# 0032 — A stateful Fleetd provider before a generic effect interface

Status: accepted proof boundary

## Context

[0031](0031_MINIMAL_SEMANTIC_SUBSTRATE.md) separated semantic capability
documents from execution-host lifecycle and required a real external host proof.
The first completed host checkpoint installed exact `WASIp1` provider and
attester artifacts, planned and linked one selected implementation, retained
receipts before interpretation, admitted only independently assessed output,
and recovered every durable phase conservatively.

That checkpoint deliberately gave its children no filesystem, network, or
credential authority. An armed provider whose completion was unknown therefore
parked instead of running twice.

The next proof must establish the complementary case: a selected external
implementation whose answer depends on durable state outside GOOIR, whose
effect may commit before the execution host captures a response, and whose own
protocol makes repeating the exact request safe. A local journal cannot create
that property. It can only remember the exact request whose external
idempotency contract already supplies it.

Inventing a generic counter, key-value store, effect IR, or credential callback
would prove machinery rather than product composition. Fleetd already exposes
one narrow real operation with the required law:

```text
POST /v1/direct-conversations

new exact unordered pair + delivery modes  -> 201 + durable conversation
same exact pair + delivery modes            -> 200 + same conversation
same pair + different delivery modes        -> 409 + no mutation
```

The durable resource key is the canonical unordered pair. Delivery modes are
immutable constraints on that resource, not another uniqueness key. Fleetd
owns the transaction, uniqueness rule, and durable conversation. GOOIR does
not reproduce any of them.

## Decision

The first stateful external-provider proof is a Fleetd-native capability:

```text
direct_pair_intent --open_or_resolve_direct_conversation--> direct_conversation_ref
```

It is not a generic conversation dialect. It represents only meaning already
owned by Fleetd's public contract.

### Fleetd-owned semantic values

One separately versioned contract package declares the dialect
`dev.fleetd.conversation@0.1.0` with two value kinds.

`dev.fleetd.conversation/direct_pair_intent@0.1.0` contains:

```text
fleetd_target
members[2]
  agent_id
  delivery_mode = inbox | stream_only
```

The two members are distinct and sorted by exact `agent_id`. Their order is
not meaning: Fleetd's durable uniqueness key is the unordered pair. The
delivery modes are meaning because Fleetd makes them immutable.

`fleetd_target` is an opaque, globally scoped, operator-governed coordinate for
one exact Fleetd deployment. It is not a base URL, credential, tenant selector,
or process handle. It has no meaning without a host-qualified proof-local deployment
lock that binds it to the exact Fleetd binary and revision, OpenAPI digest,
controlled data-directory identity, target lock-file digest, and endpoint
mapping. Provider and attester deployment policy resolve that same lock
independently. The two agent IDs must already have been observed in that exact
target; the provider never infers human, worker, author, or reviewer roles.

`dev.fleetd.conversation/direct_conversation_ref@0.1.0` contains:

```text
fleetd_target
conversation_id
created_at_ms
members[2]
  agent_id
  delivery_mode
```

The output retains the exact target coordinate, canonical pair, and modes from
the input together with Fleetd's durable conversation identity and creation
time. A conversation ID is therefore never interpreted outside its target. The
output excludes the generated display name, agent names, mutable recency
fields, messages, transport status, and presentation metadata.

The capability is
`dev.fleetd.capability/open_or_resolve_direct_conversation@0.1.0`. Its name is
intentional: resolving an existing exact pair is the same successful semantic
answer, not a failed creation.

The exact conformance obligation is
`dev.fleetd.conformance/direct_conversation_ref@0.1.0`.

### Two client offers, one effective provider composition

Fleetd, not an HTTP client, owns the operation's durable semantics. Two exact
native command artifacts independently implement the client side through
distinct HTTP stacks. Each installed offer identifies its client artifact and
runtime. Each linked invocation additionally names the target input, and the
attempt locks the host-qualified Fleetd deployment. The effective provider is the
complete composition:

```text
exact client artifact + exact native runtime + host-qualified Fleetd target
```

Changing any member changes the derivation authority even when the produced
fact does not change. Each client artifact:

1. receives one exact `CapabilityInvocation` on standard input;
2. validates the selected implementation, capability, named input, and suite;
3. resolves no endpoint or credential from the semantic document;
4. sends the exact canonical Fleetd request using host-supplied deployment
   authority;
5. accepts only `200` or `201` as produced output;
6. returns a typed inability only for Fleetd's exact immutable-mode `409` and
   treats every other non-success as an operational failure; and
7. returns one ordinary `CapabilityResult` whose output fact is constructed by
   the provider, not by a Fleetd-aware host projection.

Both client artifacts are package resources and produce distinct
`ImplementationOfferDeclaration` values for the same capability. The planner
must retain both. The caller explicitly selects one, so changing providers
changes the linked invocation, result, candidate, and authority record.

On one locked Fleetd target, the first client may receive `201` and the second
`200`. Both must produce the same exact output `Fact`. This proves that semantic
identity is independent of client choice while trust context is not. It does
not attribute Fleetd's state law to either client. The admission ledger may
therefore retain two authority records for one fact without selecting one
implicitly.

Each client must also create a conversation against an isolated fresh Fleetd
target, and the shared-target proof runs in both client orders, so
interchangeability is not inferred only from the no-op path.

### Independent conformance

The attester is a third exact artifact, packaged only as a retained resource.
It is not a planner offer.

Given the exact invocation, result, and candidate, it uses independently
supplied read authority to call `GET /v1/conversations`. It locates the proposed
conversation ID and verifies:

- the target coordinate resolves to the verifier's exact host-qualified deployment
  lock;
- the conversation is direct and active;
- the returned members are exactly the canonical input pair;
- both delivery modes match;
- the durable ID and creation time equal the candidate fact; and
- no mutable or presentation-only field was projected into semantic output.

The provider response is operational evidence, not the attester's source of
truth. Provider and attester implementation identities and artifact digests
must differ before admission is considered. Fleetd currently exposes this list
only to an operator principal, so this proof establishes implementation and
observation-path independence, not least-privilege principal independence. A
production verifier requires a read-only principal and exact-resource read API;
the proof must not claim that Fleetd has either today.

The list operation is currently unfiltered and unpaginated. The proof therefore
uses a fresh bounded target and an explicit response-byte limit. Exceeding that
limit parks rather than silently weakening observation. This is a controlled
qualification boundary, not a production liveness claim.

### Execution-host boundary

The native command host remains proof-local until Fleetd supplies a second
consumer. It owns:

- exact package installation, offer selection, and deployment locks;
- resolution of one host-qualified `fleetd_target` deployment lock;
- credential acquisition and rotation;
- bounded native process lifecycle;
- deadlines, retry timing, and crash recovery;
- bounded, scrubbed process evidence retention;
- candidate construction from a captured neutral result;
- attester execution; and
- contextual admission.

It clears the child environment, launches no shell, materializes only exact
package-owned artifact bytes, uses an absolute measured executable, bounds
standard input/output/error and wall time, and kills and reaps the child
process group on enforcement.

Each provider client receives only its exact invocation on standard input; the
attester receives only its exact assessment request there. Endpoint and bearer
authority travel through a separate proof-local inherited pipe. The child is
told only the non-secret descriptor number, immediately marks it close-on-exec
for descendants, performs one bounded EOF-delimited read, and closes it before
HTTP dispatch. Those bytes never enter argv, environment, standard input,
process receipts, journals, logs, or diagnostics. The authority document
repeats the locked non-secret target coordinate, endpoint-mapping digest, and
credential revision so the child can correlate authority without recovering
them from semantic payload.

The journal binds the exact target coordinate; Fleetd binary and revision;
OpenAPI, target lock-file, endpoint-mapping, provider artifact, native runtime,
and attester digests; controlled data-directory identity; a non-secret
credential revision; limits; suite; and admission policy. It never stores a
bearer token or base URL. A missing or changed lock parks before child launch.
Credential rotation cannot silently change authority during recovery; it needs
an explicitly versioned resolver binding and a new attempt.

No native-process or HTTP ABI is added to `gooir-core`, `gooir-capability`,
`gooir-package`, or `gooir-planning`. Package resources remain opaque bytes.

### Recovery law

The proof-local attempt advances monotonically:

```text
Prepared -> ProviderArmed -> ProviderCaptured
                              |-- typed inability -> Unable
                              `-- produced -> CandidateReady
                                  -> AttesterArmed
                                  -> AttesterCaptured
                                  -> AssessmentReady
                                  -> Admitted | Withheld
```

Before `ProviderArmed`, no request may reach Fleetd. The armed checkpoint binds
the exact invocation, selected client, complete target deployment lock, and
execution policy.

Unlike the credential-free `WASIp1` proof, a loaded Fleetd provider arm may
repeat the exact invocation. That permission is not a generic host claim. It
is specific to the exact installed capability and Fleetd's durable unordered
pair plus immutable-mode law. Replay permission is constructed by trusted
proof-host code and bound to the exact capability, invocation, selected client
artifact and runtime, target deployment lock, endpoint-mapping digest,
credential revision, limits, and suite. A child cannot grant itself replay by
returning a flag.

Every completed provider process first appends its bounded process receipt to a
prefix retained at `ProviderArmed` through compare-and-swap. Only deterministic
byte-level removal of exact authority-channel bytes may precede that append. A
redacted receipt retains a digest and marker but is never eligible to become
decisive. The driver then reloads and validates the checkpoint before
interpreting exit status, standard output, or correlation. This ordering
includes successful results and typed inability, not only failures.
`ProviderCaptured` references the exact decisive receipt already in that
prefix. Same-phase updates may only append to the exact prefix; they cannot
replace earlier evidence or change any lock.

Every load of `ProviderArmed` validates and interprets the retained prefix in
order before considering a launch. A decisive retained result advances through
its exact receipt without another process. A new launch is allowed only when
every retained receipt is non-decisive operational evidence, the prefix is
valid, and capacity remains. Transport loss, malformed output, timeout, and an
ambiguous Fleetd failure remain armed until the receipt bound is exhausted, at
which point the attempt parks. They never become a semantic inability.

The decisive crash occurs after Fleetd commits a new direct conversation but
before the host durably captures the provider receipt. A proof-local bounded
proxy observes the complete backend `201`, logs no request header or body, and
terminates the host before forwarding the response. This establishes the
window without modifying Fleetd. On restart the host reconstructs the same
invocation, client, and target lock, repeats the exact operation, receives
`200`, and recovers the original ID and creation time. The target must still
contain exactly one direct conversation and exactly two memberships.

A timeout, disconnect, killed provider, or host death after request dispatch
leaves `ProviderArmed`; it does not become `Unable`. Only a captured,
well-correlated neutral `CapabilityResult` can advance to `ProviderCaptured`.
Once that result is captured, the provider is never invoked again for that
attempt.

`200` and `201` both produce the claim that the exact conversation exists.
Neither the fact nor its authority record may claim that this attempt created
it. `ProviderCaptured` advances to `CandidateReady` only for a valid produced
result. A captured `409` becomes a typed inability and advances directly to
`Unable`, producing no candidate and no second conversation. Authentication,
configuration, and transport failures are operational failures, not semantic
inability.

Candidate construction and every phase after `AttesterCaptured` replay solely
from retained evidence. A loaded `AttesterArmed` may repeat the exact locked
attester because its qualified artifact is constrained to bounded GET
observation against the same target. It uses the same append-before-interpret
receipt-prefix law as `ProviderArmed`; `AttesterCaptured` references one exact
already-retained decisive receipt. Exhausted or malformed observations park,
never become conformance. On every load, the existing attester receipt prefix
is validated and interpreted in order; a decisive retained assessment advances
without another GET, and another launch is possible only after every retained
receipt is non-decisive and capacity remains.

Candidate, assessment, admission decision, and final snapshot are reconstructed
and compared exactly. Candidate construction remains a deliberately untrusted
lift of the provider result. The independently executed attester performs the
GET reobservation before admission, which is the trust boundary; the process
host does not learn Fleetd response semantics merely to pre-validate a
candidate.

### Fleetd is the state owner now and the execution host next

This proof calls Fleetd as the authoritative mutable product. It does not yet
claim that Fleetd is dispatching GOOIR work.

The following integration uses a distinct Fleetd deployment as the execution
host. It does not make the stateful target coordinate its own work:

```text
Host Fleetd H
  -> opaque message and durable fenced delivery
  -> external credential-owning runner
  -> selected provider worker
  -> Target Fleetd T public API
  -> neutral result
  -> strict candidate lift
  -> independent conformance and admission
```

H and T must use distinct processes, URLs, credentials, and SQLite stores. The
target operator credential may enter only the external runner and selected
client; it never enters H, an opaque message, the attempt journal, or a Fleetd
plugin. The conversation must appear only in T.

That integration begins with the already qualified deterministic data-model
provider rather than coupling the host proof to this Fleetd-native capability.
H continues to own messages, leases, worker ownership, ambiguity, restart
recovery, and operator visibility. It learns no GOOIR value kinds, direct-pair
semantics, provider-specific payloads, target credentials, or admission rules.

The two directions are deliberately complementary: ecosystem providers may
operate Fleetd's public product capabilities, and Fleetd may durably coordinate
ecosystem provider invocations, without either core absorbing the other.

## Rejected alternatives

### A generic conversation, task, workflow, or messaging dialect

One Fleetd operation cannot establish reusable cross-product meaning. The
contract remains Fleetd-native until independent authorities recur on the same
semantics.

### A generic effect or reconciliation protocol

One safe POST does not justify standardizing apply, lookup, observe, rollback,
credential, or retry interfaces. The exact Fleetd law stays in this provider
and proof host.

### Expanding the `WASIp1` authority profile

The existing profile's lack of network and credentials is a proven property,
not a missing feature. Stateful providers use a separately bounded native
host path rather than weakening it.

### A credential-free child that proposes an HTTP effect

That would hide Fleetd-specific mutation logic in the runner or invent an
effect interpreter. The selected provider artifact must be the implementation
that performs the claimed stateful capability.

### A local counter, key-value store, or SQLite register as the semantic proof

Those could test journal mechanics, but Fleetd already supplies a real,
product-owned, atomic idempotency contract. The proof should exercise the
actual customer boundary.

### Arbitrary message append as the first stateful capability

Fleetd's message idempotency key is transport-owned and distinct identical
message occurrences require a semantic identity decision. Direct-pair opening
already has a visible durable semantic key and does not require that decision.

## Acceptance gates

The proof passes only when:

1. the contract, both clients, and the attester install through public
   package APIs without a kernel change;
2. a bounded plan retains both client offers and explicit selection changes
   the invocation identity;
3. client artifacts build independently and use the same proof-local host
   adapter unchanged;
4. each client can ensure one direct conversation on a fresh Fleetd target;
5. both client orders resolve one shared exact pair to the same target-scoped
   semantic fact;
6. concurrent exact invocations converge on one conversation and target
   restart preserves its ID, creation time, and two memberships;
7. changing immutable delivery modes produces no candidate or second
   conversation;
8. a real process exit after Fleetd commit but before capture recovers through
   `200` replay with exactly one conversation;
9. loaded armed recovery never changes client, invocation, Fleetd binary,
   OpenAPI, target lock, data directory, endpoint mapping, or credential
   revision implicitly;
10. wrong-target mapping, unknown agents, altered provider output, substituted
    attester, and any lock mismatch fail closed;
11. every completed provider or attester process receipt is durably appended
    before interpretation, each loaded arm consumes retained receipts before
    launching, redacted receipts cannot become decisive, and each captured
    phase names its decisive receipt;
12. loaded attester arms repeat only the exact qualified GET observer and
    otherwise park at the bounded receipt limit;
13. the independent attester reads bounded target state rather than trusting
    provider output;
14. admission rebuilds and resolves the exact produced fact with distinct
    authority records for each client derivation;
15. terminal replay is deterministic from retained evidence;
16. credentials and base URLs are absent from semantic documents, receipts,
    journals, logs, and test diagnostics;
17. `gooir-core` remains absent and Fleetd source remains unchanged; and
18. formatting, Clippy, workspace tests, real provider tests, and independent
    exact-content review all pass.

The later host integration additionally passes only when H and T are distinct,
the conversation appears only in T, and T's operator credential is absent from
H's store, messages, logs, plugins, and worker environment.

## Consequences

- The first stateful implementation is real Fleetd dogfood, not a generic
  runtime demonstration.
- Capability and protocol remain separate: HTTP is how these providers run,
  not what the capability means.
- Exact client alternatives and their complete target compositions become
  observable before any registry ranking or default selection exists.
- Armed retry remains exceptional and contract-scoped; unknown effect
  protocols still park.
- Fleetd-specific meaning lives in an ecosystem package while Fleetd remains a
  durable coordination and messaging product.
- A reusable state, conversation, or reconciliation contract remains unearned.

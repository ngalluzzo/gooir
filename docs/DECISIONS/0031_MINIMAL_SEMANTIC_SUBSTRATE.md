# 0031 — A finite semantic substrate, an external execution host

Status: accepted recovery boundary

## Context

GOOIR discovered the right center and then implemented it twice.

The older path represented source operations, attached claims, projected those
claims into contracts, and resolved them through bridge and projection
registries. The newer path represented facts, connected exact fact kinds with
capabilities, and planned over independently implemented edges. Exact identity,
conformance, admission, and unknown preservation were then divided across both
paths.

The capability graph is the architecture. The operation/claim/resolver path is
an obsolete parallel IR.

A later reset tried to remove that duplication by declaring every represented
document a dialect and every transformation a capability. That correction
removed one type system but made two different category errors:

1. It flattened a dialect, a named value kind within that dialect, and an
   instance of that value kind into only "dialect" and "fact".
2. It changed "all semantically composed values use one graph" into "all
   compiler and execution-host machinery must be represented in the graph."

The result recursively represented package loading, provider building, process
transport, conformance harnesses, planning control, authorization, and
execution. Each represented layer required declarations, cases, evidence,
verification, and admission of its own. Local consistency increased while the
external extension path became more closed and the trusted base became harder
to identify.

This decision restores the missing levels and names where representation
stops.

## Decision

GOOIR is a semantic compiler substrate with one object-level graph and a finite
trusted implementation beneath it.

### One graph

The object-level graph contains:

```text
fact instances --capabilities--> candidate fact instances
```

A lift, bridge, projection, analysis, lowering, generation, and semantic
validation are roles of capabilities. They are not separate edge kinds.

There is no second `Operation -> Claim -> SemanticResolver` architecture.

### Three representation levels

GOOIR distinguishes:

```text
DialectId
  one independently governed, versioned vocabulary family

ValueKindId
  one exact named type in that dialect

Fact
  one content-identified value of that kind
```

For example:

```text
dialect:  org.gooi.conversation@1.0.0
kind:     org.gooi.conversation/message@1.0.0
fact:     one exact message value
```

A dialect may define multiple value kinds. Requests, observations, scopes,
faults, and receipts that share one semantic authority and lifecycle are value
kinds within a dialect; they do not become separate dialects merely because
their schemas differ.

`FactId` covers the exact `ValueKindId`, payload bytes, and every preserved
semantic extension. It does not cover the implementation, derivation,
conformance result, or admission policy that established the value. Identical
semantic values therefore retain one fact identity when independently
produced. Candidate, conformance, provenance, coverage, and admission records
have their own identities and bind the fact without renaming it.

Those authority records are an orthogonal evidence plane, not a fourth level
of semantic vocabulary. They are not automatically object-level facts or
capability outputs merely because they can be inspected or serialized.

An "admitted fact" means a fact accompanied by a locally accepted authority
record. A linked invocation binds both each exact input `FactId` and the
accepted authority-record identities on which that input's eligibility relied,
so stable semantic identity does not erase trust context.

Coverage or completeness belongs in the authority chain unless the value kind
itself defines it as payload meaning. A provider-supplied coverage summary is a
claim until independently established and admitted.

The kernel treats both dialect and value-kind identities opaquely. Restoring
this level does not create a second IR.

Capability signatures use named ports. Ports distinguish roles; value kinds
distinguish meaning. A capability may therefore consume two facts of the same
kind at different ports without inventing another kind.

### Representation membrane

A value belongs in the semantic graph when an independent participant must
produce, consume, compose, replay, qualify, or reason about its meaning.

An internal structure does not become a dialect or capability merely because
the implementation can serialize it.

The following are substrate or execution-host mechanics unless deliberately
published as an external observation:

- in-memory handles and indices;
- graph traversal state;
- parser and serializer call frames;
- package byte loading;
- process framing and supervision;
- leases, sessions, retries, deadlines, and credentials;
- local admission handles and one-use permissions;
- checkpoint write algorithms; and
- UI or CLI rendering state.

An inspectable plan, trace, or host observation may be published through an
independently governed vocabulary. Publishing it does not require the
operation that formed it to become an ecosystem capability.

### Finite trusted computing base

The GOOIR trusted computing base is a closed list:

1. exact typed identity parsing and formatting;
2. canonical hashing of opaque values and protocol documents;
3. fact envelopes and unknown-extension preservation;
4. exact package-manifest, dependency, path, resource-digest, and byte-loading
   validation;
5. capability-signature and named-port validation;
6. type-level graph planning;
7. validation of a caller-selected implementation offer and invocation
   linking;
8. invocation, result, candidate, and evidence-reference binding;
9. independent conformance-result validation; and
10. contextual admission.

The TCB does not implement or invoke domain payload validation. It consumes
independently produced, typed conformance results and applies local admission
policy to them.

The TCB is allowed to be implementation machinery. It does not need to prove
itself by recursively expressing its own loader, planner, dispatcher, or
ledger as ordinary capabilities. Its behavior is established through direct
tests, adversarial vectors, review, and distribution identity.

### Implementations are not execution-host plugins

GOOIR owns semantic documents:

```text
capability specification
implementation offer
semantic plan and alternatives
selected, linked invocation
implementation result
candidate and typed evidence references
conformance result
admission decision
```

An implementation offer binds an exact implementation identity and artifact
digest to one capability. Planning preserves all eligible alternatives.
Selection is explicit; the planner never chooses the first implementation by
iteration or lexical order.

A linked invocation fixes the selected implementation, digest, exact named
inputs, expected output kinds, and conformance suite before it reaches an
execution host.

Execution hosts own:

- artifact-to-command deployment locks;
- process and container lifecycle;
- credentials and effect authority;
- scheduling, leases, retries, and deadlines;
- sessions and resumption;
- persistence and restart recovery; and
- bounded operational evidence.

GOOIR neither launches a process nor stores host credentials. A host returns a
neutral result and typed opaque evidence references. GOOIR binds those to the
linked invocation as an untrusted candidate. Independent conformance and local
admission remain separate steps.

### One admission path

Execution success, conformance, and admission are different statements.

Installing or directly calling an implementation establishes availability, not
semantic truth. No provider-supplied coverage flag, successful exit status,
well-shaped payload, durable host result, or self-attestation mints an admitted
fact by itself.

The authority record accompanying every admitted produced fact binds:

- exact input facts;
- the capability and selected implementation offer;
- the linked invocation and returned result;
- the candidate;
- the exact conformance suite and independent result; and
- the local admission policy decision.

Hosts may define deliberate fast paths for already trusted deterministic
implementations, but those paths remain explicit admission policy and produce
the same authority record.

### Packages and ecosystem ownership

Packages declare independently installable semantic material: dialects and
their value kinds, capabilities and named ports, implementation offers,
resources, and conformance obligations.

Package loading is a substrate operation. Loading a package does not require a
`compile-package-source` capability or a recursively admitted package graph.
The loader validates exact identities, dependencies, paths, digests, and
extensions directly.

Product-specific dialects, lifters, bridges, lowerings, implementations, and
conformance suites live with their authority or in separately versioned
ecosystem packages. GOOIR core contains no Fleetd, GitHub, SQLite, React, Vue,
task, conversation, page, component, or workflow meaning.

### Decision tests for new concepts

Before adding a concept, its author must answer:

- **Dialect:** does this vocabulary have independent semantic authority,
  governance, and versioning?
- **Value kind:** is this one exact type within an existing vocabulary?
- **Capability:** is this a semantic relation for which independently
  substitutable implementations are meaningful?
- **Substrate operation:** is this generic machinery that loads, stores,
  plans, transports, authorizes, or executes the graph?

A new foundational concept must remove more special machinery than it adds. A
new extension interface remains experimental until two independent consumers
exercise it.

## First proof: Fleetd as an external execution host

Fleetd is the first customer because its existing boundary is complementary:
it owns durable opaque messages, attributed identities, leases, write-ahead
dispatch, ambiguity, sessions, recovery, and operator visibility while
refusing application semantics.

The integration lives outside both cores:

```text
GOOIR plan + explicit implementation selection
  -> linked capability invocation
  -> external GOOIR/Fleetd host appends opaque Fleetd work
  -> Fleetd reserve -> arm -> complete
  -> exact selected implementation executes
  -> neutral result + Fleetd operational evidence
  -> strict external candidate lift
  -> independent GOOIR conformance and admission
```

The GOOIR invocation digest and Fleetd invocation identity remain distinct.
The former identifies semantic/linking coordinates; the latter identifies one
durable execution attempt.

The first proof uses an existing deterministic data-model capability. It does
not introduce task, workflow, or conversation semantics. It passes only when:

1. neither GOOIR core nor Fleetd changes to add the implementation;
2. changing the selected implementation changes the linked invocation;
3. pre-dispatch failure is safely retried;
4. post-dispatch uncertainty is parked rather than repeated;
5. restart reconstructs the exact candidate and evidence;
6. independent conformance admits the result; and
7. a second implementation can be selected without changing the host adapter.

After that proof, Fleetd's existing author-review experiment may first be
lifted into Fleetd-native operational value kinds. Shared workflow meaning is
introduced only after recurrence across independent authorities earns it. Its
hard-coded prompt construction, result projection, and presentation mapping
then become candidates for external semantic adapters where their meaning is
established. Worker configuration remains a Fleetd host/deployment artifact
unless independent targets establish a reusable lowering. Fleetd continues
owning durable coordination.

## Consequences

- `gooir-core` and `gooir-analysis` are removed with the obsolete claim IR.
- `FactType` evolves into the explicit value-kind identity while preserving
  its existing display form during migration.
- capability requirements and outputs gain named ports and allow repeated
  facts of one kind in distinct roles.
- implementation alternatives remain visible until explicit linking.
- `gooir-provider` becomes an implementation-authoring SDK, not trusted core.
- process lifecycle leaves the GOOIR workspace; `gooir-plugin-process` becomes
  host-side code or a historical test quarry.
- the generic CLI stops installing the data-model distribution implicitly.
- domain and recurrence packages remain valuable ecosystem material but are
  not release dependencies of the substrate.
- historical decisions remain in the repository and are superseded rather
  than deleted.

This decision supersedes the process ownership in Decision 0019, refines the
package boundary in Decision 0023, and supplies the execution-host boundary
that Decision 0030 deliberately left outside its semantic answer.

## Non-goals

This decision does not:

- define a universal task, message, workflow, UI, or agent-session dialect;
- make Fleetd part of GOOIR or GOOIR part of Fleetd;
- define remote execution, federation, or encrypted enrollment;
- introduce a generic untyped execution escape hatch;
- standardize an effect protocol before two real hosts need one; or
- preserve the ADR-reset package universe as a compatibility surface.

## Recovery order

1. Remove the parallel claim IR and migrate identity-only consumers.
2. Establish dialect, value-kind, fact, named-port, and opaque-extension
   invariants.
3. Port implementation offers and neutral linked invocation/result/candidate
   documents from the execution-host-boundary experiment.
4. Make implementation selection explicit and converge on one admission path.
5. Port bounded process, authority, and restart adversarial tests to the layer
   that owns them.
6. Prove the external Fleetd host with one deterministic capability.
7. Extract reusable ecosystem packages only after the proof names their actual
   semantic boundaries.

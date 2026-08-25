# Architecture

## Boundary

GOOIR separates generic compiler machinery from application meaning.

```text
Semantically agnostic microkernel
  operations, types, attributes, symbols, containment/dependency edges
  exact contract identities, opaque interface transport/query
  passes, legality, artifacts, provenance, diagnostics

Separately governed semantic contracts
  vocabulary, observable meaning, laws/trace model
  verifier obligations, exact versions, conversion artifacts
  conformance evidence

Dialect implementations
  lossless source representations
  provenance-bearing claims against contracts

Analyzers
  consume contracts, never concrete dialect names

Target packs and distributions
  compatible lowerings, runtimes, defaults, coherent UX
```

## Capability composition

A capability is a separately versioned typed promise: exact required fact
types, exact produced fact types, coverage acceptance, and a named conformance
suite. Capabilities form directed hyperedges because one derivation may require
several independent semantic facts. The generic registry may plan and execute
those edges without learning what any fact means.

Capabilities are not protocols. An in-process call, ACP session, HTTP service,
external compiler, or durable Fleetd worker may provide the same capability.
The protocol handles transport and lifecycle. A concrete work contract binds
one invocation to exact facts, authority, expected outputs, ownership, and
acceptance checks. An agent session is therefore a domain-specific composition
of lifecycle and communication capabilities, not a microkernel concept.

Provider registration establishes availability only. It does not establish
conformance or trust. Coverage and trust remain distinct: a complete produced
fact reports no unresolved defeat under the provider's mechanism, while
admission still requires evidence bound to the exact provider, implementation,
suite, inputs, and output. A providerless edge remains visible as a typed
capability need so an orchestrator can acquire an implementation without
changing semantic meaning.

Before handoff, a need may be bound to exact input fact instances as a
provider-neutral capability request. Its RFC 8785/SHA-256 identity covers the
capability, requirements, facts, expected outputs, and conformance suite. The
request contains no agent, harness, transport, authority, or lease. An
orchestrator such as Fleetd adds those execution concerns durably.

The return boundary is a strict lift, not trust by response shape. A
`CapabilityCandidate` binds one request to an exact semantic provider,
implementation digest, output fact set, and opaque digest of the durable
attempt. Candidate identity uses the same RFC 8785/SHA-256 convention. It says
only what was proposed.

Admission requires a separately identified conformance provider whose exact
suite matches the request. The generating provider cannot attest its own
candidate, and sharing its implementation digest with the verifier also fails
closed. A failing check remains an immutable conformance result with no facts.
A passing result constructs facts whose derivations bind the exact request,
candidate, inputs, provider implementation, and conformance result. The result
is still evidence subject to the consuming host's contextual trust policy; it
is not universal proof.

See [decision 0011](DECISIONS/0011_CAPABILITIES_AS_TYPED_DERIVATIONS.md).
See [decision 0012](DECISIONS/0012_CANDIDATES_REQUIRE_INDEPENDENT_CONFORMANCE.md).

The first concrete implementation of this boundary is deliberately outside
the generic crate. `fleetd-capability-pack` defines Fleetd's runnable-web
artifact schema and conformance provider. The candidate names an exact trusted
Git revision and content-addressed served assets; the verifier independently
checks out that revision and injects its own black-box behavioral test. The
served `/operator/contract.json` must equal the exact web target IR, so source
meaning, generated UI, and runtime verification share one center without
teaching `gooir-core` about pages, JavaScript, Fleetd, or HTTP.

See [decision 0013](DECISIONS/0013_RUNNABLE_WEB_ARTIFACT_CONFORMANCE.md).

## Multiple semantic waists

GOOIR does not flatten every software domain into one universal semantic
dialect. The microkernel is the common structural and evidentiary substrate;
separately versioned semantic dialects may coexist and refer to the same
subjects.

```text
source-native dialects
  OpenAPI     Rust control flow     database catalogs
      \              |                    /
       \             |                   /
        DataModel   FleetdControl   other semantic contracts
             \        /
          interaction projection
             /        \
        web target   terminal target
```

Neutrality is relative. `semantics-data-model-v1` is neutral between Prisma,
PostgreSQL, OpenAPI, and compatible data targets; it is not a place to encode
authority, workflow transitions, or presentation intent. Product-specific
contracts are preferred until repeated evidence from independent products
earns a reusable semantic dialect.

A multi-hop lowering is valid only when every bridge names the meaning it
preserves and unresolved meaning remains explicit. Mixed-dialect programs are
expected during progressive lifting and lowering.

Unknown means maximally interfering, never safe. A generic pass must not reorder, duplicate, eliminate, or otherwise reinterpret an operation unless installed contracts establish the required semantics.

### Interaction enters as an optional projection

The first ecosystem recurrence probe uses source-specific AST projections over
the independent React DOM and Vue runtime-dom lineages to earn only an
activation-to-registered-handler contract. It does not introduce a universal
component tree. React and Vue programs may continue through their native
compiler/runtime routes without producing an Interaction fact; Ink participates
as non-voting React-lineage evidence with a terminal host configuration.
shadcn/ui participates through its exact registry and project materialization
APIs, while Mantine participates through exact package exports, types, CSS, and
provider setup.

A portable realization requires the interaction fact together with native
handler/effect implementation, host policy, and an evidence-bearing component
or input realization. The requested target may be native source, a runnable
artifact, or an observed behavior fact. No framework is the universal endpoint.
See [decision 0027](DECISIONS/0027_INTERACTION_ACTIVATION_RECURRENCE.md).

### Representation is not a universal semantic container

Production React, Vue, and Ink application sources do not share a source-
attested `Screen` or `Document` identity. Route bindings, application/provider
wrappers, host documents, render contributions, portals/outlets, guarded
alternatives, terminal layouts, and stdout are distinct native facts owned by
different authorities.

A screen-like result may be requested, but it is a state-scoped derived
observation over exact routing, configuration, permissions, layout, host, and
runtime output. Generic analyzers must not consume React/Vue/Ink syntax as its
meaning. Ecosystem-specific providers establish native facts and explicit
semantic adapters project only independently earned contracts. See
[decision 0028](DECISIONS/0028_REPRESENTATION_BOUNDARY_PROBE.md).

### Activity is a selected projection, not a representation tree

Exact upstream selectors from two distinct current Svelte product repositories,
plus Gemini CLI's exact React `useHistory` state machine, produce concrete
verified values of a smaller semantic object: an exact source scope emits an
ordered selection of activity locators with explicit source extent. The Gemini
trace uses projection-local keys because its numeric UI ids are neither durable
recording ids nor chronology; exact AppContainer, UI context, normal App/layout,
MainContent, and display sources retain its downstream aliased-Ink lineage
without claiming terminal visibility. React DOM and Rust/Ratatui products
continue to corroborate the candidate through
different graphs and thread-local containers. The backing model is not the
common waist.

`ActivityProjection` deliberately carries no portable payload, actor enum,
pending request, composer, stream reducer, or render tree. Those meanings are
separate facts that can join the same opaque source references. A native target
provider composes whichever facts its requested output requires; React, Vue,
Svelte, Ink, Ratatui, shadcn/ui, Mantine, and other ecosystem authorities remain
at native lift, materialization, build, renderer, or observation hops.

React and the other ecosystems can participate without semantic projection at
all. There is no universal lowering endpoint: the requested target might be the
projection itself, native source, a runnable artifact, or observed web/terminal
behavior. See
[decision 0029](DECISIONS/0029_ACTIVITY_PROJECTION_RECURRENCE.md).

## Lifting

Lifters should prefer authoritative representations such as Prisma DMMF, PostgreSQL catalogs, OpenAPI/Smithy models, Cedar schemas/ASTs, Terraform plan JSON, and `cargo metadata`. A native source dialect preserves target-specific information losslessly. Bridges into shared contracts are explicit and may be partial.

Lifted knowledge distinguishes:

- observed facts from an authoritative artifact;
- declared claims from an adapter or implementation;
- statically inferred claims;
- runtime-observed evidence;
- unknown intent;
- opaque behavior.

Negative findings must name the closed-world scope that justifies them. Runtime observation proves that a path exists; lack of an observation does not prove that no path exists.

Software-surface facts also carry an artifact role: `production`, `test`, `mock`, or `documentation`. These roles are not interchangeable. A test bridge that fabricates an event proves test coverage; it cannot satisfy a production `Produces` requirement.

Provenance explains where a lifted fact came from. A separate coverage witness explains why an absence is meaningful. A negative result requires exhaustive coverage for every mechanism named by the selected profile under one compatible scope. Excluded or failed artifacts, unresolved expansions, partial extraction, and incompatible build scopes degrade the result to unknown.

## Contract compatibility

Contract identity and version are exact. Ordinary version ranges cannot establish semantic compatibility. A version-changing relationship requires an explicit bridge that changes only the contract identity while preserving the claim payload and evidence. A conformance declaration is evidence, not universal proof.

Trust is contextual rather than intrinsic to serialized IR. The core transports an exact attester, suite identity/version, subject digest, and result digest. An analysis host validates a conformance result and admits it only when bound to an exact operation identity and semantic claim; the default policy admits nothing. Copying an admitted attestation onto a different operation, contract, payload, or source cannot make that claim safe. Multiple claims for the same exact contract remain ambiguous rather than being resolved by trust precedence. See [decision 0002](DECISIONS/0002_EVIDENCE_TRUST_POLICY.md).

## First product corpus

Buzz is the first product proof. Its source dialects may model protocol declarations, builders, CLI commands, runtime producers/consumers, storage indexes, renderers, tests, and documentation claims. These are not kernel concepts.

The first analyzer consumes generic software-surface contracts such as `Declares`, `Produces`, `Accepts`, `Consumes`, `Suspends`, `Resumes`, and `ReachesTerminal`. Known Buzz gaps are acceptance cases, never hard-coded analyzer branches.

`surface-completeness-analysis` receives only a generic `SurfaceProfile`, resolved relation claims, and resolved coverage-witness claims. A trusted opposite relation is an explicit contradiction. A missing relation becomes an error only when every coverage mechanism required by the profile has an admitted, exhaustive, gap-free witness in the exact scope; otherwise the result is unknown. Malformed, ambiguous, or unadmitted contract inputs also remain unknown. The Buzz projection and pinned local admission policy live in separate product-specific packages.

## Open-world contract parametricity

An analyzer result depends only on resolved, versioned semantic-contract projections. It must not depend on native dialect identity, operation names, raw attribute layout, or package identity.

GOOIR-000 tests this metamorphically:

```text
unfamiliar representation + verified projection → same semantic result
same representation - projection              → unknown
familiar-looking decoy - projection            → unknown
```

This invariant was identified by Pollen in `RESEARCH/GOOIR_000_CONTRACT_PARAMETRICITY.md`; the source delegation and result are Buzz events `e9932a9361b46060d70c733f91d1b1639cb5fd7ac22eda3cac4348f19ca407be` and `3354c91a9f0623a4b1131d6512080f250a6035cbe803121af793b38be7aa93bb`.

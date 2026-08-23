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

Unknown means maximally interfering, never safe. A generic pass must not reorder, duplicate, eliminate, or otherwise reinterpret an operation unless installed contracts establish the required semantics.

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

## Contract compatibility

Contract identity and version are exact. Ordinary version ranges cannot establish semantic compatibility. A version-changing relationship requires an explicit bridge that converts a claim and preserves provenance. A conformance declaration is evidence, not universal proof, and unverified declarations remain untrusted.

## First product corpus

Buzz is the first product proof. Its source dialects may model protocol declarations, builders, CLI commands, runtime producers/consumers, storage indexes, renderers, tests, and documentation claims. These are not kernel concepts.

The first analyzer consumes generic software-surface contracts such as `Declares`, `Produces`, `Accepts`, `Consumes`, `Suspends`, `Resumes`, and `ReachesTerminal`. Known Buzz gaps are acceptance cases, never hard-coded analyzer branches.

## Open-world contract parametricity

An analyzer result depends only on resolved, versioned semantic-contract projections. It must not depend on native dialect identity, operation names, raw attribute layout, or package identity.

GOOIR-000 tests this metamorphically:

```text
unfamiliar representation + verified projection → same semantic result
same representation - projection              → unknown
familiar-looking decoy - projection            → unknown
```

This invariant was identified by Pollen in `RESEARCH/GOOIR_000_CONTRACT_PARAMETRICITY.md`; the source delegation and result are Buzz events `e9932a9361b46060d70c733f91d1b1639cb5fd7ac22eda3cac4348f19ca407be` and `3354c91a9f0623a4b1131d6512080f250a6035cbe803121af793b38be7aa93bb`.

# Project brief

GOOIR is a plugin-oriented semantic compiler workbench. It lifts facts from existing software systems into a partial, provenance-bearing graph; relates those facts through separately versioned semantic contracts; and runs analyses that no single source tool can perform alone.

Existing tools remain authoritative. GOOIR composes representations from systems such as Prisma, PostgreSQL, Smithy/OpenAPI, Cedar, Terraform, and compiler metadata. It does not replace their parsers, generators, evaluators, migrations, or runtimes.

## Problem

Application meaning is repeatedly encoded across schemas, APIs, policies, workflows, runtimes, interfaces, tests, telemetry, and documentation. Each tool sees its own slice, so cross-layer gaps remain invisible: a capability may be declared but not producible, accepted but not consumed, suspended but not resumable, documented but unreachable, or privileged without an authority gate.

Traditional portability layers often hide target differences. GOOIR exposes semantic mismatches as precise diagnostics while preserving target-specific detail.

## Thesis

The first product is semantic linking and analysis, not generation.

```text
authoritative artifacts
  → lossless native/source dialects
  → explicit partial projections
  → shared semantic contracts
  → cross-dialect analysis
  → evidence-backed diagnostics / portability frontier
  → optional delegation back to native toolchains
```

A useful graph can be incomplete. Every claim carries source provenance, authority, evidence status, exact contract identity, and projection lossiness. Numeric confidence appears only when calibrated.

## Non-goals

- A universal application language or lowest-common-denominator framework.
- Perfect recovery of business intent from implementation artifacts.
- Reimplementing mature external parsers, generators, evaluators, or runtimes.
- Regeneration or migration as a prerequisite for useful analysis.
- Silent semantic defaults, weakening, or optimistic treatment of unknowns.
- Buzz-specific branches inside generic analyzers.
- Runtime swapping of stateful systems.
- Formal-proof claims where only conformance evidence exists.
- Broad UI semantics in the first architecture test.

## Proof strategy

The tiny invariant harness is the architecture proof; Buzz is the first product proof.

GOOIR-000 proves opaque round-trip, conservative unknowns, exact version bridging, and open-world contract parametricity. GOOIR-001 lifts a pinned Buzz event surface and reports a real cross-layer completeness gap with exact scope and provenance. GOOIR-003 closes one verified gap, re-lifts, and verifies convergence. GOOIR-004 imports a non-Buzz authority so a bespoke Buzz analyzer cannot masquerade as the general architecture.

## Success criteria

1. Kernel ignorance and contract-based interoperability hold without special cases.
2. GOOIR finds a real Buzz gap without hard-coded knowledge of it.
3. Observe → change → re-observe verifies convergence.
4. A second authority reuses the same contract/analyzer boundary.
5. Existing source systems remain authoritative throughout.

## Drift test

> If a change teaches the kernel what the software means, replaces an existing semantic authority, hides an unknown, or hard-codes a Buzz fact into a generic analysis, it moves GOOIR away from the thesis.

This brief was distilled by Honey from the Welcome-channel design deliberation rooted at Buzz event `37412079d25a97e68af7adc7a8b2b01f0863fd85a9a966d3298f3ad9ddd712cb` and reported in event `3f3b39c2850de8c946f69f7c87fc101177c2b40ca74039a8b31e8292517dea19`.


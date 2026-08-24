# 0013 — `gooir doctor`: the graph reports on itself

Status: complete

## Why

The mechanics are far ahead of the ergonomics, and that gap was assertable but
not measurable. Measuring it by hand produced these numbers:

| | count |
| --- | --- |
| crates | 33 |
| public types | 160 |
| runnable binaries | 14, with no single entry point |
| decision-record lines vs README lines | 1,576 vs 121 |
| exact-identity systems for one idea | **3** |

The last row is the finding underneath all the others. `gooir-capability`
depends on nothing in GOOIR — only `serde`, `serde_json`,
`serde_json_canonicalizer`, `sha2`. It reimplemented exact identity beside
`gooir-core::ContractId` and conformance admission beside `gooir-analysis`'s
819-line `EvidenceTrustPolicy`. Two architectures share this repository and
touch at exactly one crate, `semantics-data-model-v1`, which bridges them only
because it happened to need both.

A newcomer cannot tell which architecture is real, because both are.

## The tool

`gooir-doctor` analyses a capability graph and nothing else: no fact meanings,
no product, no domain verbs. Its library takes any `&CapabilityRegistry`; its
binary additionally knows this workspace's installed set, which is what
"installed" means for a tool.

It reports what a reader actually needs:

- **you must supply** — root facts nothing produces
- **you can obtain** — terminal facts, and whether each is reachable
- **open needs** — provider-less capabilities, with their conformance suites
- **unreachable** — a fact the graph describes but cannot route to
- **multiple routes** — one fact produced by several capabilities
- **unadmitted providers** — every provider, until conformance runs
- **identity systems** and **identities declared in more than one crate**

## First run against the installed set

```
capability graph
  11 capabilities, 9 providers, 15 fact types

you must supply (5)     4 Fleetd source artifacts + 1 authored entity spec
you can obtain (5)      3 available, 2 waiting on a declared need
open needs (2)          generate_runnable_web_surface, lower_typescript_types
multiple routes (1)     data_model, via author_data_model or lift_openapi_data_model
unadmitted (9)          every registered provider
identity systems (3)    FactType 23 sites, CapabilityId 17, ContractId 14
duplicate identity (1)  data_model declared in two crates
```

Three of these were previously invisible without reading Rust:

1. **The graph has five entry points and five answers.** That is the whole
   product surface, and it fits in ten lines.
2. **`data_model` has two routes** — an authored specification and a lifted
   OpenAPI document. [0012](0012_AUTHORING_AS_A_CAPABILITY.md) claimed that
   interchangeability and tested it; the graph now *shows* it.
3. **Three identity systems**, counted rather than asserted.

## A blocked terminal is not a failure

The first version exited non-zero because two terminals were unobtainable. That
is wrong: a terminal blocked by a declared open need is *accounted for* — being
assignable is the point of `CapabilityNeed`. A tool that fails because work
remains is useless.

`blocking()` now counts only what the graph cannot explain: a fact with no
route, or a terminal blocked for a reason other than a declared need. The
installed set reports **0 blocking, 2 open needs**, and exits 0.

## What it says to do next

The diagnostic was built before any renaming precisely so it could choose the
order, and it did:

1. **One identity.** Collapse `ContractId` into `FactType`. Mechanical, and it
   is what makes the repository feel like two projects.
2. **Import the shared identity rather than re-declaring it.** One duplicate
   today, guarded by a test in [0012](0012_AUTHORING_AS_A_CAPABILITY.md). That
   guard should become unnecessary.
3. **Admission.** Nine of nine providers are unadmitted, and
   `gooir-analysis` already contains the default-deny trust machinery from
   [0002](0002_EVIDENCE_TRUST_POLICY.md) that the capability registry
   reimplemented. Reconciling those is the same work as move 1.

Renaming crates and building one CLI are *not* first. The graph does not report
naming as its problem; it reports a split kernel.

## Caveat

`main` is at `7b38085`, nine branches behind this work. A rename across 33
crates on top of that lineage would be a conflict-resolution exercise rather
than a design one. Merge first.

## State

276 tests, clippy and fmt clean.

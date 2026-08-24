# 0016 — One exact identity

Status: complete

## Why now

[0015](0015_GOOIR_DOCTOR.md) built the diagnostic before any renaming so the
graph could choose the order of ergonomic work, and it did: it reported a split
kernel, not a naming problem. `gooir-capability` depended on nothing in GOOIR
and had reimplemented exact identity beside `gooir_core::ContractId`.

`main` was fifteen commits behind that work, so a refactor across the whole
workspace would have been conflict resolution rather than design. **`main` was
fast-forwarded to `6284c56` first** — one linear chain, 276 tests green. One
branch, `gooir-001-piler-shadow`, was deliberately excluded: it is a
self-describing frozen archive from 07:24 that no other branch contains.

## The move

`gooir-identity` owns the rule: package, name, version, matched exactly and
never by range. One macro generates every identity type in the workspace.

Distinct *types* were kept — a fact is not a capability, and the compiler
should say so. Two *implementations* of one rule were not: they had already
drifted in their derives, and they made the repository read as two projects
sharing a directory.

```text
gooir-identity::exact_identity!
    ├─ gooir-core        ContractId
    └─ gooir-capability  FactType, CapabilityId, ProviderId
```

The collapse also produced something neither implementation had:
`is_well_formed()`, which rejects a blank part. An identity with an empty
component cannot be matched exactly, so it cannot mean anything.

## The duplicate identity is gone structurally

[0014](0014_AUTHORING_AS_A_CAPABILITY.md) guarded `data_model_fact()` with a
test because two packs declared it. The identity now has one source:

```rust
// gooir-datamodel-pack
FactType::new(
    semantics_data_model_v1::PACKAGE,
    semantics_data_model_v1::MODEL,
    semantics_data_model_v1::VERSION,
)

// fleetd-capability-pack
pub use gooir_datamodel_pack::data_model_fact;
```

`semantics_data_model_v1::MODEL` names the whole-model concept alongside the
existing `entity` and `relation` contracts, so the *value* lives where the
concept lives. The product pack imports rather than re-declares, which is also
the correct dependency direction: product depends on neutral.

The drift-guard test was deleted. It guarded a condition that can no longer
occur, and it had created a dev-dependency cycle. The interchangeability test
moved to `fleetd-capability-pack`, the crate that legitimately depends on both.

## Measured before and after

| | before | after |
| --- | --- | --- |
| implementations of the identity rule | 2 | **1** |
| fact identities declared in >1 crate | 1 | **0** |
| tests | 276 | 281 |

## A note on the diagnostic itself

The first version of this measurement reported "3 parallel exact-identity
systems." That was wrong: it counted three type *names* from two
*implementations*. Naming the metric badly made the problem look like something
it was not.

Fixing it exposed a second class of error. The tightened scan reported four
implementations, including `gooir-doctor` itself — the tool was matching its
own search strings — and two crates holding unrelated structs that merely had
`package` and `version` fields. The check now requires all three parts, and its
needles are assembled from fragments so the scanning file cannot match itself.

**A tool that measures source must be verified against source it already
understands**, or it invents findings. That is the same lesson as the round-trip
and comparison-coverage findings in [0007](0007_STORE_ROUND_TRIP.md) and
[0008](0008_POLYMORPHIC_CRUD_SURFACE.md), arriving this time in the measuring
instrument rather than the thing measured.

## Still open, and now visible

`gooir doctor` reports 9 of 9 providers unadmitted. `gooir-analysis` holds the
default-deny trust machinery from [0002](0002_EVIDENCE_TRUST_POLICY.md) that
the capability registry reimplemented. Reconciling those two is the remaining
half of the split kernel, and it is the next thing the graph will complain
about.

## State

281 tests, clippy and fmt clean. `main` carries all of it.

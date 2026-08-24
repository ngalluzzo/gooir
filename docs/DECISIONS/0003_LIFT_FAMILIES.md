# 0003 — Lift families and the reusable lift substrate

Status: proposed for GOOIR-001

## Purpose

`buzz-relay-lifter` was written as a POC to be mined for a reusable lifting API
(3,736 implementation lines, 1,515 test lines, 97 tests). This record probes
**which** of its machinery the remaining GOOIR-001 lifters actually need, before
any code is moved.

The probe is deliberately a paper exercise. Extracting first and validating
after would commit the crate boundaries to an untested seam, which is the exact
failure this project is trying to avoid.

## Method

Read against the pinned source at `39f8b46935736334cdd7045a4e4b5d7eb1a33888`
(local checkout verified at that exact revision), plus the two existing lifters.
No code changed. Every finding below cites artifact and line.

The two open GOOIR-001 requirements under probe, from `buzz-surface-profile`:

- `sdk-constructs-4300{1..6}` — `Constructs`, subject `buzz-sdk:builders`,
  mechanism `sdk_builder_inventory`
- `runtime-dispatches-job-request` — `Dispatches`, subject
  `buzz-agent-runtime:dispatcher`, mechanism `agent_runtime_dispatch`

## Findings

### F1 — There are two lift families, and their defeaters are disjoint

Both existing lifters share one control structure: accumulate reasons into
`unresolved: Vec<String>`, then collapse `unresolved.is_empty()` to
`Exhaustive` / `Partial`. That collapse rule is the whole soundness
architecture, and it is currently duplicated rather than shared.

The *defeaters* feeding it have nothing in common.

**Family A — decision faithfulness** (`buzz-relay-lifter`). Question: *given a
closed decision over an incoming value, what does it decide, and is the value
being tested really the one that arrived?* Its 14 `Option<String>` defeaters:
unreachable-after-return, shadowed unqualified helper, incoming-kind identity,
canonical event type resolution, module helper resolution, rejection-returns,
pre-gate side-effect risk, in-arm side-effect risk, callback boundary, macro
binding, receiver binding, verification capture, scope attribute, scope symbol.

**Family B — inventory exhaustiveness** (`buzz-cli-lifter`). Question: *over the
set of all members of a surface, does any member satisfy the relation, and is
the enumeration closed?* Its defeaters: recursive subcommand enum, conditional
(`#[cfg]`) enum / command / parser surface / command field, missing modeled
derive, open command surface.

Zero overlap. Family A reasons about **dataflow into one decision**; Family B
reasons about **closure of a set**.

### F2 — Family A's 1,900 lines transfer to neither remaining lifter

`KIND_JOB_*` is referenced in exactly two files in the entire Buzz workspace:

```
crates/buzz-core/src/kind.rs      (declarations + ALL_KINDS registry)
crates/buzz-db/src/feed.rs        (activity feed queries)
```

The literal `43001` appears in only two places: `kind.rs:518` and
`crates/buzz-relay/src/handlers/event.rs:44`.

Neither `buzz-sdk` nor `buzz-agent` contains any job-kind reference. So neither
remaining requirement is a decision-faithfulness question. Both are absence
questions over an enumerable surface — Family B.

**Consequence: Family A currently has exactly one member and no second
consumer.** Extracting it as "the reusable substrate" would generalize the seam
that is under no pressure, and leave the seam that is under pressure untested.

### F3 — `sdk-constructs-*` is a Family B absence proof over 59 builders

`crates/buzz-sdk/src/builders.rs` is 4,870 lines containing 59 `pub fn build_*`
functions. Kinds reach the constructed `EventBuilder` by at least two distinct
mechanisms:

- an inline literal — `EventBuilder::new(Kind::Custom(9), content)` (`build_message`, line 242)
- a named constant imported from `buzz_core::kind::{...}` (import block, lines 6–16)
- a named constant through a cast — `Kind::Custom(KIND_WORKFLOW_TRIGGER as u16)` (line 1646)

The import block names 29 kind constants and includes **no** `KIND_JOB_*`. The
cast form matters: value resolution must handle cast expressions, not only bare
paths and literals. `Kind::Custom(9)` also occurs at line 3186 inside the test
module, so the inventory must respect `ArtifactRole` and exclude test-role
constructions from a `Production` claim.

So the lift needs: enumerate every event-constructing function; resolve the kind
each one yields to a `u32`; show none yields `43001..=43006`; and prove the
enumeration is closed. That is `buzz-cli-lifter`'s shape, not
`buzz-relay-lifter`'s. **The SDK lifter's template is the CLI lifter.**

Its likely new defeaters, none of which exist today: macro-generated builders;
builders re-exported from another module; `EventBuilder` constructed outside a
`build_*` function; a kind supplied by a non-constant expression; `#[cfg]`-gated
builders.

Note also that the module doc comment claims "38 builders" while the source has
59. Lift from source, never from a doc claim.

### F4 — `runtime-dispatches-job-request` is not liftable as currently stated

`crates/buzz-agent/src/**` contains no event-kind dispatch: no `.kind` access
and no `match` over an event kind. The single `match` on anything kind-named is
`model_capabilities.rs:320` (`rule.match_kind`), which concerns model capability
rules, not Nostr events.

The requirement's subject `buzz-agent-runtime:dispatcher` therefore names a
construct that cannot be located at this revision. **That is a
subject-unresolvable `Unknown`, not an exhaustive negative.** A lifter must not
report "the runtime does not dispatch job requests" when it cannot establish
what the dispatcher is.

### F5 — The shipped relay finding proves a narrower scope than its requirement names

The relay lifter proves the gate inside `ingest_event_inner`. Call structure at
the pinned revision:

```
api/bridge.rs:839      ─┐
                        ├─→ ingest_event (ingest.rs:2008) ─→ ingest_event_inner (ingest.rs:2068) ─→ gate (2157)
handlers/event.rs:761  ─┘
```

`ingest_event_inner` has exactly one caller, so the gate does dominate every
path *through that function* — the `Rejects` decision itself is sound. But
`ingest_event` has two callers, in two artifacts (`api/bridge.rs`,
`handlers/event.rs`) that are **not** in the relay lifter's
`included_artifacts`. `ingest_event` also calls out to
`handlers/event.rs::bounded_kind_label` (line 2017) — an unadmitted artifact
that itself contains `43001..=43006` (`event.rs:44`).

That call is benign: `kind_label` is consumed only as a metrics label
(`ingest.rs:2040`) and cannot affect acceptance. **But the lifter never proved
that. It did not look.** The requirement subject is `buzz-relay:client-ingest`
— the ingest surface — while the proof covers one nested function.

Missing Family A defeater: *the proven decision point is not established as
dominating every path from the requirement's named subject surface, and the
subject surface's own artifacts are not in the admitted set.*

### F6 — F4 and F5 are the same gap, and it lives in the contract

`SurfaceRequirement.subject` is an opaque `String`. Nothing in
`semantics-software-surface-v1` defines how a subject identity binds to a source
construct. Both lifters bind it by convention:

- relay: `buzz-relay:client-ingest` → assumed to be `ingest_event_inner`
- SDK: `buzz-sdk:builders` → assumed to be `builders.rs`
- runtime: `buzz-agent-runtime:dispatcher` → cannot be assumed at all

For the relay the assumption is true; for the runtime it is unlocatable. **The
contract permits a lifter to assert a relation about a subject it never proved
it had found.** This is a contract-level boundary defect, not a lifter bug.

### F7 — `Exhaustive` means two different things in two lifters today

`buzz-relay-lifter` proves compilation admission before claiming anything:
workspace membership, resolver and edition, package and dependency bindings,
the checksummed lock entry, and unconditional out-of-line module edges from
crate roots (~600 lines).

`buzz-cli-lifter` performs none of it. `lift_command_tree(source, authority,
artifact, revision)` takes a single source string; the crate contains zero
references to Cargo manifests, lockfiles, or module edges. It nonetheless emits
`NativeCompleteness::Exhaustive`.

The shipped product view presents both as established findings. One rests on a
proven compilation basis; the other rests on the assumption that a file it was
handed is in the build.

## Decisions

1. **Extract the shared substrate as layers 1–3, not layer 5.**
   - `lift-defeasible` — `Defeat { reason, span }`, three-valued `Truth` with
     Kleene `and`/`or`, and the single `Exhaustive`/`Partial` collapse rule.
     Currently duplicated in both lifters, and two independent three-valued
     types exist (`Truth`, `IngestDecisionKind`).
   - `lift-rust-compilation` — compilation admission, mined from the relay
     lifter.
   - `lift-rust-resolution` — constant, predicate, path, import and shadowing
     resolution.
   - `lift-rust-decision` (Family A only) — `evaluate_match` and pattern/guard
     truth.
2. **Mine the Family B inventory core from `buzz-cli-lifter`,** and build the
   SDK lifter against it.
3. **Leave Family A's 14 defeaters in `buzz-relay-lifter`** until Family A has a
   second member. A one-member abstraction is a guess.
4. **No lifter may report `Exhaustive` without compilation admission.** Fixing
   F7 is a prerequisite for the SDK lifter, and requires back-filling
   `buzz-cli-lifter`. Until then the CLI finding's completeness is overstated.
5. **`Exhaustive` is always relative to a defeater set.** The defeater-set
   identity and version belong in the existing
   `CoverageWitness.extractor.config_digest`. An undiscovered defeater is
   currently silent unsoundness; the git history shows the defeater set grew one
   commit at a time, so it must be assumed incomplete by construction.
6. **Reclassify `runtime-dispatches-job-request`.** It stays `Unknown`, but for
   the honest reason (subject unresolvable), not the current one (coverage
   lifter absent).
7. **Give subject identity a defined binding in the contract** before either
   remaining lifter lands. Without it, F5 recurs silently in every future
   lifter.

## Revised predictions

Committed before the work, so they can fail loudly:

| Unit | Predicted |
| --- | --- |
| `lift-defeasible` | ~150 lines |
| `lift-rust-compilation` | ~600 lines, moved not written |
| `lift-rust-resolution` | ~450 lines, moved not written |
| `lift-rust-decision` | ~350 lines, moved not written |
| `buzz-relay-lifter` after extraction | ~400 lines + its 14 defeaters, 97 tests still green, fixture byte-identical |
| Family B inventory core | ~300 lines, mined from the CLI lifter |
| `buzz-sdk-lifter` (new) | **under ~450 lines** |
| `buzz-cli-lifter` after compilation back-fill | +~50 lines, no behavior change except completeness honesty |

If `buzz-sdk-lifter` exceeds ~1,000 lines, the Family B seam is wrong and the
inventory core is not the reusable unit.

## What the probe cost

About an hour, and no code moved. Extracting Family A first — the plan this
probe replaces — would have been ~1,900 lines of refactoring toward a seam with
one member, while the two requirements actually waiting needed a different
substrate entirely, and while F5/F6/F7 stayed invisible.

## Follow-ups

- F5 is a live soundness gap in a shipped result. It does not invalidate the
  `Rejects` decision, but the relay coverage witness currently overstates the
  scope it proved. Fix before GOOIR-001 closes.
- F7 likewise: `buzz-cli-lifter`'s exhaustive CLI gap is the one finding the
  product view presents as fully established, and it has the weaker basis.
- The contract-vocabulary seam (F6) is independent of all Rust lifting work and
  can only be falsified by a non-Buzz authority — GOOIR-004. F6 is the first
  concrete evidence that it needs falsifying.

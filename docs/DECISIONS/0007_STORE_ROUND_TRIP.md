# 0007 — The store round trip, and why a pure law is not enough

Status: complete — the data layer of Phase 1 is generated and verified

## The problem this solves

[0006](0006_PHASE1_ROUND_TRIP.md) established `lift(lower(lift(X))) == lift(X)`
against Prisma and found the law's limit the same day: it passed while the waist
was internally inconsistent, because the mistake was **symmetric** — the
lowering wrote back exactly the wrong names the lifter read.

A law that compares my own code against my own code cannot catch that. The fix
is to put an independent implementation in the middle.

## The harness

```
waist -> PostgreSQL DDL -> a real database -> catalog -> waist
```

`scripts/store-round-trip.sh` emits DDL from the waist, applies it to a live
PostgreSQL, introspects the result, lifts that catalog back into the waist, and
compares. PostgreSQL validates the DDL — invalid output is rejected outright
rather than quietly agreed with.

## Result

| app | entities | fields | attributes | unique sets | relations |
| --- | --- | --- | --- | --- | --- |
| umami | 24 → 24 | 0 div | 0/1098 | 0 div | 28 → 28, 0 div |
| rallly | 32 → 32 | 0 div | 0/1755 | 0 div | 46 → 46, 0 div |
| ghostfolio | 19 → 19 | 0 div | 0/750 | 0 div | 19 → 19, 0 div |
| documenso | 51 → 51 | 0 div | 0/2571 | 0 div | 63 → 63, 0 div |

**Zero divergence across 6,174 attribute comparisons, and every relation
survives as a real foreign key** — which also establishes that the waist's
relations are all satisfiable by a relational store, not merely representable.

918 comparisons are recorded as authority-limited: a catalog cannot see whether
an application supplies a default, so `DefaultOrigin::None` and
`::Application` are not distinguishable from it. That is a stated limit, not a
disagreement.

## What the store caught that the pure law could not

Three real defects, none of which the Prisma round trip could see:

1. **A scalar default on an array column.** `"scopes" text[] DEFAULT ''::text`.
   My own lifter/lowerer pair would have agreed on this forever; PostgreSQL
   rejects it. An array default needs an array literal.
2. **A declared unique constraint silently dropped.** The lowering skipped
   `UNIQUE` when a field was already the primary key, reasoning that a key
   implies uniqueness. The source had declared `@id @unique`, and discarding it
   loses a stated fact — the same class of error as ignoring `@db.Uuid`.
3. **The form of a constraint decides whether it survives.** Emitting the
   constraint inline as `UNIQUE ("id")` alongside `PRIMARY KEY ("id")` produced
   only `polls_pkey`: PostgreSQL **folds** a unique constraint that duplicates
   the primary key. The original databases carry `polls_id_key` because Prisma
   emits `CREATE UNIQUE INDEX` instead, and an explicit index is never folded.

The third is the one worth remembering. **The same logical fact survives or
vanishes depending on which of two equivalent-looking encodings the lowering
picks**, and no amount of reasoning about my own code would have revealed it.
Only executing against the real target did.

## Three checks, each catching what the others miss

| check | catches | blind to |
| --- | --- | --- |
| two-authority convergence | one lifter misreading its source | anything both authorities encode the same way |
| pure round trip | asymmetric loss through a target | symmetric mistakes shared by lifter and lowerer |
| **store round trip** | invalid output, encoding choices that do not survive | what the store itself cannot express |
| internal-consistency invariants | a waist that contradicts itself | facts absent from the waist entirely |

None is sufficient. All four are cheap. This is the substitute for authoring
laws about my own middle.

## Lowering declares what it filled in

The DDL lowering reports `Lossy` records rather than inventing quietly:
store-side default expressions the waist does not carry, enum member names, a
required list (a store models absence as NULL), and any entity with no identity
field.

## Reproduction

```bash
./scripts/store-round-trip.sh          # needs a reachable PostgreSQL
cargo run -q --bin prisma-round-trip   # pure law, no database
cargo run -q --bin data-model-convergence
```

## Next

The polymorphic layers — CRUD API surface, admin table and detail form — which
[0004](0004_RECURRENCE_PROBE.md) identified as where the repetition actually
lives. The data layer they sit on is now generated and verified end to end.

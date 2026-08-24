# 0006 — Phase 1: lowering, and the round-trip law as the correctness harness

Status: in progress — the law holds; target stack not yet built

## Why this before the target stack

The previous attempt authored 334 law rules to constrain a middle nothing
external could check. This project uses a law reality checks for free instead:

```
lift(lower(lift(X))) == lift(X)
```

The lowering is *not* required to reproduce X's text — the waist is lossier than
Prisma on purpose. What must hold is that a model, once in the waist, survives a
trip through a target and back unchanged. That is fully automatic, needs no
judgement, and exercises the waist in the direction the product actually needs.

## Result

`prisma-schema-lowering` emits Prisma schema text from the neutral waist. The
law holds over all four real applications:

| app | source | emitted | entities | fields | relations | lossy |
| --- | --- | --- | --- | --- | --- | --- |
| umami | 18,479 B | 9,712 B | 24 → 24 | 214 → 214 | 28 → 28 | 28 |
| rallly | 30,252 B | 17,158 B | 32 → 32 | 335 → 335 | 46 → 46 | 82 |
| ghostfolio | 11,181 B | 7,205 B | 19 → 19 | 144 → 144 | 19 → 19 | 32 |
| documenso | 38,066 B | 25,128 B | 51 → 51 | 489 → 489 | 63 → 63 | 131 |

**1,182 fields and 156 relations survive the trip with every attribute
unchanged.** The test guards against a vacuous pass: it asserts a minimum
comparison surface and asserts the emitted text differs from the input, so a
lowering that merely echoed its source would fail.

## Lowering declares what the waist cannot supply

273 `Lossy` records across the corpus. A round trip that holds does **not** mean
the output is faithful to the original source, and conflating those would be the
same self-certification trap as before. What the waist cannot carry:

- **store-side default expressions.** The waist records that a default is
  database-generated, not what it is. The lowering emits a placeholder.
- **enum member names.** One placeholder enum stands in for all enumerations.
- **relation field names.** The waist carries edges, not the names Prisma gives
  the relation fields on either side, so both are synthesised.

Each is a candidate for the waist to carry later, and each should be added only
when a consumer needs it.

## The finding that matters more than the law

The law passed on the first run. Eyeballing the emitted schema anyway showed:

```
  user_id String                                     <- the field
  usersRel0 users @relation(fields: [userId], ...)   <- the relation
```

The Prisma lifter mapped field names through `@map` but left relation
`fields:`/`references:` as raw model-field names. The waist was **internally
inconsistent**: relations named fields their entities did not have.

The round trip could not see it, because the error was **symmetric** — the
lowering wrote the same wrong names the lifter read back. The convergence test
could not see it either, because it compared relations by endpoint only.

Two guards added, both of which now fail on that bug:

- convergence compares a relation's *carrying fields*, not just its endpoints;
- a new invariant asserts every relation names fields that exist on its
  entities, in both authorities.

After the fix, relation divergence stayed at 32 while the comparison became
strictly stronger — Prisma's mapped `from_fields` now match the catalog's column
names exactly.

**A round-trip law only catches asymmetric loss.** It is necessary and not
sufficient; internal-consistency invariants are a separate obligation.

## Direction separation

`prisma-schema-lowering` build-depends only on the waist and the defeasible
core. The lifter is a dev-dependency, used solely to state the law. Lowering and
lifting have opposite economics and must not couple.

## Next

The target stack: CRUD API, admin table and detail form, auth wiring — the
domain-polymorphic layers [0004](0004_RECURRENCE_PROBE.md) identified as where
the repetition actually lives. One stack, ugly output acceptable.

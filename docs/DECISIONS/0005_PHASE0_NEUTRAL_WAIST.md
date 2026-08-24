# 0005 — Phase 0: earning the neutral data-model waist

Status: complete — proceed to Phase 1

## Goal

Establish a neutral entity/relation vocabulary that two structurally unlike
authorities converge on, with no laws authored alongside it. Reality checks the
middle; that is what replaces the 334 hand-written law rules that sank the
previous attempt (see [0004](0004_RECURRENCE_PROBE.md) for the corpus method and
`openspecs` for the failure being avoided).

Falsification condition set before starting: if the two authorities cannot be
made to converge on one vocabulary after two honest attempts at the waist, the
approach is wrong.

## What was built

| Crate | Role |
| --- | --- |
| `lift-defeasible` | the defeasible core: `Defeasible<T>`, `Defeat`, `DefeatKind`, `Presence`-style three-valued `Truth`, and the `Exhaustive`/`Partial` collapse rule |
| `semantics-data-model-v1` | the neutral waist: `EntityShape`, `FieldShape`, `RelationEdge`, `ScalarType`, `Presence`, `DefaultOrigin` |
| `prisma-schema-lifter` | Prisma schema text -> waist |
| `postgres-catalog-lifter` | PostgreSQL catalog introspection -> waist |
| `data-model-convergence` | cross-authority comparison, report binary, and the regression test |

`DefeatKind` is deliberately five-valued (`NotLooked`, `LookedAndBlocked`,
`SubjectUnresolvable`, `OutOfScope`, `AuthorityCannotExpress`) because each
implies a different action for a reader. Collapsing them into one "unknown" was
identified as a product defect before this phase and is now fixed at the root.

## Corpus

Four real open-source applications. For each: the checked-in Prisma schema, and
a live PostgreSQL 14 catalog produced by replaying every checked-in migration in
order.

**456 migrations replayed, 0 failures.**

| app | migrations | prisma models | catalog tables |
| --- | --- | --- | --- |
| umami | 24 | 24 | 24 |
| rallly | 146 | 32 | 32 |
| ghostfolio | 123 | 19 | 21 |
| documenso | 163 | 51 | 51 |

## Result

```
TOTALS  shared_entities=126  field_div=0  attr_div=0/6174 (100.0%)
        unique_set_div=0  entity_div=2  relation_div=32
```

**Zero divergence on field existence, field attributes, and compound
uniqueness, across 6,174 attribute comparisons.** Every remaining entity and
relation divergence is accounted for by a recorded defeat:

- **umami, 28 relation divergences.** `relationMode = "prisma"`: relations are
  not enforced in the database. The catalog reports zero foreign keys and
  records `AuthorityCannotExpress`; the schema records `OutOfScope`. A catalog
  observes enforcement, not intent, so zero foreign keys is *unknown*, never
  *no relations*.
- **ghostfolio, 2 entity + 4 relation divergences.** Three implicit
  many-to-many relations. Prisma never names their join tables
  (`AuthorityCannotExpress`); the catalog sees the join tables as entities.
  Both authorities are correct.
- **22 `LookedAndBlocked`.** Uniqueness implied by a one-to-one relation, not
  re-derived here — see below.

The waist's one structural commitment — **a reference between entities is an
edge, never a field** — is what makes this work. Had it been wrong, Prisma's
relation fields (`author User`) would have appeared as thousands of
prisma-only fields. Field divergence is zero.

## Vocabulary changes earned by evidence

Each of these was forced by real disagreement between two correct authorities,
not designed up front.

1. **`has_default: bool` -> `DefaultOrigin`** (`None`/`Database`/`Application`/
   `Unknown`). 64 fields across the corpus use client-generated defaults
   (`cuid()`, `uuid()`); the store has no default for them. A boolean made two
   correct authorities look like they contradicted each other.
2. **`nullable: bool` -> `Presence`** (`Required`/`Optional`/`Unknown`). Prisma
   collapses null and empty for list fields, so it cannot express presence for
   them at all. Six divergences were this and nothing else.
3. **`unique: bool` narrowed to singleton-only, plus `EntityShape::unique_sets`.**
   Marking every member of a compound unique as individually unique asserts
   something strictly stronger than the authority established. This alone was
   47 false divergences.
4. **Field lookup is exact-first; normalization is a fallback used only when
   unambiguous.** documenso's `Account` really does carry both `createdAt`
   (timestamp) and `created_at` (integer, from an upstream provider), meaning
   different things. Folding case *and* separators collides them.

The general lesson, which should govern every future waist attribute:
**every attribute needs an `Unknown` state, because authorities differ in what
they are able to express.** A boolean forces a lifter to invent an answer.

## Defects found in my own lifters

All fixed. Recorded because the pattern matters more than the list: every one
was information an authority had supplied and the lifter discarded.

- `@db.Uuid` native-type attributes ignored (59 occurrences; Prisma has no UUID
  scalar, so the native attribute *is* the domain).
- Relation targets not resolved through `@@map` — 92 false divergences in rallly
  alone, and exactly zero in documenso, which uses no `@@map`.
- Catalog read unique *constraints* only. Prisma's `@unique` emits a unique
  *index*, which may have no constraint row (113 false divergences).
- Catalog then counted primary-key indexes as unique (117 false divergences in
  the other direction). Identity and uniqueness are separate claims.
- Enum arrays undetected: for `"Role"[]` the attribute type is the array type,
  so the element type must be resolved.
- `dbgenerated("gen_random_uuid()")` classified as an application default by a
  naive substring match on `uuid(`.
- Single-element `@@unique([token])` dropped entirely.

## One inference attempted and withdrawn

Prisma's engine derives a unique index for the foreign key of a one-to-one
relation. Re-deriving that rule here produced **four false positives** — a
relation key that is also the primary key is identity, not a separate unique
constraint.

The rule belongs to Prisma. It is now recorded as a `LookedAndBlocked` defeat
instead of guessed. This is the session's own lesson at small scale: *do not
re-derive what an authority already computes.* The same mistake at large scale
is what produced 334 law rules in the previous attempt.

## Verdict

**Go.** The waist represents both authorities with zero unexplained divergence,
carries no laws, and its four vocabulary changes were each forced by evidence.

## Limitations — read before trusting this

- **The two authorities share a lineage.** Prisma generated these migrations, so
  the catalog is downstream of the schema. This establishes that the waist can
  faithfully represent two very different *representations* (a declarative DSL
  and a relational catalog) — it does **not** establish that an unrelated
  authority would converge. A genuinely independent authority (hand-written SQL,
  a different ORM, a GraphQL SDL) is the stronger test and has not been run.
- Four applications, one store (PostgreSQL), one schema language.
- Normalization cannot bridge pluralization by design; authorities that disagree
  on it must say so via an explicit mapping.
- No lowering exists yet, so the round-trip law `lift(lower(X)) == X` is not yet
  available.

## Next

Phase 1: lower the waist to one target stack (entities, CRUD API, admin table
and detail form, auth wiring) and use the round trip against Prisma as the
correctness harness. Keep it to one stack and accept ugly output; per
[0004](0004_RECURRENCE_PROBE.md) the differentiating value is in the
domain-polymorphic layers, not the entity layer.

Worth doing alongside, cheaply: add one independent authority to close the
limitation above before the waist accumulates dependents.

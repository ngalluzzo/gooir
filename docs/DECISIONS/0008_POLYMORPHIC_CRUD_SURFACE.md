# 0008 — The polymorphic CRUD surface, and a non-relational target

Status: complete

## What was built

`openapi-lowering` generates a complete OpenAPI 3.1 CRUD surface from the waist,
and `openapi-lifter` reads resource schemas back out of one.

| app | schemas | operations | bytes |
| --- | --- | --- | --- |
| umami | 96 | 117 | 70 KB |
| rallly | 128 | 160 | 96 KB |
| ghostfolio | 76 | 89 | 47 KB |
| documenso | 204 | 252 | 147 KB |

**618 operations and 504 schemas, none of them hand-written.** Per entity: a
resource schema, a `Create` variant that drops server-supplied fields, an
`Update` variant where nothing is required, a `List` page, and five operations.
That shaping is identical for every entity regardless of domain, which is
exactly the repetition [0004](0004_RECURRENCE_PROBE.md) located.

## Why this target specifically

JSON documents have no primary keys, no unique constraints and no foreign keys.
Lowering to OpenAPI and lifting back therefore answers a question the relational
targets could not: **is the waist genuinely neutral, or quietly relational?**

It is neutral. Entity and field sets survive exactly; every fact the target
cannot carry comes back as `Unknown` rather than as a wrong answer.

## Four defects it exposed

**1. "Required to write" is not "always present when read" (307 divergences).**
The resource schema reused the create request's `required` computation, so every
field with a server-supplied default looked optional to anyone reading the
resource. Two different facts, one calculation. Now three explicit modes:
`AsRead`, `AsWritten`, `Nothing`.

**2. `identity` and `unique` had to become three-valued (199 divergences).**
[0005](0005_PHASE0_NEUTRAL_WAIST.md) already concluded that *every* attribute
needs an `Unknown` state, then applied it only to nullability and defaults. A
JSON Schema cannot state a primary key, so a boolean forced the lifter to answer
`false` — asserting something never established. There is now one `Tri` type,
and the general rule is honoured rather than restated.

**3. The waist carried no enum members.** Both relational authorities can
express them, OpenAPI can express them, and without them a generated schema
cannot validate a value and a generated form cannot render a choice — most of
what makes the output useful. `Enumeration { name, members }` is now carried,
and enums lower to shared named types in all three targets.

**4. Enum names were not mapped (27 divergences).** `@@map` was read for models
and fields but not for enums, so `PollStatus` never matched `poll_status`. The
same defect class as the relation-field names in
[0006](0006_PHASE1_ROUND_TRIP.md): mapping some names and not others.

## The methodological finding

Adding `enumeration` to the comparison changed the totals from `0/6174` to
`27/7356`. The earlier `0/6174` was not wrong — it was **narrower than it
looked**. Enum names and members had never been compared at all, so the waist
could have been dropping them silently while every check reported perfect
agreement.

> **A comparison only checks what it compares.** A clean result is a statement
> about the comparison's coverage as much as about the code.

This is the same shape as [0007](0007_STORE_ROUND_TRIP.md)'s symmetric-error
finding, at a different layer: a green check earns confidence only over the
surface it actually inspects. Both were found by looking at output rather than
by trusting a passing suite.

## Enum member order is source-local

The last 15 divergences were pure ordering: same names, same members, different
sequence. A schema lists declaration order; a store reports the order values
were added. Both are locally correct and they disagree consistently.

Order is therefore **kept but not compared** — `Enumeration::members` preserves
whatever the authority reported, destroying nothing, while
`Enumeration::member_set` provides the canonical form that compares across
authorities. Normalising on lift would have thrown away real information; a
store that gives enums ordering semantics still has it.

## Current state of the four checks

| check | surface | result |
| --- | --- | --- |
| two-authority convergence | 126 entities, 7,356 attributes | 0 divergence |
| pure round trip (Prisma) | 1,182 fields, 156 relations | holds |
| store round trip (live PostgreSQL) | 6,174 attributes | 0 divergence |
| OpenAPI round trip | 4,722 attributes, 618 operations | 0 divergence, structure valid |

220 tests, clippy and fmt clean.

## Next

The remaining half of the polymorphic layer: an admin table and detail form.
The enum work above was the prerequisite — a form cannot render a choice field
without members. That target is harder to verify automatically than the three so
far, which is itself the thing to design for rather than skip.

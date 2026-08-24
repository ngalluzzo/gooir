# 0022 — One loss type

Status: complete

## What the study found

Reading every non-kernel provider crate produced one number worth acting on:

> **842 lines of pack. Nine of them call a lifter or a lowering.**

98% ceremony, and five helper functions — `descriptor`,
`implementation_digest`, `input`, `produced`, `coverage` — defined in *both*
packs, because the second was copied from the first.

Underneath that sat the actual defect. Four types meant one thing:

```text
sql-ddl-lowering::Lossy            not Serialize
openapi-lowering::Lossy            not Serialize
prisma-schema-lowering::Lossy      not Serialize
gooir-datamodel-pack::LossyRecord  added only to map the others by hand
```

Lifts returned `Defeasible<T>`; lowerings returned a `Lowered` struct with a
private, unserialisable loss type. **Lowerings did not use the defeasible core
at all.**

## Why that was not cosmetic

A plugin answers in JSON ([0019](0019_PLUGIN_LIFECYCLE.md)). A lowering's
losses could not be serialised. So a lowering could only ever be an in-process
Rust provider: the plugin lifecycle was structurally unavailable to half the
system, and `gooir-datamodel-pack` had to hand-map every loss into a local
struct just to put it in a fact.

## The change

Every lowering now returns `Defeasible<T>` and reports `Defeat`s, exactly as
every lift does:

```text
lower_to_postgres_ddl(&DataModel) -> Defeasible<String>
lower_to_openapi(&DataModel)      -> Defeasible<Value>
lower_to_prisma(&DataModel)       -> Defeasible<String>
```

Seventeen loss sites were converted, each classified rather than blanket-mapped:

| the loss is | kind |
| --- | --- |
| the target is structurally unable to carry it | `AuthorityCannotExpress` |
| the input never established it | `LookedAndBlocked` |
| something referenced is missing | `SubjectUnresolvable` |

The hand-mapping in the pack is gone: an artifact fact now carries the
lowering's own envelope, and its coverage comes from `is_exhaustive()` rather
than a separately computed boolean.

## Two defects this surfaced in my own work

**The classifier read the wrong argument.** My first pass keyed the defeat kind
off `sink.push`'s *first* argument — the subject — instead of the reason. Every
OpenAPI loss came out `LookedAndBlocked`, so the report said *"JSON Schema has
no notion of a primary key"* was something the lowering had looked at and
failed to establish, when it is the target being structurally incapable. Four
kinds corrected.

**Unwrapping the envelope broke the artifact.** With payloads now enveloped,
`gooir derive postgres_ddl` printed the DDL as a JSON string with escaped
newlines — the exact defect [0018](0018_ONE_ENTRY_POINT.md) fixed, reintroduced
one layer up. The CLI now understands the envelope generally: it prints the
value, then what the target could not carry.

```text
4 thing(s) the target could not carry:
  [authority_cannot_express] identity: JSON Schema has no notion of a primary key
  [authority_cannot_express] uniqueness: JSON Schema has no notion of a unique constraint
  [authority_cannot_express] relations: a relation is carried only as its foreign-key property
  [authority_cannot_express] defaults: the origin of a default has no representation
```

That reads better than the count it replaced, and it is derived rather than
written down.

## What this unblocks

A lowering's whole result is now serialisable, so **a lowering can be a plugin**
— written in any language, over `org.gooi.plugin/v1`. Nothing about the
protocol needed to change; the obstacle was entirely on this side.

## Deliberately not done

Two inconsistencies remain, named so they are decisions:

- `lift_prisma_schema` is infallible while `lift_catalog` and `lift_openapi`
  return `Result<_, String>`. Unparseable input is arguably a
  `SubjectUnresolvable` defeat over an empty value, which composes where an
  `Err` dead-ends a plan. That is a judgement call, not a measurement, and it
  is a separate change.
- Fact payloads use two conventions: enveloped (`Defeasible<T>`, now including
  every artifact) and bare (`WebSurface`, in the Fleetd chain). Unifying that
  would change fact digests and so the checked-in cross-repository fixtures,
  which [0021](0021_SUITE_ON_REQUEST_AND_OPAQUE_OUTCOMES.md) already deferred
  for cause.

## State

305 tests, clippy and fmt clean. Loss types: 4 -> 0. Pack lines: 842 -> 795,
with the remaining ceremony now the target of the manifest and SDK work rather
than something to hand-write.

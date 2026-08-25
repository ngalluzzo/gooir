# 0030 — An answer at the door

Status: complete

## The defect

GOOIR had a front door and no shape for what comes back through it.

`gooir derive` computed five distinct typed outcomes and destroyed all of them:

```rust
.map_err(|e| e.to_string())?     // five times in one file
```

`PlanError::Unreachable`, ten `ExecutionError` variants, `Vec<CapabilityNeed>`,
and `ExecutionReport` all arrived typed and left as strings printed to a
terminal. Five subcommands, five hand-written printers, no shared shape. A
library caller, an agent seat, or Fleetd would each have had to invent one.

Nothing here is new information. This is a name for what was already computed.

## The layer this sits in

Fleetd already publishes `work.capability.attempt/v2`, which owns the envelope:
status, correlation, causation, stop reason, captured assistant messages,
usage, session persistence. Its `structured_result` vocabulary answers a
transport question — could a result be captured from an agent's messages at
all — and its contract describes where the value came from, never what it
means.

The semantic payload sits in `structured_result.value`, and today that value is
`{"request_id": "sha256:..."}`. The wire carries an identifier where an answer
belongs.

So the split was already drawn, in `CapabilityRequestBody`'s own doc comment:

> Authority, ownership, deadlines, and settlement belong to the orchestrator
> that durably consumes this request.

An answer is what goes inside `structured_result.value`, and it must carry
nothing the envelope already owns.

## The change

```rust
pub struct DerivationRequest { pub target: FactType, pub inputs: Vec<FactInstance> }

pub enum Answer {
    Produced(Box<ExecutionReport>),
    Blocked(DerivationPlan),
    Unreachable(PlanError),
    Refused(RequestRefusal),
    Failed(ExecutionError),
}

pub fn answer(registry: &CapabilityRegistry, request: &DerivationRequest) -> Answer
```

`DerivationRequest` is exactly the arguments `plan` and `execute` already take.
It names a `FactType` and nothing else — no target kind, no host, no frontend
selector. GOOIR does not need to know what end the caller is targeting, and now
that is a property of the type rather than a sentence in a decision record.

**`answer` returns no `Result`.** A `Result` at the door would sort outcomes
into answers and errors, when the premise is that "I cannot" is an answer that
names a remedy. This is the same discipline as coverage being derived rather
than declared.

Five variants exist because they imply five different next actions:

| answer | remedy |
| --- | --- |
| `Produced` | use the fact; read its coverage |
| `Blocked` | assign the open needs — the one answer that leaves the building |
| `Unreachable` | declare a capability, not a provider |
| `Refused` | fix the request |
| `Failed` | fix or replace the provider that failed |

`Blocked` and `Unreachable` look alike and are opposites: one is assignable
work, the other means the graph cannot express the question. A test holds all
five remedy strings distinct, so a variant that stopped earning its place would
fail rather than linger.

`Answer::needs()` reads from the plan instead of copying the list beside it.
Two lists of the same needs would be two authorities on one meaning.

## Verifying the instrument

Six perturbations, each scoped to `answer` alone so that `execute`'s own
independent guard could not be mistaken for this one:

| perturbation | caught |
| --- | --- |
| drop the `is_executable` guard | yes |
| never report `Blocked` | yes |
| always report `Blocked` | yes |
| stop refusing duplicate inputs | yes |
| two variants share a remedy | yes |
| the answer restates orchestration state | yes |

**The first attempt found two of its own tests were vacuous.** Both named the
right property and asserted the wrong thing:

- *a fact is never reported produced when the route had open needs* asserted
  `!matches!(given, Produced)`. `Failed` also satisfies that, and `Failed` is
  the wrong answer here — it sends the caller to fix a provider that was never
  installed. Now asserts the variant.
- *work is never reported assignable when the fact was derivable* asserted
  `needs().is_empty()`. An executable plan has no needs **by construction**, so
  the assertion held whatever variant came back. It could not fail. Now asserts
  the variant.

Neither test fired on any perturbation until it was fixed. A first pass at the
perturbations was also unscoped — the replaced string occurs in `execute` too —
which made two results unattributable until they were narrowed.

The orchestrator-boundary guard walks the serialized answer and rejects any of
nine envelope-owned keys, skipping `payload` subtrees: what a fact says is the
provider's business, not the door's.

## Deliberately not done

**`plan` was not collapsed onto `answer`, reversing what this change set out to
do.** The plan was to make `gooir plan` the same call with inputs unbound. On
contact with the code that is wrong: `plan` routes from fact *types* — the
graph's roots — while a request carries fact *instances*. Planning from types
is a query about the graph, which is what `doctor` is. The boundary is real:
`doctor` and `plan` report on the registry; `answer` responds to a request.

Also not done: no transport, no orchestration fields, and no field that cannot
be traced to a type that already existed.

`--json` still prints the exact payload for a produced fact, as
[0022](0022_ONE_LOSS_TYPE.md) established. For the four answers that have no
payload it prints the answer itself, which is the document that rides a
request.

## State

29 tests in `gooir-capability`, clippy and fmt clean, `derive` output unchanged
byte-for-byte for produced and blocked facts, exit code 3 preserved for blocked.

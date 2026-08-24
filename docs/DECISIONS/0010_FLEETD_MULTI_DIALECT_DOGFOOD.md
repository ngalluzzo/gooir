# 0010 — Fleetd multi-dialect dogfood

Status: first target-IR probe complete; runnable target generation not started

## Question

Can GOOIR derive one operator interaction from Fleetd itself without putting
workflow or UI concepts into the neutral data-model waist, and can two targets
preserve the same meaning?

The probe is intentionally narrow: inspect unresolved blocked deliveries and
choose `requeue` or `abandon` for one exact block.

## Source authority

The live probe was run against Fleetd revision
`98bb6c70c0be29727b177326b5eb2644c2cc0e62`.

Four source artifacts establish different facts:

| Artifact | What it may establish |
| --- | --- |
| `openapi/fleetd-v1.json` | public collection and resolution operations, record shape, selector, wire alternatives |
| `src/api.rs` | the operator guards actually called by both handlers |
| `src/model.rs` | the Rust resolution alternatives and their wire names |
| `src/delivery.rs` | the delivery-state effect executed by each resolution arm |

The checker resolves `HEAD`, rejects modifications to any of these four files,
and records a SHA-256 digest for each input. The native lift becomes partial if
an operation, guard, enum mapping, selector, match arm, or exact state effect
cannot be established.

## Shape

```text
generated Fleetd OpenAPI ──> openapi-lifter ──> DataModel
          |                                      |
Fleetd Rust API/model/delivery ─> native lift    |
          |                         |             |
          └────────────────────> FleetdControl   |
                                      \           /
                                   interaction plan
                                     /          \
                                web target   terminal target
```

`semantics-fleetd-control-v0` is deliberately product-specific. It knows a
Fleetd blocked-delivery review, operator authority, named resolutions, and
their observable delivery outcomes. It knows no HTTP paths, Rust symbols, SQL,
pages, components, buttons, or terminal keys.

The target-independent interaction plan composes that control meaning with the
`BlockedDelivery` shape from `semantics-data-model-v1`. It checks that the
exact selector and every displayed field exist before either target may lower.

## Result

The live lift was exhaustive for the named mechanism and produced no control
or interaction defeats:

```text
record       BlockedDelivery
selector     block_id
authority    operator
fields       block_id, agent_id, message, attempt, reason, blocked_at_ms
requeue      delivery becomes pending
abandon      delivery becomes dead
```

The web target chose table columns and submit buttons. The terminal target
chose list columns and numbered actions. Their normalized semantic
fingerprints are equal.

This is the first concrete multi-dialect, multi-hop proof:

```text
OpenAPI data + Fleetd control -> interaction intent -> web | terminal
```

It is not `Fleetd -> DataModel -> UI`; control meaning never passes through the
data waist.

## Vocabulary earned by Fleetd

The probe has earned these product-specific concepts:

- a review record and exact selector;
- fields that must be observable before deciding;
- an authority required to inspect and act;
- a closed set of named decisions;
- an observable outcome for each decision.

It has **not** earned a generic `UI`, `Workflow`, or `Authority` dialect. The
interaction plan remains a probe until another product and two runnable target
implementations demonstrate which parts recur.

## Dogfood defects found

Fleetd returns some collections as direct JSON arrays. The existing OpenAPI
lifter recognized only named envelopes with a `data` array. The lifter now
supports both authority-equivalent forms, and Fleetd's generated document lifts
`Agent`, `Channel`, `BlockedDelivery`, and `Invocation` resource shapes.

The probe also exposed why defeats must be scoped to the consumer's question.
OpenAPI cannot establish storage identity, uniqueness, defaults, or relations,
but those unknowns do not prevent an interaction from displaying fields whose
presence the document positively establishes. Relevant record or field defeats
still block both lowerings.

## Limitations and next falsification

- The web and terminal outputs are target IRs, not runnable clients.
- Resolution replay/idempotency, confirmation intent, notes, and retry-delay
  semantics are not represented yet.
- The Rust-to-effect lift recognizes the direct `input.resolution` match and
  exact `pending`/`dead` SQL assignments used by this revision. A refactor it
  cannot follow degrades to partial.
- OpenAPI and Rust are two representations of one implementation, not two
  independent products.

Next, lower both target IRs into runnable surfaces against Fleetd's public API.
If either target requires meaning absent from the interaction plan, add it first
to the Fleetd product contract and re-lift; do not patch it into one generator.
Only after the same concept survives both targets and a second product should
it be proposed as a reusable Interaction contract.

# 0020 — Target neutrality probe

Status: findings — no code changed

## Question

`generate_runnable_web_surface` is structurally a lowering — one input fact,
one output fact — but is declared product-specific in all three of its
identities. [0019](0019_PLUGIN_LIFECYCLE.md) left it as the last open need.

Can `ReviewAuthority` and `DeliveryOutcome` be made opaque without losing what
the interaction plan and the conformance suite rely on?

Paper only, before touching anything.

## F1 — Nothing consumes a named variant

Both enums have the same shape: named product values plus `Unknown`.

```rust
ReviewAuthority { Operator, Unknown }
DeliveryOutcome { Pending, Dead, Unknown }
```

Cross-referencing every use against each file's `mod tests` boundary, the named
variants appear in **exactly three lines of non-test code**, and all three are
in the *producer*:

```text
fleetd-control-projection:20   ReviewAuthority::Operator
fleetd-control-projection:37   Some("pending") => DeliveryOutcome::Pending
fleetd-control-projection:38   Some("dead")    => DeliveryOutcome::Dead
```

Every other occurrence is a test fixture. **No consumer branches on `Operator`,
`Pending`, or `Dead`.** There is no exhaustive `match` anywhere that
generalising would break.

## F2 — Every consuming decision is the same decision

Two sites consume these types, both in `fleetd-interaction-plan`:

```rust
if plan.value.authority == ReviewAuthority::Unknown { defeat(...) }
.filter(|choice| choice.outcome == DeliveryOutcome::Unknown)
```

Both ask *"was this established?"* — and `Unknown` is not a Fleetd concept. It
is the defeasible not-established state that `lift-defeasible` already models
for every other attribute in the system.

## F3 — The contract already disagrees with itself

`BlockedDeliveryReview` represents "not established" two different ways in one
struct:

```rust
pub record_type: Option<String>,      // None means not established
pub selector_field: Option<String>,   // None means not established
pub authority: ReviewAuthority,       // an Unknown variant
pub resolutions: Vec<ResolutionChoice>, // outcome has an Unknown variant
```

The generalisation proposed here is simply what two of these four fields
already do.

## F4 — The one real cost, and where it should go instead

Lines 37–38 are a **closed allowlist**: only `"pending"` and `"dead"` are
accepted from the lift, and anything else degrades to `Unknown`. That vetting
is genuine and must not be lost.

It should move rather than disappear — from the *type* to the *projection*, as
a defeat. That is strictly better, because a defeat can name what it saw:

```text
now:      outcome degrades to Unknown         (the observed name is discarded)
instead:  LookedAndBlocked — "resolution `quarantined` is
          not in this projection's vetted outcome set"
```

The type stops being the vetting mechanism; the product projection keeps doing
the vetting, and reports it usefully.

## F5 — The product-specific surface is much smaller than the naming suggests

With the two enums opaque, `WebSurface` has nothing product-typed left, and
`BlockedDeliveryReview` is a generic "review surface over a record with named
resolutions". Of the six crates in the Fleetd chain:

| crate | genuinely product-specific? |
| --- | --- |
| `fleetd-control-lifter` | **yes** — reads Fleetd's Rust |
| `semantics-fleetd-control-v0` | no — generic in shape |
| `fleetd-control-projection` | **yes** — maps Fleetd's lift, owns the vetted set |
| `fleetd-interaction-plan` | no — its checks are all "was this established?" |
| `fleetd-surface-lowering` | no — a surface description |
| `fleetd-capability-pack` | **yes** — registrations and the suite |

Three of six are neutral in substance and product-named by habit. The
conformance suite is irreducibly product-specific — it links against `fleetd`,
opens `fleetd.db`, and drives the real server — and that is correct.

## F6 — The actual blocker is not the enums

Even with both enums opaque, a neutral capability cannot be declared, because
`CapabilitySpec.conformance_suite` is a single `String` and
`CapabilityRequest::bind` copies it straight from the need:

```rust
conformance_suite: need.conformance_suite.clone(),
```

One capability, one suite. Since only a Fleetd-linked suite can verify a
runnable Fleetd surface, that specificity propagates up into the capability
identity and outward into both fact identities. **Three neutral things wear
product names because one genuinely product-specific thing has nowhere else to
live.**

`CapabilityRequestBody` already carries `conformance_suite` as its own field,
so the machinery is nearly there: a spec could name the general obligation
while a request binds the concrete suite. The safety control already exists —
`verify_and_admit` requires the verifier's suite to match the *request's*, and
[0017](0017_ONE_ADMISSION_RULE.md)'s `AdmissionPolicy` decides which
(attester, suite) pairs this host accepts, so binding a weaker suite still
cannot get facts admitted.

## Verdict

**Yes — both can be opaque, and the reporting improves.** The enums are not the
obstacle they appear to be: they are consumed only as "established or not", and
their vetting belongs in the projection.

The obstacle is the single-suite field. Generalising the enums without moving
the suite would produce neutral *shapes* that still cannot be given neutral
*identities*.

## Committed predictions

If this is done, in order:

| step | prediction |
| --- | --- |
| `Established<T>` in `lift-defeasible`; both enums replaced | ~120 lines changed, no test deleted, projection gains one defeat naming the unvetted value |
| suite moves from spec to request | `CapabilitySpec.conformance_suite` becomes the default obligation; `bind` accepts an override; `verify_and_admit` unchanged |
| target IR and artifact facts renamed neutral | `org.gooi.target.web/surface@0.1.0`, `org.gooi.artifact.web/runnable_surface@0.1.0` |
| capability renamed neutral | `org.gooi.capability/generate_runnable_web_surface@0.1.0` |
| `gooir doctor` | duplicate declarations stay 0; one provider becomes reusable across products |

If step 2 turns out to need changes in `verify_and_admit`, the seam is in the
wrong place and this should stop.

## Not checked

Whether the web/terminal semantic-fingerprint equality survives — it compares
`authority` by value, so an opaque type should be fine, but that is reasoning
rather than evidence. No code was changed and nothing was measured by running.

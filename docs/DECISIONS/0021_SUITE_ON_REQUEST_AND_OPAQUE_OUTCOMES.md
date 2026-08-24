# 0021 — The suite belongs to the request; outcomes are names

Status: steps 1 and 2 complete; steps 3 and 4 deferred with cause

Executes the path from [0020](0020_TARGET_NEUTRALITY_PROBE.md).

## Step 1 — the suite moves to the request

The probe carried a stop condition: *if moving the suite requires changing
`verify_and_admit`, the seam is in the wrong place and this should stop.*

It did not. Nothing compared a request's suite to the spec's; the only
comparison is verifier-against-request, and it is untouched. The spec's suite
had never been enforced — only copied into the need and validated non-empty.

`CapabilitySpec.conformance_suite` is therefore renamed
**`default_conformance_suite`**, because it is an obligation a capability
declares, not a requirement it enforces. Leaving the old name would have
invited exactly the misreading that the rename prevents.

`CapabilityRequest::bind_with_suite` names the suite that will actually run;
`bind` keeps the declared default. This is what lets a capability be neutral
while its verification is not: only a suite that knows a particular system can
check that a generated surface really serves it.

It is not a hole, and two tests state why. An attester admitted for one suite
cannot verify a request naming another — `verify_and_admit` still refuses on
`SuiteMismatch` — and admitted facts still require the host to have admitted an
attester *for the suite the request names*, which is
[0017](0017_ONE_ADMISSION_RULE.md)'s `AdmissionPolicy` doing its job.

## Step 2 — the two enums become names

`ReviewAuthority { Operator, Unknown }` and
`DeliveryOutcome { Pending, Dead, Unknown }` are now `Option<String>`.

The probe predicted an `Established<T>` type in `lift-defeasible`. **That
prediction was wrong, and the probe's own F3 says why**: `BlockedDeliveryReview`
already used `Option<String>` for `record_type` and `selector_field`. Adding a
new type would have given one struct three ways to say "not established"
instead of reducing it to one. The smaller change was the right one, and a test
now asserts the single convention: nothing serialises the word `unknown`.

The vetting is preserved and now lives where the product knowledge is:

```rust
// fleetd-control-projection
pub const VETTED_OUTCOMES: [&str; 2] = ["pending", "dead"];
```

A correction to the probe: F4 claimed moving the allowlist would *gain* naming
of the unvetted value. The projection already did that. What was genuinely
silent was the `None` case — a lift that established no resulting state
produced an anonymous unknown with no defeat. That now defeats too.

## Verified, not assumed

The checked-in cross-repository fixtures embed a web-surface payload, and their
identities are digests over it. They contain only established values —
`"operator"`, `"pending"`, `"dead"` — so `Option<String>` leaves the wire
byte-identical. Checked rather than reasoned:

```text
cargo test -p gooir-capability --test fleetd_candidate   1 passed
git status crates/gooir-capability/tests/fixtures/       unchanged
```

## Steps 3 and 4 deferred, with cause

Renaming the target-IR and artifact facts to `org.gooi.target.web/surface` and
`org.gooi.artifact.web/runnable_surface`, and the capability to
`org.gooi.capability/generate_runnable_web_surface`, is now *unblocked in
principle*: nothing product-typed remains in `WebSurface`.

It is not done, because a fact identity is part of a request's digest, so
renaming invalidates the checked-in cross-repository fixture pair. Regenerating
them is not mechanical:

- Fleetd's HEAD has moved to `a5e3181`, so a regenerated request would carry a
  different revision. My rename and a revision bump would land as one
  indistinguishable change.
- The candidate fixture is a **deliberately-crafted negative** — it fails
  conformance on purpose, to prove that successful transport cannot masquerade
  as a runnable artifact. That is authored evidence, not a build output.

Rewriting another track's carefully-built negative fixture as a side effect of
a rename is not a refactor, and hand-editing its digests to match would be
manufacturing evidence. It is a decision to take deliberately, at a chosen
Fleetd revision.

**What unblocks it:** a decision on which Fleetd revision to re-pin, and a
regenerated pair produced by the projector and conformance commands rather than
edited — with the negative fixture re-crafted knowingly.

## A note on neutral fact types

One consequence worth stating before anyone takes step 3. A single
`org.gooi.target.web/surface` means two products' surfaces share a fact type,
so `gooir doctor` will report multiple routes to it and the planner will pick
by score.

That is not a fault, and there is precedent: `data_model` already has two
routes — authored and lifted — and planning self-disambiguates, because a route
is reachable only from the roots actually supplied. Naming it here so it is an
expected reading of the report rather than a surprise.

## State

305 tests, clippy and fmt clean. Fixtures untouched.

# Slice 1 demo — understand one real behavior

## User story

> As a technical founder with an existing application, I want GOOIR to show
> what one important behavior actually does across my codebase, so I can adopt
> it without rewriting the product first.

## Run the product view

From a clean GOOIR checkout:

```bash
cargo run -q -p buzz-surface-check
```

The command analyzes reviewed, source-derived lift documents for Buzz desktop
`v0.5.18` at exact revision
`39f8b46935736334cdd7045a4e4b5d7eb1a33888`. It shows:

- one agent-job event path in product language: declared → produced → accepted
  → consumed;
- the production relay rejection with exact protocol and relay source
  locations;
- the exhaustively established missing CLI surface and its searched roots;
- six SDK and one runtime requirement kept unknown because those coverage
  lifters do not exist yet; and
- a summary of seven actionable gaps and seven honest unknowns.

For the complete deterministic report:

```bash
cargo run -q -p buzz-surface-check -- --details
cargo run -q -p buzz-surface-check -- --json
```

The details view exposes exact revisions, byte spans, repeated kinds, and the
CLI coverage witness. The JSON view preserves the analyzer's complete data
contract.

## Show the trust boundary

Copy the reviewed native inputs, change one byte without changing its parsed
meaning, and run the same product view against that directory:

```bash
slice_demo_dir="$(mktemp -d)"
cp fixtures/buzz/desktop-v0.5.18/*.lift.json "$slice_demo_dir/"
printf '\n' >> "$slice_demo_dir/job-protocol.lift.json"
cargo run -q -p buzz-surface-check -- --input-dir "$slice_demo_dir"
```

The command must fail before analysis with a `protocol native lift document
mismatch`. Exact reviewed bytes are admitted; a mutated document cannot retain
their trust.

## Value and product gate

Value earned now: GOOIR is an observable tool that imports facts from a real
application, exposes an actionable cross-layer gap, cites its evidence, and
states what it cannot yet know.

The go/no-go question is:

> Can a technical founder understand and act on this result in five minutes
> without learning contracts, evidence admission, or crate topology — and was
> the finding derived rather than encoded?

# Slice 1 demo — understand one real behavior

> Historical record: this demo exercised the retired parallel operation/claim
> IR. Its `buzz-surface-check` package is not part of the recovered workspace,
> so the invocations below are recorded behavior rather than runnable commands.

## User story

> As a technical founder with an existing application, I want GOOIR to show
> what one important behavior actually does across my codebase, so I can adopt
> it without rewriting the product first.

## Historical product view

The retired command was `cargo run -q -p buzz-surface-check`.

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

Its complete deterministic report used the historical `--details` and `--json`
options.

The details view exposes exact revisions, byte spans, repeated kinds, and the
CLI coverage witness. The JSON view preserves the analyzer's complete data
contract.

## Show the trust boundary

Copy the reviewed native inputs, change one byte without changing its parsed
meaning, and run the same product view against that directory:

The historical falsifier copied the reviewed native inputs, appended one byte
to `job-protocol.lift.json`, and passed that directory with `--input-dir`.

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

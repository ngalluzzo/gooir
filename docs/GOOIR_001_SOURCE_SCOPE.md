# GOOIR-001 source scope

GOOIR-001 uses two separate authorities:

- installed Buzz application `0.5.18`, CLI SHA-256 `9c7457b193d386a8fad2d903d4321c4bbcaa2edb4722031a2c8d5f9790e02f54`;
- public Buzz source tag `desktop-v0.5.18`, commit `39f8b46935736334cdd7045a4e4b5d7eb1a33888`.

The matching versions justify the selected source scope, but no build attestation links that installed binary to the source commit. Claims from the two authorities remain separate.

## Staged source finding

The pinned source declares and registers Nostr job kinds `43001–43006`. Desktop and mobile query and render all six; the database activity feed queries request, progress, and result; and the desktop E2E bridge fabricates progress events in a mock role.

The production relay's closed `required_scope_for_kind` match has no job-kind arm. Its fallback rejects unknown event kinds, and client ingest invokes the check before persistence. The staged relation snapshot therefore contains six provenance-bearing `Rejects` relations for the production ingest surface.

Scoped searches also found no SDK job builder, CLI job command, or runtime dispatcher in the selected roots. Those are not universal absence claims: until the corresponding lifters emit exhaustive compatible coverage witnesses, the generic analyzer must return unknown.

## Checked-in staging fixture

`fixtures/buzz/desktop-v0.5.18/job-surface.json` groups the expected contract relations with:

- immutable repository revision and Cargo lock digest;
- explicit unresolved feature/target selection;
- production/test root separation;
- artifact SHA-256 plus byte and line ranges;
- declared, statically inferred, and mock evidence categories;
- exhaustive coverage only for the relay's closed ingest allowlist;
- best-effort coverage for the provisional SDK, CLI, and runtime searches.

`buzz-surface-profile` expands the grouped rows and declares Buzz-specific requirements. `semantics-software-surface-v1` owns only the generic relation, artifact-role, profile, and coverage vocabulary. The eventual analyzer must depend on that contract package, never on the Buzz profile or fixture crate.

The fixture is an oracle for staged development, not a source authority. GOOIR-001 closes only when independently versioned lifters reproduce the relations from the pinned source and the evidence/trust prerequisite has landed.

## First native lifter

`buzz-protocol-lifter` uses `syn` rather than a handwritten Rust parser. It extracts direct `KIND_JOB_*: u32` declarations, resolves their membership in the direct `ALL_KINDS` registry, computes source digests and byte spans, and marks coverage partial if any top-level macro invocation could hide additional declarations.

The pinned run is checked in as `fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json`. It was produced with:

```text
cargo run -q -p buzz-protocol-lifter -- \
  <buzz-root>/crates/buzz-core/src/kind.rs \
  crates/buzz-core/src/kind.rs \
  github:block/buzz \
  39f8b46935736334cdd7045a4e4b5d7eb1a33888
```

The native output remains separate from software-surface contracts. `buzz-surface-projection` maps its declarations and registry membership into `Declares` and `Registers` claims without teaching the lifter or kernel about analysis requirements.

## Closed relay-ingest lifter

`buzz-relay-lifter` consumes the pinned `buzz-protocol-lifter` output plus the
exact `kind.rs` and `ingest.rs` bytes. It checks that the kind-source digest
matches the upstream lift, resolves direct constants and named `matches!`
predicates, evaluates every preceding match arm for each lifted job-kind value,
and proves a direct top-level `required_scope_for_kind` match gate inside
`ingest_event_inner`. Exhaustive coverage requires that the gate receive the
latest incoming-event-derived kind binding, return an error through every
`Err` arm including an unguarded catch-all, and follow only the explicitly
modeled validation/read calls used by the pinned handler. Wrong or shadowed
arguments, ignored results, conditional or dead calls, non-terminating
rejection arms, mutation, divergence, and unrecognized pre-gate calls all
degrade the affected decisions to unknown.

The pinned run is checked in as
`fixtures/buzz/desktop-v0.5.18/job-relay.lift.json`. It was produced with:

```text
cargo run -q -p buzz-relay-lifter -- \
  <buzz-root>/crates/buzz-relay/src/handlers/ingest.rs \
  <buzz-root>/crates/buzz-core/src/kind.rs \
  fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json \
  crates/buzz-relay/src/handlers/ingest.rs \
  github:block/buzz \
  39f8b46935736334cdd7045a4e4b5d7eb1a33888
```

All six values reach the wildcard error `restricted: unknown event kind`; the
native witness records the function at lines 342–455, fallback at line 453,
and production gate call at line 2157. An unsupported constant or guard makes
the affected decisions unknown and the coverage partial, so textual resemblance
cannot be promoted into an exhaustive rejection.

## Closed CLI command-tree lifter

`buzz-cli-lifter` parses the Clap-derived surface beginning at
`Cli.command: Cmd`, verifies the `Parser`/`Subcommand` wiring, and recursively
follows direct `#[command(subcommand)]` enum edges. It preserves explicit names,
aliases, exact spans, and every group/leaf path. Implicit names and enum-level
`rename_all` use Clap's `heck` casing rules rather than a local approximation.
`#[command(skip)]` variants are omitted. Conditional variants, missing
referenced enums, flattening, external subcommands, unparsed alias shapes, or
any other unhandled variant-level invocation attribute make coverage partial;
partial trees cannot project positive command-surface relations.

The pinned run is checked in as
`fixtures/buzz/desktop-v0.5.18/job-cli.lift.json`. It was produced with:

```text
cargo run -q -p buzz-cli-lifter -- \
  <buzz-root>/crates/buzz-cli/src/lib.rs \
  crates/buzz-cli/src/lib.rs \
  github:block/buzz \
  39f8b46935736334cdd7045a4e4b5d7eb1a33888
```

The source-derived tree contains 138 command groups/leaves and no `job`/`jobs`
path or alias, with exhaustive coverage of this explicit Clap mechanism. This
closes only the CLI command-surface mechanism; it does not claim arbitrary Rust
code elsewhere cannot construct or publish a job event.

## Contract projection, admission, and analysis

`buzz-surface-projection` consumes only the three checked native lift documents.
Before deserialization or projection it hashes the raw bytes and checks their
exact reviewed document digests plus the Buzz
authority, revision, artifact names, source digests, and the relay lift's
upstream protocol binding. It emits generic
relation and coverage-witness claims with exact source spans. Those claims carry
a local claim-binding conformance reference, but remain untrusted until
`admit_pinned_surface` first requires exact equality with the projection of the
embedded reviewed lift documents, then revalidates the pinned authority and
exact result digest and admits each operation-plus-claim tuple through
`EvidenceTrustPolicy`.

`surface-completeness-analysis` has no Buzz dependency. Given the admitted
claims and `buzz-surface-profile`, the pinned result is:

- six `surface.contradicted` errors for relay acceptance of kinds `43001–43006`,
  each citing the kind declaration, closed allowlist, fallback, and production
  gate;
- one `surface.missing_relation` error for the absent CLI job surface, backed by
  exhaustive `crates/buzz-cli/src` command-tree coverage;
- seven `surface.coverage_incomplete` unknowns for SDK construction and runtime
  dispatch, whose native coverage lifters have not landed.

The deterministic report is checked in at
`fixtures/buzz/desktop-v0.5.18/job-surface.analysis.json` and can be reproduced
with:

```text
cargo run -q -p buzz-surface-check -- \
  fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json \
  fixtures/buzz/desktop-v0.5.18/job-relay.lift.json \
  fixtures/buzz/desktop-v0.5.18/job-cli.lift.json
```

This is a checked local admission policy, not a claim of cryptographic proof.
The staging snapshot remains outside the trusted execution path.

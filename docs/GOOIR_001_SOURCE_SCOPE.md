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

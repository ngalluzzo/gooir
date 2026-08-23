# GOOIR

GOOIR is a lift-first semantic compiler workbench for existing software.

It imports facts from authoritative tools and formats, preserves their distinctions and unknown regions, links those facts through separately versioned semantic contracts, and runs analyses that no individual tool can perform alone. Generation and lowering are later projections, not prerequisites for value.

```text
existing semantic artifacts
          ↓ lift
native, lossless dialects
          ↓ explicit bridge
versioned semantic contracts
          ↓ link + analyze
scoped, provenance-bearing findings
          ↓ optional lowering
existing generators and runtimes
```

The microkernel does not know `page`, `entity`, `retry`, React, Postgres, or Buzz event kinds. It knows only structural IR, exact contract identities, evidence/provenance transport, opaque extension data, pass mechanics, legality, artifacts, and diagnostics.

## Current milestone

`GOOIR-000` is merged and proves the architectural boundary:

- unknown dialect data round-trips without a plugin;
- analyzers consume exact semantic contracts rather than dialect names;
- unfamiliar dialects with equivalent projections produce equivalent normalized results;
- unverified or unknown claims never become safety facts;
- meaning-changing contract versions require an explicit bridge.
- partial legality reports the exact pinned/unknown portability frontier.

`GOOIR-001` is now lifting Buzz's pinned event surface. Its first staged input preserves separate production, test, mock, and documentation roles; exact source authority and byte-range provenance; and coverage witnesses that prevent incomplete searches from becoming universal negative claims. The staging snapshot is not trusted lifter output and cannot by itself close the milestone.

See the [project brief](docs/PROJECT_BRIEF.md), [architecture](docs/ARCHITECTURE.md), and [milestones](docs/MILESTONES.md).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

# 0001 — Bootstrap boundaries

Status: accepted for GOOIR-000

## Decisions

- Implement the first kernel slice in Rust 2024. The portable boundary is serialized IR and exact semantic contracts, not a Rust dynamic-library ABI.
- Define lossless native round-trip as structural equivalence of all authoritative information plus opaque residue. Byte-for-byte formatting preservation is not required. Bridges/projections into shared contracts may be explicitly partial or lossy.
- Represent contract identity as exact package, name, and version. Never infer semantic compatibility from a version range.
- Accept a claim as trusted in the first analysis only when it carries verified status plus conformance-suite evidence. Declared, inferred, observed, missing, conflicting, or invalidly projected claims remain unknown for safety analysis.
- Treat native-to-contract projections separately from contract-version bridges. An analyzer consumes resolved claims and cannot depend on the native dialect.
- Keep plugin loading in-process for GOOIR-000 tests. Dynamic loading, registry governance, and sandboxing remain undecided.

## Rationale

These are the smallest choices that make the architecture falsifiable. They do not claim permanent language, trust, or plugin-runtime commitments.

## Follow-ups

- Make closed-world analysis scope first-class before GOOIR-001.
- Add an explicit portability-frontier legality test before closing GOOIR-000.
- Revisit trust composition only with concrete conflicting/observed claim cases.


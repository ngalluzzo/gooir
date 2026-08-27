# GOOIR repository instructions

Read `README.md`, `docs/ARCHITECTURE.md`, and `docs/MILESTONES.md` before making non-trivial changes.

- Follow `CONTRIBUTING.md`: one issue per branch, no direct pushes to `main`, every PR states its scope and acceptance criteria, and an agent other than the author must approve before merge.
- Keep `gooir-identity` and `gooir-capability` semantically agnostic. Domain concepts belong in separately versioned contract or dialect crates.
- Analyzers depend on semantic contracts, never concrete source dialects.
- Unknown, unverified, ambiguous, or incompatible claims must degrade conservatively; never infer safety from missing semantics.
- Preserve unknown operations and extension data through serialization.
- Keep findings scoped to the exact artifacts, revision, configuration, and evidence that produced them.
- Reuse authoritative external parsers, schemas, compilers, and runtimes. Do not reimplement mature semantic tools without a demonstrated gap.
- Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` before claiming a Rust change is complete.
- Every commit must use the repository-local human identity for matching `Co-authored-by` and `Signed-off-by` trailers, in that order.

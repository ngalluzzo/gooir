# 0043 — Exact capability outputs are first-class derivation goals

Status: accepted

Date: 2026-08-28

Supersedes only the value-kind-only target statements in Decisions 0034 and
0036. Their complete-selection, authority, execution, and remedy boundaries
remain in force.

## Context

External generators are ordinary capabilities and may converge on the
portable `ContentSet` artifact contract. A raw source bundle can use that same
contract. The 0.1 façade and compiler driver previously accepted only a target
`ValueKindId`.

That erased product intent. Given a `ContentSet` source plus HTTP and SQL
generators that both produce `ContentSet`, a kind query either returned the
initial bundle without running a generator or was ambiguous across unrelated
terminal capabilities. A complete `ExplicitSelection` was not a suitable
replacement: it also fixes provider offers, input bindings, attesters, and an
inventory-bound plan rather than naming only the semantic terminal.

The planning protocol already used `RouteOutputRef` for the exact coordinate
of a selected capability output.

## Decision

`DerivationGoal` accepts either:

- a `ValueKindId`, retaining discovery and compatibility behavior; or
- a `RouteOutputRef`, naming one exact capability and output port.

`SemanticPlan` retains `target_value_kind` and adds an optional
`target_output`. The optional field is omitted for value-kind plans, preserving
their serialized form and canonical identity. Exact-output plans root slicing,
availability, route construction, blockage, validation, and plan identity at
the named coordinate. An initially available value of the same kind cannot
satisfy that goal.

`UniqueOnly` remains conservative below the terminal. Naming the output does
not rank or choose dependency routes, provider offers, fact bindings, suites,
or attesters. `CompilerDriver::compile_output` exposes this behavior without a
second execution or admission protocol.

An unreachable exact output is retained and diagnosed by capability and port,
even when a sibling generator can reach the same value kind.

## Consequences

- Independent HTTP, SQL, OpenAPI, CLI, MCP, and language generators can share
  `ContentSet` without a kernel `Backend` taxonomy.
- A generic consumer can use `ContentSet` for raw source bytes and generated
  bytes without short-circuiting a requested reader/generator route.
- Product calls must name the capability output they intend to materialize;
  a value-kind query remains useful for graph discovery but is insufficient
  whenever multiple semantic terminals share a carrier.
- Old exact value-kind request JSON and plans remain decodable. Rust callers
  that constructed `DerivationRequest` fields directly must wrap the target in
  `DerivationGoal::ValueKind`; constructors and `CompilerDriver::compile`
  retain their prior signatures.
- No backend role, recipe, lens, lowering/lifting taxonomy, target-specific
  materializer, or implementation selection rule enters the kernel.

## Rejected alternatives

### Treat `ContentSet` as the generator target

The kind says what a value is, not which semantic transformation the caller
requested. It cannot distinguish two generators and may already be present as
an input.

### Use `ExplicitSelection` as the public target

That binds transient inventory and authority choices that must remain under
conservative host selection. Ambiguity answers are witnesses, not an
enumerable generator catalog.

### Add `Backend`, `GenerationRecipe`, or a lens

No additional edge kind or bidirectional law is demonstrated. Exact output
coordinates solve the observed failure using concepts already present in the
planner.

## Qualification

- A source and two independent terminal generators share one artifact kind;
  kind-only planning returns the initial value while each exact output selects
  only its own dependency closure.
- A blocked exact generator cannot fall through to an available sibling.
- Dependency-route and offer ambiguity remain refusals under an exact goal.
- Unknown capability/port coordinates, target extensions, output-port
  substitution, target-kind forgery, and exact-output unreachability fail
  closed.
- Workspace formatting, strict Clippy, and tests pass, followed by downstream
  data-model and HTTP qualification against this revision.

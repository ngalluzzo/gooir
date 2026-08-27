# Activation authority corpus

This corpus pins the smallest audited upstream runtime and conformance
documents needed to test one candidate interaction recurrence:

> A source-established binding delivers an activation to its registered
> application handler.

`authorities.lock.json` binds 17 authority snapshots and five license snapshots
to an upstream repository, full Git commit, original path, SHA-256 digest,
authority group, structural role, and preserved license. It intentionally
contains no semantic verdicts or defeats. The source and test snapshots are
byte-for-byte copies; they are evidence inputs, not vendored build
dependencies.

## Independent recurrence

React DOM and Vue runtime-dom are the independent authority groups:

- React maps native click input into its synthetic event dispatch and suppresses
  mouse listeners on disabled interactive elements.
- Vue installs, replaces, and removes DOM event invokers and supports multiple
  handlers for one activation.
Their source-projected compatible intersection is bound-activation dispatch.
Their native event types, propagation, enablement, scheduling, host rendering,
and output are not equated. Semantic observations are generated into
`observations.lift.json` by the pinned AST lifters; they are not declared here.
React's projection includes `DOMPluginEventSystem.js`, which closes the static
path from accumulated listeners to the actual `listener(event)` call.

## Same-system evidence is not convergence

Ink, shadcn, and Mantine show how real React ecosystem participants preserve
this route, but none is an independent semantic authority from React DOM:

- Ink parses terminal input, invokes active `useInput` handlers through React's
  discrete-update boundary, and suppresses hooks marked inactive. Its pinned
  `use-input.ts` imports the pinned Ink reconciler, whose source imports both
  `react-reconciler` and the React runtime; this source-derived lineage is why
  Ink shares React's runtime identity instead of adding an independent vote.

- shadcn resolves registry data and materializes source into a project. Its
  Base UI and React Aria button variants forward different upstream prop types.
- Mantine is an installed React component package. `Button` forwards remaining
  props through `UnstyledButton` toward a native button, and its tests declare
  accessibility, focus, and disabled-attribute expectations.

These documents falsify a closed GOOIR component universe. They do not add
three more votes for a shared interaction contract.

## Scope

The generated static projection earns a callable dispatch path only. Its
upstream test declarations are corroboration, not durable passed run results.
The corpus does not by itself establish a
generic Button operation, application state transition, visual equivalence,
accessibility equivalence, or a lowering between any two ecosystems. Those
claims require separately pinned evidence and conformance.

Copyright and license attribution is preserved in each ecosystem directory and
summarized in `THIRD_PARTY_NOTICES.md`.

The deterministic suite verifies all checked-in bytes:

```bash
cargo test -p interaction-activation-recurrence
```

The AST projection is regenerated and checked with:

```bash
npm ci --prefix tools/interaction-activation-lifters
npm test --prefix tools/interaction-activation-lifters
npm run check --prefix tools/interaction-activation-lifters
```

The ignored live refresh fetches each exact Git object into a temporary
repository and byte-compares it with the corpus:

```bash
cargo test -p interaction-activation-recurrence \
  refreshing_authorities_from_clean_upstream_checkouts_is_byte_identical \
  -- --ignored --nocapture
```

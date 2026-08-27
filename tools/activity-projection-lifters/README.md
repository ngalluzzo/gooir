# Activity projection source lifters

This package parses exact, revision-pinned product state and projection code
from LobeChat, LibreChat, Open WebUI, Hugging Face Chat UI, Gemini CLI, and
Codex. Each product has a source-specific static projector. Exact positive
evidence nodes are separately review-pinned so a changed source digest cannot
authorize semantics by itself. The six routes corroborate this candidate:

```text
exact opaque source scope
  + exact native selection snapshot
  -> activity entry references in emitted ordinal order
  + explicit non-boolean source extent
```

The tool does not lift a component tree, content payload, actor enum, backing
branch graph, or pending decision. Those are separate facts and capabilities.

Only the two behavioral cases produce semantic values. The branch case extracts
the exact reviewed `createMessagesList` function node from Open WebUI and
`buildSubtree` from Chat UI, transpiles them with pinned TypeScript, and executes
the same branching fixture in an isolated context. The React case admits only
the exact review-pinned Gemini CLI `useHistory` function digest, then compiles
and mounts it under React 19.2.4 in a permission-restricted, time-bounded child
process with no handwritten reducer. Its action trace establishes the settled
state vector `[20, 10, 22]`, including duplicate suppression and an allocated
id gap. Those numeric ids become projection-local keys, never durable recording
references.

Gemini's exact AppContainer, UIStateContext, App normal branch,
DefaultAppLayout, MainContent, and HistoryItemDisplay sources establish native
lineage from that state to the product's `npm:@jrichman/ink@6.6.9` consumer.
They are static evidence: the test does not execute the full application
dependency closure or claim rendered terminal equivalence.

Run:

```sh
npm ci
npm test
npm run check -- --root /absolute/path/to/gooir/fixtures/activity/projection
```

Refresh the locked upstream bytes only after intentionally updating revisions
and SHA-256 digests in `authorities.lock.json`:

```sh
npm run refresh -- --lock /absolute/path/to/gooir/fixtures/activity/projection/authorities.lock.json
```

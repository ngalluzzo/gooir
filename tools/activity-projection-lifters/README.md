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

Only the behavioral case produces semantic values. It extracts the exact
reviewed `createMessagesList` function node from Open WebUI and `buildSubtree`
from Chat UI, transpiles them with pinned TypeScript, and executes the same
branching fixture in an isolated context. Each selected result becomes a
concrete `ActivityProjection` consumed by the Rust semantic verifier. This does
not claim that either full application dependency closure ran.

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

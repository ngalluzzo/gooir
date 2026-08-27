# Interaction activation source lifters

These source-specific lifters project one narrow, falsifiable activation fact
from the pinned React DOM, Vue runtime-dom, and Ink corpus. They parse exact
upstream bytes with `@babel/parser`; they do not match source text with regular
expressions, consume semantic verdicts from the authority lock, or claim to
lift arbitrary programs.

The output is `fixtures/interaction/activation/observations.lift.json`.

## Evidence boundary

Every positive observation requires all of the following AST structure:

1. an application handler binding;
2. a native stimulus in the pinned upstream test or fixture;
3. a callable runtime path that reaches the registered handler parameter; and
4. a positive upstream assertion corroborating the path.

An upstream test declaration is not represented as a passed test run. Each
observation therefore carries typed, non-blocking limits for the unexecuted
durable suite and the incomplete imported dependency closure. A missing parse,
binding, stimulus, assertion, runtime invocation, source, or digest aborts the
lift and emits no positive observation.

The source-specific paths are:

- React: JSX `onClick={onClick}` → mounted `element.click()` →
  `SimpleEventPlugin` listener accumulation and dispatch queue →
  `DOMPluginEventSystem.executeDispatch` calling `listener(event)` → Jest call
  count. Disabled-interactive suppression remains native evidence.
- Vue: `patchProp(el, 'onClick', null, fn)` → DOM `dispatchEvent` →
  `createInvoker` and native listener installation →
  `callWithAsyncErrorHandling(value, ..., [e])` → Vitest call count. Handler
  removal remains native evidence.
- Ink: active `useInput(handleInput)` → PTY input → internal `input` subscription
  → `inputHandler(input, key)` → fixture state/render effect → AVA output
  assertion. `isActive: false` remains native suppression evidence. The
  `use-input` import of Ink's reconciler and that reconciler's imports of
  `react-reconciler` and `react` produce lineage `react/renderer`; Ink is not a
  third independent runtime vote.

Every evidence node records its upstream authority ID, Babel node type,
line/column location, Babel's UTF-16 start/end offsets, and byte offsets derived
from the exact UTF-8 source. Every source reference carries the original path,
full Git commit, and SHA-256 digest from the provenance-only authority lock.
The parser provenance maps every parsed authority to a grammar variant. The
React conformance file uses Flow+JSX; the pinned React runtime files use
TypeScript+JSX because that revision contains TypeScript-style `as` assertions
despite retaining `@flow` headers. No compatibility rewrite is applied.

## Reproduce

From the repository root:

```bash
npm ci --prefix tools/interaction-activation-lifters
npm test --prefix tools/interaction-activation-lifters
npm run lift --prefix tools/interaction-activation-lifters
npm run check --prefix tools/interaction-activation-lifters
```

`lift` writes the deterministic projection. `check` reconstructs it and fails
if source bytes, lock metadata, lifter code, dependency lock, parser setup, AST
evidence, or generated output differ.

## Generator identity

The output binds the exact parser package/version/configuration, the exact
`package-lock.json` bytes, and an aggregate implementation digest. The
implementation paths are emitted in their canonical order. The aggregate is
computed by initializing SHA-256 and, for each path in that order, hashing:

```text
UTF-8 repository-relative path || NUL || exact file bytes || NUL
```

The two NUL frame separators are present for every file, including the last.
This avoids the ambiguity of hashing an unframed concatenation. The package
lock digest is a separate SHA-256 over the exact `package-lock.json` bytes.

The mutation tests remove each ecosystem's binding, stimulus, assertion, and
runtime handler call by its emitted AST span, update only that temporary source
digest, invoke the real lifter on the temporary corpus, and require the
corresponding positive lift to fail. A separate lineage mutation removes Ink's
`react-reconciler` import and requires the React-renderer classification to fail
rather than falling back to a lock label.

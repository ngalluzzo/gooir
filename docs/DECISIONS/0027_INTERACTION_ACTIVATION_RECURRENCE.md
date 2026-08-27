# 0027 — Interaction starts at activation, not components

Status: provisional contract earned by recurrence; target realizers open

## Question

What is the smallest interaction meaning that recurs in real React, Vue, and
Ink implementations, and where do shadcn/ui and Mantine enter the resulting
capability graph?

The question is deliberately narrower than "what is the GOOIR UI model?" A UI
model written before measuring the ecosystem would become a parallel component
system. This probe instead applies the data-model method: pin unlike upstream
authorities, preserve their native meaning, project positive paths from their
actual runtime and test source, compare only the independently recurring
intersection, and require every disagreement to remain native or become an
explicit defeat.

## Corpus and method

The checked-in corpus locks source and tests from five upstream repositories:

| Authority | Revision | Role in the probe |
| --- | --- | --- |
| `facebook/react` | `6c3bd60a90cde43e12a6c0021de8f1ecb69491b9` | React DOM listener selection and dispatch |
| `vuejs/core` | `e2bede96134f757aad5c5b33ac9be055022dbfc8` | Vue runtime-dom listener installation and invocation |
| `vadimdemedes/ink` | `ad9e3ea430acd3411be1c7578a2859f810a848ec` | terminal input delivered through a React renderer |
| `shadcn-ui/ui` | `b9938d94635fca7a4560449713b0b1ba87d77bc6` | registry resolution and React source materialization |
| `mantinedev/mantine` | `8a284e2c2c53a9cb6f39f5dc389bf41b7a2073f8` | installed, polymorphic React component package |

The framework runtime implementations are the semantic authorities. Their test
sources provide declared corroboration; example component names and
documentation prose do not establish the fact. The provenance-only source lock
records exact paths and SHA-256 digests and contains no authored semantic
verdict.

A pinned `@babel/parser` parses the exact JavaScript, Flow/JSX, TypeScript, and
TSX bytes. Three ecosystem-specific projectors must reconstruct a native
positive path:

```text
binding -> native stimulus -> selected runtime callable -> invocation
        -> positive upstream test assertion
```

The generated observation binds its source and UTF-8/UTF-16 spans, parser
configuration and package lock, generator implementation digest, authority
lock digest, native differences, and typed limits. Replacing a binding,
stimulus, assertion, or runtime invocation in any lineage makes that projector
fail closed. The generator output is checked byte-for-byte; it is not an
annotation that gets to select the result.

The upstream suites were reproduced during development, but no durable run
result is admitted in this change. Test declarations therefore corroborate the
static callable path; this record makes no claim that a checked-in execution
artifact proves those suites passed.

This is a recurrence probe, not yet a same-application convergence proof.
React DOM and Vue runtime-dom are the two independently governed lineages that
earn the narrow law. Ink demonstrates the same path through a terminal host but
shares React/reconciler lineage and adds no independent vote. That relationship
is projected from Ink's pinned local-reconciler import and its reconciler's
imports of `react-reconciler` and `react`, not assigned from an ecosystem label.
The observations do not describe one shared application or give their local
handlers a common identity.

## Findings

### F1 — Bound activation dispatches a registered handler

The positive intersection is small:

```text
an authority-local activation occurs
  -> the active native binding dispatches
  -> a registered handler is invoked
```

React establishes this through its event plugin, dispatch queue, and exact
`listener(event)` invocation. Vue establishes it through `patchEvent` and the
runtime-dom invoker's `callWithAsyncErrorHandling(value, ..., [event])` path.
Those two source projections are the independent recurrence. Ink's `useInput`
path reaches `inputHandler(input, key)` through reconciler discrete updates and
provides cross-host React-lineage evidence without becoming a third vote.

The provisional semantic payload therefore contains only an action identity,
an optional `InvokesRegisteredHandler` outcome, and preserved extension data.
An absent outcome does not mean "does nothing"; it is unknown and requires a
defeat explaining why dispatch was not established.

### F2 — `Button` is not the semantic center

The selected React witness binds `onClick` on a DOM `div`; the selected Vue
witness binds `onClick` to a separately created DOM `div`. Ink's witness writes
`x` through a PTY and observes rendered text. Even this narrow corpus therefore
diverges in binding mechanism, stimulus route, renderer, and output medium.

The component-library evidence is stronger still. shadcn/ui publishes the same
registry name while materializing wrappers over different underlying
primitives. Mantine's `Button` is polymorphic and can select a component other
than the default HTML button. A component name cannot prove activation meaning.

### F3 — Suppression has not converged

React suppresses selected mouse listeners for disabled interactive DOM
elements. Vue removes or replaces native event invokers and also supports
`once`, capture, passive, and multiple-handler behavior. Ink suppresses hook
registration with `isActive`. Mantine keeps `disabled`, `loading`, and
`data-disabled` observably distinct.

These are not evidence for one generic `enabled` bit. They remain native facts
until a same-application, cross-target trace proves a shared availability law.

### F4 — One activation does not imply one application effect

React's own nested-event test demonstrates multiple state updates from one
click. Vue accepts an array of handlers and preserves immediate-propagation
behavior. The v0 contract therefore claims handler invocation, not effect
cardinality, idempotence, state transition, or outcome count.

### F5 — The ecosystem participants occupy different hops

The real routes are:

```text
React source -> React reconciler -> selected host renderer
Vue source   -> Vue compiler/runtime-dom -> DOM
Ink source   -> React reconciler + Ink host config -> terminal

shadcn registry + project config -> materialized React source
Mantine package + CSS/provider setup -> imported React components
```

Ink is a React renderer, not a peer component dialect. shadcn/ui is a registry
and source materializer, not a renderer. Mantine is an installed React package,
not a registry and not a renderer.

## Decision

Add the provisional `semantics-interaction-activation-v0` contract and keep it
smaller than every source authority. Do not add a generic component tree,
`Button`, `Click`, key binding, label, availability flag, state machine, or
effect cardinality.

Interaction is an optional semantic projection. Existing React, Vue, and Ink
programs can continue directly through their native toolchains without ever
producing this fact. The fact becomes useful when a request needs portable
interaction meaning, cross-target analysis, or independently conformed target
realization.

There is no universal lowering target. The target is the requested fact, often
an independently conformed runnable artifact. A future realization edge has
the following shape:

```text
activation meaning
+ handler/effect implementation
+ target-host policy
+ available component or input realization
        -> native project
        -> authoritative ecosystem build/runtime
        -> runnable artifact
        -> verifier-owned stimulus and observed handler dispatch
```

The native project is a valid intermediate requested target. It is not the
semantic center and React is not the final target by definition.

Component ecosystems participate through providers over their real authority:

- a shadcn provider resolves an exact registry item against exact project
  configuration and returns the materialized source and project changes;
- a Mantine provider resolves exact package exports, types, CSS, and provider
  setup;
- an adapter may claim that a concrete component realizes an activation only
  with evidence over that exact implementation and dependency closure.

React lowering therefore does not need a built-in list of shadcn, Mantine, or
other components. It consumes a separately supplied, evidence-bearing native
realization. Missing realization or build providers remain typed capability
needs rather than fallback guesses.

## Required next proof

The honest round trip is behavioral:

```text
earned activation
  -> actual target revision
  -> authoritative build and runtime
  -> verifier-owned stimulus
  -> observed handler dispatch
  -> lifted activation subset
```

It must not compare emitted source spelling or claim that arbitrary framework
source is statically round-trippable. Browser routes should use the actual
TypeScript/Vite/framework build and an accessibility-oriented browser driver;
Ink should run under its real input/test or PTY boundary. shadcn and Mantine
must first pass their distinct materialization or package-setup checks.

Promotion beyond v0 requires a second product or a same-application
cross-target corpus that earns additional shared laws. Unknowns and native
extensions remain preserved in the meantime.

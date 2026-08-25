# 0028 — A screen is a derived observation, not the semantic waist

Status: negative generic result; narrower navigation and agent-session
candidates retained for separate probes

## Question

Does interaction take place on a reusable semantic `Screen`, `Document`, or
other representation object, or are those native targets?

This probe applies the data-model correction from
[0004](0004_RECURRENCE_PROBE.md) to production UI code. Product applications
are used to establish which meaning is independently needed. Framework,
router, compiler, renderer, and host authorities are separately responsible
for establishing how that meaning is represented. Similar JSX or template
shape is never counted as semantic recurrence.

## Corpus

The checked-in corpus pins 45 native source documents, eight license records,
six current products, and one historical production corroborator:

| Product | Exact revision | Product axis | Declared native route |
| --- | --- | --- | --- |
| Grafana | `553f2f7de01bdb50d037ca40911fd166509a890a` | current, Grafana Labs | React, explicit descriptors and JSX routes |
| Papermark | `1a9a0998831775cd5cdd93c5303d9194ddb90660` | current, Papermark | React, Next Pages and App routers |
| Directus | `5869c06f6997af0d2f13b39b3d19297dd2ed2f65` | current, Directus | Vue Router plus dynamic module registration |
| NocoDB | `17d8acf1f279e6147cc508b73ca52fbb737794c2` | current, NocoDB | Vue, Nuxt filesystem routing |
| Gemini CLI | `812f7a2bcf20b6e80e2e50c3c8fa8e26567bc1e8` | current, Google | React through Ink terminal renderer |
| Shopify CLI | `1149f9f8dfe8fb2ff9f60c01410d24995de125e3` | current, Shopify | React through Ink or direct stdout |
| TypeScript Codex CLI | `5aafe190e2657dc8b9d53e98e7bf6ec6389183b1` | historical, OpenAI | React through Ink |

The last product is not allowed to inflate a claim about current prevalence.
It is retained because its former production source independently corroborates
a narrower agent-session candidate.

The native inventory is generated with pinned `@babel/parser`,
`@vue/compiler-sfc`, and `@vue/compiler-dom` packages. It records exact imports,
exports, JSX/template nodes, conditionals, iterations, returns, directives,
dynamic components, route outlets, teleports, JSON keys, and source spans. It
does not label those structures visible, accessible, a screen, a document, or
semantically equivalent.

## Admission has two axes

The earlier interaction probe separated Ink from React DOM because Ink shares
React/reconciler lineage. UI product recurrence requires the same correction in
both directions:

| Product meaning recurrence | Runtime realization recurrence | Interpretation |
| --- | --- | --- |
| no | no | anecdote |
| yes | no | provisional product/domain meaning; portability unknown |
| no | yes | one product's realization capability, not recurring meaning |
| yes | yes | candidate portable semantic fact |

Product independence requires at least two independently governed products
whose product-owned state and behavior demand the same meaning. Shared
components, framework nodes, or renderer APIs do not count.

Runtime independence separately requires non-derived compilers/renderers. Two
React applications, different Ink versions, or an Ink fork do not become
independent realization lineages. Product diversity and host diversity remain
useful evidence, but they answer different questions.

This is the UI counterpart to 0004's rejected shape matcher. A `<Box>`, `<div>`,
Vue compiler root, JSX fragment, or nested component tree is as semantically
weak as two unrelated database entities sharing the same scalar-type multiset.

## Findings

### F1 — `Screen` has no source-attested cross-host identity

The web products do not agree on a screen boundary even within one framework:

- Grafana source contains local `RouteDescriptor` objects and nested JSX
  `<Route>` elements. Manually audited targets include dynamic render producers,
  redirects, and plugin deferral; the generic inventory does not project that
  provider behavior.
- Papermark contains both Next Pages Router and App Router file conventions.
  `_app` supplies a provider-shaped envelope and `_document` an HTML host
  envelope; only the Next provider can establish their configured routing
  roles, and it has not yet been projected.
- Directus source conditionally calls `router.addRoute` after current-user and
  permission checks and contains dynamic layouts, named slots, nested
  `RouterView` outlets, teleports, and global overlays. Vue Router behavior is
  not inferred from those syntax nodes.
- NocoDB contains a path following Nuxt's filesystem convention, conditional
  layouts, nested-page nodes, and nine guarded product-view alternatives. Its
  route identity remains provider-unverified in this probe.

The terminal products supply the cross-host falsifier:

- Gemini selects default and screen-reader layouts for the same application
  state, and separately selects scrollable versus static history realization.
- Shopify renders an interactive Ink surface only when the terminal supports
  prompting. The same development operation can take a direct-stdout path.
- The historical TypeScript Codex application root selects onboarding,
  historical rollout, confirmation, or live-chat contributions.

A source component is therefore not a screen. A route is not necessarily a
screen. A viewport is not bounded by a route subtree. A screen-like result can
only be synthesized relative to exact route state, permissions, feature
configuration, dynamic resolution, layout/portal state, host dimensions, and
runtime output.

### F2 — `Document` is three unrelated native/domain concepts

`Document` is actively overloaded in the corpus:

- Papermark documents are product-domain entities.
- Next `_document` and Directus `index.html` concern the HTML host envelope.
- live terminal activity, confirmations, process output, input state, tabs, and
  actions are not documents.

Vue's compiler `RootNode`, React's element/fiber roots, a DOM `Document`, and an
Ink render tree are native compiler, framework, or runtime concepts. Similar
hierarchy does not give them one semantic identity.

The host document also has separate authority. Directus explicitly owns HTML
hosts for the app, dialogs, and menus. NocoDB delegates its host generation to
Nuxt. Route SFCs cannot prove either document.

### F3 — The web subset recurs on routing, not representation

Across Grafana, Papermark, Directus, and NocoDB, a narrower candidate survives:

```text
provider-backed navigation selector
  -> render contribution | redirect | extension target
  -> zero or more provider/application composition boundaries
```

The provider is load-bearing. Grafana owns a local descriptor schema; React
Router owns JSX route behavior; Next and Nuxt derive bindings from filesystem
conventions; Vue Router owns explicit route records. A React or Vue AST alone
cannot establish the binding.

This is a candidate navigation/routing fact family, not a generic presentation
fact. It does not recur in the terminal subset, does not prove reachability,
does not bound the rendered viewport, and has not yet been projected through
the authoritative Next, Nuxt, React Router, and Vue Router implementations.
It is retained for a separate recurrence probe; no contract is admitted here.

### F4 — Render contribution, composition, and guarded alternative are native facts

The parser can deterministically establish that source contains component
invocation, route outlets, named slots, conditional alternatives, iterations,
fragments, dynamic components, or multiple roots. Those are useful lossless
native-dialect facts.

They do not establish that a contribution:

- reaches a configured build;
- is reachable under current state;
- produces a host node;
- is visible or perceivable;
- carries a particular product meaning; or
- is equivalent to another contribution.

Providers, context-only components, `null` returns, CSS, terminal layout nodes,
permissions, plugins, and portals all supply direct counterexamples. A future
state-scoped `presented surface` analyzer would require semantic contracts and
runtime evidence for those missing facts; it must not consume raw React/Vue/Ink
syntax as if it were meaning.

### F5 — The agent-session meaning is real but not generic UI

Gemini CLI and the historical TypeScript Codex CLI independently recur on a
narrower product-family candidate:

> an ordered heterogeneous record of human, agent, tool, and system activity,
> together with a current input or decision locus.

This is the semantic center behind the transcript-like experience, not the
terminal boxes that happen to render it. It aligns with the product value of a
shared human/agent conversation without making chat layout part of the kernel.

Shopify is the necessary falsifier. Its production Ink view is concurrent
process output, status, shortcuts, tabs, and actions, with no transcript or
composer and with a direct-stdout fallback. Ink does not imply agent-session
meaning.

The candidate currently has product-axis corroboration but only one derived
React-to-Ink realization family, and one corroborator is historical. It belongs
in a separately versioned agent-session/activity probe. It earns neither a
generic presentation contract nor portable lowering in this decision.

### F6 — Component ecosystems remain providers at native hops

Papermark provides an in-product proof of a shadcn-configured local-source
consumption shape:

```text
shadcn-style project configuration
  .. unverified materialization provenance ..
  -> locally owned React source
  -> application import
  -> React/host toolchain
```

Its checked-in `components.json` names the shadcn schema and selects aliases;
its local button source uses Radix `Slot` and a polymorphic `asChild` branch;
application source imports that local button. The corpus does not contain a
registry item or generator receipt proving that a shadcn tool created the
customized file. Decision 0027 separately proves the ecosystem's general
registry/materializer mechanism, but no causal edge joins that mechanism to
this file here.

React still does not need a catalog of shadcn components. A lowering provider
can request or accept exact materialized source plus project changes and then
delegate to React, while materialization provenance remains explicit.

No selected product naturally used Mantine. That is negative corpus evidence,
not evidence that Mantine is unsupported; its separately proven role from
0027 remains an installed React package/provider route.

## Decision

Do not add `Screen`, `Document`, a universal component tree, or a generic
representation dialect.

Keep the hops explicit:

```text
domain/product meaning contracts        optional interaction facts
            \                                   /
             requested capability and host policy
                           |
        evidence-bearing provider/native realization
             /             |                 \
       React source      Vue source        Ink/React source
             |             |                 |
       native compiler/router/renderer/runtime toolchains
             |             |                 |
       DOM + host doc   DOM + host doc   terminal output / stdout
             \             |                 /
             runnable or runtime-observed requested fact
```

React, Vue, and Ink can participate directly without an Interaction dialect.
Interaction activation is an optional semantic projection useful for portable
behavior or analysis. It does not own the representation boundary.

There is still no universal final target. A request may target a route graph,
native project, built application, DOM/accessibility observation, terminal
frame, handler dispatch, or another exact fact. Multi-hop lowering selects the
route that can produce the requested fact and preserves every unprojected
native extension.

Capabilities fill the ecosystem-specific gaps rather than moving them into a
central UI catalog:

- a Next or Nuxt provider establishes filesystem route bindings;
- a React Router or Vue Router provider establishes its native route graph;
- a shadcn provider materializes exact source and project changes;
- a package provider resolves Mantine exports, types, CSS, and setup;
- a native build/runtime provider produces the target artifact;
- a browser, accessibility, PTY, or stdout observer establishes runtime output;
- a semantic adapter claims only the exact meaning its evidence supports.

Missing route authority, build closure, state, component resolution, or runtime
observation becomes a typed capability need or defeat. It never becomes a
guessed screen.

## Required next proofs

1. Probe the navigation candidate through authoritative Next, Nuxt, React
   Router, and Vue Router providers. Preserve render, redirect, extension,
   guard, shell, relative-scope, and open-route-set differences.
2. Probe the agent-session candidate against at least one independently
   governed current web product and its product-owned activity state, then
   require an independent non-React realization before claiming portable
   lowering.
3. For one exact product meaning, run an actual native build and observe the
   DOM/accessibility tree or terminal/stdout behavior under verifier-owned
   state and stimulus. Only that can promote native composition into a
   state-scoped presented-surface fact.
4. Keep product-meaning and runtime-realization independence as separate
   admission dimensions in all future UI recurrence work.

## Reproduction

```sh
npm ci --prefix tools/representation-boundary-lifters
npm test --prefix tools/representation-boundary-lifters
npm run lift --prefix tools/representation-boundary-lifters -- \
  --lock "$PWD/fixtures/representation/boundaries/authorities.lock.json" \
  --output "$PWD/fixtures/representation/boundaries/native-observations.lift.json"
npm run check --prefix tools/representation-boundary-lifters -- \
  --lock "$PWD/fixtures/representation/boundaries/authorities.lock.json" \
  --output "$PWD/fixtures/representation/boundaries/native-observations.lift.json"
```

The lock contains no semantic verdict. The deterministic generated observation
document is a native syntax inventory. This decision supplies the defeasible
interpretation and deliberately admits no new semantic contract.

# 0029 — Agent activity recurs as a selected ordered projection

Status: provisional v0 semantic contract; two concrete source projections and
six-product static corroboration implemented

## Question

What semantic object, if any, lies beneath a Slack-like human/agent activity
experience across current web and terminal products?

Decision [0028](0028_REPRESENTATION_BOUNDARY_PROBE.md) retained an agent-session
candidate but described it too broadly as a heterogeneous record plus one
current input or decision locus. This probe applies the same method that earned
the data-model contracts: inspect independent product-owned state, preserve the
native models, and admit only the smaller meaning their differences cannot
falsify.

## Corpus

The checked-in corpus pins 27 product-owned source documents and eight license
records from six current, independently governed products:

| Product | Exact revision | Native route |
| --- | --- | --- |
| LobeChat | `0a44f1b23fdc6af52bcdbe7199ae5937d43722a1` | React DOM; parent-linked records, active branches, overlays, and virtual groups |
| LibreChat | `ac2aef00f6ebed74cde89b51d28e77da5db6c97b` | React DOM; two-pass tree construction and per-parent sibling selection |
| Open WebUI | `01f4282f1ffe0d6212f58d3afbeae21fffd0c4be` | Svelte DOM; current-head walk over a parent-linked map |
| Hugging Face Chat UI | `d34daa15dab956dfc14fa56b781fa2d992a41508` | Svelte DOM; selected-leaf ancestor materialization |
| Gemini CLI | `812f7a2bcf20b6e80e2e50c3c8fa8e26567bc1e8` | React/Ink; append recording with rewind and checkpoint materialization |
| Codex | `9c9675d3d038d9e827875c6bdceb2c6d68439dfc` | Rust/Ratatui; thread-local ordered turns and items with explicit load extent |

Pinned Babel, Svelte, tree-sitter Python/Rust, TOML, and TypeScript authorities
parse every selected source. Product-specific static projectors require exact
native declarations and selection structures. Every positive evidence node has
a second digest pinned in projector code, so relocking changed source cannot
silently authorize new semantics. The provenance lock contains no semantic
verdict fields.

## Findings

### F1 — The recurring object is a projection, not a transcript

The six products' static state and selection routes corroborate an exact scope
and a selected sequence of activity. They do not share the structure from which
that sequence is obtained:

- LobeChat and LibreChat derive a route through graph-like state, but disagree
  on overlays, grouping, sibling selection, and durable identity.
- Open WebUI and Chat UI select a branch with different stored topology and
  different malformed-input behavior.
- Gemini materializes one ordered recording after applying rewind records.
- Codex returns thread- and turn-local item containers and can explicitly say
  their content is not loaded, summarized, or full.

This evidence retains the following smallest candidate shape:

```text
exact opaque source scope
  + source-relative selection
  + explicit non-boolean source extent
  -> entries in emitted ordinal order
       each joined by zero or more opaque source refs
       or by a projection-local key
```

Vector position is observable order for that exact projection. It is not a
claim of global chronology, causality, storage order, or sibling-branch order.
`full` means full under the named source scope and selection rules; it never
means that every branch or all potentially existing activity was included.
Source extent is also separate from GOOIR evidence completeness. Codex's
`NotLoaded | Summary | Full` is the strongest explicit falsifier of a boolean
extent; the contract requires every producer to state an extent and allows
`unknown` when its authority cannot establish one.

### F2 — Entry identity cannot be reduced to one message id

LobeChat can synthesize virtual groups and combine source records. LibreChat can
rewrite message ids while streaming. Gemini nests tool records under message
records. Projection entries consequently carry zero or more authority-local
source references, or a key whose identity is explicitly local to the exact
projection.

The contract does not turn those references into globally stable entities.
Content, native role, grouping, timestamps, and other uninterpreted fields may
round-trip as extensions but acquire no portable meaning merely by being
present.

### F3 — Actor, content, graph, interaction, and streaming are separate facts

No portable actor enum survived the corpus. A `user` or `assistant` role can
describe protocol position rather than the human or agent that contributed an
entry; subagent and collaboration activity makes that distinction observable.
Participant attribution therefore needs an exact identity/reference contract,
not an inline `human | agent | tool | system` label.

The following also failed as fields of this contract:

- portable entry payload;
- the backing branch graph;
- a singular current input or decision locus;
- a streaming delta reducer; and
- direct render or component meaning.

Those meanings may recur independently and join the same source references.
They must be earned as separate contracts so one provider's absence does not
erase or fabricate the others.

### F4 — Two real selectors converge, while their defeats remain distinct

The generator extracts the exact reviewed upstream selection function nodes
from Open WebUI and Chat UI and executes them in an isolated context with
ambient process, module loading, network, clock, and timer entry points removed.
Given:

```text
system -> user -> { assistant_a, assistant_b }
selected = assistant_b
```

both functions emit `system, user, assistant_b`; selecting the other leaf emits
`system, user, assistant_a`. Each valid result is then lowered into a concrete
`ActivityProjection`, deserialized by the Rust semantic crate, and passed
through its verifier. This is the verified two-product vertical for selected
emitted order, not merely similar source shape.

Malformed topology remains a falsifier. Open WebUI returns the reachable suffix
while Chat UI throws `Ancestor not found`; neither result is admitted as a
valid common projection. The test executes the reviewed extracted functions,
not the applications' dependency closures, and proves no visual equivalence.

### F5 — The data-model pattern applies without creating a UI metamodel

GOOIR did not make Prisma, PostgreSQL, or OpenAPI lower into one another. Their
authoritative native models project into a smaller recurring data-model fact,
and later capabilities consume or realize that fact.

The first concrete activity route follows the same pattern:

```text
Open WebUI native graph + exact upstream selector --\
                                                    +-> source-specific adapter
Chat UI native graph + exact upstream selector -----/          |
                                                               v
                                                    ActivityProjection::verify

Lobe / Libre / Gemini / Codex native routes
  -> static corroboration only; concrete projection still required
```

The branch graph is an optional upstream fact, not the common waist. Products
that already own an ordered recording can eventually project directly. No
product must rewrite its storage model to participate, but static route shape
alone is not accepted as a produced semantic value.

### F6 — React, Vue, Ink, and component libraries occupy native hops

React can participate without an Interaction fact or an ActivityProjection.
An existing React application can continue through React's compiler and
renderer authorities unchanged. The same is true of Vue, Svelte, Ink, and
Ratatui.

When portable meaning is requested, a product adapter may lift native state to
`ActivityProjection`. A target provider may later combine that projection with
separately established content, participant, interaction, and implementation
facts to produce native React, Vue, Ink, or another target. Interaction does
not lower to React by itself, and activity does not contain interaction:

```text
ActivityProjection -----------\
entry content facts -----------+
participant attribution -------+--> target-native realization provider
interaction activation --------+          |
native handler/effect code -----+          +--> React/Vue/Ink/Ratatui source
host and package policy --------/          +--> runnable or observed artifact
```

shadcn/ui, Mantine, and other component ecosystems can fill the final native
realization hop as source materializers or installed package providers. A
React-target capability need not know every component. It requests the facts
and target constraints it needs; a matching provider owns exact library
selection, imports, setup, styling, and native source. Another provider can
produce an equivalent requested fact through a different library.

## Decision

Add `org.gooi.semantics.activity_projection/ordered_activity@0.1.0` as a
separately versioned provisional semantic contract. Two distinct current Svelte
product repositories now produce concrete verifier-owned fixture values
through their exact upstream selection code. Four other products, including two
React web products, statically corroborate the narrower shape but do not count
as concrete contract projections. No cross-runtime lowering claim is admitted
yet.

The contract owns exact opaque scope, selection-relative emitted order, entry
locators, explicit source extent, and lossless extensions. It does not own
payload, participants, branch topology, pending requests, direct input,
streaming, interaction, layout, components, or rendering.

There is no universal final target. As with data models, the target is the exact
fact the caller requests: a semantic projection, native source, a runnable
artifact, an observed DOM/accessibility result, terminal behavior, or another
versioned fact. Capabilities are the typed bridges between those facts;
providers are the ecosystem authorities that implement individual bridges.

Do not add a demonstration renderer yet. Rendering anonymous rows would hide
the absence of earned content and participant meaning behind plausible UI.
This slice completes one honest vertical at the source boundary: two independent
web products execute their real selection functions, adapters produce concrete
contract values, and an independent Rust checker byte-binds the canonical
generator output and invokes the semantic verifier. The remaining four product
routes are explicitly static corroboration.

## Required next proofs

1. Produce a concrete projection from an independent non-Svelte runtime route;
   React/Ink or Rust/Ratatui is the strongest next portability test.
2. Probe outstanding interaction requests as zero-to-many correlated requests
   with optional activity subjects. Do not collapse them into one composer or
   one current decision.
3. Probe participant attribution through exact contributor identities and
   delegation relationships, independent of source-native message roles.
4. Probe content as separately addressable facts joined through exact source
   references, preserving tool payloads, structured parts, and unknown forms.
5. Once enough of those facts recur, compose one exact projection through a
   native web and terminal provider and observe both under verifier-owned state.

## Reproduction

```sh
npm ci --prefix tools/activity-projection-lifters
npm test --prefix tools/activity-projection-lifters
npm run lift --prefix tools/activity-projection-lifters -- \
  --root "$PWD/fixtures/activity/projection"
cargo test -p semantics-activity-projection-v0
cargo test -p activity-projection-recurrence
```

The checked-in observation document is deterministic generator output bound to
the exact source, license, authority-lock, parser, package-lock, and generator
implementation digests.

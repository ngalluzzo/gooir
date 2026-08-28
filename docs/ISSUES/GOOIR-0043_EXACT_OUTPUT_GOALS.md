# GOOIR-0043 — Let derivations name an exact capability output

Status: complete

Origin: owner request to prove a usable, backend-neutral consumer path before
the 0.1 kernel is frozen.

## Problem

The product façade currently asks only for a target `ValueKindId`. That is
insufficient once independent generators converge on the same portable
artifact contract. An HTTP route generator and a SQL migration generator can
both correctly produce `ContentSet`; a source-spec bundle can also correctly
enter as `ContentSet`.

With that inventory, asking for `ContentSet` either selects no generator at
all because the kind is already an initial value, or becomes ambiguous across
unrelated generators. The caller's actual intent — one exact capability output
port — was erased at the product door.

`RouteOutputRef` already represents that coordinate inside selected routes.
The missing property is the ability to retain it as a planning and derivation
goal. Mature compiler and build systems likewise make the caller name a pass,
generator, rule, or target; they do not infer intent from a shared file
carrier.

## Scope

- Add an optional exact output coordinate to a semantic plan while retaining
  value-kind planning for discovery and compatibility.
- Let the planner build, validate, select, and diagnose the dependency closure
  rooted at that exact output, even when its value kind is initially present.
- Let the product façade and compiler driver accept either a value-kind goal or
  an exact capability-output goal.
- Preserve conservative unique-only route and offer selection beneath the
  named output. Naming a generator must not silently choose among its input
  routes or implementation offers.
- Preserve old value-kind request and plan decoding where that can be done
  without weakening validation.

## Acceptance

- Two independent generators may terminate in the same `ContentSet` kind and
  remain separately requestable by exact capability and output port.
- A `ContentSet` input does not short-circuit a requested generator whose
  output is also `ContentSet`.
- The exact output coordinate participates in plan identity and selected-route
  validation.
- A missing capability, missing output port, type mismatch, target
  substitution, unsupported extension, unavailable offer, and ambiguous
  dependency route all fail closed with the existing remedy distinctions.
- Existing value-kind requests retain their current discovery/ambiguity
  behavior.
- No backend, recipe, workflow, lowering/lifting taxonomy, lens, or execution
  policy is added to the kernel.

## Non-goals

- No generic source-file observer or filesystem publication command in this
  issue.
- No concrete HTTP, SQL, OpenAPI, CLI, MCP, or language generator.
- No ranking or implicit selection among capabilities, offers, inputs, or
  attesters.

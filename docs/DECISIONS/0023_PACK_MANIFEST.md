# 0023 — A capability graph is data

Status: complete

## What was code that should not have been

A capability is a promise about types: what it requires, what it produces, and
which suite a provider must eventually pass. None of that is code. Written as
Rust struct literals, it meant **a graph could only be declared by someone
compiling this workspace** — which is not an ecosystem.

Eleven `CapabilitySpec` literals across two packs are now
`org.gooi.pack/v1` manifests:

```json
{
  "protocol": "org.gooi.pack/v1",
  "capabilities": [
    {
      "id": "org.gooi.capability/author_data_model@0.1.0",
      "requires": [
        { "fact": "org.gooi.source.authored/entity_spec@0.1.0",
          "acceptance": "complete_only" }
      ],
      "produces": ["org.gooi.semantics.data_model/model@1.0.0"],
      "default_conformance_suite": "org.gooi.conformance.authored_data_model@0.1.0"
    }
  ]
}
```

`read_pack` turns a manifest into ordinary specs; `register_pack` installs
them; `write_pack` renders specs back out, so a host can publish the graph it
installed. The registry validates a declared spec exactly as it validates a
hand-written one — a manifest cannot declare something the kernel would refuse,
and a test asserts that.

## Three decisions inside it

**Identities are display strings, not nested objects.** `package/name@version`
is what `Display` already produced and what every error message already showed.
`ExactId::parse` is the inverse, and it refuses anything it cannot read rather
than filling in a default part — six malformed forms are covered.

**Fact types are not listed separately.** They are exactly the identities the
capabilities mention, so a separate list could only agree or drift. Derived
beats duplicated.

**Providers stay code, because they are code.** What a manifest can declare is
the *graph*; an implementation is an implementation. An out-of-process provider
already has its own manifest ([0019](0019_PLUGIN_LIFECYCLE.md)), and its
identity is its measured digest, which no declaration could supply.

## The manifests were generated, not transcribed

Hand-typing eleven capabilities from Rust into JSON is exactly the transcription
error this change exists to prevent. `write_pack` emitted both files from the
specs the code already registered, so the data is what the code said by
construction.

## The drift this introduces, and the guard

A manifest creates a second place an identity can be named — the risk this
project exists to remove. Both packs now assert that every capability accessor
is declared, every fact accessor is mentioned, and every registered provider
implements a declared capability.

The guard was verified rather than assumed. Changing one manifest identity from
`@0.1.0` to `@0.2.0` fails the test with the name of what broke:

```text
`org.gooi.capability/author_data_model@0.1.0` is named in code but not in pack.json
```

That check is itself an instrument, and [0016](0016_ONE_EXACT_IDENTITY.md) is
the reason it was tested against real drift before being trusted.

## Something the data says better than the code did

`fleetd-capability-pack` declares `generate_runnable_web_surface` with no
provider on purpose. In Rust that intent lived in a comment. In the manifest it
is simply a capability with no implementation, and a test states the
expectation directly. The open need is now a property of the declared graph
rather than of a comment someone might delete.

## State

321 tests, clippy and fmt clean. Pack source: 795 -> 704 lines; 177 lines of
those became data. Eleven `CapabilitySpec` literals remain in the workspace:
zero.

The remaining pack ceremony — five helper functions duplicated across both
packs, and a provider impl whose body is one call — is what the SDK work
addresses next. The manifest had to come first because it defines what an SDK
generates against.

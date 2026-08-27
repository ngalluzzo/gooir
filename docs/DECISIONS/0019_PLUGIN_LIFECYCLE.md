# 0019 — Out-of-process providers

Status: complete

## Recovery amendment

[0031](0031_MINIMAL_SEMANTIC_SUBSTRATE.md) supersedes this decision's process
ownership. The sections below preserve the historical experiment and its
evidence; they do not make process launch, supervision, timeout, credentials,
or admission responsibilities of the semantic substrate. In the target
architecture an external execution host owns that lifecycle and returns a
neutral result plus opaque evidence to GOOIR's single candidate, conformance,
and admission path.

`org.gooi.plugin/v2` is only a transitional compatibility wire. The existing
process adapter needed a named input/output shape after `CapabilitySpec`
acquired exact named ports, so v2 carries those names rather than inventing or
discarding them. It is not the target execution-host protocol and creates no
stable process ABI. `ProcessProvider` remains useful as historical quarry and
as a compatibility adapter while consumers migrate; it is not process
machinery that GOOIR core intends to own.

## The deferral this closes

[0001](0001_BOOTSTRAP_BOUNDARIES.md) made the right call and then postponed the
consequence: *"the portable boundary is serialized IR and exact semantic
contracts, not a Rust dynamic-library ABI"*, followed by *"keep plugin loading
in-process… dynamic loading, registry governance, and sandboxing remain
undecided."*

The first capability experiment restated it as a known gap.
Because the boundary was chosen correctly, closing it needed no new
architecture: **a provider is any program that reads one JSON document and
writes another.**

`org.gooi.plugin/v1` was that document pair. During recovery,
`org.gooi.plugin/v2` changed the compatibility document to follow the named
ports introduced by [0031](0031_MINIMAL_SEMANTIC_SUBSTRATE.md).
`ProcessProvider` implemented the
ordinary `CapabilityProvider` trait by running a command, so the planner cannot
tell a plugin from an in-process pass, and the registry validates its outputs
and computes fact identities exactly as before. Protocol is orthogonal to
capability, as 0011 said it was.

## The first plugin is not Rust

The data-model graph had been reporting `lower_typescript_types` as an open
need. The provider fixture now lives in the extracted data-model ecosystem:

```bash
gooir derive model_types \
  --pack /path/to/data-model-pack.json \
  --from /path/to/input-fact.json \
  --plugin /path/to/typescript-types/plugin.json
```

Hand-written text becomes a data model in Rust, crosses a process boundary into
Python, and comes back as TypeScript with enum members rendered as a union
type. Open needs drop from two to one. The plugin declares its own losses —
timestamps carried as ISO strings — so the artifact is honestly `Partial`.

This is the first provider that could have been written by someone who has
never seen this repository.

## The host measures; the plugin does not declare

A manifest names the provider, the capability, and the command. It does **not**
name its implementation digest.

That is the load-bearing decision. [0017](0017_ONE_ADMISSION_RULE.md) binds
admission to an exact implementation digest so a different build cannot inherit
a decision made about other code. A plugin that could state its own digest
would defeat that completely. So the host hashes the manifest bytes plus every
file the manifest declares as its implementation, and a test asserts that
changing the implementation changes the identity.

The manifest declares *which* files are covered, and the count is reported on
load (`digest covers 1 file(s)`). A plugin that under-declares gets a digest
that does not move when its real code does. That is a genuine weakness, made
visible rather than hidden — the same honesty 0011 applied to the in-process
pack digest, which is also a registration fingerprint and not a
reproducible-build attestation.

## Nothing is discovered

Manifests are named by the caller, one `--plugin` at a time. There is no
directory scan, because scanning for programs to execute is a supply-chain
hole rather than a feature.

There is also no sandbox, and this does not pretend otherwise: running a plugin
runs a program with the host's privileges. Installing one is a trust decision,
and the measured digest is what makes it an exact one.

## Two out-of-process paths, deliberately different

This comparison records the architecture at the time of the experiment. Its
direct trust and process-ownership conclusions are superseded by 0031:
installing process machinery establishes availability, not semantic truth,
and both locally and remotely executed implementations now converge on one
admission path.

| | `ProcessProvider` | request / candidate / `verify_and_admit` |
| --- | --- | --- |
| who runs it | the host, synchronously | someone else, later |
| trust basis | the host chose to install this exact implementation | independent conformance against the request's suite |
| derivation | `Produced` | `Admitted` |

They are not competing designs. Installing a plugin *is* the trust decision;
dispatching work to a party you did not install is not, so that path requires a
suite. Requiring conformance for every plugin invocation would make plugins
useless; admitting a stranger's output without one would be the laundering hole
0017 closed.

## Every way a program can misbehave

Eleven tests, one per failure mode, because a provider that is a process can
crash, hang, lie, or answer a question it was not asked — and none of those may
become a silent success:

| failure | result |
| --- | --- |
| manifest declares another protocol | refused before anything runs |
| declared implementation file absent | refused before anything runs |
| non-zero exit | provider error carrying the **first** stderr line, not a dump |
| unparseable output | error, not an empty success |
| plugin reports its own failure | surfaced verbatim |
| answers a different protocol | refused |
| neither outputs nor an error | error |
| **hangs** | killed after a timeout; the host does not hang |
| returns a fact nobody asked for | rejected by the registry, not the adapter |

That last row matters: the adapter deliberately does not judge which outputs
are correct. `validate_outputs` already did that for in-process providers, and
a plugin gets the same treatment rather than a parallel one.

## State

299 tests, clippy and fmt clean. With the plugin installed: 11 capabilities,
10 providers, 1 open need.

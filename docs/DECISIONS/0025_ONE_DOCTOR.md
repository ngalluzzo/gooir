# 0025 — One doctor, and a guard that fails

Status: complete

## The defect

[0018](0018_ONE_ENTRY_POINT.md) established `gooir` as the single entry point.
[0015](0015_GOOIR_DOCTOR.md) established `gooir doctor`. Both were true, and
there were still two doctors:

```text
$ gooir doctor        | 2 lines
$ gooir-doctor        | 62 lines
```

The documented command printed a summary. A separate binary printed the roots,
the terminals, the open needs, the ambiguous routes, the admission state and
the identity scan. Nothing in the repository ran both, so the difference was
invisible — and a user following the README got the weaker one, which hid the
two open needs entirely.

0018 named this exact failure without noticing it applied here:

> This is exactly the duplicate-declaration drift `gooir doctor` detects for
> fact types.

## The change

`Report` renders itself. One `Display` implementation, so a caller cannot
render its own weaker version, and the standalone binary is deleted.

That also removed two dependencies. `gooir-doctor` had pulled in
`fleetd-capability-pack` and `gooir-datamodel-pack` so its binary could know
the installed set. With the binary gone the library depends on
`gooir-capability` alone, which is what its own first paragraph always claimed:

> This analyzer consumes a registry and nothing else. It knows no fact
> meanings, no product, and no domain verbs.

Binaries: 12 → 11.

## The scan became a test

The old binary also scanned Rust source for two kinds of drift: more than one
implementation of the exact-identity rule, and one fact identity written down
in two crates. That is not a graph property — it is only meaningful inside a
checkout, and `Report` describes an installed registry that could be anywhere.

So it moved to `gooir_doctor::declarations`, consumed by tests that **fail**
rather than print. A printed warning nobody reads guards nothing, and this
project exists because wrong boundaries were found too late.

Test scaffolding is excluded, because fixtures share identities deliberately in
order to exercise the registry. Excluding them is the difference between a
guard that is green until something breaks and one that is red forever and
therefore ignored.

## Verifying the instrument

The guard was green on arrival, which is exactly when a guard is least
trustworthy. Two orphan source files — never `mod`-declared, so never compiled,
but read by the scanner — introduced real drift:

| perturbation | caught |
| --- | --- |
| a second struct carrying `package` / `name` / `version` | yes — `["gooir-capability (struct)", "gooir-identity (macro)"]` |
| `org.gooi.artifact.sql/postgres_ddl@0.1.0` declared in a second crate | yes |

A third test asserts the property that an earlier version of this scan got
wrong: the scanner must not count itself. It once matched its own search
strings, so the needles are split with `concat!`. The test checks the outcome
rather than trusting the trick.

## Deliberately not done

Ten binaries remain besides `gooir`: round-trip harnesses, conformance checks,
and the app runtime. Seven are cited by decision records, which makes them this
project's reproducible-evidence surface rather than clutter. Whether the cheap
deterministic ones belong in `cargo test` — by the same argument that moved the
source scan — is a real question, and one that needs each binary read rather
than grepped. A first pass classified them by searching for `env::var` and
`Command::new`, which is not a sound basis for deleting anything.

## State

334 tests, clippy and fmt clean.

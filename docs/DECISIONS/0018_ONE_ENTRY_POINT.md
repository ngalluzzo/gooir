# 0018 — One entry point, and one page

Status: complete

## What was justified, and what was not

[0015](0015_GOOIR_DOCTOR.md) proposed five ergonomic moves. Two of them —
collapsing the identity rule and reconciling admission — were chosen *by the
measurement*, and are done ([0016](0016_ONE_EXACT_IDENTITY.md),
[0017](0017_ONE_ADMISSION_RULE.md)).

Of the three remaining, one is dropped. **Renaming thirty-six crates from ten
role-words to two was proposed before the diagnostic existed, and the
diagnostic never endorsed it.** It reported a split kernel, not bad names. A
rename would be a very large diff justified by nothing measured, so the
vocabulary is *documented* instead: six roles, every crate in exactly one, and
a note that `*-lifter` and `*-lowering` are both providers differing only in
direction of travel.

That is the same rule this project applies to code — do not build for a
consumer that has not appeared — applied to its own housekeeping.

## One entry point

`gooir` is the whole surface:

```text
gooir facts                        every fact type, and how it is reached
gooir capabilities                 every promise, and whether it has a provider
gooir needs                        promises with no provider, as work contracts
gooir doctor                       graph health
gooir plan <target>                the route to a target
gooir derive <target> --from FILE  run it, and print the derivation chain
```

Three deliberate choices:

**A target may be a bare name.** `gooir plan postgres_ddl` rather than
`org.gooi.artifact.sql/postgres_ddl@0.1.0`. When a bare name matches more than
one fact type the candidates are listed and nothing is chosen — the same
refusal to resolve ambiguity by preference that the planner makes about
contract versions.

**A missing provider is an exit code, not an error.** `derive` exits 3 and
prints the need. Asking for something nothing can produce yet is a normal
outcome in this system, and the shell should be able to tell that apart from a
failure.

**Artifacts print as themselves.** A generated schema is text; rendering it as
a JSON string with escaped newlines would have defeated the point of having one
entry point at all. `--json` still gives the exact payload. Structured
artifacts show their shape instead of their bytes.

The specialised binaries remain. `fleetd-capability-check`,
`buzz-surface-check`, and the round-trip harnesses are verification
instruments, not user commands, and collapsing them into `gooir` would confuse
two different jobs. The honest claim is *one entry point for using the system*,
not fourteen binaries reduced to one.

Its resolution logic lives in a library so the ergonomics are tested rather
than only demonstrated: exact identity, unambiguous bare name, ambiguity, and
an unknown name that points at `gooir facts`.

## One page

The README was 121 lines whose headings were `GOOIR`, `Current milestone`,
`Fleetd multi-dialect dogfood`, and `Development` — no way in. It now opens
with what the system does, the five concepts, and a command that turns a text
file into a real artifact. Every command in it was executed and every link
resolves.

## A collision I caused

Writing this up surfaced **duplicate decision numbers**: two `0012`s and two
`0013`s. The capability track landed `0012_CANDIDATES_REQUIRE_INDEPENDENT_CONFORMANCE`
and `0013_RUNNABLE_WEB_ARTIFACT_CONFORMANCE` in `78216d7`; I later wrote my own
0012 and 0013 without listing the directory first.

Mine renumbered to 0014–0017, and every cross-reference was repaired.

This is exactly the duplicate-declaration drift `gooir doctor` detects for fact
identities — the same failure, in a place nothing checks. It is worth noting
that the tool found the fact-identity duplicate immediately and could not see
this one at all, because prose is not in the graph.

## State

288 tests, clippy and fmt clean. Seventeen decision records, sequentially
numbered, no dangling links.

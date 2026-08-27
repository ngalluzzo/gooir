# 0033 — Subtract the kernel and extract proven ecosystems

Status: accepted

## Context

[0031](0031_MINIMAL_SEMANTIC_SUBSTRATE.md) recovered a finite semantic center,
but the repository still physically contained 47 Cargo packages: the ten
neutral kernel/support crates, two proven domain families, and superseded Buzz,
Fleetd-control, UI activation, representation, and activity-projection probes.

That physical layout contradicted the dependency rule. The generic CLI also
installed the data-model pack in code, so an allegedly empty GOOIR
installation already knew one domain.

## Decision

The GOOIR repository contains only the neutral kernel and narrow host support.
The data-model family and Fleetd direct-conversation family are independent
downstream repositories with explicit dependencies on GOOIR public crates.
GOOIR has no dependency back to either repository.

The generic CLI installs nothing implicitly. Every capability declaration is
named with `--pack`; every transitional process provider is named with
`--plugin`.

Superseded research leaves the active tree. Git history and the owner-only
retirement archive are its recovery mechanism, not dormant Cargo packages or
multi-megabyte fixture corpora in the release workspace.

## Consequences

- The compile graph now enforces the architectural diagram.
- A new ecosystem begins with a contract and package outside GOOIR.
- A domain cannot enter the kernel accidentally through a convenience binary.
- The extracted repositories retain their real tests and proof boundaries;
  extraction does not promote experiments into protocols.
- Cross-repository local development currently uses explicit sibling path
  dependencies. Released versions may replace those paths later without
  changing dependency direction.

## Non-claims

This split does not declare every retained compatibility adapter stable, make
the Fleetd proof a production host, or standardize the data-model vocabulary.
It establishes where those things belong.

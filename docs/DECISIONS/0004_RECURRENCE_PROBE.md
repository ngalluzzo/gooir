# 0004 — Semantic recurrence probe (the "80%" claim)

Status: findings, proposed for architecture direction

## Purpose

The product thesis rests on a load-bearing empirical claim: *~80% of what a new
application needs is repetitive work someone has already written.* If true,
lifting solves cold start. If false, the catalog never reaches useful size and
the vision needs rework before more machinery is built.

This probe measures recurrence directly, in one vocabulary family, against real
software.

## Method

Corpus: **13 real open-source production applications** using Prisma, fetched at
`HEAD` (schema files only, ~1 MB, no clones). Split-schema repos had every
fragment fetched and unioned per app; within-app duplicates (typebot ships
MySQL + PostgreSQL, teable ships a template copy) were merged by model name.

**596 distinct entities, 9,855 fields.**

`cal.com · documenso · formbricks · typebot · rallly · dub · ghostfolio ·
papermark · trigger.dev · linen.dev · teable · umami · inbox-zero`

A second cohort captured each app's **earliest schema** from git history. Six
had genuinely early snapshots (4–19 models — actual v0.1 scale): umami,
documenso, rallly, ghostfolio, inbox-zero, cal.com. Five were rejected because
the path heuristic hit a late-added fragment, making their "v0" ≈ current.

Granularities: **entity** (name), **field** (name + type, entity-agnostic),
**qualified** (entity + field + type). Universal fields (`id`, `createdAt`,
`updatedAt`, `deletedAt`) reported both included and excluded; their removal
moved nothing materially. Measures are leave-one-out (order-independent) plus a
saturation curve averaged over 400 random orderings.

## Findings

### F1 — The 80% claim is not supported in the entity/data-model family

Leave-one-out coverage — *what fraction of this app already exists in some other app*:

| Granularity | Mature apps | Early-stage (v0) |
| --- | --- | --- |
| entity | 24.5% | 38.8% |
| field (name+type) | 32.4% | **51.2%** |
| qualified (entity.field.type) | 9.5% | 17.6% |

Early-stage apps are meaningfully more generic than mature ones, as expected —
but the best figure anywhere is ~51%, and structure-level recurrence is under
20%.

### F2 — The catalog saturates early, and it saturates low

Mean coverage of app #k by a catalog built from apps 1..k-1 (field granularity,
universal fields excluded):

```
 1 app  -> 11.3%      7 apps -> 29.2%
 2 apps -> 17.5%      8 apps -> 31.1%
 3 apps -> 22.0%      9 apps -> 32.2%
 4 apps -> 23.7%     10 apps -> 34.2%
 5 apps -> 27.0%     11 apps -> 34.0%
 6 apps -> 28.6%     12 apps -> 34.8%
```

Going from 10 to 12 apps moved the curve 0.6 points. It is asymptotic around
35%, not climbing toward 80%. At qualified granularity it asymptotes near 8.5%.

### F3 — 90% of entities are bespoke

Of 596 distinct entities, **538 (90.3%) appear in exactly one app.** Only 58
recur at all.

### F4 — Structural (name-independent) matching carries no signal

Matching entities by field-type multiset rather than name appeared to rescue the
claim — 67.9% of entities had a structural "twin" at Jaccard ≥ 0.8, 89.5% at
≥ 0.7. A null model with identical entity sizes and field types drawn at random
from the corpus type distribution scored **as high or higher**:

| threshold | real | null | verdict |
| --- | --- | --- | --- |
| 0.9 | 35.0% | 29.2% | no signal |
| 0.8 | 67.9% | 76.6% | no signal |
| 0.7 | 89.5% | 96.4% | no signal |
| 0.6 | 96.8% | 99.5% | no signal |

With ~9 scalar types available, shape collisions are forced by pigeonhole. Only
19 of 621 structural matches shared a name. The measurement is an artifact and
is discarded.

### F5 — What recurs is the platform substrate; what is novel is the product

Entities appearing in the most apps:

```
user 12/13 · session 11/13 · account 10/13 · verificationtoken 8/13
webhook 6/13 · team 5/13 · apikey 5/13 · invitation 4/13 · integration 4/13
tag 4/13 · organization 3/13 · subscription 3/13 · oauthclient 3/13
passwordresettoken 3/13 · membership 2/13 · workspace 2/13
```

Per-app v0 breakdown, catalog-covered versus novel:

| app | covered by catalog | novel |
| --- | --- | --- |
| umami | session | event, pageview, website |
| rallly | user, comment | poll, option, participant, vote |
| ghostfolio | user | order, marketdata, platform, access, settings |
| inbox-zero | user, session, account, verificationtoken | rule, action, executedrule, label |
| documenso | user, document | recipient |
| cal.com | user, team, membership, booking, eventtype, webhook, payment, schedule, credential | attendee, availability, selectedcalendar, destinationcalendar |

In every case the novel entities *are the reason the product exists*. This is
not a catalog failure. **The data model is where differentiation concentrates by
definition** — if a catalog covered it, the app would not be a product.

## Interpretation

The claim was about **code**, and this probe measured **schema**. Those come
apart, and the way they come apart is the actual finding:

> "80% of the code is already written" and "80% of the entities are already
> written" can both be true and false respectively — because the code that
> repeats is precisely the code that is *generic over* the domain model.

A table view, detail form, filter, sort, pagination, search, bulk select, empty
state, CRUD endpoint, validation, ownership check, role scoping, audit trail,
notification, retry — none of these care whether the entity is a `Poll` or an
`Order`. That polymorphism is why Knack works at all: its views are generic over
any table. The entity layer is the one family where recurrence *should* be low,
and this probe measured exactly that family.

## Decisions

1. **Do not build a lifting program to acquire the generic entity core.** The
   recurring set is ~58 entities, dominated by ~15 that appear in a third or
   more of applications. That is direct authoring work, not an ecosystem
   problem. Lifting is the wrong tool for this family.
2. **Treat the recurring set as a market map, not a disappointment.**
   `user + session + account + verificationtoken` is Clerk/Auth0.
   `organization + membership + invitation` is WorkOS. `subscription` is Stripe
   billing. `webhook` is Svix. `apikey` is Unkey — which is itself in this
   corpus. Each recurring cluster is a company that exists because that thing
   is worth not writing.
3. **Relocate the 80% hypothesis to the domain-polymorphic families** —
   view/form, authority/permission, workflow/state, and CRUD plumbing — and
   probe there before building more machinery.
4. **Change the corpus class for catalog work.** Generic-over-entity code lives
   in frameworks and component libraries, not in applications' schemas.
   Applications were the artifact class *least* likely to show recurrence.
5. **The entity family still needs its vocabulary**, earned by lifting, for
   representing a user's own domain model. That is a different job from
   populating a catalog, and it stays.

## Limitations

- One vocabulary family. Says nothing about view/form, authority, or workflow.
- Name-based matching. The structural alternative was tested and discarded as
  noise (F4), so synonym-level recurrence that a semantic matcher would find
  remains **an open question, not a settled one**.
- Prisma/TypeScript-SaaS corpus: aligned with the target market, not universal.
- The v0 cohort is 6 apps.
- Measures declared schema, not lowered implementation. Two apps sharing `user`
  may still need different auth realizations.

## Reproduction

Fetch and analysis scripts, plus both corpora, are in this session's scratchpad
(`fetch2.py`, `analyze.py`, `analyze_v0.py`, `analyze_struct.py`,
`null_test.py`). They are not yet committed.

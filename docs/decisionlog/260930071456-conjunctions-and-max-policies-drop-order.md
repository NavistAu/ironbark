---
id: "DEC-260930071456"
title: "Conjunction policy names and IRONBARK_MAX_POLICIES with a fixed drop order"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of secrets needing both a target and a person, facing an
  unbounded requested-policy list, we decided for conjunction names plus a cap
  that drops attribute names in fixed order, against no cap, to achieve bounded
  deterministic mints, accepting silently narrowed grants when capped.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "policy"]
supersedes: []
---

# Conjunction policy names and IRONBARK_MAX_POLICIES with a fixed drop order

## Context and Problem Statement

Vault grants are a union of policies, so "target `prod` AND team `ops`"
cannot be expressed by holding `.target/prod` and `.team/ops`. A
secret limited to people on one target needs its own name. With up to 8
target prefixes, an actor and many teams, the request can grow large;
Vault has no explicit cap, but mint size and audit volume grow with it.

## Decision Drivers

* Express "this target and this person/team" without Vault identity templating.
* Keep the mint bounded and the outcome deterministic.
* Dropping must only narrow, never touch P1/P2 or the actor.

## Considered Options

* Conjunctions `.target-actor`/`.target-team` per target prefix; cap (default 64, ≥ 3) dropping team conjunctions, actor conjunctions, teams, then targets (deepest first; reverse team order on ties)
* Conjunctions with no cap
* No conjunctions; target and actor/team as independent grants only

## Decision Outcome

Chosen option: "Conjunctions with a fixed-order cap", because
conjunctions are the only union-safe way to require two attributes, and
a cap with a documented drop order keeps large team sets from producing
oversized or unpredictable requests. Dropped names are audited.

### Consequences

* Good, because narrowing to people on a target is expressible and grant-only.
* Good, because the kept and dropped sets are deterministic and tested.
* Bad, because a capped request loses the most specific grants first, which an operator sees only in `policies_dropped`.

## Pros and Cons of the Options

### Conjunctions with a cap

* Good, because bounded and predictable.
* Bad, because the drop order is one more rule to learn.

### No cap

* Good, because nothing is ever dropped.
* Bad, because request size grows with team count × target depth.

### No conjunctions

* Good, because fewer names.
* Bad, because a target-only policy grants anyone who can name the target.

## More Information

Design §3; plan decisions D1 (request order) and D2 (tie-break). SPEC §2.3, §8.1.

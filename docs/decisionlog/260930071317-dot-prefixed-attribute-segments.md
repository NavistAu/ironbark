---
id: "DEC-260930071317"
title: "Dot-prefixed attribute segments and whole-prefix target escaping"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of naming attribute policies under P1, facing collisions with
  escaped branches and nested targets, we decided for reserved dot-prefixed
  segments with each target prefix escaped whole, against plain segment names,
  to achieve collision-free non-nesting names, accepting escaped-looking names.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "naming", "encoding"]
supersedes: []
---

# Dot-prefixed attribute segments and whole-prefix target escaping

## Context and Problem Statement

Attribute policies hang off P1 (`<prefix>/<org>/<repo>/<event>`), the
same parent as P2 (`P1/<esc(branch)>`). A plain segment such as
`P1/target/…` equals the tier of a branch literally named `target`, and
a target `a/b` kept as two segments makes `.target/a` a path-prefix of
`.target/a/b`, so a trailing-`*` policy for one target reads the other.

## Decision Drivers

* No attribute name may equal or nest another name or P2.
* Attacker-chosen values (branch, target, actor, team) must not forge a shape.
* Reuse the existing injective `esc` rather than a second encoding.

## Considered Options

* Dot-prefixed segments (`.target`, `.actor`, `.team`, `.target-actor`, `.target-team`), whole-prefix `esc(T)`
* Plain segments (`target`, `actor`, …) with per-segment target escaping
* A separate policy prefix per attribute kind

## Decision Outcome

Chosen option: "Dot-prefixed segments with whole-prefix esc(T)", because
`esc` never emits a leading dot, so no escaped value can equal a reserved
segment, and escaping each target prefix whole makes every target one
segment, giving each shape a fixed segment count.

### Consequences

* Good, because `a/.actor/x` escapes to `a%2f.actor%2fx` under `.target`, never a conjunction.
* Good, because even a trailing-`*` attribute policy reaches no other attribute prefix.
* Bad, because names like `.target/a%2fb` are unfriendly to hand-write; raw-HTTP writers must send `%25`.

## Pros and Cons of the Options

### Dot-prefixed, whole-prefix esc

* Good, because collision freedom follows from an existing, property-tested invariant.
* Bad, because `%` in policy names and KV paths needed verification on both products (integration-tested).

### Plain segments

* Good, because readable.
* Bad, because a branch named `target` collides, and nested targets nest.

### Separate policy prefix per kind

* Good, because no shared parent with P2.
* Bad, because it widens the token role glob and splits a repo's policies across trees.

## More Information

Design §3. SPEC §2.2–§2.4. Relies on the `esc` contract of DEC-260711114103 (never dot-prefixed, injective); changes nothing in it.

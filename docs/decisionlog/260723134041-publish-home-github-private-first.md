---
id: "DEC-260723134041"
title: "Publish home: GitHub NavistAu/ironbark, canonical, private-first flip"
status: accepted
date: 2026-07-23
y-statement: >-
  In the context of publishing ironbark, facing the need for public contribution
  workflows and trustworthy CI, we decided for GitHub as canonical, private then
  flipped public, internal forge pull-mirroring it, against making the forge
  canonical with a push mirror.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "repository", "process"]
supersedes: []
---

# Publish home: GitHub NavistAu/ironbark, canonical, private-first flip

## Context and Problem Statement

ironbark was developed on a private forge. Publishing requires a home where
strangers can file issues, open PRs, and see trustworthy CI — while the
authors' own deployment (driven from their forge) must keep working.

## Decision Drivers

* Public PRs must get CI checks; that requires CI native to the public host.
* The NavistAu GitHub org already hosts published tools (beachcomber) —
  established precedent and audience.
* The internal deployment must not depend on manual sync.
* Everything before the public flip must remain freely revisable.

## Considered Options

* GitHub canonical, internal forge pull-mirrors (chosen)
* Internal forge canonical, push-mirror to GitHub
* Dual-primary (manual sync)

## Decision Outcome

`NavistAu/ironbark` on GitHub is canonical. The repo is created **private
first**; CI, release plumbing, and the docs-quality gate are proven there;
the public flip happens only when the pre-flight gate in the publish plan
passes. The authors' forge becomes a pull mirror consuming GitHub.

### Consequences

* Good, because public contribution is first-class from day one.
* Good, because the flip-public moment is the only irreversible step and
  everything is rehearsed before it.
* Bad, because the authors' deployment now depends on mirror freshness —
  acceptable; pull mirroring is automatic.

## Pros and Cons of the Options

### GitHub canonical, internal forge pull-mirrors

* Good, because issues, PRs, and CI live where contributors are.
* Good, because the internal deployment consumes the mirror with no
  workflow change.
* Bad, because the canonical home moves off infrastructure the authors
  control.

### Internal forge canonical, push-mirror out

* Good, because no repo move.
* Bad, because GitHub PRs would land on a mirror — second-class,
  perpetually racing the push; rejected.

### Dual-primary (manual sync)

* Good, because both sides feel first-class.
* Bad, because manual sync guarantees divergence; rejected outright.

## More Information

Publish plan: docs/plans/2026-07-23-publish.md (W2 covers the private
repo bring-up and pre-flight gate). Related: DEC-260723134042 (release model on
the new home), DEC-260723134044 (content genericization gating the public flip).

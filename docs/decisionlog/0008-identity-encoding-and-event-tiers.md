---
id: "DEC-0008"
title: "Identity encoding: branch case preserved injectively; event-tier mapping"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of deriving policy names and KV paths from forge-set
  identity, facing attacker-chosen branch names (case variants,
  delimiters, path-special strings) and unverified branch fields on some
  events, we decided for lowercasing org/repo/event while preserving
  branch bytes through injective percent-encoding (uppercase and leading
  dots encoded; output lowercase, single-segment, never dot-prefixed),
  with branchful tiers only for push/pull_request/pull_request_closed/
  release/cron and event-tier-only handling for manual/deployment/tag and
  unknown events, and against case-folding branch names and against
  rejecting unknown events, to achieve escalation-proof injective naming
  aligned with Vault's policy lowercasing and Woodpecker's secret
  matching, accepting that case-colliding repo names remain an
  operator-flagged concern and unknown events get only coarse tiers.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["convention", "encoding", "security-model", "spec-acceptance"]
supersedes: []
---

# Identity encoding: branch case preserved injectively; event-tier mapping

## Context and Problem Statement

Source verification showed `pipeline.Branch` is per-event: target branch
on PRs, empty on tags, caller-supplied on manual, inherited on deploy.
Vault lowercases policy names; Woodpecker matching is effectively
lowercase. Review cycle 2 found that case-folding the branch would
collapse an attacker's branch `Main` onto protected `main`'s tier — a
privilege escalation, since git refs are case-sensitive and protection
binds to the exact name. Cycle 3 added that path-special outputs
(`.`, `..`, dot-prefixed) must be impossible.

## Decision Drivers

* Branch names are the one attacker-chosen input in the naming scheme.
* Encoding must be injective end-to-end and survive Vault's lowercasing.
* Branch fields on manual/deploy events are not forge-verified.

## Considered Options

* Case-preserving injective escape + event-tier map (chosen)
* Lowercase everything (original draft)
* Reject non-lowercase or path-special branch names with 400

## Decision Outcome

Chosen option: `esc()` percent-encodes every byte outside
`[a-z0-9._-]`, always encodes `%` and any LEADING `.`; uppercase is
encoded, not folded (`Main` → `%4dain`). Org/repo/event are lowercased
(forges enforce case-insensitive owner/repo uniqueness; IaC/doctor flag
collisions). Branchful events: push, pull_request, pull_request_closed,
release, cron. manual/deployment/tag and unknown events derive the event
tier only. Unknown events are accepted, lowercased, logged.

### Consequences

* Good, because the `Main`-vs-`main` escalation is structurally impossible.
* Good, because no output is ever `.`, `..`, or dot-prefixed — no path
  tricks, no directive-namespace collisions.
* Bad, because escaped branch names are less pretty in Vault paths
  (`%4dain`) — the IaC module generates them, humans rarely read them.

## Pros and Cons of the Options

### Case-preserving escape

* Good, because injective and lowercase-stable simultaneously.
* Bad, because cosmetically noisy for unusual branch names.

### Lowercase everything

* Good, because uniform.
* Bad, because provably escalation-prone (review C2-3) — disqualifying.

### Reject unusual names

* Good, because simplest encoding.
* Bad, because breaks legitimate mixed-case branch workflows and adds a
  failure mode where encoding suffices.

## More Information

SPEC.md §2.1–§2.3. Review trail: C2-3, G3-1, C6.
Facts: mechanisms doc §6; research doc §7.2.

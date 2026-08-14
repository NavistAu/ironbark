---
id: "DEC-260711114104"
title: "Sweep and response semantics: independent tiers, specific-wins, string-only"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of returning masked secrets from the KV subtree, facing tier
  isolation via 403s, we decided for independent per-tier sweeps, most-specific-
  wins, string-only values, against discovery-based descent and value coercion,
  to achieve deterministic least-privilege-tolerant responses.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["convention", "sweep", "spec-acceptance"]
supersedes: []
---

# Sweep and response semantics: independent tiers, specific-wins, string-only

## Context and Problem Statement

The sweep is where the convention meets Vault ACL reality. Review cycles
found four defects in the draft semantics: discovery-based descent broke
least-privilege policies (a tier-only grant yielded nothing); sweep order
plus first-writer-wins made the LEAST specific secret win collisions;
non-string JSON values would break Woodpecker's response decode
(fail-open); and the empty-response rule was ambiguous with `vault_addr`
configured.

## Decision Drivers

* Partial 403 visibility IS the tiering mechanism — the sweep must
  tolerate any subset of tiers being readable.
* Responses must be deterministic and safe for Woodpecker to decode.
* Un-onboarded repos must resolve to a clean 204, detected via mint
  warnings, with no dangling token.

## Considered Options

* Independent tier LISTs, specific-first, string-only (chosen)
* Discovery descent from the base (original draft)
* Value coercion (stringify non-string values)

## Decision Outcome

Chosen option: as specified in SPEC.md §4 and §6. The three tier
prefixes are derived a priori and LISTed independently, most specific
first (branch → event → base; lexicographic within a level);
first-writer-wins therefore means most-specific-wins. Keys beginning
with `.` are never secrets at any level. Values must be JSON strings —
anything else is skipped with a warning, never coerced. Entry forms:
`{"value": v}` shorthand → secret named `E`; general map → `E_f` per
field; `{"$ref": path}` → one-level dereference under the pipeline's own
token. `vault_addr` never counts toward emptiness; empty-and-suppressed,
un-onboarded, and identity-mismatch outcomes revoke and return 204.

### Consequences

* Good, because a policy granting only one tier works (least privilege).
* Good, because collision behavior matches operator intuition (specific
  overrides general).
* Good, because malformed values cannot poison the whole response.
* Bad, because nesting deeper than the three conventional levels is
  invisible in v1 (documented constraint).

## Pros and Cons of the Options

### Independent tiers, specific-first, string-only

* Good, because closes all four review findings at once.
* Bad, because three LISTs per request even when tiers are absent.

### Discovery descent

* Good, because fewer calls on sparse repos.
* Bad, because ancestor list-permission becomes load-bearing —
  disqualifying for least-privilege policies (review C2).

### Value coercion

* Good, because nothing is dropped.
* Bad, because coerced values (float formatting, nested JSON) are
  surprising and unauditable; skip-with-warning is honest.

## More Information

SPEC.md §4, §6. Review trail: G2, C2, C3, C4, C7, G3-3.

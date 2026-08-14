---
id: "DEC-260711061323"
title: "Stateless broker: convention over Vault, no configuration tables"
status: accepted
date: 2026-07-11
y-statement: >-
  In ironbark's policy model, facing config drift from a broker-side rule table,
  we decided for a stateless broker deriving names from convention, against a
  rule table and yaml-declared fetch lists, to achieve single-authority
  onboarding, accepting the tree must match convention.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["architecture", "policy-model", "statelessness"]
supersedes: []
---

# Stateless broker: convention over Vault, no configuration tables

## Context and Problem Statement

The original design gave ironbark a declarative rule table mapping
`(repo, branch, event)` to token-roles, policies, and TTLs. Adding value
return (DEC-260711061322) would have grown that into per-repo fetch lists too — a
partial policy engine, explicitly a non-goal. The user requirement: ironbark
holds no rule tables or path maps. A constraint shapes the solution: the
secret-extension request carries only `{repo, pipeline}` (forge-set
metadata); Woodpecker never sends the `.woodpecker.yaml` or requested secret
names, so the CI job configuration *cannot* declare paths to ironbark.

## Decision Drivers

* Single source of authority: Vault already owns policy; a broker-side table
  is a second place that must agree with it.
* Onboarding a repo should touch only Vault (policies + KV entries), no
  broker redeploy or config edit.
* Protocol reality: no channel exists for yaml-declared fetch lists.
* Vault policies are not enumerable from a token, so "return everything this
  token can read" is impossible; a *conventional location* is the only
  stateless way to know what to fetch.

## Considered Options

* Ironbark-side rule table (original design)
* Fetch lists declared in `.woodpecker.yaml`
* Fixed convention over the Vault tree; Vault-side data decides what exists
  (chosen)

## Decision Outcome

Chosen option: "Convention over Vault". ironbark becomes a pure function of
the signed payload: derive conventional policy names from
`(org, repo, event, branch)` and request them all (nonexistent policies
attach harmlessly and grant nothing — which tiers exist is Vault-side data);
mint against a single glob-backstopped token-role; sweep the conventional KV
subtree `kv/ci/<org>/<repo>/…` with the minted token, tolerating partial
denials (the 403s *are* the tiering mechanism); TTL from the role. ironbark's
entire config: Woodpecker public key, Vault address, its own AppRole, and
the convention templates.

### Consequences

* Good, because onboarding = Vault-side IaC only; ironbark never redeploys
  for a new repo.
* Good, because ironbark's domain of authority shrinks to a naming
  convention; all real policy lives where it is enforced.
* Good, because there is no state to back up, replicate, or drift.
* Bad, because correct operation depends on the Vault tree matching
  convention exactly; typo'd policy names fail silently and over-wide globs
  fail open — motivating DEC-260711061325.
* Bad, because the KV path layout must mirror the policy convention
  (event/branch tiers in the path) or the sweep breaks tiering.
* Bad, because path/policy-name encoding of attacker-chosen branch names
  must be injective (delimiter-injection-proof) — a load-bearing detail.

## Pros and Cons of the Options

### Ironbark-side rule table

* Good, because arbitrary per-repo flexibility.
* Bad, because a second source of authority that must agree with Vault.
* Bad, because per-repo onboarding touches broker config.

### Fetch lists in .woodpecker.yaml

* Good, because paths visible in the repo (would have been fine
  security-wise: the minted token's policy still gates all reads).
* Bad, because protocol-impossible — the extension request has no channel
  for it. Only realizable as token-mode (pipeline curls), which loses
  masking.

### Convention over Vault

* Good, because stateless, single-authority, onboarding-in-Vault.
* Bad, because convention correctness becomes operationally critical.

## More Information

Builds on DEC-260711061322. The misconfiguration failure modes drive DEC-260711061325
(IaC module + doctor). Working choice: one glob token-role (`ci`) for M1;
per-repo roles stamped by the IaC module remain a hardening option for a
stronger per-repo backstop.

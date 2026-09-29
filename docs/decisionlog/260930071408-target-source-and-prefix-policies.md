---
id: "DEC-260930071408"
title: "Target from deploy_to or a configured manual variable, with path-prefix policies"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of scoping monorepo deploys, facing one grant per event and
  branch, we decided for a target from deploy_to or IRONBARK_TARGET_VAR with a
  policy per path prefix and a strict grammar, against exact-match targets, to
  achieve component-level scopes, accepting caller-chosen targets.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "identity", "policy"]
supersedes: []
---

# Target from deploy_to or a configured manual variable, with path-prefix policies

## Context and Problem Statement

In a monorepo every pipeline of one event and branch receives the same
grant. Woodpecker carries a deploy target in `deploy_to` for deployment
events; manual runs carry caller-set `variables`. The target is free text
chosen by whoever can trigger the run, and a per-repo `.config` override
cannot choose the variable because `.config` is read only after the mint.

## Decision Drivers

* Admins scope a secret to a component (`api`) or a finer target (`api/eu`).
* Hostile or malformed targets must never widen a grant.
* The target must be known before the mint, from payload plus env config.

## Considered Options

* `deploy_to` (deployment) or `variables[IRONBARK_TARGET_VAR]` (manual); a policy per `/`-prefix; grammar ≤ 8 non-empty segments, ≤ 256 bytes, else no target
* Exact-match target only (one policy per full target)
* `deploy_to` only, no manual-run target

## Decision Outcome

Chosen option: "deploy_to or configured manual variable, prefix policies,
strict grammar", because prefix policies let the admin create the policy at
the depth that owns the scope, and an invalid target degrades to no target
policies rather than an error.

### Consequences

* Good, because `api` covers `api/eu` and `api/us` without enumerating them.
* Good, because manual deploys (the common Gitea/Forgejo path) get targets too.
* Bad, because anyone who can trigger the event can name any target; restricting people needs a conjunction.

## Pros and Cons of the Options

### Prefix policies from deploy_to or a manual variable

* Good, because one policy per component depth.
* Bad, because up to 8 target names per request feed the policy cap.

### Exact-match only

* Good, because fewer requested names.
* Bad, because every sub-target needs its own policy and data copy.

### deploy_to only

* Good, because a single, server-set source.
* Bad, because Gitea/Forgejo have no deployment webhook; manual runs are their deploy path.

## More Information

Design §1, §5. SPEC §2.1, §2.3.

---
id: "DEC-260930071432"
title: "Optional forge team resolution that fails closed; attribute policies are grant-only"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of team-scoped pipeline secrets, facing a forge call on the
  request path, we decided for optional forge-owned team lookup that fails
  closed to no team policies, against failing the request, to achieve pipelines
  unaffected by forge outages, accepting that attribute policies cannot carry denies.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "forge", "security"]
supersedes: []
---

# Optional forge team resolution that fails closed; attribute policies are grant-only

## Context and Problem Statement

Teams are not in the payload; they must be read from the forge (Gitea
family first) during the request. The forge can be slow or down, and
any attribute can also be absent for other reasons (no target, empty
actor, a name dropped by the policy cap). The choice is what a failed
lookup does, and so what team and attribute policies may express.

## Decision Drivers

* A forge outage must not stop CI.
* Vault stays the authority over what a grant is; the forge only says who is in a team.
* An absent attribute must never widen a grant.

## Considered Options

* Optional lookup; any failure fails closed (no team policies, request continues, audited); attribute policies are grant-only
* Fail the request (502) when the lookup fails, so team policies may carry `deny`
* No team support; actor and target only

## Decision Outcome

Chosen option: "Optional lookup, fail closed, grant-only", because a
lookup failure then only narrows a grant. The consequence is the rule
that attribute policies are grant-only as a security boundary: a `deny`
in an attribute policy is lifted by exactly the pipelines it targets
whenever the attribute is absent, so narrowing is done by placing a
secret only under the prefix that should reach it.

### Consequences

* Good, because a forge outage costs only team-scoped secrets, visible as `teams_error`.
* Good, because the same rule covers every absent attribute and every capped name.
* Bad, because the forge becomes the authority over team membership: whoever edits a team widens its grant.

## Pros and Cons of the Options

### Fail closed, grant-only

* Good, because availability does not depend on the forge.
* Bad, because deny-style narrowing via attributes is unavailable.

### Fail the request

* Good, because team policies could carry denies safely.
* Bad, because every forge hiccup fails every actor pipeline.

### No team support

* Good, because no forge call and no new trust.
* Bad, because per-person policies do not scale to groups.

## More Information

Design §2, §3; the design's "grant-only" item is recorded here rather than
as a separate entry, since its only alternative is this entry's
fail-the-request option. SPEC §2.3, §2.5.

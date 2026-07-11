---
id: "DEC-0007"
title: "Minted-token lifecycle: orphan non-renewable service tokens, canary-gated"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of the per-pipeline tokens ironbark mints, facing lease
  parenting, revocation needs, renewal escape, and silent role
  misconfiguration, we decided for orphan non-renewable service tokens
  minted against a role contract (token_type=service forced,
  renewable=false, token_no_default_policy=false, glob covering the
  convention) enforced at runtime by a startup canary that hard-gates
  minting plus a per-mint token_type assertion, with revocation by
  outcome (every non-200 revokes via revoke-self, cascading leases; a 200
  never revokes), and against batch tokens, renewable tokens, num_uses
  caps, and role-read preflight, to achieve TTL as the single absolute
  lifetime bound and fail-closed behavior on misconfiguration without
  widening ironbark's create-only Vault footprint, accepting that
  operators must configure the role exactly as documented.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["security-model", "vault", "spec-acceptance"]
supersedes: []
---

# Minted-token lifecycle: orphan non-renewable service tokens, canary-gated

## Context and Problem Statement

Research established (all source-verified): batch-token leases parent to
the batch token's PARENT — i.e. ironbark's own credential; service-token
revocation cascades to child leases; token roles can hard-force
token_type; the default policy's renew-self would let a leaked token
outlive its TTL; and roles bypass the child-subset rule with only the
root-policy guard surviving. Cross-AI review then showed the role
contract's settings fail silently if misconfigured, and that revocation
and renewal behavior needed pinning.

## Decision Drivers

* Pipeline STS lease lifetime must bind to the pipeline token, not
  ironbark's AppRole session (DEC-0003).
* "Leaked token dies in minutes" must be literally true — no renewal
  escape, no unbounded lifetime.
* ironbark's Vault identity stays create-only; no role-read permission.
* Misconfiguration must fail loudly, not silently mint unsafe tokens.

## Considered Options

* Orphan non-renewable service tokens + canary hard gate (chosen)
* Batch tokens (cheaper, no storage)
* Role-read preflight (ironbark reads role config at startup)
* Documentation-only role contract

## Decision Outcome

Chosen option: as specified in SPEC.md §3. Role contract:
`token_type=service`, `orphan=true`, `renewable=false`,
`token_no_default_policy=false`, glob covering the convention prefix.
Runtime enforcement without new permissions: a startup canary mint
(nonexistent conventional policy, asserts service/non-renewable/
revoke-self, then revokes itself) is a HARD GATE — failed/unknown canary
→ POST 502 with no mint; plus a per-mint token_type assertion. num_uses
is not used (every API request consumes a use — incompatible with the
sweep and the returned token). Revocation is by outcome: every non-200
revokes (cascading any deref leases — correct cleanup since nothing was
delivered); a 200 never revokes.

### Consequences

* Good, because TTL is the one lifetime bound, enforced by construction.
* Good, because misconfigured roles stop the service loudly instead of
  minting unsafe tokens.
* Good, because pipeline tokens survive ironbark credential rotation
  (orphan).
* Bad, because a canary failure blocks all pipelines until fixed
  (deliberate fail-closed).
* Bad, because orphan tokens mean ironbark cannot mass-revoke its
  children by revoking itself (TTL is the cleanup).

## Pros and Cons of the Options

### Orphan non-renewable service + canary gate

* Good, because every research-verified hazard is closed.
* Bad, because more moving parts (canary state machine).

### Batch tokens

* Good, because no token storage in Vault.
* Bad, because leases would parent to ironbark's own token — disqualifying.

### Role-read preflight

* Good, because direct config inspection.
* Bad, because widens the create-only footprint; mint-response assertion
  achieves the same signal without it.

### Documentation-only

* Good, because zero code.
* Bad, because silent failure modes (review finding G1).

## More Information

SPEC.md §3, §1.2.6. Review trail: G1, C5, C2-1, C2-2, G2-3, C3-1 in
docs/reviews/SPEC-REVIEWS.md. Research: research doc §4, §7.4, §7.6.

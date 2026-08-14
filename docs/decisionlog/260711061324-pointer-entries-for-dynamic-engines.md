---
id: "DEC-260711061324"
title: "Pointer entries dereference dynamic engines into the masked path"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of dynamic engine credentials in ironbark's masked path, facing
  Vault's lack of cross-mount aliasing, we decided for $ref pointer entries
  dereferenced with the pipeline's token, against vault_token-only access and
  baked-in engine paths, to achieve masked, policy-gated delivery.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["convention", "dynamic-secrets", "kv"]
supersedes: []
---

# Pointer entries dereference dynamic engines into the masked path

## Context and Problem Statement

The KV sweep (DEC-260711061322/DEC-260711061323) only reaches the conventional KV subtree.
Dynamic engine credentials — AWS STS via the Vault AWS secrets engine being
the motivating case — live on other mounts, and Vault/OpenBao have no
symlink/alias mechanism to surface them under KV. Without something extra,
dynamic creds are only reachable via the returned `vault_token`, i.e.
unmasked curl territory — the exact ergonomics DEC-260711061322 exists to avoid.

## Decision Drivers

* Dynamic creds are the highest-value secrets (ephemeral, auto-expiring) and
  deserve the masked path most.
* Statelessness (DEC-260711061323): the indirection must live in Vault, not ironbark
  config.
* Authority must stay with Vault policy: an indirection must not be able to
  grant anything the pipeline's policy does not already allow.

## Considered Options

* Dynamic creds via `vault_token` only (pipeline curls the engine)
* Engine paths in ironbark configuration
* `$ref` pointer entries in the KV subtree, dereferenced with the minted
  token (chosen)

## Decision Outcome

Chosen option: "$ref pointer entries". A KV entry whose value ironbark
recognizes as a reference (e.g. `{"$ref": "aws/creds/widgets-deploy"}`)
causes ironbark, during the sweep, to read *that* path with the same minted
token and return the result as masked secrets. Multi-field responses flatten
by convention: entry `aws` yields `aws_access_key`, `aws_secret_key`,
`aws_security_token`. The dereference is a convenience, not an authority:
it happens under the pipeline's own token, so a pointer at anything the
policy does not grant simply 403s and is skipped. Writing the KV subtree
therefore cannot escalate beyond the policy.

### Consequences

* Good, because dynamic credentials arrive masked via `from_secret` like
  everything else; `vault_token` shrinks to genuinely interactive uses.
* Good, because statelessness holds — the pointer is Vault-side data.
* Good, because policy gates every dereference by construction.
* Bad, because leases parent to the minted token: ironbark must not
  revoke-after-fetch when a dereference occurred, and token TTL becomes
  "how long the pipeline's dynamic creds live", covering queue + runtime.
* Bad, because creds are generated eagerly per pipeline whether used or not
  (engine API traffic, Vault audit noise).
* Bad, because a flattening naming convention is now part of the contract.

## Pros and Cons of the Options

### vault_token only

* Good, because zero new mechanism.
* Bad, because the highest-value secrets get the worst (unmasked, curl)
  ergonomics.

### Engine paths in ironbark config

* Good, because explicit.
* Bad, because reintroduces the path map DEC-260711061323 just removed.

### $ref pointer entries

* Good, because masked, stateless, policy-gated.
* Bad, because lease-lifetime coupling to the token TTL.

## More Information

"Who doesn't love a good pointer." Builds on DEC-260711061322/DEC-260711061323. Lease/TTL
interaction is documented as an honest limit in DESIGN.md.

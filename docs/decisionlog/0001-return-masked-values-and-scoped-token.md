---
id: "DEC-0001"
title: "Return masked secret values and a scoped token, not a token alone"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of ironbark's secret-extension response, facing loss of
  Woodpecker's automatic log masking and curl-based pipeline ergonomics under
  a token-only response, we decided for sweeping the pipeline's conventional
  Vault KV subtree with the freshly-minted scoped token and returning the
  values as masked Woodpecker secrets alongside the token, and against a
  token-only response and against a broker holding a standing read credential,
  to achieve full masking and from_secret ergonomics with no standing read
  capability anywhere, accepting that secret values transit ironbark's memory
  transiently and that every pipeline triggers reads of its subtree.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["security-model", "extension-response"]
supersedes: []
---

# Return masked secret values and a scoped token, not a token alone

## Context and Problem Statement

The original DESIGN.md (2026-07-10) had ironbark return only a minted
Vault/OpenBao token; pipelines fetched values themselves with `curl`. That
design was justified as avoiding a "standing decryption oracle", but it cost
Woodpecker's automatic log masking (only the token was masked; fetched values
were not) and forced Vault HTTP plumbing into every consuming pipeline. On
review, the oracle argument was found to be overstated: ironbark's
token-create capability against the CI token-role is *transitive read
capability* for an active attacker — mint a token bearing the target policy,
read with it — so token-only was not buying a categorical security boundary.

## Decision Drivers

* Woodpecker's extension-returned secrets are native secrets: automatically
  masked, `from_secret`-addressable, per-secret event/image pinning.
* Token-only forces `curl`+`jq` incantations and `set +x` discipline into
  every pipeline; values fetched at runtime are never masked.
* The token-only "broker cannot read secrets" claim is transitively false
  under active compromise; the honest deltas are leak-surface and audit
  loudness, not capability.
* No standing read credential should exist anywhere in the system.

## Considered Options

* Token-only response (original design)
* Value-returning broker with its own standing read credential
* Transient mint-then-sweep: values + token, read under the pipeline's own
  minted token (chosen)

## Decision Outcome

Chosen option: "Transient mint-then-sweep", because it recovers full masking
and zero-tooling ergonomics for the common case while preserving every
property token-only actually delivered: ironbark's Vault identity remains
create-only, no standing reader credential exists, every read is performed
under a per-pipeline, policy-scoped, short-TTL token and is audit-logged as
such. The token is still returned (`vault_token`) as the escape hatch for
interactive uses (mid-run renewals, transit, off-convention paths).

### Consequences

* Good, because all conventional secrets arrive masked via `from_secret`
  with no Vault client code in pipeline images.
* Good, because the security posture is unchanged against an active attacker
  and improved in honesty of description.
* Good, because dynamic-engine credentials can also flow through the masked
  path (see DEC-0003).
* Bad, because values transit ironbark's memory transiently each pipeline
  (accepted: nothing at rest, nothing logged).
* Bad, because every pipeline reads its whole visible subtree even if unused
  (Vault audit noise, eager dynamic-cred generation).

## Pros and Cons of the Options

### Token-only response

* Good, because values never transit ironbark at all.
* Bad, because masking is lost for every fetched value.
* Bad, because every pipeline needs curl/jq plumbing and shell discipline.
* Bad, because its headline security claim ("cannot read secrets") is
  transitively false under compromise anyway.

### Standing read credential broker

* Good, because simplest implementation.
* Bad, because a stealable, silent, read-everything credential exists at
  rest; reads need no mint and are indistinguishable in audit.

### Transient mint-then-sweep (values + token)

* Good, because masking, ergonomics, and no-standing-credential all hold.
* Good, because attacker reads still require loud, per-role audited mints.
* Bad, because ironbark touches values transiently and does more Vault I/O
  per pipeline.

## More Information

Supersedes the "What the extension returns: a token" row of the 2026-07-10
DESIGN.md decisions table (pre-dates this decision log; see git history).
See DEC-0002 (statelessness) and DEC-0003 (pointer entries), which build on
this response shape.

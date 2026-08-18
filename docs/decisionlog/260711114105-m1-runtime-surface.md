---
id: "DEC-260711114105"
title: "M1 runtime surface: 10s freshness, env-only config, dual audit shapes"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of ironbark's operational envelope, facing replay risk bounded
  only by a signed timestamp, we decided for a 10-second freshness window, env-
  only config, and dual-shape audit lines, against config files and nonce-based
  replay prevention, accepting in-window replay duplicates.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["operations", "configuration", "spec-acceptance"]
supersedes: []
---

# M1 runtime surface: 10s freshness, env-only config, dual audit shapes

## Context and Problem Statement

Source verification established the replay material available (signed
`created`, no nonce) and review refined the operational edges: the
freshness window default, the contradiction between "log every request's
identity" and "trust nothing before the signature verifies", SIGHUP's
ambiguous status, and the AppRole session's own permission needs.

## Decision Drivers

* The extension call is synchronous server-to-server — freshness can be
  tight.
* Untrusted payload data must never reach logs on refused requests.
* k8s deployment: ESO supplies credentials as files; TLS belongs to the
  mesh/ingress; config files would be a second config surface.

## Considered Options

* As specified (chosen)
* Wider window / config file / in-process TLS variants
* Nonce-based replay prevention

## Decision Outcome

Chosen option: as specified in SPEC.md §1.1, §1.3, §5, §7, §8. Window:
`|now − created| > 10s` rejects (configurable). Config: env vars only,
each secret-bearing var with a `_FILE` variant. Rotation: restart;
SIGHUP explicitly optional, not v1. Audit: refused-signature lines are
`ts, remote_addr, reason, outcome` only; verified lines carry identity
fields, policy warnings, secret NAMES, token accessor — never values,
tokens, or netrc. AppRole session: renewable token retaining `default`;
sole ACL grant is create on the token role; stripped-default degrades to
re-login.

### Consequences

* Good, because replay exposure is one order of magnitude tighter than
  the draft (30s → 10s) at zero cost.
* Good, because a refused request cannot be used to inject attacker
  strings into logs.
* Bad, because in-window byte-identical replays still mint duplicate
  tokens — accepted, documented in the threat table; the duplicate is
  same-identity, short-lived, and audit-visible.
* Bad, because key rotation interrupts service for a restart (seconds,
  k8s rolling).

## Pros and Cons of the Options

### As specified

* Good, because smallest coherent surface; every knob traceable to a
  verified fact or review finding.
* Bad, because SIGHUP users must build it themselves later.

### Nonce-based replay prevention

* Good, because kills replays entirely.
* Bad, because the protocol sends no nonce [WP§8] — would require
  upstream Woodpecker changes; not ours to add.

## More Information

SPEC.md §1, §5, §7, §8. Review trail: G4, C2-4, G2-4, C3-1.
Facts: mechanisms doc §8.

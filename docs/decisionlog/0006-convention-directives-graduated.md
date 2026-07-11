---
id: "DEC-0006"
title: "Convention directives: .identity binding, .config, custom_metadata pins"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of ironbark's stateless KV convention, facing the
  repo-rename inheritance hole, per-repo opt-outs, and per-secret
  event/image pinning without broker config, we decided for reserved
  dot-entry directives (.identity forge-ID binding with fail-closed
  malformation handling; .config flat string-map directives) plus KV v2
  custom_metadata keys (ironbark_images, ironbark_events), and against
  broker-side configuration and yaml-declared metadata (the extension
  protocol has no channel for it), to achieve Vault-resident,
  IaC-writable control data consistent with DEC-0002, accepting extra
  reads per pipeline and fail-closed 502/204 outcomes on malformed
  directives.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["convention", "kv", "spec-acceptance"]
supersedes: []
---

# Convention directives: .identity binding, .config, custom_metadata pins

## Context and Problem Statement

Three mechanisms were proposed in DESIGN.md §5 (2026-07-11) and marked
pending: a forge-remote-ID binding to close the repo-rename/recreate
inheritance hole; a per-repo directive entry for opt-outs (notably
suppressing `vault_token`); and per-secret `events`/`images` pins that
lost their home when the config table was deleted (DEC-0002). Research
confirmed their preconditions (`forge_remote_id` present in the payload;
custom_metadata supported), and SPEC.md §4.4–§4.6 specified them with
fail-closed semantics that survived four adversarial review cycles.

## Decision Drivers

* Statelessness (DEC-0002): control data must live in Vault, not broker
  config.
* Repo rename/recreate inheritance is a real threat-table row.
* A broken directive must never silently degrade (review finding C1).

## Considered Options

* The three directives as specified (chosen)
* Broker-side configuration for pins/bindings
* No mechanism (accept rename inheritance; no opt-outs; no image pins)

## Decision Outcome

Chosen option: the directives as specified in SPEC.md §4.4–§4.6:
`.identity` compares `forge_remote_id` and fails closed on mismatch or
malformation; `.config` is a flat string map (unknown keys ignored,
malformed → 502 + revoke); custom_metadata keys `ironbark_images` /
`ironbark_events` become the returned secret's pins. Dot-entries are
never returned as secrets at any level.

### Consequences

* Good, because onboarding tooling (M2 IaC module) writes all three —
  humans never hand-edit.
* Good, because rename protection is opt-in per repo and verifiable.
* Bad, because each pipeline pays extra reads (directives + metadata).
* Bad, because fail-closed malformation handling can 502 a repo until an
  operator fixes a broken directive (accepted deliberately).

## Pros and Cons of the Options

### Directives as specified

* Good, because stateless and IaC-writable.
* Bad, because more per-request Vault I/O.

### Broker-side configuration

* Good, because fewer Vault reads.
* Bad, because reintroduces the config table DEC-0002 deleted.

### No mechanism

* Good, because simplest.
* Bad, because rename inheritance stays open and image pinning is lost.

## More Information

Graduates the DESIGN.md §5 proposals. Spec: SPEC.md §4.4–§4.6.
Review trail: docs/reviews/SPEC-REVIEWS.md (C1, G3-1, G3-3).

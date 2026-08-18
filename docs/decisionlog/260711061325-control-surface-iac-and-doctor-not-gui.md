---
id: "DEC-260711061325"
title: "Control surface is IaC plus a doctor CLI, not a GUI"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of ironbark's convention-critical Vault config, facing silent-
  failure and fail-open misconfiguration, we decided for a Terraform module plus
  a read-only doctor lint, against a GUI management plane and hand
  configuration, to achieve machine-generated onboarding with no new credential.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["milestones", "operations", "iac"]
supersedes: []
---

# Control surface is IaC plus a doctor CLI, not a GUI

## Context and Problem Statement

DEC-260711061323 moved all authority into Vault-side convention. The convention's
weakness is that admins must configure Vault pitch-perfectly: a typo'd
policy name attaches harmlessly and grants nothing (pipelines just 403,
silently), and a fat-fingered `allowed_policies_glob` fails open. Some
control surface is needed. Candidates ranged from IaC modules through a
management UI to a custom Vault plugin (the latter recorded as a research
note, DESIGN.md §12).
Framing adopted: IaC is a form of UI; UI is not GUI — and a GUI has little
value inside an already-automated space.

## Decision Drivers

* Both misconfiguration modes (silent-fail, fail-open) are eliminated by
  machine-generating the convention names rather than hand-writing them.
* The delimiter-injection footgun in name encoding disappears when humans
  never write the names.
* Anything that *writes* Vault policy holds escalation-to-anything
  capability; a standing credentialed management service is a large new
  blast radius right after ironbark's own state was deleted.
* Vault and OpenBao already ship UIs for inspection.
* Terraform/OpenTofu's Vault provider is shared by Vault and OpenBao.

## Considered Options

* Generic Terraform/OpenTofu module + `ironbark doctor` read-only lint
  (chosen)
* Web GUI management plane with policy-write capability
* Documentation only; admins hand-configure

## Decision Outcome

Chosen option: "IaC module + doctor". Milestone 2 ships (a) a generic
`ironbark-repo` Terraform/OpenTofu module living in the ironbark repo that
stamps out the per-repo unit — convention-correct policies, KV skeleton,
pointer entries — consumed by estate-specific integration code elsewhere;
and (b) `ironbark doctor`, a CLI subcommand that lints a Vault instance
against the convention (role exists, glob not over-wide, policy names parse
to convention, KV subtrees not orphaned from any policy). Doctor is
read-only and takes its own admin-ish credential at invocation rather than
widening the server's create-only AppRole. No GUI; drop unless a concrete
need survives M2.

### Consequences

* Good, because onboarding a repo is one `module` block; names are never
  hand-written.
* Good, because no new standing credentialed service exists.
* Good, because doctor catches drift/misconfiguration cheaply.
* Bad, because doctor needs Vault read permissions beyond the server's
  footprint — handled by a separate invocation-time credential.
* Bad, because the module is a second maintained, versioned artifact.

## Pros and Cons of the Options

### IaC module + doctor

* Good, because kills both failure modes at the source.
* Good, because fits an estate already managed as code.
* Bad, because assumes Terraform/OpenTofu in the adopter's toolchain
  (doctor still helps hand-configured installs).

### Web GUI management plane

* Good, because approachable for non-IaC users.
* Bad, because must hold policy-write capability = escalation-to-anything;
  needs its own authn/authz/audit; reintroduces a stateful service.
* Bad, because redundant with Vault/OpenBao's own UIs for inspection.

### Documentation only

* Good, because zero artifacts.
* Bad, because leaves both silent-fail and fail-open modes to human
  discipline.

## More Information

Depends on DEC-260711061323. Custom Vault plugin alternative recorded as a
research note in DESIGN.md §12.

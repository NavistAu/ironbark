---
id: "DEC-260930071344"
title: "Actor source per event; deployments have no actor; push actor only on a declared forge"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of deriving a pipeline's actor, facing sender and author
  fields whose meaning varies by forge and event, we decided for manual=author,
  push-family=sender only on an operator-declared forge, deployment=none, against
  sender everywhere, to achieve a trustworthy actor, accepting fewer actor grants.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "identity"]
supersedes: []
---

# Actor source per event; deployments have no actor; push actor only on a declared forge

## Context and Problem Statement

The signed payload carries `sender` and `author`, but neither means "who
acted" everywhere (Woodpecker v3.18.0 source). GitLab sets no `sender` on
push and a committer-settable display name on release; Bitbucket Data
Center sets none; a Woodpecker promotion copies the parent's `sender`; a
manual run has an empty `sender` and the starter's login in `author`. The
payload does not say which forge sent it.

## Decision Drivers

* An actor policy must only fire for the person it names.
* Nothing in the payload identifies the forge, so the operator must.
* Safe default: a new deployment grants no push-family actor policies.

## Considered Options

* Per-event source; push-family `sender` only when `IRONBARK_ACTOR_FORGE` declares a login forge (default `none`); deployment has no actor
* `sender` on every event
* Push-family actor defaulting to `gitea` when the team provider is `gitea`

## Decision Outcome

Chosen option: "Per-event source, declared forge, default none", because
it never treats a display name, a parent's sender or a deployment creator
as the actor. Maintainer ruling (2026-09-30): `IRONBARK_ACTOR_FORGE`
defaults to `none` unconditionally, superseding the design's earlier
"`gitea` when the provider is `gitea`"; with provider `gitea` only
`gitea` or `none` is accepted.

### Consequences

* Good, because a GitLab display name or an inherited sender can never match an actor policy.
* Good, because enabling team lookup alone does not silently start push-family actor grants.
* Bad, because promotions cannot be scoped to a person until Woodpecker records the promoter.

## Pros and Cons of the Options

### Per-event, declared forge, default none

* Good, because each source is used only where its meaning is verified.
* Bad, because an operator must set two vars to get push actor plus teams.

### sender everywhere

* Good, because simplest.
* Bad, because GitLab release senders are committer-chosen display names and promotions carry the parent's sender.

### Default gitea with a gitea team provider

* Good, because one var enables both on Gitea.
* Bad, because turning on teams would implicitly change which push pipelines get actor grants.

## More Information

Design §1, §2, §Payload facts; plan "Maintainer rulings" 1. SPEC §2.1, §7.

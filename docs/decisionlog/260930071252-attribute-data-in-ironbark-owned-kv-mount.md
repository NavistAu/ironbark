---
id: "DEC-260930071252"
title: "Attribute data in an ironbark-owned KV mount; existing tiers stay put"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of pipeline-attribute secrets, facing tier policies whose kv/
  globs can reach any path under the repo, we decided for a separate
  ironbark-owned KV v2 mount and against nesting attribute data under kv/, to
  achieve isolation by mount path, accepting a second operator-created mount.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "kv-layout", "security"]
supersedes: []
---

# Attribute data in an ironbark-owned KV mount; existing tiers stay put

## Context and Problem Statement

Pipeline attributes (target, actor, team) add policies that grant KV
prefixes. Operators already write tier policies on `kv/`, and the
published README example itself used a repo-root `*` that crossed tiers.
Any attribute prefix placed under `kv/ci/<org>/<repo>/…` is reachable by
such a glob, so an ordinary tier token could read attribute-gated data.

## Decision Drivers

* A `kv/` policy of any shape must never reach attribute data.
* No migration of existing P1/P2 data; repos without attributes unchanged.
* Isolation must not rely on operators writing tight globs.

## Considered Options

* Separate ironbark-owned KV v2 mount (`IRONBARK_ATTR_MOUNT`, default `ironbark`)
* Attribute prefixes under the existing `kv/` tiers
* Move all tiers, old and new, into a new mount

## Decision Outcome

Chosen option: "Separate ironbark-owned KV v2 mount", because ACL paths
begin with the mount, so no policy on `kv/` can match attribute data
whatever glob it uses, and existing tiers need no migration.

### Consequences

* Good, because isolation holds by construction, proven per product by `TestAttributeIsolation`.
* Good, because P1/P2 data and policies are untouched.
* Bad, because operators create and back up a second mount; overlapping mount settings must be refused at startup.

## Pros and Cons of the Options

### Separate mount

* Good, because the boundary is the mount, not glob discipline.
* Bad, because one more prerequisite for attribute users.

### Under kv/

* Good, because one mount, one set of tooling.
* Bad, because `kv/data/ci/<org>/<repo>/*`, `kv/*` and similar globs reach attribute data.

### Move all tiers

* Good, because one consistent layout.
* Bad, because it breaks every existing deployment's data and policies; possible later as an opt-in change.

## More Information

Design: `docs/plans/2026-09-30-pipeline-attributes-design.md` §4. SPEC §2.4, §4.1, §7.

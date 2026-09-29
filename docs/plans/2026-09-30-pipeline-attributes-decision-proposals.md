# Proposed decision-log entries — NOT accepted

Written by an agent without the maintainer's agreement (2026-09-30). Removed from docs/decisionlog/ until the maintainer accepts each one.

---

<!-- proposed file: docs/decisionlog/260930071252-attribute-data-in-ironbark-owned-kv-mount.md -->
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

---

<!-- proposed file: docs/decisionlog/260930071317-dot-prefixed-attribute-segments.md -->
---
id: "DEC-260930071317"
title: "Dot-prefixed attribute segments and whole-prefix target escaping"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of naming attribute policies under P1, facing collisions with
  escaped branches and nested targets, we decided for reserved dot-prefixed
  segments with each target prefix escaped whole, against plain segment names,
  to achieve collision-free non-nesting names, accepting escaped-looking names.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "naming", "encoding"]
supersedes: []
---

# Dot-prefixed attribute segments and whole-prefix target escaping

## Context and Problem Statement

Attribute policies hang off P1 (`<prefix>/<org>/<repo>/<event>`), the
same parent as P2 (`P1/<esc(branch)>`). A plain segment such as
`P1/target/…` equals the tier of a branch literally named `target`, and
a target `a/b` kept as two segments makes `.target/a` a path-prefix of
`.target/a/b`, so a trailing-`*` policy for one target reads the other.

## Decision Drivers

* No attribute name may equal or nest another name or P2.
* Attacker-chosen values (branch, target, actor, team) must not forge a shape.
* Reuse the existing injective `esc` rather than a second encoding.

## Considered Options

* Dot-prefixed segments (`.target`, `.actor`, `.team`, `.target-actor`, `.target-team`), whole-prefix `esc(T)`
* Plain segments (`target`, `actor`, …) with per-segment target escaping
* A separate policy prefix per attribute kind

## Decision Outcome

Chosen option: "Dot-prefixed segments with whole-prefix esc(T)", because
`esc` never emits a leading dot, so no escaped value can equal a reserved
segment, and escaping each target prefix whole makes every target one
segment, giving each shape a fixed segment count.

### Consequences

* Good, because `a/.actor/x` escapes to `a%2f.actor%2fx` under `.target`, never a conjunction.
* Good, because even a trailing-`*` attribute policy reaches no other attribute prefix.
* Bad, because names like `.target/a%2fb` are unfriendly to hand-write; raw-HTTP writers must send `%25`.

## Pros and Cons of the Options

### Dot-prefixed, whole-prefix esc

* Good, because collision freedom follows from an existing, property-tested invariant.
* Bad, because `%` in policy names and KV paths needed verification on both products (integration-tested).

### Plain segments

* Good, because readable.
* Bad, because a branch named `target` collides, and nested targets nest.

### Separate policy prefix per kind

* Good, because no shared parent with P2.
* Bad, because it widens the token role glob and splits a repo's policies across trees.

## More Information

Design §3. SPEC §2.2–§2.4. Relies on the `esc` contract of DEC-260711114103 (never dot-prefixed, injective); changes nothing in it.

---

<!-- proposed file: docs/decisionlog/260930071344-actor-source-per-event.md -->
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

---

<!-- proposed file: docs/decisionlog/260930071408-target-source-and-prefix-policies.md -->
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

---

<!-- proposed file: docs/decisionlog/260930071432-team-resolution-fails-closed-grant-only.md -->
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

---

<!-- proposed file: docs/decisionlog/260930071456-conjunctions-and-max-policies-drop-order.md -->
---
id: "DEC-260930071456"
title: "Conjunction policy names and IRONBARK_MAX_POLICIES with a fixed drop order"
status: accepted
date: 2026-09-30
y-statement: >-
  In the context of secrets needing both a target and a person, facing an
  unbounded requested-policy list, we decided for conjunction names plus a cap
  that drops attribute names in fixed order, against no cap, to achieve bounded
  deterministic mints, accepting silently narrowed grants when capped.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["pipeline-attributes", "policy"]
supersedes: []
---

# Conjunction policy names and IRONBARK_MAX_POLICIES with a fixed drop order

## Context and Problem Statement

Vault grants are a union of policies, so "target `prod` AND team `ops`"
cannot be expressed by holding `.target/prod` and `.team/ops`. A
secret limited to people on one target needs its own name. With up to 8
target prefixes, an actor and many teams, the request can grow large;
Vault has no explicit cap, but mint size and audit volume grow with it.

## Decision Drivers

* Express "this target and this person/team" without Vault identity templating.
* Keep the mint bounded and the outcome deterministic.
* Dropping must only narrow, never touch P1/P2 or the actor.

## Considered Options

* Conjunctions `.target-actor`/`.target-team` per target prefix; cap (default 64, ≥ 3) dropping team conjunctions, actor conjunctions, teams, then targets (deepest first; reverse team order on ties)
* Conjunctions with no cap
* No conjunctions; target and actor/team as independent grants only

## Decision Outcome

Chosen option: "Conjunctions with a fixed-order cap", because
conjunctions are the only union-safe way to require two attributes, and
a cap with a documented drop order keeps large team sets from producing
oversized or unpredictable requests. Dropped names are audited.

### Consequences

* Good, because narrowing to people on a target is expressible and grant-only.
* Good, because the kept and dropped sets are deterministic and tested.
* Bad, because a capped request loses the most specific grants first, which an operator sees only in `policies_dropped`.

## Pros and Cons of the Options

### Conjunctions with a cap

* Good, because bounded and predictable.
* Bad, because the drop order is one more rule to learn.

### No cap

* Good, because nothing is ever dropped.
* Bad, because request size grows with team count × target depth.

### No conjunctions

* Good, because fewer names.
* Bad, because a target-only policy grants anyone who can name the target.

## More Information

Design §3; plan decisions D1 (request order) and D2 (tie-break). SPEC §2.3, §8.1.


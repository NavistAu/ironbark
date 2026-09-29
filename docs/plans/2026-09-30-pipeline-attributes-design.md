# Pipeline attributes: actor, target and teams in the grant

Status: design, agreed with the maintainer 2026-09-30; for review. Built as
development images only — no release is cut until the payload facts below
are confirmed on real pipelines (§8).

Research: `docs/research/2026-09-29-pipeline-attributes.md`.

## Problem

ironbark derives policies from `repo`, `event` and `branch` (SPEC §2.3). In
a monorepo every pipeline of one event+branch receives the same grant: a
docs build and a deploy of the most sensitive component read the same
secrets. The signed payload carries more — who acted, what is being
deployed — and ironbark ignores it.

## Payload facts (Woodpecker v3.18.0 source)

| Event | Who acted | Target |
|---|---|---|
| push, tag, pull_request, pull_request_closed, release | `pipeline.sender` — the webhook user's login on Gitea-family forges, GitHub and Bitbucket Cloud; see forge caveats below | — (`changed_files` present on push) |
| manual | `pipeline.author` — the Woodpecker user who started it (a forge login via OAuth); `sender` is empty | `pipeline.variables` (caller-set) |
| deployment (Woodpecker promote) | **unknown** — a promotion copies the parent pipeline (`server/pipeline/restart.go`); the handler never reads the session user (`server/api/pipeline.go` `PostPipeline`); `sender` is whatever the *parent* carried | `pipeline.deploy_to`, `deploy_task` |
| deployment (GitHub deployment webhook) | `sender` is the deployment's creator (`server/forge/github/parse.go` `parseDeployHook`) — indistinguishable in the payload from a promotion | `deploy_to` = the deployment environment |
| cron | nobody | — |

Forge caveats for `sender`: GitLab sets no `sender` on push, tag or merge
request hooks, and on `release` sets it to the commit author's *display
name* (`server/forge/gitlab/convert.go` `convertReleaseHook`) — not a login,
and settable by any committer; Bitbucket Data Center sets no `sender`. The
payload does not say which forge sent it (`repo.forge_id` is a Woodpecker
row id, not a forge kind).

Also: the promote endpoint requires push access (`server/router/api.go:122`,
`session.MustPush`); on approval the extension is called again but
`reviewed_by` is set only afterwards (`server/api/approve.go:60` vs `:74`).
A promotion's `deploy_to` and `deploy_task` query parameters *do* reach the
payload; its other query parameters become pipeline environment only and do
not reach the payload's `variables` (the parent's `variables` are carried).
`author` on non-manual events is forge- and event-dependent (mostly the
webhook sender; the PR poster or release author on some forges; the commit
author's display name on GitLab `release`) — never used as identity
outside `manual`.

## Design

### 1. Normalised attributes
`identity.Parse` gains three fields, filled per event from the table above:

- **Actor** — a person, or empty. manual: `author` (any forge).
  push-family: `sender`, but only when the operator declares a forge whose
  `sender` is a login (`IRONBARK_ACTOR_FORGE`, §7; `none` → push-family
  actor is empty). GitLab and
  Bitbucket Data Center are never declarable (caveats above). deployment
  and cron: empty.
- **Target** — a slash-separated path, or empty. deployment: `deploy_to`;
  manual: `variables[IRONBARK_TARGET_VAR]` (default `DEPLOY_TO`); others:
  empty. Grammar: split on `/`; every segment non-empty (no leading,
  trailing or doubled `/`); at most 8 segments and 256 bytes. A value
  violating this is treated as no target (no target policies) and the audit
  line records `target_invalid`.
- **CodeAuthor** — `sender` on push-family events, recorded verbatim for
  audit only; not used for policy. Not recorded on deployments, where
  `sender` is either the parent's value or the deployment creator and the
  payload cannot tell which.

Target and actor are caller-influenced (target is free text chosen by
whoever can trigger a manual run or promote; actor is whoever holds repo
access), so they only ever *add* policies an admin chose to create — the
authority stays in Vault (DEC-260711061323). A target-only policy
therefore scopes a secret away from other pipelines of the same event, but
does not restrict *who* gets it: anyone able to trigger that event can
name any target. A secret that must be limited to people uses a
conjunction (§3).

### 2. Teams (optional forge integration)
A provider interface resolves an actor's teams for the repo:

```go
type TeamResolver interface {
    Teams(ctx context.Context, org, repo, login string) ([]string, error)
}
```

- First implementation: Gitea-family forges (Gitea, Forgejo) — the repo's
  teams, then membership of `login` in each. Designed so other forges can be
  added behind the same interface.
- Config: the `IRONBARK_FORGE_*` variables (§7).
- Only called when Actor is non-empty. No caching.
- One forge namespace: actor logins and team membership must come from the
  same forge. ironbark assumes a single-forge Woodpecker server (the payload
  cannot distinguish forges, §Payload facts). The two settings are
  independent except for one rule: when `IRONBARK_FORGE_PROVIDER=gitea`,
  `IRONBARK_ACTOR_FORGE` defaults to `gitea` and may only be `gitea` or
  `none` — `github`/`bitbucket` alongside a Gitea team provider is a
  startup error. With the provider `none`, any actor-forge value is valid
  (actor policies without teams). This covers the manual actor too —
  `author` is a login on the server's one forge.
- Failure (timeout, error, non-200) **fails closed**: no team policies, the
  pipeline continues with its other policies, and the audit line records
  the failure. A team lookup never fails a pipeline. Because a failed
  lookup silently drops team policies, a team policy can only ever be a
  grant — never the carrier of a `deny` relied on for safety (§3).
- ironbark does not assume how the forge fills teams (directory sync or
  manual).
- Trust: Vault stays the sole authority over *what* a team grants; the
  forge becomes the authority over *who* is in a team. Anyone who can edit
  forge team membership (forge admins, org owners, a leaked
  `IRONBARK_FORGE_TOKEN` with write scope) can widen a pipeline's grant
  through team policies. The token needs read scope only.

### 3. Policy names (additions to SPEC §2.3)
With `E = <prefix>/<org>/<repo>/<event>` (today's P1), ironbark additionally
requests:

- **Target prefixes** — for target `a/b/c` the prefixes are `a`, `a/b` and
  `a/b/c`; each prefix `T` is requested as `E/.target/<esc(T)>`, i.e.
  `E/.target/a`, `E/.target/a%2fb`, `E/.target/a%2fb%2fc`. `esc` is applied
  to the whole prefix string, so its `/` becomes `%2f` and every prefix is
  one path segment (injective, SPEC §2.2). The admin creates a policy at
  the depth that owns the scope (e.g. only the top-level component); deeper
  names grant nothing unless created.
- **Actor** — `E/.actor/<esc(actor)>`.
- **Teams** — `E/.team/<esc(team)>` per resolved team.
- **Conjunctions** — for each target prefix `T`:
  `E/.target-actor/<esc(T)>/<esc(actor)>` and
  `E/.target-team/<esc(T)>/<esc(team)>` per team. These let a secret
  require both "this target" and "this person/team".

Every attribute name is `E/<rel>` where `<rel>` is one of the five shapes
above, and each shape is a fixed number of segments. No attribute name is
a path-prefix of another attribute name, of P2, or of a name of a
different shape — this is what keeps a `*`-glob KV policy for one name from
reaching another name's data (§4).

The attribute segments `.target`, `.actor`, `.team`, `.target-actor` and
`.target-team` are dot-prefixed on purpose: `identity.Esc` output is never
dot-prefixed (SPEC §2.2), so no escaped branch (P2), target, actor or team
can equal one. A branch literally named `target` keeps its own tier
`E/target`, and a caller-chosen target `a/.actor/x` is escaped into the
single segment `a%2f.actor%2fx` under `.target`, never a conjunction.

Union semantics as today. Attribute policies are **grant-only as a
security boundary**: every attribute can be absent (target omitted or
invalid, actor empty, team lookup failed, policy dropped by the cap below),
so a `deny` placed in an attribute policy is lifted by exactly the
pipelines it was meant to stop. Narrowing is done by placing a secret
*only* under the attribute or conjunction prefix that should reach it, not
by denying it from a broader tier. Each target prefix is escaped whole
(`esc(T)`, above), so in names and KV paths a target is always one
segment and never a path-prefix of a deeper target. `IRONBARK_MAX_POLICIES` (default 64) bounds the
request; when exceeded, names are dropped in a fixed order — team
conjunctions deepest target first, then actor conjunctions deepest first,
then team policies, then target prefixes deepest first — never P1/P2 or
the actor policy, and the audit line lists the dropped names. Since
attribute policies only grant, a drop can only narrow. Existing P1/P2 are
unchanged. The token role's `allowed_policies_glob` already covers
`<prefix>/*` (SPEC §3.1: substring glob, `*` crosses `/`).

### 4. KV layout and sweep (additions to SPEC §2.4, §4.1)
**Attribute data lives in an ironbark-owned KV v2 mount**,
`IRONBARK_ATTR_MOUNT` (default `ironbark`, §7), never under the shared
`KV_MOUNT` — the way voidstar owns its `vs/` mount. Vault/OpenBao ACL paths
begin with the mount path, so no policy written on `kv/…` — `*`, `+`,
repo-root globs like the README's `kv/data/ci/acme/widgets/*`, or a
careless `kv/*` — can match attribute data, whatever glob it uses. Only a
policy that names the attribute mount reaches it, and those are exactly the
attribute policies an admin chose to create. This holds only if neither
mount contains the other, so after trimming slashes `IRONBARK_ATTR_MOUNT`
equal to `IRONBARK_KV_MOUNT`, or either one a `/`-prefix of the other
(`kv/attrs` under `kv`), is a startup error.

With `A = <ATTR_MOUNT>` and the relative name `<rel>` from §3, each
attribute policy `E/<rel>` has exactly one KV prefix:
`<org>/<repo>/<event>/<rel>` in the attribute mount, holding plain keys:

```
<org>/<repo>/<event>/.target/<esc(T)>/<key>
<org>/<repo>/<event>/.actor/<esc(actor)>/<key>
<org>/<repo>/<event>/.team/<esc(team)>/<key>
<org>/<repo>/<event>/.target-actor/<esc(T)>/<esc(actor)>/<key>
<org>/<repo>/<event>/.target-team/<esc(T)>/<esc(team)>/<key>
```

The documented attribute policy grants one prefix's plain keys and nothing
else: `read` on `A/data/<org>/<repo>/<event>/<rel>/+` and `list` on
`A/metadata/<org>/<repo>/<event>/<rel>/` (`+` is one path segment; `*`
crosses `/`; probed on Vault 1.20.4 and OpenBao dev servers: this exact
metadata grant authorizes the sweep's LIST with or without a trailing
slash on the request). Because no attribute prefix is a path-prefix of another
(§3), even a trailing-`*` form `…/<rel>/*` reaches no other attribute
prefix — a target-`a` policy does not reach `a%2fb`'s keys nor any
conjunction on `a`, and an actor policy does not reach a conjunction naming
that actor; it additionally reaches only unswept keys an admin nests below
`<rel>/`, which the returned `vault_token` could then read. (A policy that
globs above a prefix, e.g. `A/data/<org>/<repo>/*`, grants everything
below it — an admin's explicit choice, as with any KV policy.)

The read set is still derived a priori — each prefix is LISTed
independently (`A/metadata/…`), plain keys only, no descent, 403/404
tolerated (including a missing attribute mount), in this total order (most
specific first):

1. For each target prefix `T`, deepest first:
   `.target-actor/<esc(T)>/<esc(actor)>`, then `.target-team/<esc(T)>/<esc(team)>`
   for each team in byte order of `esc(team)`.
2. `.target/<esc(T)>`, deepest `T` first.
3. `.actor/<esc(actor)>`.
4. `.team/<esc(team)>`, teams in byte order of `esc(team)`.
5. Today's tiers in `KV_MOUNT` (SPEC §4.1): branch, event, base.

Keys within one prefix are taken in lexicographic order, as today; keys
beginning with `.` are skipped, as in every tier. Name collisions: first
writer wins (SPEC §4.2), so the earliest prefix in this order wins.
`.identity` and `.config` stay at `B` in `KV_MOUNT` (SPEC §4.4, §4.5); the
attribute mount has no directives.

Pointer entries (SPEC §4.3) are unchanged: a `$ref` found in any tier is
dereferenced with the minted token, so it reaches attribute data only if
that pipeline's token already holds the attribute policy — a pointer in an
ordinary tier cannot lift attribute-gated data into a pipeline without it.

**Existing tiers stay where they are.** P1/P2 data remains at
`B = <KV_PREFIX>/<org>/<repo>` in `KV_MOUNT`, unchanged and backwards
compatible; this iteration moves nothing. Their isolation from each other
relies on operators scoping each tier policy's paths to its own tier
(README "Use exact paths under the tier") — and the README's own
`pull_request` example breaks that rule: `kv/data/ci/acme/widgets/*` also
reads the `push/main` tier. That is a documentation defect, not a layout
one (a correctly scoped tier policy cannot cross tiers), so it is fixed in
the README (§9), not by moving the tiers. Moving them into the attribute
mount later is possible as a separate, opt-in change.

**`ib` (CLIENT-SPEC) does not read the attribute mount in this
iteration.** A local run has no signed payload to take a target or actor
from, so attribute secrets are CI-only; CLIENT-SPEC's "same secrets as a
CI run" is qualified to repo/event/branch tiers (§9).

### 5. Directives
None. (A per-repo `.config` override of the target variable is impossible:
the target must be known to derive the policy names *before* the mint,
and `.config` is read only *after* it, with the minted token — SPEC §1.2.)

### 6. Audit line (SPEC §8.1)
Adds `actor`, `target` (or `target_invalid`), `code_author`, `teams` (or
`teams_error`), `policies_dropped`, and the count of requested and
existing-policy warnings.

### 7. Configuration and compatibility
Additions to SPEC §7 (same conventions; `_FILE` only where marked):

| Var | Default | Values / notes |
|---|---|---|
| `IRONBARK_ACTOR_FORGE` | `gitea` if `IRONBARK_FORGE_PROVIDER=gitea`, else `none` | `none` \| `gitea` \| `github` \| `bitbucket` (Bitbucket Cloud); anything else is a startup error; with provider `gitea` only `gitea` or `none` (§2) |
| `IRONBARK_ATTR_MOUNT` | `ironbark` | KV v2 mount holding all attribute data (§4); equal to, containing, or contained in `IRONBARK_KV_MOUNT` is a startup error |
| `IRONBARK_TARGET_VAR` | `DEPLOY_TO` | manual-run variable naming the target (§1) |
| `IRONBARK_MAX_POLICIES` | `64` | integer ≥ 3 (P1, P2, actor are never dropped) (§3) |
| `IRONBARK_FORGE_PROVIDER` | `none` | `none` \| `gitea` (Gitea, Forgejo) |
| `IRONBARK_FORGE_URL` | — | required when provider ≠ `none` |
| `IRONBARK_FORGE_TOKEN` / `_FILE` | — | required when provider ≠ `none`; read scope on org teams |
| `IRONBARK_FORGE_TIMEOUT` | `3s` | Go duration |

A repo with no attribute policies behaves exactly as today. No new
required config; `IRONBARK_FORGE_PROVIDER=none` disables team lookup and
`IRONBARK_ACTOR_FORGE=none` leaves push-family actor empty. The attribute
mount is an operator prerequisite only for using attribute tiers
(`vault secrets enable -path=ironbark -version=2 kv`); until it exists its
LISTs return 403/404 and are skipped.

### 8. Verification before release
- Development images log the parsed attributes (debug level) for every
  request.
- On a real deployment before any release: one push, one manual run with
  a target variable, one deployment promotion, one approval-gated run —
  confirm every row of the payload table, and that `reviewed_by` is empty
  at call time.
- Unit: extraction per event and per `IRONBARK_ACTOR_FORGE` value from
  recorded payloads (Gitea push, manual, promotion, GitHub deployment
  webhook, GitLab release with a display-name `sender` → empty actor);
  target grammar (empty segments, leading/trailing/doubled `/`, depth and
  length limits → `target_invalid`); no collision between the dot-prefixed
  attribute segments and branches or target segments named `target`,
  `actor`, `team` or `.target` (escaped to `%2etarget`);
  config validation (`IRONBARK_ACTOR_FORGE` vs `IRONBARK_FORGE_PROVIDER`
  mismatch is a startup error); escaping of hostile actor, team and
  target values (`/`, `.`, `..`, `%`, uppercase) in both policy names and
  KV paths; policy list construction incl. conjunctions and the
  `IRONBARK_MAX_POLICIES` drop order; first-writer-wins across attribute
  and existing tiers.
- Integration (Vault and OpenBao): dot-prefixed segments and `%2f` are
  accepted in policy names and KV paths; a target-only policy is granted to
  any manual run naming that target, while a conjunction policy is not;
  team lookup timeout fails closed and grants nothing from team prefixes;
  overflow drops only attribute policies.
- Integration, attribute isolation (Vault and OpenBao; data seeded at every
  §4 shape, incl. nested targets `a`, `a/b` and conjunctions under `a`):
  - a token holding only ordinary tier policies — the README's examples
    verbatim, plus `kv/data/ci/acme/widgets/*`, `kv/data/ci/*`, `kv/*` and
    `+`-segment variants — gets 403 on LIST and GET of every attribute
    path, and the sweep returns no attribute secret;
  - a token holding one attribute policy, in both the documented `+` form
    and a trailing-`*` form (§4), reads exactly that prefix's keys and gets
    403 on every other attribute prefix — the target-`a` policy on `a%2fb`
    and on both conjunctions on `a`; the actor policy on conjunctions
    naming that actor; a team policy on team conjunctions;
  - the corrected README tier examples (§9) grant each tier's own keys and
    403 on every other tier's;
  - `IRONBARK_ATTR_MOUNT` equal to, containing or contained in
    `IRONBARK_KV_MOUNT` fails startup, and a missing attribute mount leaves
    the sweep as today.

### 9. Documentation deltas
- SPEC: §2.3 (§3 names), §2.4 and §4.1 (§4 mount, layout, read order),
  §4.3 (pointer note), §7 (§7 table), §8.1 (§6), §9.2/§9.3 (§8 tests).
- README: operator contract gains the attribute-mount prerequisite and one
  attribute policy example on that mount (generic `acme/widgets`), and
  states that attribute data is never under `kv/`, so tier policies on
  `kv/` cannot reach it; configuration table gains the §7 rows. The
  existing tier examples are corrected to per-tier paths (`+` for the key
  segment, exact metadata LIST path) so the `pull_request` example no
  longer reads the `push/main` tier (§4).
- CLIENT-SPEC: "same secrets as a CI run" is qualified to repo/event/branch
  tiers; `ib` does not read the attribute mount (§4).

## Out of scope
- Recording who promoted a deployment (needs Woodpecker upstream).
- `reviewed_by`-based gating (empty at call time).
- Providers other than Gitea-family.
- Policy on `code_author` or `changed_files`.

## Decisions to log on acceptance
- Attribute data in an ironbark-owned KV mount (`IRONBARK_ATTR_MOUNT`),
  never under the shared `KV_MOUNT`; existing tiers stay put.
- Dot-prefixed attribute segments (`.target`, `.actor`, `.team`,
  `.target-actor`, `.target-team`), relying on `esc` never emitting a
  leading dot; whole-prefix `esc(T)` so no attribute prefix nests another.
- Actor source per event, "deployment has no actor", and push-family actor
  only on an operator-declared forge whose `sender` is a login.
- Target from `deploy_to` or a configured manual variable; path-prefix
  policies; target grammar.
- Optional team resolution via a forge provider, failing closed; the forge
  owns team membership, Vault owns grants.
- Attribute policies are grant-only as a security boundary.
- Conjunction names and `IRONBARK_MAX_POLICIES` with its drop order.

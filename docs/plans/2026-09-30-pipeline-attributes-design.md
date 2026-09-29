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
`author` on non-manual events is forge-dependent (the pusher on
Gitea-family forges, the commit author elsewhere) — never used as identity
outside `manual`.

## Design

### 1. Normalised attributes
`identity.Parse` gains three fields, filled per event from the table above:

- **Actor** — a person, or empty. manual: `author` (any forge).
  push-family: `sender`, but only when the operator declares a forge whose
  `sender` is a login (`IRONBARK_ACTOR_FORGE`: `gitea` | `github` |
  `bitbucket`; default `none` → push-family actor is empty). GitLab and
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
- Config (SPEC §7 conventions): `IRONBARK_FORGE_PROVIDER` (`none` default |
  `gitea`), `IRONBARK_FORGE_URL`, `IRONBARK_FORGE_TOKEN` / `_FILE` (read
  access to org teams), `IRONBARK_FORGE_TIMEOUT` (default 3s).
- Only called when Actor is non-empty. No caching.
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

- **Target prefixes** — for target `a/b/c`: `E/target/a`, `E/target/a/b`,
  `E/target/a/b/c`. The admin creates a policy at the depth that owns the
  scope (e.g. only the top-level component); deeper names grant nothing
  unless created.
- **Actor** — `E/actor/<esc(actor)>`.
- **Teams** — `E/team/<esc(team)>` per resolved team.
- **Conjunctions** — for each target prefix `T`:
  `T/actor/<esc(actor)>` and `T/team/<esc(team)>` per team. These let a
  secret require both "this target" and "this person/team".

Union semantics as today. Attribute policies are **grant-only as a
security boundary**: every attribute can be absent (target omitted or
invalid, actor empty, team lookup failed, policy dropped by the cap below),
so a `deny` placed in an attribute policy is lifted by exactly the
pipelines it was meant to stop. Narrowing is done by placing a secret
*only* under the attribute or conjunction prefix that should reach it, not
by denying it from a broader tier. Target
segments are escaped individually with `identity.Esc`; `/` stays the
hierarchy separator. `IRONBARK_MAX_POLICIES` (default 64) bounds the
request; when exceeded, names are dropped in a fixed order — team
conjunctions deepest target first, then actor conjunctions deepest first,
then team policies, then target prefixes deepest first — never P1/P2 or
the actor policy, and the audit line lists the dropped names. Since
attribute policies only grant, a drop can only narrow. Existing P1/P2 are
unchanged. The token role's `allowed_policies_glob` already covers
`<prefix>/*` (SPEC §3.1: substring glob, `*` crosses `/`).

### 4. KV layout and sweep (additions to SPEC §2.4, §4.1)
Each new policy name has a KV prefix of the same shape under `B`
(`E` → `B/<event>`), with the same escaping as the policy name:
`B/<event>/target/<esc(a)>[/<esc(b)>…]/<key>`,
`B/<event>/actor/<esc(actor)>/<key>`, `B/<event>/team/<esc(team)>/<key>`,
and the conjunction prefixes. The read set is still derived a priori — each
prefix is LISTed independently, most specific first (conjunctions, then
target deepest-first, then actor, team, then today's tiers), no descent,
403/404 tolerated. Name collisions: first writer wins, as today (SPEC
§4.2), so the more specific key wins.

### 5. Directives
None. (A per-repo `.config` override of the target variable is impossible:
the target must be known to derive the policy names *before* the mint,
and `.config` is read only *after* it, with the minted token — SPEC §1.2.)

### 6. Audit line (SPEC §8.1)
Adds `actor`, `target` (or `target_invalid`), `code_author`, `teams` (or
`teams_error`), `policies_dropped`, and the count of requested and
existing-policy warnings.

### 7. Compatibility
A repo with no attribute policies behaves exactly as today. No new
required config; `IRONBARK_FORGE_PROVIDER=none` disables team lookup and
`IRONBARK_ACTOR_FORGE=none` leaves push-family actor empty.

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
  length limits → `target_invalid`); escaping of hostile actor, team and
  target values (`/`, `.`, `..`, `%`, uppercase) in both policy names and
  KV paths; policy list construction incl. conjunctions and the
  `IRONBARK_MAX_POLICIES` drop order; first-writer-wins across attribute
  and existing tiers.
- Integration (Vault and OpenBao): a target-prefix policy grants only its
  subtree; a target-only policy is granted to any manual run naming that
  target, while a conjunction policy is not; team lookup timeout fails
  closed and grants nothing from team prefixes; overflow drops only
  attribute policies.

## Out of scope
- Recording who promoted a deployment (needs Woodpecker upstream).
- `reviewed_by`-based gating (empty at call time).
- Providers other than Gitea-family.
- Policy on `code_author` or `changed_files`.

## Decisions to log on acceptance
- Actor source per event, "deployment has no actor", and push-family actor
  only on an operator-declared forge whose `sender` is a login.
- Target from `deploy_to` or a configured manual variable; path-prefix
  policies; target grammar.
- Optional team resolution via a forge provider, failing closed; the forge
  owns team membership, Vault owns grants.
- Attribute policies are grant-only as a security boundary.
- Conjunction names and `IRONBARK_MAX_POLICIES` with its drop order.

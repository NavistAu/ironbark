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
| push, tag, pull_request, pull_request_closed, release | `pipeline.sender` — the forge login from the webhook | — (`changed_files` present on push) |
| manual | `pipeline.author` — the Woodpecker user who started it (a forge login via OAuth); `sender` is empty | `pipeline.variables` (caller-set) |
| deployment | **unknown** — a deployment copies the parent pipeline (`server/pipeline/restart.go`); the handler never reads the session user (`server/api/pipeline.go` `PostPipeline`); `sender` is the *parent's* pusher | `pipeline.deploy_to`, `deploy_task` |
| cron | nobody | — |

Also: the promote endpoint requires push access (`server/router/api.go:122`,
`session.MustPush`); on approval the extension is called again but
`reviewed_by` is set only afterwards (`server/api/approve.go:60` vs `:74`);
deployment-only query parameters do not reach the payload (the parent's
`variables` are carried). `author` on non-manual events is forge-dependent
(the pusher on Gitea-family forges, the commit author elsewhere) — never
used as identity outside `manual`.

## Design

### 1. Normalised attributes
`identity.Parse` gains three fields, filled per event from the table above:

- **Actor** — a person, or empty. push-family: `sender`; manual: `author`;
  deployment and cron: empty.
- **Target** — a slash-separated path, or empty. deployment: `deploy_to`;
  manual: `variables[TARGET_VAR]` (config, default `DEPLOY_TO`); others:
  empty.
- **CodeAuthor** — `sender` on push-family and deployment events (on a
  deployment it is the pusher of the commit being deployed). Audit only in
  this iteration; not used for policy.

Target and actor are caller-influenced (target is free text; actor is
whoever holds repo access), so they only ever *add* policies an admin chose
to create — the authority stays in Vault (DEC-260711061323).

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
- Config: `FORGE_PROVIDER` (`none` default | `gitea`), `FORGE_URL`,
  `FORGE_TOKEN` (read access to org teams), `FORGE_TIMEOUT` (default 3s).
- Only called when Actor is non-empty. No caching.
- Failure (timeout, error, non-200) **fails closed**: no team policies, the
  pipeline continues with its other policies, and the audit line records
  the failure. A team lookup never fails a pipeline.
- ironbark does not assume how the forge fills teams (directory sync or
  manual).

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

Union semantics as today; an attribute policy may also carry `deny` rules,
which win over every grant — narrowing needs no broker state. Target
segments are escaped individually with `identity.Esc`; `/` stays the
hierarchy separator. `MAX_POLICIES` (config, default 64) bounds the request;
when exceeded, the deepest conjunctions are dropped first and the audit line
says so. Existing P1/P2 are unchanged. The token role's
`allowed_policies_glob` already covers `<prefix>/*`.

### 4. KV layout and sweep (additions to SPEC §2.4, §4.1)
Each new policy name has a KV prefix of the same shape under `B`
(`E` → `B/<event>`): `B/<event>/target/a[/b…]/<key>`,
`B/<event>/actor/<login>/<key>`, `B/<event>/team/<team>/<key>`, and the
conjunction prefixes. The read set is still derived a priori — each prefix
is LISTed independently, most specific first (conjunctions, then target
deepest-first, then actor, team, then today's tiers), no descent, 403/404
tolerated. Later (more specific) keys win name collisions, as today.

### 5. Directives
`.config` gains `target_var` (overrides `TARGET_VAR` per repo). Nothing
else.

### 6. Audit line (SPEC §8.1)
Adds `actor`, `target`, `code_author`, `teams` (or `teams_error`), and the
count of requested and existing-policy warnings.

### 7. Compatibility
A repo with no attribute policies behaves exactly as today. No new
required config; `FORGE_PROVIDER=none` disables team lookup.

### 8. Verification before release
- Development images log the parsed attributes (debug level) for every
  request.
- On a real deployment before any release: one push, one manual run with
  a target variable, one deployment promotion, one approval-gated run —
  confirm every row of the payload table, and that `reviewed_by` is empty
  at call time.
- Unit: extraction per event from recorded payloads; escaping of target
  segments; policy list construction incl. conjunctions and `MAX_POLICIES`.
- Integration (Vault and OpenBao): a target-prefix policy grants only its
  subtree; a deny-bearing attribute policy narrows; team lookup timeout
  fails closed.

## Out of scope
- Recording who promoted a deployment (needs Woodpecker upstream).
- `reviewed_by`-based gating (empty at call time).
- Providers other than Gitea-family.
- Policy on `code_author` or `changed_files`.

## Decisions to log on acceptance
- Actor source per event, and "deployment has no actor".
- Target from `deploy_to` or a configured manual variable; path-prefix
  policies.
- Optional team resolution via a forge provider, failing closed.
- Conjunction names and `MAX_POLICIES`.

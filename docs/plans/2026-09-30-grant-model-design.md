# Grant model: layered data, verified facts, OpenBao-enforced gates

Status: draft for review, 2026-09-30, revised the same day to the
operator's rulings. Nothing here is implemented. It
replaces the grant half of [`SPEC.md`](../SPEC.md) (§2.3–§2.5, §3, §4.1,
§4.4–§4.6, §7) and of [`CLIENT-SPEC.md`](../CLIENT-SPEC.md) (§3–§5), and
supersedes the attribute tiers of
[`2026-09-30-pipeline-attributes-design.md`](2026-09-30-pipeline-attributes-design.md)
("the attributes design"). Signature verification (SPEC §5) stays as it is.
The response shape (SPEC §6) gains an always-present `ironbark_status`
secret, and revocation-by-outcome (SPEC §3.4) is restated for it (§9).
Several parts depend on voidstar features that do not exist yet (§16).

Decisions this design would introduce are listed under
[Proposed decisions](#19-proposed-decisions); none is recorded in
`docs/decisionlog/` yet.

## 1. Why change

Today ironbark is a rules engine. It turns `(repo, event, branch)` plus
target, actor and team into up to 64 policy names, requests all of them, and
sweeps a KV tree whose shape mirrors those names: event tiers, branch tiers,
and five dot-prefixed attribute shapes in a second mount. Three problems:

1. **Access is decided in two places.** Which policies exist is Vault data;
   which ones ironbark asks for is Go code. A branch strategy ("only
   protected `main` deploys production") has no single home.
2. **The data layout encodes who may read, not what the secret is.** A
   database password shared by two events and one team lives in three tiers,
   or behind three pointers.
3. **Everything is a grant, nothing is a gate.** Attribute policies can only
   add, so "only team X may deploy this" is expressed by where a copy of the
   secret sits, never as a condition.

The new model separates the two questions. **Where a secret lives** is
decided by what changes its value (project, environment, target). **Who may
read a level** is decided by OpenBao, from facts ironbark verifies and signs.

## 2. Goals and non-goals

Goals:

- Each secret stored once, at a path named by what it is.
- Access decisions live in OpenBao configuration (roles, policies, groups)
  written as IaC, not in ironbark code.
- Stock Vault/OpenBao features only: JWT auth, templated ACL policies,
  identity groups. No plugin.
- ironbark shrinks to: verify the Woodpecker request, establish facts, sign
  them, log in, walk the levels, return values.
- `ib` walks the same levels with the caller's own login.
- Every failure gives the pipeline less or nothing, never more.
- ironbark never fails a pipeline. It reports what happened in an
  `ironbark_status` secret, and the job decides whether to fail, warn or
  carry on (§9).
- Small data-side declarations over derivation logic: which branches an
  environment serves, which steps may see a secret, and whether a pipeline
  gets a token are all metadata on voidstar levels and mappings.

Non-goals:

- Per-step or per-workflow secrets. Woodpecker calls the extension once per
  pipeline, before workflows exist; one secret list per pipeline stays.
- Knowing who promoted a deployment (Woodpecker does not say).
- Branch facts for `tag` and `release` events.
- Replacing voidstar or any secrets engine. ironbark reads views and
  engines, it does not host them.
- Vault Enterprise features (Sentinel, control groups).

## 3. The model

### 3.1 Levels

Secret data sits in a tree of **levels**, shallow to deep. The examples use
an estate prefix `pipelines` and the repo `acme/mono`:

| Level | Path (example) | Holds |
|---|---|---|
| repo (project) | `vs/data/pipelines/acme/mono/` | secrets every pipeline of the repo may use |
| environment | `vs/data/pipelines/acme/mono/prod/` | secrets whose value differs per environment |
| target | `vs/data/pipelines/acme/mono/prod/web/` | secrets specific to one deployable part in one environment |
| nested target | `vs/data/pipelines/acme/mono/prod/web/api/` | a part of a part; each target segment is its own level |

Generic secrets sit high and customisations sit low. A key present at more
than one level resolves to the deepest one the pipeline can read (§8).
Nested targets inherit: the target `web/api` walks `prod/web/` and then
`prod/web/api/`.

**An environment is a named level under the repo.** Its name is free (it
need not match a branch). The level's own metadata says which branches it
serves:

```
vs/data/pipelines/acme/mono/prod/        level metadata: branches = main
vs/data/pipelines/acme/mono/prod/web/
vs/data/pipelines/acme/mono/staging/     level metadata: branches = staging
```

That one declaration is the whole branch-to-environment mapping: no alias
per branch, no role-existence convention (§4.5).

The tree is normally a set of voidstar views, one per secret, each resolving
upstream (1Password, KV, anything voidstar supports). A voidstar mapping is
a record in its own right, like a symlink with its own metadata: it carries
the secret's image pins (§8.4), can point at a dynamic engine without
fetching it (§7), or can have no target at all and exist only for its
metadata (`vault_token`, §8.5). §16 lists the voidstar changes this needs.

ironbark does not require voidstar. A plain KV v2 mount works, with less:
entries carry pins in their own `custom_metadata`, an empty entry named
`vault_token` is the token marker, there is no level metadata (so
environments are selected by `DEPLOY_ENV` only) and there are no dynamic
pointers.

### 3.2 Levels and gates

A fact about a pipeline is one of two kinds:

- A **level** fact changes a secret's *value*: environment, target. It
  becomes a path segment.
- A **gate** fact changes *who may read*: team, actor, protected branch,
  event. It never becomes a path segment. It is a condition in OpenBao: a
  role's `bound_claims`, or the membership of an identity group that carries
  a policy.

Mixing them caused today's tier explosion (`.target-team/<t>/<team>` holds
data that only differs from `.target/<t>` in who reads it). The rule is:
if two pipelines should see *different values*, split a level; if they
should see *the same value or nothing*, add a gate.

### 3.3 Only credentials in the secret tree

The tree holds credentials: passwords, tokens, keys, anything whose
disclosure is harmful. Identifiers (usernames, hostnames, ports, account
ids) are configuration. They belong in the repo or the pipeline file, not
the secret tree. Two reasons: every returned value is masked in logs
(including `ib`, §12.3), so an identifier in the tree turns every log line
mentioning a host into `********`; and a smaller tree is a smaller grant.

### 3.4 Selectors never entitle

`DEPLOY_ENV` and `DEPLOY_TO` (names configurable, §11) *select* which
environment and target a pipeline acts on, in the GitLab sense of "this job
acts on environment X". Selection only chooses the path. OpenBao refuses any
level the verified facts do not allow. A caller who names `prod` from
an unprotected branch gets a refused login and only `ironbark_status` (§9),
not production secrets. The same holds for the level metadata `branches`:
it selects an environment for a push, it never admits one.

### 3.5 Where each decision lives

| Decision | Lives in | Written by |
|---|---|---|
| Which facts are true for this pipeline | ironbark (§4) | ironbark code |
| Which environment a branch selects | level metadata `branches` (§4.5) | IaC (voidstar) |
| Which environment and target to walk | ironbark selectors (§4.5, §4.6) | pipeline variables, promote field, commit trailer, level metadata |
| Whether this pipeline may act for an environment (branch strategy, events, which repos) | the environment's JWT role `bound_claims` | IaC |
| Which levels a login may read | templated policies, one per level kind | IaC |
| Team conditions | identity groups via `groups_claim`, with group policies | IaC |
| Where a secret's value comes from | voidstar view mapping (or KV) | IaC |
| Which steps may see a secret (image pins) | voidstar mapping `custom_metadata` | IaC |
| Whether a pipeline gets `vault_token` | a metadata-only `vault_token` mapping | IaC |
| Whether the job fails on what ironbark reports | the job, from `ironbark_status` | pipeline author |

## 4. Facts per event

### 4.1 Fact table

Facts come from the signed Woodpecker payload (integrity-protected end to
end, not trustworthy by virtue of the signature: fields still originate
from webhooks, API callers and repo admins) plus two forge lookups. Only
the facts below are used; every other payload field is ignored.

| Fact | push | pull_request (`pull_request`) | tag | release | manual | deployment (promote) | cron |
|---|---|---|---|---|---|---|---|
| `org`, `repo` | `repo.full_name` split at its single `/` | same | same | same | same | same | same |
| `repo_key` | `<org>/<repo>#<repo.forge_remote_id>` | same | same | same | same | same | same |
| `event` | `push` | `pull_request` | `tag` | `release` | `manual` | `deployment` | `cron` |
| `branch` | pushed branch | **absent** (base branch is not a trust signal) | absent | absent | caller-chosen | inherited from parent | cron's branch |
| `ref` | forge | payload `refs/pull/N/head`, not used | payload `refs/tags/X`, not used | payload `refs/tags/X`, not used | `refs/heads/<branch>` | inherited from parent | `refs/heads/<branch>` |
| `branch_protected` | lookup (§4.2) | absent | absent | absent | lookup | lookup | lookup |
| `actor` | `sender` iff `IRONBARK_ACTOR_FORGE` declares a login forge | same rule | same rule | same rule | `author` | **none** | none |
| `teams` | lookup (§4.4) when actor and env | not resolved | not resolved | not resolved | lookup when env | none (no actor) | none |
| `env` | level metadata (§4.5) | none | none | none | variable, then level metadata | inherited variable, then level metadata | variable, then level metadata |
| `target` | `Deploy-To:` trailer (§4.6) | none | none | none | variable | `deploy_to` | none |

Only `pull_request` is a named PR event. Other PR variants
(`pull_request_closed`, `pull_request_metadata`) are unknown events: they
pass through lowercased with no branch, so they match only roles that list
them in `event`, and the shipped roles do not.

`manual` and `cron` read `pipeline.variables`; a `deployment` carries its
parent's `variables` (the promote form's own parameters never reach the
payload). Push, PR, tag and release carry no variables.

### 4.2 Branch verification

`branch` is only as good as whoever chose it: the pusher on `push`, the
caller on `manual`, the cron creator on `cron`, the *parent pipeline* on a
promote. Two checks turn it into a fact a role may bind on:

1. **Protected on the forge.** ironbark asks the forge
   (`GET /api/v1/repos/{org}/{repo}/branches/{branch}` on Gitea-family forges,
   read scope) and takes its `protected` field.
2. **`ref == "refs/heads/" + branch`.** A promote copies the parent's `ref`.
   Promoting a pull-request pipeline yields `event=deployment`,
   `branch=main` (protected), `ref=refs/pull/N/head` and the unreviewed PR
   head commit. Without this check, "protected branch" is bypassable by
   anyone allowed to promote.

`branch_protected` is `"true"` only when both hold. It is `"false"`
otherwise, including a failed or timed-out lookup and
`IRONBARK_FORGE_PROVIDER=none`. It is absent when `branch` is absent.

"Protected" means "only people the forge allows could have produced this
commit on this branch". It equals "reviewed" only if the forge rule blocks
direct pushes. That is forge configuration, and the forge admin is in the
trust base either way.

### 4.3 Actor per event

Unchanged from the attributes design: `manual` → `author` (the Woodpecker
user, a forge login); push family → `sender` only when the operator declares
a forge whose `sender` is a login; `deployment` and `cron` → none. A promote
carries the parent's `sender`/`author`, so it has **no actor**: no role or
group can require one of a promote (§14).

`actor` is a gate input only: it may appear in `bound_claims` (for example,
a break-glass role bound to two logins). It is never a path level and never
mapped into alias metadata.

### 4.4 Teams

Resolved on the forge as today (SPEC §2.5: the repo's teams, then the
actor's membership in each; site-admin or org-owner token; fail closed).
Two changes:

- Teams are resolved only when an actor exists **and** an environment is
  selected. Team gates apply to the environment level and below; the
  project level is ungated by definition (§3.1), so a lookup without an
  environment has nothing to gate. When the environment comes from level
  metadata, the lookup runs after the discovery login (§4.5).
- Teams go into the JWT `teams` claim as `esc(org)/esc(team)`, for example
  `acme/deployers`, and reach OpenBao through `groups_claim`. Qualifying by
  org stops a team named `deployers` in one org from satisfying a gate meant
  for another org's `deployers`.
- **Team case is safe because the claim is escaped.** OpenBao matches
  group-alias names case-insensitively (lab, Q11): alias `uat-approvers`
  matched claims `uat-approvers`, `UAT-Approvers` and `Uat-approvers`. But
  `esc()` encodes every uppercase byte (`Deployers` becomes `%44eployers`,
  lowercase hex), so `Deployers` and `deployers` reach OpenBao as different
  strings. Group aliases are therefore created with the escaped name, and
  the IaC derives it with the same `esc()`.

A failed lookup (timeout, transport error, unexpected status) emits no
`teams` claim. Every team-gated level is then unreadable: less, never more.

### 4.5 Environment selection

First match wins:

1. The variable named by `IRONBARK_ENV_VAR` (default `DEPLOY_ENV`) in
   `pipeline.variables` (`manual`, `cron`, and a `deployment`'s inherited
   parent variables). It names the environment level directly. This is an
   **explicit** selection (`env_source=variable`).
2. The verified branch, by **level metadata**: when `branch_protected` is
   `"true"`, ironbark lists the directories under the repo level and reads
   each one's level metadata (§8.1). The environment is the level whose
   `branches` includes the branch (`env_source=branch`).
   - No level claims the branch: no environment, the repo level only. Not an
     error; most branches are not environments.
   - Two or more levels claim it: a configuration error. ironbark returns
     only `ironbark_status` (`outcome=config_error`, naming the levels) and
     the job decides (§9). It never picks one.
3. None. The walk reads the repo level only.

`branches` is a comma-separated list of exact branch names, as the forge
spells them (`main`, `release/1`), compared bytewise with the pushed branch.
A level without `branches` is an environment that only `DEPLOY_ENV` selects.

Rule 2 needs a token to read level metadata before the environment is known.
ironbark therefore logs in to the no-environment role (`ci`) first, reads
the level metadata with that token, and then either keeps that token (no
level claims the branch) or revokes it and logs in to the environment's role
(§5.5). The discovery login only ever reads metadata; it never delivers a
secret alongside an environment login. (Open question 1, §17.)

An environment name must match `^[a-z0-9][a-z0-9_-]{0,62}$`, which keeps it
valid as a role-name suffix and as a path segment without escaping.
Environment names are independent of branch names: `prod` can serve `main`.
An explicit value outside the grammar is refused: only `ironbark_status`
(`outcome=invalid`, `env_invalid`), never degraded to rule 2 or to the repo
level. A level whose name is outside the grammar never matches rule 2 and is
recorded.

`DEPLOY_ENV` does not consult `branches`. Selection never entitles: the
environment's role decides whether this branch may act for it (§6.2). The
level metadata and the role's `branch` binding should therefore come from
the same IaC declaration (§14).

### 4.6 Target selection

The target is a selector only. Gates decide access, so it may come from a
cascade (first match wins):

1. `IRONBARK_TARGET_VAR` (default `DEPLOY_TO`) from `pipeline.variables`,
   **on `manual` only**. A promote's inherited variables are the parent's.
   They are ignored so that the promote's own field wins.
2. `pipeline.deploy_to`, on `deployment`.
3. A `Deploy-To:` trailer on the head commit message, on `push` (for
   example on the merge commit of a pull request). Exactly one such trailer
   in the final trailer block; zero or several means no target from this
   rule.
4. None: the walk stops at the environment level.

ironbark does not derive a target from `changed_files`. A job that needs
that works it out in an earlier pipeline and passes the result forward as a
variable (`DEPLOY_TO` on a manual run, the `deploy_to` field on a promote).

Grammar (as today): split on `/`, every segment non-empty, at
most 8 segments and 256 bytes; case, `.` and `..` are kept. Each segment
is escaped on its own (`esc()`, §5.3) and **each segment is a level**:
`srv.talos/svc/gear` walks `prod/srv.talos/`, `prod/srv.talos/svc/` and
`prod/srv.talos/svc/gear/`, deepest wins, so a nested target inherits its
parents' secrets. An explicit value violating the grammar is (proposed, §17.4) refused like
an invalid environment: only `ironbark_status` (`outcome=invalid`,
`target_invalid`), never a silent walk that stops at the environment.

A target without an environment is recorded and ignored: the walk has no
environment to hang it under.

One target per pipeline. A change touching several parts deploys each part
in its own run (manual or promote), each with its own secret list.

## 5. JWT issuance

### 5.1 Key

ironbark holds an RSA private key (3072-bit, PEM) and signs RS256. RS256 is
the algorithm the pre-design spike proved against OpenBao 2.7. The public
key goes into the JWT auth mount's `jwt_validation_pubkeys`, a list. To
rotate, add the new public key, roll ironbark onto the new private key,
then remove the old public key. ironbark sets `kid` to the SHA-256 of its
public key's DER form, for correlation only. No JWKS endpoint is hosted.

The signing key replaces ironbark's AppRole. ironbark holds **no OpenBao
credential at all**: JWT login is unauthenticated, and the signature is the
credential.

### 5.2 Claims

| Claim | Value | Notes |
|---|---|---|
| `iss` | `ironbark` | fixed; mount `bound_issuer` |
| `aud` | `ironbark` | fixed; role `bound_audiences` |
| `sub` | §5.4 | the entity alias key |
| `iat`, `nbf` | now | |
| `exp` | now + 60s | the JWT only has to survive the login call |
| `jti` | random 128-bit hex | audit correlation |
| `org`, `repo` | lowercase, `esc()` | |
| `repo_key` | `esc(org) "/" esc(repo) "#" esc(forge_remote_id)` | bound by every role (§6.2); never mapped |
| `event` | lowercase | unknown events pass through lowercased |
| `branch` | `esc(branch)` | absent per §4.1 |
| `ref` | `esc(ref)` | absent per §4.1 |
| `branch_protected` | `"true"` / `"false"` | absent when `branch` is |
| `actor` | `esc(actor)` | absent when none |
| `teams` | list of `esc(org)/esc(team)` | absent when not resolved or none |
| `env` | selected env | absent when none |
| `env_source` | `variable` / `branch` | absent when no env |
| `target` | escaped segments joined by `/` | audit and `bound_claims` only; never mapped (it contains `/`) |
| `t1` … `t8` | `esc(segment n)` | one claim per target segment, mapped to alias metadata; absent beyond the target's depth |
| `pipeline` | pipeline number, as a string | audit only |

Absent means the claim is omitted, never sent empty. A role that binds an
absent claim refuses the login, and an absent mapped claim renders an
empty path segment that matches nothing. Both fail closed.

### 5.3 Escaping

Every string claim that is or could be mapped into alias metadata goes
through `esc()` (SPEC §2.2, unchanged: bytewise percent-encoding outside
`[a-z0-9._-]`, `%` always encoded, a leading `.` always encoded, lowercase
hex). OpenBao refuses to build an ACL whose template substitution contains
`/`, `*` or `+`, and the failure takes the whole token down, even
`lookup-self`. `esc()` never emits any of the three. Uppercase is encoded,
not folded (`Main` → `%4dain`), so case variants of a protected branch stay
distinct.

`bound_claims` compare escaped values: a role binding `release/*` branches
writes the glob `release%2f*`. `repo_key` is built from escaped parts, so
its `/` and `#` are always the separators.

### 5.4 `sub` derivation

OpenBao keys the entity alias on `sub` and overwrites alias metadata and
external group membership at every login. Policy templates are evaluated
per request, so a second login with the same `sub` and different claims
silently changes what an *earlier*, still-live token can read. The spike
reproduced this. Therefore:

```
sub = "ib-" + hex(sha256(org "\n" repo "\n" env "\n" target "\n" join(sort(teams), ","))) [first 40 chars]
```

Every value that feeds alias metadata or group membership is in the hash,
so two logins share a `sub` only when their effective grants are
identical (`target` is the joined path, so it covers `t1`…`t8`). Actor,
event and branch are checked at login (`bound_claims`) and are not
persisted, so they stay out of the hash. This bounds entity growth by the
number of distinct `(repo, env, target, team-set)` tuples, not by pipelines
(§14, §20).

### 5.5 Login and token contract

`POST auth/<IRONBARK_JWT_MOUNT>/login` with `{"role": <role>, "jwt": <jwt>}`.
`<role>` is `IRONBARK_JWT_ROLE` rendered with the env. With no env, the
`{env}` placeholder and one adjoining separator (`-`, `_` or `.`) are
removed: `ci-{env}` → `ci-staging`, or `ci`. There is **one role per
environment level** and one login role per run: deployers hang any number
of policies and groups off it, and a refused login is never retried with a
second role. The only other login is the metadata-only discovery login to
`ci` that precedes an environment chosen by level metadata (§4.5); it is
revoked before the environment login.

Every role must set:

```
token_type              = "service"   # leases must parent to the pipeline token
token_ttl               = "15m"       # sized to queue + run time (README TTL budgeting)
token_explicit_max_ttl  = "15m"       # hard cap: renewals cannot extend past it
token_no_default_policy = false       # revoke-self powers failure-path revocation
```

Tokens from an auth login are orphans by construction, which is what
SPEC §3.3 required of the token role. Per login, ironbark asserts
`auth.token_type == "service"` and `auth.orphan == true`, then calls
`auth/token/lookup-self` and asserts `explicit_max_ttl > 0`. Any violation
→ `revoke-self`, only `ironbark_status` (`outcome=error`), error log naming
the role. This per-login check
replaces the startup canary (SPEC §3.5): there is no ironbark credential to
canary, and each environment role can be misconfigured on its own.

## 6. OpenBao configuration

The examples use repo `acme/mono` (forge id 4711), environments `prod`
(`branches = main`) and `staging` (`branches = staging`), targets `web` and
`web/api`, and
`IRONBARK_DATA_PATH=vs/data/pipelines/{repo}/{env}/{target...}`. `ACC`
stands for the JWT mount accessor, and `M(x)` abbreviates
`{{identity.entity.aliases.ACC.metadata.x}}`; real policies spell it out.

### 6.1 Mount

```
bao auth enable -path=jwt jwt
bao write auth/jwt/config \
  bound_issuer=ironbark \
  jwt_validation_pubkeys=@ironbark-jwt.pub
```

### 6.2 Roles: the branch strategy

One role per environment level plus the no-environment role. `bound_claims`
is where the branch strategy, the event pins and the list of repos served
live. Roles are written as JSON (`bound_claims` and `claim_mappings` do not
survive the CLI's `k=v` form). A list value in `bound_claims` means "any
of".

`auth/jwt/role/ci`, the repo level (and the discovery login, §4.5) for
every onboarded repo:

```json
{
  "role_type": "jwt", "user_claim": "sub", "bound_audiences": ["ironbark"],
  "bound_claims_type": "glob",
  "bound_claims": {
    "repo_key": ["acme/mono#4711", "acme/other#*"],
    "event": ["push", "pull_request", "tag", "release", "manual", "deployment", "cron"]
  },
  "claim_mappings": {"org": "org", "repo": "repo"},
  "token_policies": ["ci-project"],
  "token_type": "service", "token_ttl": "15m", "token_explicit_max_ttl": "15m"
}
```

`auth/jwt/role/ci-prod`, where only a verified protected `main` acts for
the `prod` level:

```json
{
  "role_type": "jwt", "user_claim": "sub", "bound_audiences": ["ironbark"],
  "bound_claims_type": "glob",
  "bound_claims": {
    "repo_key": ["acme/mono#4711"],
    "env": "prod",
    "branch": "main",
    "branch_protected": "true",
    "event": ["push", "deployment"]
  },
  "claim_mappings": {"org": "org", "repo": "repo", "env": "env",
                     "t1": "t1", "t2": "t2", "t3": "t3", "t4": "t4",
                     "t5": "t5", "t6": "t6", "t7": "t7", "t8": "t8"},
  "groups_claim": "teams",
  "token_policies": ["ci-project", "ci-env"],
  "token_type": "service", "token_ttl": "15m", "token_explicit_max_ttl": "15m"
}
```

`auth/jwt/role/ci-staging`, where staging runs from its own protected
branch by push, manual, promote or cron: as `ci-prod`, with
`"env": "staging"`, `"branch": "staging"`,
`"event": ["push", "manual", "deployment", "cron"]` and
`"token_policies": ["ci-project", "ci-env", "ci-target"]`.

Notes:

- `env` is bound as well as implied by the role name. A role rendered for
  the wrong environment cannot log in.
- **`repo_key` pins repos to their forge id.** Every role lists the repos it
  serves, one entry each: `acme/mono#4711` (pinned: a repo renamed away, or
  deleted and recreated under the same name, has a new id and cannot log
  in) or `acme/other#*` (named, not pinned). Never an org-wide
  (`acme/*`) or catch-all glob: the list is an OR, so a wider entry
  silently undoes every pin beside it. IaC appends the entry at onboarding.
  Lab result (OpenBao 2.7.0): with `["acme/mono#4711", "acme/other#*"]`,
  `acme/mono#4711` and `acme/other#9999` log in; `acme/mono#9999`,
  `acme/mono#47110` and a bare `acme/mono` are refused
  (`claim "repo_key" does not match any associated bound claim values`).
  Adding `acme/*#*` lets `acme/mono#9999` in: the wide glob demonstrably
  undoes the pin.
  OpenBao parameter constraints cannot do this job: they restrict writes,
  not KV v2 reads, and login happens before any policy applies.
- `bound_claims_type` is per role. With `glob`, the exact values above are
  globs without wildcards; `esc()` never emits `*`, so no escaped fact can
  act as a wildcard.
- **Event pins are per role.** An environment that only manual runs and
  promotes may act for lists exactly `["manual", "deployment"]`. A secret
  that needs a narrower event set than its level's role lives at a level
  whose role has that set. Lab result: with `event: ["manual", "deployment"]`
  bound, `manual` and `deployment` log in; `push` and `pull_request` are
  refused (`claim "event" does not match...`), and a JWT with no `event`
  claim is refused too (`claim "event" is missing`).
- `ci-prod` deliberately omits `ci-target` from `token_policies`: its target
  levels are team-gated (§6.4).
- `pull_request` in `ci`'s event list is a choice. Leave it out and PR
  pipelines get only `ironbark_status`. Keep it and they get the repo level,
  which therefore must hold nothing a PR head may not see (§3.1).
- The role's `branch` binding and the level's `branches` metadata (§4.5)
  describe the same strategy from two sides (gate and selector). Write both
  from one IaC declaration.

### 6.3 Templated policies, one per level kind

```hcl
# ci-project: the repo level, plus level metadata for discovery (§4.5)
path "vs/data/pipelines/M(org)/M(repo)/+"      { capabilities = ["read"] }
path "vs/metadata/pipelines/M(org)/M(repo)/"   { capabilities = ["list"] }
path "vs/metadata/pipelines/M(org)/M(repo)/+/" { capabilities = ["read"] }

# ci-env
path "vs/data/pipelines/M(org)/M(repo)/M(env)/+"    { capabilities = ["read"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/" { capabilities = ["list"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/+" { capabilities = ["read"] }

# ci-target: one triple per target depth, 1 to 8
path "vs/data/pipelines/M(org)/M(repo)/M(env)/M(t1)/+"          { capabilities = ["read"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/M(t1)/"       { capabilities = ["list"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/M(t1)/+"      { capabilities = ["read"] }
path "vs/data/pipelines/M(org)/M(repo)/M(env)/M(t1)/M(t2)/+"    { capabilities = ["read"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/M(t1)/M(t2)/" { capabilities = ["list"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/M(t1)/M(t2)/+" { capabilities = ["read"] }
# ... and so on through M(t8)
```

The lab (spike 5, OpenBao 2.7.0 with voidstar) proved this shape. Claims
`org`, `repo`, `env`, `t1`..`t8` are mapped through `claim_mappings`; each
level gets one stanza triple whose data path ends in `/+`. For the target
`srv.talos/svc/gear`, with views
`est/acme/mono/{db, prod/db, prod/srv.talos/db, prod/srv.talos/svc/db, prod/srv.talos/svc/gear/db}`
(mount `vs/`, path `est/{org}/{name}/{env}/{t1}/...`), the level-2 triple is:

```hcl
path "vs/data/est/{{...metadata.org}}/{{...metadata.repo}}/{{...metadata.env}}/{{...metadata.t1}}/{{...metadata.t2}}/+" { capabilities = ["read"] }
path "vs/metadata/est/{{...metadata.org}}/{{...metadata.repo}}/{{...metadata.env}}/{{...metadata.t1}}/{{...metadata.t2}}/"  { capabilities = ["list"] }
path "vs/metadata/est/{{...metadata.org}}/{{...metadata.repo}}/{{...metadata.env}}/{{...metadata.t1}}/{{...metadata.t2}}/+" { capabilities = ["read"] }
```

(`{{...metadata.x}}` abbreviates `{{identity.entity.aliases.ACC.metadata.x}}`.
The lab named the repo claim `name`; this design calls it `repo`. Group
policies below use the same triple per level; the third stanza is omitted
there for brevity.)
Results: the token for `srv.talos/svc/gear` read all five levels and could
list each; sibling `svc/other`, another environment and another repo got
403. A token whose JWT lacked `t2` and `t3` had those stanzas silently
skipped, the rest still applied, and nothing extra was granted. A target
segment with a literal `%2f` matched its wire path (`%252f`).

**Pitfall: never end a level stanza with `*`.** A trailing `*` in an
OpenBao policy path is a prefix match, so `.../{{t1}}/*` grants every level
below `t1` as well and destroys the level separation. `+` is exactly one
segment and is the only correct terminator.

Three policies serve every repo, environment and target. `+` is exactly one
segment, so no level's grant reaches the level below it, and a target
`web/api` reads `web/` and `web/api/` but never a sibling such as
`web/cli/`. A missing `env` or `tN` renders an empty segment that matches
nothing, so the stanzas deeper than the selected target grant nothing.

The policies and `IRONBARK_DATA_PATH` must describe the same levels in the
same order. Generate both from one IaC variable, or use
`ironbark render-policies` (§11.3), which prints these three from the
configured path.

### 6.4 Groups: team gates

A team gate is a group policy. `ci-prod` above grants `prod`'s target
levels only through groups. A group per gated target lists that target's
levels literally below the templated environment:

```hcl
# ci-prod-web (group acme-deployers)
path "vs/data/pipelines/M(org)/M(repo)/M(env)/web/+"         { capabilities = ["read"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/web/"      { capabilities = ["list"] }
path "vs/data/pipelines/M(org)/M(repo)/M(env)/web/api/+"     { capabilities = ["read"] }
path "vs/metadata/pipelines/M(org)/M(repo)/M(env)/web/api/"  { capabilities = ["list"] }
```

```
bao write identity/group name=acme-deployers type=external policies=ci-prod-web
bao write identity/group-alias name=acme/deployers \
  mount_accessor=ACC canonical_id=<group id>
```

A pipeline whose `teams` claim contains `acme/deployers` gets
`ci-prod-web` as an identity policy.

Group policies apply to **every** login of the entity, whatever the role.
Identity policies are additive, and a role cannot cap them. So:

- A group policy must be templated on `env`, never a fully literal path.
  Rendered for a login without an environment, it matches nothing. The
  environment was admitted by the role, so the group adds only levels below
  an environment the role already accepted.
- A gate on one target in an environment that has an ungated generic
  `ci-target` is impossible, because templating has no exclusion and
  `deny` would override the group grant too. Such an environment must not
  carry `ci-target` on its role. Gate granularity is the environment;
  per-target gates are hand-listed, one stanza pair per gated level.
- A literal gated stanza is not tied to the selected target. The walk
  never reads it for another target, but the token can (§8.5, §14).

### 6.5 Recipes

| Wanted | OpenBao and voidstar config |
|---|---|
| only protected `main` deploys `prod` | level `prod` metadata `branches = main`; role `ci-prod`: `branch=main`, `branch_protected=true` |
| staging also from manual runs | add `manual` to `ci-staging`'s `event` list; the run is on branch `staging` |
| an environment only manual runs and promotes may act for | its role's `event` is `["manual", "deployment"]` |
| `prod` targets only for team `deployers` | per-target group policies on `acme-deployers`; no `ci-target` on `ci-prod` |
| one target for one team, the rest open | role without `ci-target`; one group policy per gated target, one open policy listing the other targets |
| a break-glass person | a second level `prod-breakglass` (no `branches`) whose mappings point at the same upstream items as `prod`; its role binds `actor: ["alice"]`; selected with `DEPLOY_ENV` |
| PRs see nothing | drop `pull_request` from `ci`'s events |
| onboard a repo | append `acme/mono#<id>` to `repo_key` on every role that serves it |
| a step may see a secret only from one image | `ironbark_images` on that secret's mapping (§8.4) |
| a repo's pipelines get `vault_token` | a metadata-only `vault_token` mapping at the level that should get it, with its image pins (§8.5) |

## 7. Dynamic credentials

Dynamic engines (AWS STS, database creds) cannot be ordinary voidstar
views. If voidstar fetched them, the lease would belong to voidstar's token
and outlive the pipeline. voidstar also cannot act as the caller: OpenBao
salts the client token it hands a plugin mount, and `X-Vault-Token` cannot
be passed through.

So a view can be a **resolve-don't-fetch mapping** (§16). Reading it
returns the engine path it points at plus the mapping's own
`custom_metadata` (its pins), and never touches the engine. ironbark then
reads that path with the pipeline's own token, so the lease parents to that
token and is revoked with it:

```
vs/data/pipelines/acme/mono/staging/web/aws   resolve -> aws/creds/staging-web
```

The engine path is **named by convention** after the levels, so a templated
policy grants it and a mapping can only reach what the pipeline could read
anyway:

```hcl
# ci-dynamic (attached next to ci-env / ci-target)
path "aws/creds/M(env)"        { capabilities = ["read"] }
path "aws/creds/M(env)-M(t1)"  { capabilities = ["read"] }
```

The view's key names the result, and the engine response's fields are
flattened into names by the SPEC §4.2 rules (`aws` → `aws_access_key`,
`aws_secret_key`, `aws_security_token`). One hop only: the engine response
is never itself treated as a pointer. The mapping's pins apply to every
name it produces, so "pins live on the mapping" holds for static and
dynamic secrets alike.

A step can also read an engine path itself with `vault_token`, where a
`vault_token` mapping issues one (§8.5). ironbark adds nothing then, and the
value is not masked by Woodpecker (the honest limit in DESIGN §3).

`$ref` is removed. Resolve-don't-fetch is the only pointer, and it is data
the IaC writes, not a convention inside a KV value. A plain KV v2 tree has
no dynamic pointers.

## 8. The walk

### 8.1 Path template and levels

`IRONBARK_DATA_PATH` is a path whose placeholders are whole segments:
`{repo}` (required; it expands to `esc(org)/esc(repo)`, two segments), then
`{env}` and `{target...}`, which must be the last two in that order. Its
second segment must be `data` (the KV v2 convention). The metadata path
used for `LIST` swaps it for `metadata`. Anything else is a startup error.

The levels are the template's prefix ending at `{repo}`, the prefix ending
at `{env}`, and one level per target segment:

```
vs/data/pipelines/acme/mono/                  repo
vs/data/pipelines/acme/mono/prod/             env
vs/data/pipelines/acme/mono/prod/web/         target, depth 1
vs/data/pipelines/acme/mono/prod/web/api/     target, depth 2
```

A level whose placeholder value is absent ends the list.

**Level metadata** is read as `GET` on a level's metadata path with a
trailing slash (`vs/metadata/pipelines/acme/mono/prod/`), which voidstar
answers with the prefix's own `custom_metadata` (§16). 404 means the level
has none. Only environment discovery (§4.5) reads it, and only for the
directories directly under the repo level. Every directory there is an
environment level.

### 8.2 Algorithm

```
levels = [repo]; if env: levels += [env]
if env and target: levels += [env/t1, env/t1/t2, ...]      # one per segment
result = {}                                   # name -> (value, level, pins)
for level in levels (shallow to deep):
    keys = LIST <metadata path of level>
    on 403 or 404: record level as skipped; continue      # unreadable levels are skipped
    on other error: fail
    for key in keys, sorted bytewise, skipping directory entries ("x/"):
        entry = GET <data path of level>/<key>
        on 403 or 404: skip entry, record; continue
        on other error: fail
        pins = entry.custom_metadata.ironbark_images      # §8.4
        if key == "vault_token":                          # §8.5
            if entry has data: skip, warn; continue
            result["vault_token"] = (<pipeline token>, level, pins); continue
        if entry is a resolve mapping:                    # §7
            payload = GET entry.target with the pipeline token
            on 403 or 404: skip entry, record; continue
            on other error: fail
        else: payload = entry.data
        for (name, value) in flatten(key, payload):       # SPEC §4.2 names
            if name == "ironbark_status": skip, warn; continue   # reserved
            result[name] = (value, level, pins)           # deeper level wins
fail = revoke the token (leases taken so far go with it); return only ironbark_status
```

- **Unreadable levels are skipped, and the walk continues deeper.** A
  target level may be readable where its environment level is not (a gated
  environment, an open target). The walk does not infer denial below from
  denial above.
- **Clash resolution:** across levels the deepest wins. Within one level
  (two keys flattening to the same name, `a_b` and `a` field `b`) the first
  in bytewise key order wins and the clash is logged, as today. Cross-level
  overrides are documented behaviour and are neither logged specially nor
  linted.
- Names, string-only values, `-` → `_` and the `[a-z0-9_]+` check are as in
  SPEC §4.2. A key that does not produce a valid name is skipped with a
  warning. `ironbark_status` is reserved.
- No descent below a level other than into the next selected level.
  Sub-directories that are not the selected environment or target segment
  are never read.

### 8.3 What the walk does not do

It does not list targets, and it lists environments only to read their
`branches` during discovery (§4.5). It never reads a level it was not asked
for, even if the token could.

### 8.4 Image pins

Image pins are per step, so only Woodpecker can enforce them; ironbark
relays them. They live on the voidstar **mapping**, as `ironbark_images` in
its `custom_metadata`, which voidstar returns in the view's synthetic
metadata on read (§16). ironbark reads it where it reads KV v2
`custom_metadata` today (SPEC §4.6) and returns it as the secret's image
list. The upstream target's own metadata is never copied through. On a
plain KV v2 tree the entry's own `custom_metadata` serves the same purpose.

`ironbark_events` is no longer read: event pins are role `bound_claims`
(§6.2). An entry still carrying it is logged as ignored.

### 8.5 `vault_token`

`vault_token` is an escape hatch, restricted like any other secret. ironbark
returns the pipeline token as `vault_token` only when a walked level holds a
**metadata-only mapping** named `vault_token` (for example
`vs/data/pipelines/acme/mono/vault_token`, with no upstream target), and
attaches that mapping's image pins. No mapping, or a mapping the token cannot
read, → no `vault_token`. Default off. On a plain KV v2 mount the marker is
an empty entry of that name (§3.1). A `vault_token` entry that carries
data is skipped with a warning, so nobody stores a real token there.

The token never widens access beyond the login's policies, and its TTL is
the pipeline token's (§5.5). It can, however, read more than the walk did:
the union of the login's policies includes literal per-target group stanzas
(§6.4) and every convention-named engine path the policies grant (§7). The
pin keeps it from untrusted steps.

## 9. Request sequence and failure behaviour

### 9.1 Sequence

1. Read body, verify signature, parse: SPEC §1.2 steps 1–4, unchanged.
   An invalid signature is still `401` with nothing: the request is not a
   verified pipeline, so there is no job to report to.
2. Establish facts (§4): the forge lookup for branch protection. Bounded by
   `IRONBARK_FORGE_TIMEOUT`, fails closed.
3. Select the target (§4.6) and, if `DEPLOY_ENV` is set, the environment.
   An invalid explicit selector → status only.
4. No explicit environment, protected branch: discovery login to `ci`, read
   level metadata (§4.5). No claimant → keep this token, go to 7. Two
   claimants → revoke, status only. One claimant → revoke, go on.
5. With an environment and an actor: the team lookup (§4.4), bounded and
   fail-closed.
6. Build and sign the JWT (§5). Log in with the rendered role. A refusal →
   status only.
7. Per-login assertions (§5.5).
8. Walk (§8), resolving mappings (§7).
9. Respond `200` with the walk's secrets and `ironbark_status`.

Every verified request gets a `200` carrying `ironbark_status`. `204` and
`502` are gone. **Revocation by outcome** (SPEC §3.4) is restated: a
response carrying only `ironbark_status` revokes any token the request
obtained; a response carrying any other secret never does.

### 9.2 ironbark never fails a pipeline

A login is refused when the role does not exist or the claims do not
satisfy its `bound_claims`, for example `DEPLOY_ENV=prod` from an
unprotected branch. The result is **no secrets** and an `ironbark_status`
saying so. It is never a silent fallback to another environment or to the
repo level: a deploy that asked for `prod` and got repo-level secrets would
run half-configured.

Deciding the job's status (fail, warn, pass) is the job's responsibility,
not the CI plumbing's. ironbark reports, the job decides.

`ironbark_status` is one line, a version tag followed by `key=value` pairs:

```
ironbark/v1 outcome=refused env=prod env_source=variable target=web role=ci-prod reason=bound_claims
```

| `outcome` | Meaning | Other secrets |
|---|---|---|
| `ok` | walk ran (levels may have been skipped; `skipped=` lists them) | the walk's |
| `refused` | OpenBao refused the login (role missing or claims not met) | none |
| `invalid` | an explicit selector failed its grammar | none |
| `config_error` | two environment levels claim the branch (`levels=` names them; proposed, §17.3) | none |
| `error` | anything else: OpenBao or voidstar unreachable, JWT rejected, a per-login assertion, a broken view (`reason=` says which) | none |

Values never appear in it, only names, levels and reasons. A pipeline
can gate on it:

```yaml
steps:
  - name: check-secrets
    image: alpine
    environment:
      STATUS: { from_secret: ironbark_status }
    commands:
      - case "$STATUS" in *"outcome=ok"*) ;; *) exit 1 ;; esac
```

Two Woodpecker behaviours bound this:

- **A missing `from_secret` errors the whole pipeline at compile.** Any step
  naming a secret ironbark did not return makes Woodpecker refuse the
  pipeline before any step runs, a CI-system error the job cannot catch.
  This is accepted as a Woodpecker limitation. Jobs that want to decide
  for themselves reference only secrets that are always returned
  (`ironbark_status`, repo-level secrets) in the steps that decide.
- **`ironbark_status` is masked like any secret.** Woodpecker replaces its
  exact value in logs. The `ironbark/v1` prefix makes the whole line
  unlikely to occur elsewhere; printing it needs a transform (for example
  `echo "$STATUS" | tr ' ' '\n'`). Confirmed against Woodpecker v3.18.0: a
  secret extension cannot mark a secret as unmasked (§17 item 2).

### 9.3 Fail closed everywhere

| Failure | Result |
|---|---|
| signature invalid | 401, nothing (unchanged) |
| forge down or slow, protection lookup | `branch_protected=false`: no discovery, repo level only; an explicit env is refused by a role that binds `branch_protected` → `refused` |
| forge down or slow, team lookup | no `teams` claim: team-gated levels skipped |
| OpenBao unreachable | `error`, nothing else |
| JWT rejected (bad key, expired, wrong audience) | `error`, nothing else, error log (a config fault, not a policy outcome) |
| role missing or claims refused | `refused`, nothing else |
| level metadata unreadable during discovery (other than 404) | revoke, `error`, nothing else: a hidden claimant must not let another level win |
| two levels claim the branch | revoke, `config_error`, nothing else |
| per-login assertion fails | revoke, `error`, nothing else |
| template renders a forbidden character | cannot happen via `esc()`; if it did, OpenBao builds no ACL and every read 403s → empty walk, `ok` with every level skipped |
| level `LIST` 403/404 | level skipped |
| entry `GET` 403/404 | entry skipped |
| view 502 (voidstar quarantine or loopback broken) | revoke, `error` naming the entry, nothing else: a broken view is reported instead of silently dropping one secret |
| resolved engine path 403/404 | entry skipped |
| resolved engine path, other error | revoke (the cascade revokes leases already taken), `error`, nothing else |

## 10. Audit line

The verified-request line (SPEC §8.1) becomes:
`ts, org, repo, repo_key, event, branch, ref, branch_protected, actor, teams |
teams_error, env, env_source (variable|branch), env_claimants, env_invalid,
env_refused, target, target_source (variable|deploy_to|trailer),
target_invalid, discovery_login, role, sub, jti, levels (label ->
read|skipped_403|skipped_404), secrets_returned (names), images_relayed
(names), vault_token_issued, token_accessor, token_ttl, outcome` (the same
`outcome` as `ironbark_status`). Payload
values that are not facts (variables other than the two selectors, message
text) are never logged. The debug `payload attributes` line stays.

## 11. Configuration

### 11.1 The grant model: four variables

```
IRONBARK_DATA_PATH   = vs/data/<estate>/{repo}/{env}/{target...}
IRONBARK_ENV_VAR     = DEPLOY_ENV
IRONBARK_TARGET_VAR  = DEPLOY_TO
IRONBARK_JWT_ROLE    = ci-{env}          # "ci" when no env
```

How they reach ironbark (plain env, External Secrets, a mounted file) is the
deployer's choice. Everything that decides access is OpenBao configuration.

### 11.2 Plumbing (kept or added)

Kept: `IRONBARK_LISTEN_ADDR`, `IRONBARK_WOODPECKER_PUBLIC_KEY[_FILE]`,
`IRONBARK_VAULT_ADDR`, `IRONBARK_FRESHNESS_WINDOW`,
`IRONBARK_ADVERTISE_VAULT_ADDR`, `IRONBARK_LOG_LEVEL`,
`IRONBARK_ACTOR_FORGE`, `IRONBARK_FORGE_PROVIDER`, `IRONBARK_FORGE_URL`,
`IRONBARK_FORGE_TOKEN[_FILE]`, `IRONBARK_FORGE_TIMEOUT` (now bounds each
lookup: protection and teams).

Added: `IRONBARK_JWT_SIGNING_KEY[_FILE]` (required, PEM RSA private key),
`IRONBARK_JWT_MOUNT` (default `jwt`).

Removed: `IRONBARK_VAULT_ROLE_ID`, `IRONBARK_VAULT_SECRET_ID`,
`IRONBARK_TOKEN_ROLE`, `IRONBARK_KV_MOUNT`, `IRONBARK_KV_PREFIX`,
`IRONBARK_POLICY_PREFIX`, `IRONBARK_ATTR_MOUNT`, `IRONBARK_MAX_POLICIES`.

With `IRONBARK_FORGE_PROVIDER=none`, `branch_protected` is always `"false"`.
No environment is then discovered from level metadata, and only explicit
environments on roles that do not bind `branch_protected` can be reached. A
startup warning says so.

### 11.3 `ironbark render-policies`

A subcommand that prints the three level policies (§6.3, with all eight
target depths) for a given mount accessor from `IRONBARK_DATA_PATH`. It keeps the policy paths and the walk
order from drifting. It needs no OpenBao access. Optional to use.

## 12. `ib` changes

### 12.1 Configuration

`ib` reads the same four settings under the same names, plus the OpenBao
address, from:

1. environment variables (`BAO_ADDR`/`VAULT_ADDR`, `IRONBARK_*`), then
2. `~/.config/ib/config`, a `KEY=value` file in `ib run --env-file` syntax
   holding the same names.

Environment wins over the file. `IB_KV_MOUNT` and `IB_KV_PREFIX` are removed.
Token handling (`BAO_TOKEN`, `VAULT_TOKEN`, `~/.vault-token`, `ib auth`) is
unchanged.

### 12.2 Selection and walk

`ib` does the same walk as ironbark (§8), via the same code, with the
caller's own token (resolve mappings included, so dynamic leases are the
caller's and are revoked after `ib run` as today):

- `org`/`repo` from the `origin` remote, as today.
- `--env <name>` / `IB_ENV` replace `DEPLOY_ENV`, and `--target <path>` /
  `IB_TARGET` replace `DEPLOY_TO`. The same grammars apply.
- Without `--env`, `ib` runs the level-metadata rule (§4.5 rule 2) for the
  current local branch, over the environment levels the caller can read:
  one claimant → that environment; none → the repo level only; several →
  exit with an error naming them. There is no protection check: the
  caller's own policies are the gate. The CLIENT-SPEC §3 branch-tier
  selection and the `--branch` flag go.
- Without `--target`, the walk stops at the environment level. `ib` does
  not derive a target from the working tree. A nested `--target` walks
  every segment, as in §8.1.
- `ib` never returns `ironbark_status` or `vault_token`; it reports on
  stderr and exits non-zero on a failed login or walk.

Access is the caller's own policies. The templated CI policies key on JWT
alias metadata and do nothing for a human token. People get static
policies (for example `read` on `vs/data/pipelines/acme/+/staging/*`, plus
`read` on `vs/metadata/pipelines/acme/+/+/` for level metadata). Personal
policies are the gate.

### 12.3 Masking

Every value `ib run` injects or substitutes is masked in the child's output.
The length ≥ 4 exemption goes. A short value that masks noise is a sign
it is an identifier stored as a secret (§3.3), and the fix is on the data
side. `--no-masking` stays for interactive commands.

### 12.4 Missing names

`ib` does not check that expected names were produced. An
`ironbark://<name>` reference the walk did not produce leaves that variable
unset, with one stderr line naming it. The wrapped tool validates its own
inputs. Exit code 3 remains only for `ib get <name>`, where there is
nothing to print.

### 12.5 Unchanged

`.identity` and `.config` were never read by `ib`. They are gone anyway
(§13). Lease revocation after `ib run` is unchanged, as are the `get` and
`env` output shapes (the `json` form's `branch`/`rule` become `env`/`rule`).

## 13. Removed from ironbark

- The KV tier tree: `<KV_PREFIX>/<org>/<repo>/<event>[/<branch>]`, and the
  attribute mount with its `.target`, `.actor`, `.team`, `.target-actor`,
  `.target-team` shapes.
- Per-tier policy names (P1, P2, attribute names), the `allowed_policies_glob`
  token role, `IRONBARK_MAX_POLICIES` and its drop order.
- The dot notation: `.identity`, `.config` and the dot-key namespace. The
  rename guard `.identity` gave moves to `repo_key` in role `bound_claims`
  (§6.2); the `vault_token` switch `.config` gave becomes the `vault_token`
  mapping (§8.5).
- The `ironbark_events` pin. Event pins are role `bound_claims` (§6.2).
  `ironbark_images` stays, read from the mapping (§8.4).
- `$ref`. Resolve-don't-fetch mappings replace it (§7).
- ironbark's AppRole, the token-store mint, and the startup canary.
- `204` and `502` for verified requests: every verified request gets `200`
  with `ironbark_status` (§9).

## 14. Limits, stated plainly

- **A promote has no actor.** Woodpecker copies the parent's `sender` and
  `author`. A promote can never satisfy an actor or team gate. A team-gated
  level is unreachable by promote: the gate holds, and promotes into gated
  levels get no secrets from them.
- **A push has no target of its own.** Only a `Deploy-To:` trailer gives it
  one. Otherwise it stops at the environment level.
- **One secret list per pipeline.** Every workflow and step of a pipeline
  sees the same list. Part isolation within one pipeline is impossible, so
  split parts across runs (§4.6).
- **ironbark never fails a pipeline, but Woodpecker can.** A step whose
  `from_secret` names a secret ironbark did not return errors the whole
  pipeline at compile, before the job can read `ironbark_status`. Accepted
  as a Woodpecker limitation (§9.2).
- **`ironbark_status` is masked** in logs like every secret (§9.2).
- **Gate granularity is the environment.** Per-target gates are literal
  group policies (§6.4).
- **A branch strategy is written twice**: as the level's `branches`
  (selector) and the role's `branch` binding (gate). If they disagree, the
  result is less, never more: a level claiming a branch its role refuses →
  `refused`; a role admitting a branch no level claims → pushes get the
  repo level, `DEPLOY_ENV` still works. The IaC should write both from one
  declaration.
- **Implicit environments cost a second login.** A protected push without
  `DEPLOY_ENV` logs in to `ci` to read level metadata, then to the
  environment's role. Every `ci` login of a repo can read its environments'
  names and `branches` (metadata only, never values).
- **Target depth is at most 8**, fixed by the eight `tN` claims and the
  eight stanza pairs of `ci-target`.
- **`vault_token` can read beyond the walk** where it is issued: literal
  group stanzas (§6.4) and convention-named engine paths (§7). It is
  opt-in per level and image-pinned (§8.5).
- **Tag and release pipelines never reach an environment.** They have no
  verified branch and no variables.
- **Entity build-up.** Each distinct `sub` leaves an entity and an alias
  that OpenBao never removes. Growth is bounded by distinct
  `(repo, env, target, team-set)` tuples. Clean-up is out of scope (§20).
- **Repo pins are IaC data.** A pinned repo that is renamed or recreated
  cannot log in until its `repo_key` entry (and its data path) is updated.
  An `org/repo#*` entry is not pinned, by choice.
- **Metadata is string-only.** A list claim in `claim_mappings` fails the
  login. Teams therefore travel only through `groups_claim` and gate only
  through groups. No policy can template on a team. `branches` is a
  comma-separated string.
- **A plain KV v2 tree gets less**: no environment discovery (explicit
  `DEPLOY_ENV` only) and no dynamic pointers (§3.1).
- **voidstar dependency.** Image pins on views, dynamic pointers,
  `vault_token` on views and environment discovery all need the voidstar
  changes in §16. Until they ship, only the plain-KV subset works.
- **ironbark's signing key is the CI secret estate.** Whoever holds it can
  sign any claims and log in to any role. This is the same bound as today's
  token-create capability, and every login is audited with its claims.
- **Team names are case-insensitive to OpenBao.** Group aliases match
  regardless of case; escaping the claim (§4.4) keeps teams that differ only
  in case apart, so the alias must be written escaped.
- **Proven on OpenBao 2.7 only.** Vault has the same JWT auth and templating
  features, but nothing here has been run against it yet. The integration
  suite must prove both before ironbark claims both.

## 15. Migration

### 15.1 Coexistence

Woodpecker 3.x sets the secret-extension endpoint **per repo**
(`secret_extension_endpoint`). The legacy release and the grant-model
release run side by side as two deployments with the same Woodpecker public
key, and repos move one at a time by changing their endpoint. Rollback is
the reverse change. No dual-mode code: the grant-model release drops the
legacy path entirely.

OpenBao holds both configurations during the period. The legacy token role,
AppRole and `kv/ci/...` tree stay untouched until the last repo has moved.

### 15.2 Moving one repo

1. **Inventory** the repo's tiers: base, event, branch, attribute entries,
   pointers, pins and `.config`/`.identity` directives.
2. **Classify each secret by what changes its value:**
   - same value for every pipeline, and safe for PR heads → repo level;
   - differs per deployment environment → an environment level, named for
     what it is (`prod`), with `branches` naming the branch that feeds it
     (`push/main/*` → `prod/`, `branches = main`);
   - specific to one part → `<env>/<target>/`, nested parts as nested
     levels (`.target/web` in the `manual` or `deployment` tier →
     `<env>/web/`);
   - identifiers → out of the tree, into repo config (§3.3).
3. **Turn access-only distinctions into gates and metadata:**
   - event tiers (`pull_request`, `manual`, `cron`) and `ironbark_events`
     pins → `event` lists in role `bound_claims`;
   - branch tiers → an environment role binding `branch` and
     `branch_protected`;
   - `.actor/<login>` → `actor` in a role's `bound_claims`;
   - `.team/<team>`, `.target-team/...` → group policies (§6.4);
   - `.target-actor/...` → a single-member group, or a dedicated level and
     role;
   - `ironbark_images` → the same key on the new mapping's
     `custom_metadata`;
   - `.config` allowing `vault_token` → a `vault_token` mapping at that
     level, with pins;
   - `.identity` → the repo's `repo_key` entry on every role that serves it.
4. **Create views** (one per secret, at its canonical level) and level
   metadata. Create roles and groups. The three level policies are
   estate-wide and exist once.
5. **Dynamic pointers:** rename engine roles to the `<env>[-<target>]`
   convention and replace each `$ref` with a resolve mapping (§7).
6. **Pipelines:** manual runs from a branch no level claims set
   `DEPLOY_ENV`. Merges that deploy one part add a `Deploy-To:` trailer.
   Workflows that chose a part from changed files compute it in an earlier
   pipeline and pass it forward (`DEPLOY_TO` for a manual run, `deploy_to` for a promote). Steps that must
   decide for themselves read `ironbark_status` and reference no secret that
   can be absent (§9.2).
7. **Cut over** the repo's endpoint and run its acceptance cases (§18.3).
8. **After a soak**, delete the repo's `kv/ci/...` subtree and its tier
   policies.

## 16. Required voidstar changes

The model treats a voidstar mapping as a record in its own right. voidstar
needs five changes, and should close any similar KV v2 feature gap views
turn out to need.

1. **Mapping `custom_metadata`.** A string map set when the mapping is
   written, and returned as `custom_metadata` in the view's synthetic KV v2
   metadata on every read (data and metadata endpoints). The upstream
   target's own metadata is never copied through or merged. ironbark reads
   `ironbark_images` from it (§8.4).
2. **Resolve-don't-fetch mode.** A mapping flagged to resolve, pointing at
   an engine path. Reading the view returns the target path and the
   mapping's `custom_metadata`, and never calls the target: no lease, no
   quarantine, no voidstar token involved. The exact response field is
   voidstar's choice; ironbark needs the mode, the path and the metadata,
   distinguishable from an ordinary view whose value happens to look like a
   path (§7).
3. **Metadata-only mappings.** A mapping with no target. It lists like any
   view, reads as empty data plus its `custom_metadata`, and exists to carry
   metadata (the `vault_token` marker, §8.5).
4. **Metadata on a level.** `custom_metadata` attached to a path prefix,
   set by IaC and returned by `GET <mount>/metadata/<prefix>/` (trailing
   slash; 404 when none). `LIST` is unaffected. ironbark reads `branches`
   from it (§4.5).

5. **Reject unknown fields, then support `custom_metadata`.** Today a
   mapping write (`admin/map/<view>`) accepts only `target` and `adapter`,
   and a posted `custom_metadata` is accepted and silently ignored (lab,
   2.7.0: read back shows none). An IaC that writes it today gets no error
   and no metadata. voidstar should reject unknown fields on mapping
   writes until item 1 ships, then support `custom_metadata`.

Today a view's synthetic metadata is `custom_metadata: {}` (or
`{voidstar_target}` with `expose_targets`), and writing to a prefix
(`.../prod/`) is an error. No level or prefix metadata exists, hence items 1
to 4.

The lab also confirms (Q12 closed) that voidstar accepts `%xx` in view names
(`grp%2fbeta`, wire `%252f`): data and metadata reads return 200, `LIST`
shows `grp%2fbeta/` unchanged, and the decoded `grp/beta` is a different
view (404) (§18.3).

## 17. Open questions

Resolved by the operator's rulings and folded in above: refused login
(no secrets plus `ironbark_status`, §9.2), branch-as-environment (replaced by
level metadata, §4.5), one role per run (§5.5), overrides (documented, no
lint or logging, §8.2), image and event pins (§6.2, §8.4), `vault_token`
(§8.5), repo rename (§6.2), target inheritance (§4.6), entity clean-up
(§20), `changed_files` (removed, §4.6). Group-alias case (case-insensitive at OpenBao,
moot after `esc()`, §4.4) and `%xx` view names (accepted, §16) are closed by the lab. Still open:

1. **The discovery login.** An environment chosen by level metadata needs a
   token before the environment is known, so such pushes log in twice: to
   `ci` for metadata, then to the environment role (§4.5). Is that
   compatible with "one login role per run", or should level metadata be
   read another way (for example a separate discovery role granting only
   metadata reads)?
2. **`ironbark_status` masking. Answered (Woodpecker v3.18.0 source): no,
   it cannot be unmasked.** An extension secret carries only `name`,
   `value`, `images`, `events` and `note`, with no mask flag, and the
   pipeline compiler and agent treat every returned secret value as a
   masking string. So every returned secret is masked, including
   `ironbark_status`. The design stands: the job reads the variable normally
   and decides from it; logs show the whole line masked, which is acceptable
   because it holds only names and reasons; to see it, print it through a
   transform (`echo "$STATUS" | tr ' ' '\n'`), since masking replaces the
   exact full value (§9.2). No other channel is needed.
3. **Two claimants.** Proposed: status only, no secrets, like a refusal
   (§4.5). The alternative is the repo level plus `config_error`.
4. **Invalid explicit target.** Proposed: status only, like an invalid
   environment (§4.6). The earlier draft walked to the environment level
   and recorded `target_invalid`.
5. **`branches` syntax.** Exact names only (proposed), or globs such as
   `release/*`?

## 18. Testing

### 18.1 Unit

- Fact building per event from the recorded payload fixtures, including
  the promoted-PR trap (`ref` mismatch → `branch_protected=false`) and
  every `IRONBARK_ACTOR_FORGE` value.
- Environment selection: explicit variable; level metadata with no, one and
  two claimants; unreadable metadata; a level name outside the grammar.
- Target cascade: every rule, precedence, the grammar (including `.`/`..`
  segments), trailer parsing (none, one, two), per-segment escaping.
- JWT claims: omission of absent claims, `repo_key`, `t1`…`t8`, escaping of
  hostile values (`/`, `*`, `+`, `%`, `.`, `..`, uppercase), `sub`
  determinism and sensitivity (changes with env, target or team set; not
  with actor, event or pipeline).
- Role rendering (`ci-{env}` → `ci`), path-template validation, the level
  list including nested targets, `render-policies` output.
- Walk: deepest wins across nested target levels, unreadable levels skipped
  with the walk continuing, within-level clash, reserved `ironbark_status`,
  the `vault_token` marker (present, absent, carrying data), resolve
  mappings, image pins relayed from the mapping and never from the target.
- `ironbark_status`: format and every `outcome`; revocation whenever it is
  the only secret.

### 18.2 Integration (containerised OpenBao, and Vault before claiming it)

Each spike finding becomes a test: templated read at each level and 403
one level away; a nested target reading its parents but not a sibling
(`web/api` vs `web/cli`); login refused by `bound_claims` (string, glob,
list), including a `repo_key` with a changed forge id; `groups_claim` to an
external group granting a level; a forbidden character in metadata building
no ACL; the same-`sub` race (asserted absent with the §5.4 derivation,
present with a fixed `sub`); an empty mapped claim matching nothing;
per-login assertions against a role missing `token_explicit_max_ttl` or set
to `batch`; the discovery login revoked before the environment login; lease
parenting and cascade revocation of a resolve-mapped dynamic credential.

### 18.3 Acceptance: an end-to-end lab

An end-to-end acceptance lab (a Woodpecker + forge + OpenBao acceptance
catalogue of 45 cases, including a nine-step branch-as-environment UAT
scenario U1–U9) is rebuilt on this model. The lab applies its own fixture
data (views, level metadata, JWT roles, templated policies, groups),
because it is test data with no reason to live anywhere else. Fixture
shape:

- repo L: repo level; environment levels `prod` (`branches = main`) and
  `uat` (`branches = uat`; branch protected, merge-only with an approvers
  whitelist); targets under `prod` (`svc.alpha`, `grp/beta`, `grp2`,
  `svc.gamma/sub`, …) as nested levels with their deploy-root markers;
  targets `part%41` and `part%42` (`partA`, `partB` escaped) under `uat`;
- repo O: repo level and `prod`, for isolation;
- roles `ci`, `ci-prod` (push, manual, deployment, cron; carries
  `ci-target`), `ci-uat` (push, manual, deployment; no `ci-target`, its
  targets gated by approver groups, §6.4), each listing L and O by
  `repo_key`; teams via the fake or real forge.

In every rendered case, `delivered`/`denied` are re-derived for the new
paths, every case also expects `ironbark_status`, and the actor, team and
conjunction canaries leave `delivered` because those facts are now gates.
That alone is not flagged below. A case is flagged **changed** when its
pipeline outcome or its stated intent changes.

| Case | Today | Under the grant model | Flag |
|---|---|---|---|
| M1 | manual, no target: manual tier + actor + team data | project + `prod` (branch `main` claimed by `prod`); actor/team deliver nothing, they only gate | **changed** (intent) |
| M2 | manual `svc.alpha`: target, target-actor, target-team prefixes | project + `prod` + `prod/svc.alpha`; conjunctions become group gates; deploy success | **changed** (intent) |
| M3 | `svc.alpha/svc/gear`: inherits `svc.alpha` marker, success | walks `svc.alpha`, `…/svc`, `…/svc/gear`; inherits the marker; success | same |
| M4 | `grp/beta`: success | `prod/grp/beta` marker, success | same |
| M5 | `grp`: no marker, error | `prod/grp` has no marker, error | same |
| M6 | `grp2` rogue marker: guard refuses group | same | same |
| M7 | `svc.alpha/grouping`: inherited marker, guard refuses "no deploy marker" | inherited marker, `grouping` level absent (skipped); guard refuses | same |
| M8 | `svc.locked`: error | same | same |
| M9 | typo: error | same | same |
| M10–M14 | invalid target: error | `invalid`, status only; marker missing, error | same (5 cases) |
| M15 | literal `%2f`: unknown segment, error | `%` escaped to `%25`, no such level, error | same |
| M16 | `svc.gamma/sub` rogue marker: guard refuses | `sub`'s rogue marker overrides `svc.gamma`'s (deepest wins), guard refuses | same |
| M17 | 8 segments: 17 team conjunctions dropped by the cap, success | no cap exists; all 8 levels walked, marker inherited, success. The case now proves the depth-8 stanzas; a many-teams case (G8) takes over the cap's role | **changed** (intent) |
| M18, M19 | guard refuses task missing / invalid | same | same |
| M20 | `svc.alpha/../svc.gamma`: guard refuses | `..` escaped to `%2e.` (leading dot encoded), no such level, cannot traverse; marker missing → error, as M15 | same |
| D1 | promote push to `svc.alpha`: deployment tier, no actor | env `prod` from the inherited verified branch; project + `prod` + target; no event tier | **changed** (intent) |
| D2 | promote to `grp/beta`: guard reads deployment fields | target from `deploy_to`, variables ignored on deployment; success | same |
| D3, D4 | locked / invalid target: error | same | same |
| D5, D6 | guard refuses task | same | same |
| P1 | push `main`, member: push + `push/main` + actor + team | project + `prod`; a target only from a `Deploy-To:` trailer | **changed** (intent) |
| P2 | push `main`, collaborator without team | identical to P1 unless `prod` is team-gated in the fixture | **changed** (intent) |
| P3 | push branch `target`: branch tier must not meet `.target` | unprotected, unclaimed branch → repo level only; the collision cannot exist | **changed** (intent) |
| P4 | outsider push refused by forge | same | same |
| R1 | PR: PR tier + PR actor data | role `ci` → repo level (or status only if PRs are excluded) | **changed** (intent) |
| C1 | cron: cron tier | cron on `main` → `prod` (`ci-prod` admits cron); a role that did not would give status only, never a fallback | **changed** (intent) |
| O1 | other repo, approval: O's grants only | O's project + `prod`; isolation by templated `repo` and `repo_key` | same |
| X1 | Woodpecker fact pin | independent of ironbark | same |
| U1–U3 | forge refuses push / merge; approver merges | forge behaviour, unchanged | same (3 cases) |
| U4 | PR into `uat`: PR tier + `pull_request/uat`, none of `push/uat` | repo level only; the PR-per-base-branch tier has no equivalent; still none of `uat` | **changed** (intent) |
| U5 | merge push to `uat`: whole `push/uat` tier incl. partB (pinned leak) | the merge message carries `Deploy-To: partA` → project + `uat` + `uat/part%41` if the merger's team gates it; **partB never delivered**, leak closed. Without the trailer: project + `uat` only | **changed** (intent and trigger) |
| U6 | direct push to `uat`, trigger file only: whole `push/uat` tier | project + `uat`; no trailer, no target, no part secrets | **changed** (intent) |
| U7 | push `uat-next`: nothing of `uat` | unprotected, unclaimed → repo level only | same |
| U8 | manual `uat/partA`, approver group: target + group conjunction | manual on branch `uat` with `DEPLOY_TO=partA` (env from `uat`'s `branches`); approver group grants `uat/part%41`; success | **changed** (trigger shape) |
| U9 | promote U8 to `uat/partA`: deployment tier + marker, success | no actor → no teams → gated `uat/part%41` skipped → marker missing → **error** | **changed** (outcome) |
| S1 | static: manual-matching workflows evaluate `DEPLOY_TO == ""` | same, extended to `DEPLOY_ENV` | same |
| S2 | static: repo settings | same, plus the per-repo extension endpoint | same |

Summary: 31 cases keep their expectation and 14 change: 1 in **outcome**
(U9, the promote-has-no-actor limit now enforced) and 13 in **intent or trigger** (M1, M2, M17, D1, P1, P2, P3, R1,
C1, U4, U5, U6, U8). Against the first draft of this spec, nested-target
inheritance returns M3 and M7 to **same** and M17 to intent-only; C1 loses
its fallback; U5 now needs a `Deploy-To:` trailer because `changed_files`
is gone. U5 and U6 remain deliberate improvements (the pinned leak is
closed).

New cases the model needs:

| Id | Case | Expect |
|---|---|---|
| G1 | manual `DEPLOY_ENV=uat` from an unprotected branch | `refused`, status only; a step naming a `uat` secret errors at compile; a step reading only `ironbark_status` runs and decides |
| G2 | push to an unprotected branch that a level's `branches` names | no discovery, repo level only |
| G3 | promote of a PR pipeline | `ref` mismatch → `branch_protected=false` → repo level only |
| G4 | merge with `Deploy-To: partB`; then with two trailers | target `partB`; then no target |
| G5 | a second level also claiming `uat` | `config_error` naming both, status only |
| G6 | same key at project and env | env value |
| G7 | two concurrent pipelines, same repo+env, different targets | each reads only its own target (race regression) |
| G8 | many teams (8+) | all reach `groups_claim`, no cap |
| G9 | tag pipeline | repo level only |
| G10 | protected branch no level claims | repo level only, `ok` |
| G11 | cron with `DEPLOY_ENV=uat` (event not on `ci-uat`) | `refused`, status only |
| G12 | `vault_token`: no mapping; mapping with image pins | not issued; issued with those pins |
| G13 | image pin on a mapping whose upstream carries other metadata | the mapping's pins only |
| G14 | resolve mapping to a dynamic engine | lease owned by the pipeline token, revoked with it |
| G15 | repo L recreated under the same name (new forge id) | login refused by `repo_key`, status only |

Lab check (factual, not a decision): voidstar accepts `%xx` in view names
(`part%41`) and lists them unchanged. Group-alias case is settled (§4.4).

### 18.4 Failure-mode stack

Toy Forgejo, Woodpecker, OpenBao, voidstar and ironbark run in docker on a
disposable build VM, stood up per test run and torn down after, so
dependencies can be broken on purpose without touching production CI.
Each case asserts less or nothing, never more, and always an
`ironbark_status` for a verified request:

| Fault | Expect |
|---|---|
| forge down / slow (> timeout) | no discovery, no teams: repo level; explicit env → `refused` |
| OpenBao down | `error`, status only |
| JWT signed with a key not in `jwt_validation_pubkeys` | `error`, status only |
| JWT clock skew beyond leeway | `error`, status only |
| role missing (explicit or discovered env) | `refused`, status only |
| role with `token_type=batch` or no explicit max TTL | revoke, `error`, status only |
| level metadata unreadable during discovery | revoke, `error`, status only |
| view absent (no mapping, 403/404) | entry skipped |
| view mapped but its upstream target missing or unreadable | revoke, `error`, status only (§9.3) |
| view quarantined / voidstar loopback broken | revoke, `error`, status only |
| resolved engine path erroring | revoke (leases cascade), `error`, status only |
| group alias deleted mid-run | gated level skipped on the next login |
| hostile values (`/`, `*`, `+`, `..`, uppercase) in branch, target, actor, team | escaped; no ACL failure; nothing extra |

## 19. Proposed decisions

Not recorded. Each would become one entry if accepted.

1. **Levels by value, gates by access.** Data is layered repo → env →
   target segments. Team, actor, event and protected branch are OpenBao
   conditions, never path levels.
2. **ironbark signs facts; OpenBao decides.** Stock JWT auth, one role per
   environment level with `bound_claims` as the branch strategy, templated
   policies per level kind, teams as external groups via `groups_claim`.
   No plugin. No AppRole: the signing key is ironbark's only credential.
3. **Branch verification = forge `protected` AND `ref == refs/heads/<branch>`.**
4. **Selectors never entitle.** Env and target come from variables, the
   promote field, a trailer or level metadata. OpenBao refuses what the
   facts do not allow.
5. **Environments are named levels whose metadata lists the branches they
   serve.** `DEPLOY_ENV` names a level directly; an unclaimed branch gets
   the repo level; two claimants are a configuration error.
6. **Target cascade:** manual variable, promote `deploy_to`, `Deploy-To:`
   trailer, none. No `changed_files`. One target per pipeline; each segment
   is a level, so nested targets inherit.
7. **ironbark never fails a pipeline.** A refused login returns no secrets,
   never a fallback; `ironbark_status` is always returned and the job
   decides. Woodpecker's compile error on a missing `from_secret` is an
   accepted platform limit.
8. **One login role per run**, rendered by `IRONBARK_JWT_ROLE`; no retry.
9. **`sub` = hash of every claim that feeds metadata or groups.**
10. **Deepest level wins; overrides are documented behaviour, not logged or
    linted.**
11. **Repo pins by `repo_key` in role `bound_claims`**, one entry per repo,
    never a wide glob. **Event pins by role.** **Image pins on the voidstar
    mapping.**
12. **Dynamic credentials by resolve-don't-fetch mappings**, read with the
    pipeline's token. `$ref` removed.
13. **`vault_token` only where a metadata-only mapping declares it**, with
    its image pins.
14. **Four grant settings.** `IRONBARK_DATA_PATH`
    (`vs/data/<estate>/{repo}/{env}/{target...}`), `IRONBARK_ENV_VAR`,
    `IRONBARK_TARGET_VAR`, `IRONBARK_JWT_ROLE`, shared by `ib` through
    `~/.config/ib/config` (env wins).
15. **`ib` walks the same levels with the caller's login, masks every
    value with no length threshold, and checks no names.**
16. **Removed:** KV tier tree, attribute mount, per-tier policy names, dot
    directives, `ironbark_events`, `$ref`, the token-store mint and canary.
17. **Migration by per-repo extension endpoint.** Two deployments side by
    side, no dual-mode code.
18. **Acceptance:** the end-to-end acceptance lab applies its own fixtures, and
    failure modes run on an ephemeral docker stack.

## 20. Roadmap (someday)

Not planned; recorded so they are not rediscovered.

- **Entity clean-up**, if build-up proves a real problem. The tuple-derived
  `sub` (§5.4) bounds growth. A reaper would need its own identity
  credential, which ironbark does not hold.
- **Upstream Woodpecker**: a way for a step to tolerate a missing
  `from_secret`, which would let every job, not only the careful ones,
  decide from `ironbark_status`.

# Grant model: layered data, verified facts, OpenBao-enforced gates

Status: draft for review, 2026-09-30. Nothing here is implemented. It
replaces the grant half of [`SPEC.md`](../SPEC.md) (§2.3–§2.5, §3, §4.1,
§4.4–§4.6, §7) and of [`CLIENT-SPEC.md`](../CLIENT-SPEC.md) (§3–§5), and
supersedes the attribute tiers of
[`2026-09-30-pipeline-attributes-design.md`](2026-09-30-pipeline-attributes-design.md)
("the attributes design"). Signature verification (SPEC §5), the response
shape (SPEC §6) and revocation-by-outcome (SPEC §3.4) stay as they are.

Decisions this design would introduce are listed under
[Proposed decisions](#18-proposed-decisions); none is recorded in
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

Secret data sits in a tree with three **levels**, shallow to deep:

| Level | Path (example) | Holds |
|---|---|---|
| project | `vs/data/acme/mono/` | secrets every pipeline of the repo may use |
| environment | `vs/data/acme/mono/staging/` | secrets whose value differs per environment |
| target | `vs/data/acme/mono/staging/web/` | secrets specific to one deployable part in one environment |

Generic secrets sit high and customisations sit low. A key present at more
than one level resolves to the deepest one the pipeline can read (§8).

The tree is normally a set of voidstar views, one per secret, each resolving
upstream (1Password, KV, anything voidstar supports). ironbark does not
depend on voidstar: any KV v2-shaped tree that answers `LIST` on
`<mount>/metadata/...` and `GET` on `<mount>/data/...` works, including a
plain KV v2 mount.

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
level the verified facts do not allow. A caller who names `production` from
an unprotected branch gets a refused login (§9), not production secrets.

### 3.5 Where each decision lives

| Decision | Lives in | Written by |
|---|---|---|
| Which facts are true for this pipeline | ironbark (§4) | ironbark code |
| Which environment and target to walk | ironbark selectors (§4.5, §4.6) | pipeline variables, promote fields, commit trailer, changed files |
| Whether this pipeline may act for an environment (branch strategy, events) | JWT role `bound_claims` | IaC |
| Which levels a login may read | templated policies, one per level | IaC |
| Team conditions | identity groups via `groups_claim`, with group policies | IaC |
| Where a secret's value comes from | voidstar view mapping (or KV) | IaC |

## 4. Facts per event

### 4.1 Fact table

Facts come from the signed Woodpecker payload (integrity-protected end to
end, not trustworthy by virtue of the signature: fields still originate
from webhooks, API callers and repo admins) plus two forge lookups. Only
the facts below are used; every other payload field is ignored.

| Fact | push | pull_request (`pull_request`) | tag | release | manual | deployment (promote) | cron |
|---|---|---|---|---|---|---|---|
| `org`, `repo` | `repo.full_name` | same | same | same | same | same | same |
| `repo_id` | `repo.forge_remote_id` | same | same | same | same | same | same |
| `event` | `push` | `pull_request` | `tag` | `release` | `manual` | `deployment` | `cron` |
| `branch` | pushed branch | **absent** (base branch is not a trust signal) | absent | absent | caller-chosen | inherited from parent | cron's branch |
| `ref` | forge | not emitted | not emitted | not emitted | `refs/heads/<branch>` | inherited from parent | `refs/heads/<branch>` |
| `branch_protected` | lookup (§4.2) | absent | absent | absent | lookup | lookup | lookup |
| `actor` | `sender` iff `IRONBARK_ACTOR_FORGE` declares a login forge | same rule | same rule | same rule | `author` | **none** | none |
| `teams` | lookup (§4.4) when actor and env | not resolved | not resolved | not resolved | lookup when env | none (no actor) | none |
| `env` | cascade §4.5 | none | none | none | cascade | cascade | cascade |
| `target` | cascade §4.6 | none | none | none | cascade | cascade | none |

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
  environment has nothing to gate.
- Teams go into the JWT `teams` claim as `esc(org)/esc(team)`, for example
  `acme/deployers`, and reach OpenBao through `groups_claim`. Qualifying by
  org stops a team named `deployers` in one org from satisfying a gate meant
  for another org's `deployers`.

A failed lookup (timeout, transport error, unexpected status) emits no
`teams` claim. Every team-gated level is then unreadable: less, never more.

### 4.5 Environment selection

First match wins:

1. The variable named by `IRONBARK_ENV_VAR` (default `DEPLOY_ENV`) in
   `pipeline.variables` (`manual`, `cron`, and a `deployment`'s inherited
   parent variables). This is an **explicit** selection.
2. The verified branch: when `branch_protected` is `"true"`, `env = branch`.
   This is an **implicit** selection, the branch-as-environment convention.
3. None. The walk reads the project level only.

A value must match `^[a-z0-9][a-z0-9_-]{0,62}$`. An explicit value that
does not is refused like any explicit request (§9.2 (A): nothing returned,
502), never degraded to the implicit rule or to the project level; the audit
line records `env_invalid`. An implicit (branch) value that does not match is
simply no environment. The grammar keeps env
names valid as a role-name suffix and as a path segment without escaping.
Branch names outside it (`release/1`, `Main`) never select an environment
implicitly. Rule 2 means environment levels are named after the branches
that feed them (`main`, `staging`). A branch that is not an environment
simply has no role (§9.2).

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
4. `pipeline.changed_files`, on `push`, only when every changed path shares
   one first path segment. That segment is the target (`web/src/a.go` and
   `web/README.md` → `web`). Root-level files or two segments → no target
   from this rule.
5. None: the walk stops at the environment level.

Grammar (as today, plus one rule): split on `/`, every segment non-empty, at
most 8 segments and 256 bytes, and **no `.` or `..` segment**. The target is
escaped **whole** into one path segment (`grp/beta` → `grp%2fbeta`), so a
target level is opaque: `grp/beta` does not inherit from `grp` (§14). A
value violating the grammar is no target, and the audit line records
`target_invalid`.

A target without an environment is recorded and ignored: the walk has no
environment to hang it under.

`changed_files` is incomplete on some pushes (large pushes, some merge
commits, force pushes). A truncated list can at worst pick one target
where two changed. The pipeline is then entitled to that target anyway, so
the effect is a narrower grant, never a wider one. For deterministic merges,
put a `Deploy-To:` trailer in the merge message.

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
| `repo_id` | `esc(forge_remote_id)` | bindable; see §16 on rename protection |
| `event` | lowercase | unknown events pass through lowercased |
| `branch` | `esc(branch)` | absent per §4.1 |
| `ref` | `esc(ref)` | absent per §4.1 |
| `branch_protected` | `"true"` / `"false"` | absent when `branch` is |
| `actor` | `esc(actor)` | absent when none |
| `teams` | list of `esc(org)/esc(team)` | absent when not resolved or none |
| `env` | selected env | absent when none |
| `env_source` | `variable` / `branch` | absent when no env |
| `target` | `esc(target)` | absent when none |
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
writes the glob `release%2f*`.

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
identical. Actor, event and branch are checked at login (`bound_claims`)
and are not persisted, so they stay out of the hash. This bounds entity
growth by the number of distinct `(repo, env, target, team-set)` tuples,
not by pipelines (§14).

### 5.5 Login and token contract

`POST auth/<IRONBARK_JWT_MOUNT>/login` with `{"role": <role>, "jwt": <jwt>}`.
`<role>` is `IRONBARK_JWT_ROLE` rendered with the env. With no env, the
`{env}` placeholder and one adjoining separator (`-`, `_` or `.`) are
removed: `ci-{env}` → `ci-staging`, or `ci`.

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
→ `revoke-self`, `502`, error log naming the role. This per-login check
replaces the startup canary (SPEC §3.5): there is no ironbark credential to
canary, and each environment role can be misconfigured on its own.

## 6. OpenBao configuration

The examples use repo `acme/mono`, environments `main` and `staging`, targets
`web` and `api`, and `IRONBARK_DATA_PATH=vs/data/acme/{repo}/{env}/{target}`.
`ACC` stands for the JWT mount accessor.

### 6.1 Mount

```
bao auth enable -path=jwt jwt
bao write auth/jwt/config \
  bound_issuer=ironbark \
  jwt_validation_pubkeys=@ironbark-jwt.pub
```

### 6.2 Roles: the branch strategy

One role per environment plus the no-environment role. `bound_claims` is
where the branch strategy lives. Roles are written as JSON
(`bound_claims` and `claim_mappings` do not survive the CLI's `k=v` form).
A list value in `bound_claims` means "any of".

`auth/jwt/role/ci`, the project level for every pipeline of the org:

```json
{
  "role_type": "jwt", "user_claim": "sub", "bound_audiences": ["ironbark"],
  "bound_claims_type": "string",
  "bound_claims": {
    "org": "acme",
    "event": ["push", "pull_request", "tag", "release", "manual", "deployment", "cron"]
  },
  "claim_mappings": {"org": "org", "repo": "repo"},
  "token_policies": ["ci-project"],
  "token_type": "service", "token_ttl": "15m", "token_explicit_max_ttl": "15m"
}
```

`auth/jwt/role/ci-main`, where only a verified protected `main` acts for env `main`:

```json
{
  "role_type": "jwt", "user_claim": "sub", "bound_audiences": ["ironbark"],
  "bound_claims_type": "string",
  "bound_claims": {
    "org": "acme",
    "env": "main",
    "branch": "main",
    "branch_protected": "true",
    "event": ["push", "deployment"]
  },
  "claim_mappings": {"org": "org", "repo": "repo", "env": "env", "target": "target"},
  "groups_claim": "teams",
  "token_policies": ["ci-project", "ci-env"],
  "token_type": "service", "token_ttl": "15m", "token_explicit_max_ttl": "15m"
}
```

`auth/jwt/role/ci-staging`, where staging runs from its own protected branch by push, manual, promote or cron:

```json
{
  "role_type": "jwt", "user_claim": "sub", "bound_audiences": ["ironbark"],
  "bound_claims_type": "string",
  "bound_claims": {
    "org": "acme", "env": "staging",
    "branch": "staging", "branch_protected": "true",
    "event": ["push", "manual", "deployment", "cron"]
  },
  "claim_mappings": {"org": "org", "repo": "repo", "env": "env", "target": "target"},
  "groups_claim": "teams",
  "token_policies": ["ci-project", "ci-env", "ci-target"],
  "token_type": "service", "token_ttl": "15m", "token_explicit_max_ttl": "15m"
}
```

Notes:

- `env` is bound as well as implied by the role name. A role rendered for
  the wrong environment cannot log in.
- `ci-main` deliberately omits `ci-target` from `token_policies`: its target
  level is team-gated (§6.4).
- Roles are estate-wide. To restrict an environment to some repos, bind
  `repo` (a list, or a glob with `bound_claims_type: glob`).
- `bound_claims_type` is per role: a role mixing exact values and globs
  writes the exact values as globs without wildcards.
- `pull_request` in `ci`'s event list is a choice. Leave it out and PR
  pipelines get nothing. Keep it and they get the project level, which
  therefore must hold nothing a PR head may not see (§3.1).

### 6.3 Templated policies, one per level

```hcl
# ci-project
path "vs/data/acme/{{identity.entity.aliases.ACC.metadata.repo}}/+" {
  capabilities = ["read"]
}
path "vs/metadata/acme/{{identity.entity.aliases.ACC.metadata.repo}}/" {
  capabilities = ["list"]
}

# ci-env
path "vs/data/acme/{{identity.entity.aliases.ACC.metadata.repo}}/{{identity.entity.aliases.ACC.metadata.env}}/+" {
  capabilities = ["read"]
}
path "vs/metadata/acme/{{identity.entity.aliases.ACC.metadata.repo}}/{{identity.entity.aliases.ACC.metadata.env}}/" {
  capabilities = ["list"]
}

# ci-target
path "vs/data/acme/{{identity.entity.aliases.ACC.metadata.repo}}/{{identity.entity.aliases.ACC.metadata.env}}/{{identity.entity.aliases.ACC.metadata.target}}/+" {
  capabilities = ["read"]
}
path "vs/metadata/acme/{{identity.entity.aliases.ACC.metadata.repo}}/{{identity.entity.aliases.ACC.metadata.env}}/{{identity.entity.aliases.ACC.metadata.target}}/" {
  capabilities = ["list"]
}
```

Three policies serve every repo, environment and target. `+` is exactly one
segment, so no level's grant reaches the level below it. A missing
`env`/`target` renders an empty segment that matches nothing.

The literal `acme` prefix ties these policies to one org. Serving several
orgs, either put `{org}` in `IRONBARK_DATA_PATH` and template
`metadata.org`, or keep one prefix per org and bind `org` on every role (as
above). The policies and `IRONBARK_DATA_PATH` must describe the same levels
in the same order. Generate both from one IaC variable, or use
`ironbark render-policies` (§11.3), which prints these three from the
configured path.

### 6.4 Groups: team gates

A team gate is a group policy. `ci-main` above grants the `main` target
level only through a group:

```
bao write identity/group name=acme-deployers type=external policies=ci-target
bao write identity/group-alias name=acme/deployers \
  mount_accessor=ACC canonical_id=<group id>
```

A pipeline whose `teams` claim contains `acme/deployers` gets `ci-target`
as an identity policy.

Group policies apply to **every** login of the entity, whatever the role.
Identity policies are additive, and a role cannot cap them. So:

- A group policy must be templated on `env` (and `target`), never a literal
  path. Rendered for a login without an environment, it matches nothing.
  The environment was admitted by the role, so the group adds only levels
  below an environment the role already accepted.
- A gate on one target in an environment that has an ungated generic
  `ci-target` is impossible, because templating has no exclusion and
  `deny` would override the group grant too. Such an environment must not
  carry `ci-target` on its role. Its group policies then name the gated
  targets literally below the templated env segment:
  `vs/data/acme/{{...repo}}/{{...env}}/web/+`. Gate granularity is the
  environment. Per-target gates are hand-listed.

### 6.5 Recipes

| Wanted | OpenBao config |
|---|---|
| only protected `main` deploys `main` | role `ci-main`: `branch=main`, `branch_protected=true` |
| staging also from manual runs | add `manual` to `ci-staging`'s `event` list; the manual run must be on branch `staging` |
| production targets only for team `deployers` | `ci-target` on group `acme-deployers`, not on role `ci-main` |
| one target for one team, the rest open | role without `ci-target`; one group policy per gated target, one open policy listing the other targets |
| a break-glass person | not expressible yet: one role name per env (open question 3). Nearest today: a separate env level `main-breakglass` whose role binds `actor: ["alice"]`, selected with `DEPLOY_ENV` |
| PRs see nothing | drop `pull_request` from `ci`'s events |

## 7. Dynamic credentials

Dynamic engines (AWS STS, database creds) cannot be voidstar views: voidstar
revokes and quarantines any lease-bearing read, by design. A lease taken by
voidstar's own credential would outlive the pipeline. They are read directly
from engine paths **named by convention** after the levels, with the
pipeline's own token, so each lease parents to that token and dies with it:

```hcl
# ci-dynamic (attached next to ci-env / ci-target)
path "aws/creds/{{identity.entity.aliases.ACC.metadata.env}}-{{identity.entity.aliases.ACC.metadata.target}}" {
  capabilities = ["read"]
}
path "aws/creds/{{identity.entity.aliases.ACC.metadata.env}}" {
  capabilities = ["read"]
}
```

Two ways a pipeline gets them:

1. **Directly, with `vault_token`** (primary). The step reads
   `aws/creds/staging-web` itself. ironbark adds nothing. The value is not
   masked by Woodpecker (the honest limit in DESIGN §3).
2. **Masked, through a pointer** (the one surviving use of `$ref`). A level
   holds an entry whose data is exactly `{"$ref": "aws/creds/staging-web"}`
   (a voidstar view onto a KV entry holding that pointer, or a plain KV
   entry). ironbark dereferences it with the pipeline token, exactly as
   SPEC §4.3 does today: one level, GET only, 403/404 skipped. The
   convention-named path means a pointer can only reach what the templated
   policy already grants the pipeline.

## 8. The walk

### 8.1 Path template

`IRONBARK_DATA_PATH` is a path whose placeholders are whole segments:
`{repo}` (required), `{org}` (optional, before `{repo}`), then `{env}` and
`{target}`, which must be the last two segments in that order. Its second
segment must be `data` (the KV v2 convention). The metadata path used for
`LIST` swaps it for `metadata`. Anything else is a startup error.

The levels are the template's prefixes ending at `{repo}`, at `{env}` and
at `{target}`, filled with the escaped values. A level whose placeholder
value is absent ends the walk.

### 8.2 Algorithm

```
levels = [project]; if env: levels += [env]; if env and target: levels += [target]
result = {}                                   # name -> (value, level)
for level in levels (shallow to deep):
    keys = LIST <metadata path of level>
    on 403 or 404: record level as skipped; continue      # unreadable levels are skipped
    on other error: revoke, 502
    for key in keys, sorted bytewise, skipping directory entries ("x/"):
        entry = GET <data path of level>/<key>
        on 403 or 404: skip entry, record; continue
        on other error: revoke, 502
        for (name, value) in classify(entry):             # SPEC §4.2 forms; $ref per §7
            if name in result and result[name].level != level:
                record override (name, result[name].level -> level)
            result[name] = (value, level)                 # deeper level wins
```

- **Unreadable levels are skipped, and the walk continues deeper.** A
  target level may be readable where its environment level is not (a gated
  environment, an open target). The walk does not infer denial below from
  denial above.
- **Clash resolution:** across levels the deepest wins. Within one level
  (two keys flattening to the same name, `a_b` and `a` field `b`) the first
  in bytewise key order wins and the clash is logged, as today.
- **Override logging:** every cross-level override is logged at info, with
  names and level labels only (`db: project -> staging`). Values are never
  logged. An override is usually intended (a customisation) and sometimes an
  accident (a generic name reused). The audit line carries the list, so a
  lint can flag unexpected ones (§16).
- Names, string-only values, `-` → `_` and the `[a-z0-9_]+` check are as in
  SPEC §4.2. A key that does not produce a valid name is skipped with a
  warning.
- No descent below a level other than into the next selected level. Sub-
  directories that are not the selected env or target are never read.

### 8.3 What the walk does not do

It does not list environments or targets to choose among them. Selection
happened before login (§4.5, §4.6). It never reads a level it was not asked
for, even if the token could.

## 9. Request sequence and failure behaviour

### 9.1 Sequence

1. Read body, verify signature, parse: SPEC §1.2 steps 1–4, unchanged.
2. Establish facts (§4): forge lookups for branch protection and, when
   needed, teams. Each is bounded by `IRONBARK_FORGE_TIMEOUT` and fails
   closed.
3. Select env and target (§4.5, §4.6).
4. Build and sign the JWT (§5). Log in with the rendered role.
5. On refusal: §9.2.
6. Per-login assertions (§5.5).
7. Walk (§8). Dereference pointers (§7).
8. Respond (SPEC §6). Revocation by outcome (SPEC §3.4): every non-200
   revokes, a 200 never does. An empty walk with `vault_token` returned is
   still a 200. An empty walk with nothing else to return is 204.

### 9.2 A refused login

A login is refused when the role does not exist or the claims do not satisfy
its `bound_claims`, for example `DEPLOY_ENV=main` from an unprotected
branch. Two options:

- **(A) Fail.** Return nothing (revoke nothing, since there is no token;
  respond 502 and log). Woodpecker is fail-open towards the extension: it
  proceeds with its own DB secrets, and any step naming an extension secret
  in `from_secret` makes the pipeline error at compile.
- **(B) Fall back.** Log in to the no-env role (`ci`) and return the project
  level only.

Both fail closed: each yields less than was asked for. They differ in
visibility. A deploy that asked for `main` and silently got project-level
secrets runs half-configured and fails somewhere less obvious, or, worse,
succeeds against defaults. A feature-branch push that "asked" for nothing
should not be broken because its branch is not an environment.

**Recommendation:** decide by how the environment was selected.

| Env source | Role missing | Claims refused |
|---|---|---|
| explicit (`DEPLOY_ENV` variable) | (A) fail | (A) fail |
| implicit (verified branch) | (B) fall back | (B) fall back |
| none (`ci` role itself refused) | (A) fail | (A) fail |

An explicit request is a statement of intent, and refusing it must be
loud. An implicit one is ironbark's guess from the branch name, and a wrong
guess must not break ordinary pushes. Every fallback is recorded in the
audit line (`env_refused`, with the OpenBao error). Telling "role missing"
from "claims refused" relies on OpenBao's error text. That distinction is
not needed by the table above (both columns agree per row), and ironbark
does not depend on it.

### 9.3 Fail closed everywhere

| Failure | Result |
|---|---|
| signature invalid | 401, nothing (unchanged) |
| forge down or slow, protection lookup | `branch_protected=false`: no implicit env; explicit env refused → fail |
| forge down or slow, team lookup | no `teams` claim: team-gated levels unreadable |
| OpenBao unreachable | 502, nothing |
| JWT refused (bad key, expired, wrong audience) | 502, nothing, error log (a config fault, not a policy outcome) |
| role refused | §9.2 |
| per-login assertion fails | revoke, 502 |
| template renders a forbidden character | cannot happen via `esc()`; if it did, OpenBao builds no ACL and every read 403s → empty walk |
| level `LIST` 403/404 | level skipped |
| entry `GET` 403/404 | entry skipped |
| view 502 (voidstar quarantine or loopback broken) | revoke, 502, nothing: a broken view fails the pipeline loudly instead of silently dropping a secret |
| pointer deref non-403/404 error | revoke, 502; the cascade revokes leases already taken |

## 10. Audit line

The verified-request line (SPEC §8.1) becomes:
`ts, org, repo, repo_id, event, branch, ref, branch_protected, actor, teams |
teams_error, env, env_source, env_invalid, env_refused, target,
target_source (variable|deploy_to|trailer|changed_files), target_invalid,
role, sub, jti, levels (label -> read|skipped_403|skipped_404), overrides,
secrets_returned (names), token_accessor, token_ttl, outcome`. Payload
values that are not facts (variables other than the two selectors, message
text) are never logged. The debug `payload attributes` line stays.

## 11. Configuration

### 11.1 The grant model: four variables

```
IRONBARK_DATA_PATH   = vs/data/acme/{repo}/{env}/{target}
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
Only explicit environments on roles that do not bind it can then be
reached. A startup warning says so.

### 11.3 `ironbark render-policies`

A subcommand that prints the three level policies (§6.3) for a given mount
accessor from `IRONBARK_DATA_PATH`. It keeps the policy paths and the walk
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
caller's own token:

- `org`/`repo` from the `origin` remote, as today.
- `--env <name>` / `IB_ENV` replace `DEPLOY_ENV`, and `--target <path>` /
  `IB_TARGET` replace `DEPLOY_TO`. The same grammars apply.
- Without `--env`, the CLIENT-SPEC §3 selection runs over **environment
  names** instead of branch tiers. The candidates are the directories at the
  project level the caller can `LIST`, matched against remote-tracking
  branches (branch-as-environment, §4.5 rule 2). No environment directory
  visible → project level only. The `--branch` flag becomes `--env`.
- Without `--target`, the walk stops at the environment level. `ib` does
  not derive a target from the working tree.

Access is the caller's own policies. The templated CI policies key on JWT
alias metadata and do nothing for a human token. People get static
policies (for example `read` on `vs/data/acme/+/staging/*`). Personal
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
- The dot notation: `.identity`, `.config` and the dot-key namespace.
- Per-secret pins from KV `custom_metadata` (`ironbark_images`,
  `ironbark_events`). Views do not carry `custom_metadata` (§16).
- `$ref`, except as the masked dynamic-credential escape hatch (§7).
- ironbark's AppRole, the token-store mint, and the startup canary.

## 14. Limits, stated plainly

- **A promote has no actor.** Woodpecker copies the parent's `sender` and
  `author`. A promote can never satisfy an actor or team gate. A team-gated
  level is unreachable by promote: the gate holds, and promotes into gated
  levels fail.
- **A push has no target of its own.** Only a trailer or a one-part change
  gives it one. Otherwise it stops at the environment level.
- **One secret list per pipeline.** Every workflow and step of a pipeline
  sees the same list. Part isolation within one pipeline is impossible, so
  split parts across runs (§4.6).
- **Gate granularity is the environment.** Per-target gates are literal
  group policies (§6.4).
- **Target levels are opaque.** `grp/beta` does not inherit from `grp`. A
  secret shared by several targets sits at the environment level.
- **Environment names are branch names** for implicit selection. A
  `production` environment fed by `main` is spelled `main`, or must be
  selected explicitly.
- **Tag and release pipelines never reach an environment.** They have no
  verified branch and no variables.
- **Entity build-up.** Each distinct `sub` leaves an entity and an alias
  that OpenBao never removes. Growth is bounded by distinct
  `(repo, env, target, team-set)` tuples. Cleaning up needs a reaper
  outside ironbark, since ironbark holds no identity permissions.
- **Repo rename protection is not carried over.** Data paths are keyed by
  repo name. A repo renamed away, or deleted, and a new repo taking the old
  name would read the old repo's levels. The `.identity` binding that closed
  this is gone (§13). Until §16.7 is decided, deployers who need the guard
  bind `repo_id` in per-repo roles, and rename or delete-recreate is a
  data-path migration step.
- **Per-secret image and event pins are not carried over.** A secret that
  was pinned to some events or step images becomes visible to every event
  its level's role admits. Migration must move such a secret to a level whose
  role lists only those events (§15 step 3), or leave it out of the view
  until §16.5 is decided. Image pins have no interim equivalent.
- **`vault_token` suppression is not carried over.** The token is always
  returned when the role grants one; it can read only what the role's
  policies grant, which is what the walk would return anyway. A repo that
  relied on suppression as defence in depth loses that layer.
- **Metadata is string-only.** A list claim in `claim_mappings` fails the
  login. Teams therefore travel only through `groups_claim` and gate only
  through groups. No policy can template on a team.
- **ironbark's signing key is the CI secret estate.** Whoever holds it can
  sign any claims and log in to any role. This is the same bound as today's
  token-create capability, and every login is audited with its claims.
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
   and pointers.
2. **Classify each secret by what changes its value:**
   - same value for every pipeline, and safe for PR heads → project level;
   - differs per deployment environment → environment level, named after the
     branch that feeds it (`push/main/*` → `main/`);
   - specific to one part → `<env>/<target>/` (`.target/web` in the `manual`
     or `deployment` tier → `<env>/web/`);
   - identifiers → out of the tree, into repo config (§3.3).
3. **Turn access-only distinctions into gates** (an event pin on a single
   secret becomes an event-restricted level and role; image pins are
   dropped, §14):
   - event tiers (`pull_request`, `manual`, `cron`) → `event` lists in role
     `bound_claims`;
   - branch tiers → an environment role binding `branch` and
     `branch_protected`;
   - `.actor/<login>` → `actor` in a role's `bound_claims`;
   - `.team/<team>`, `.target-team/...` → group policies (§6.4);
   - `.target-actor/...` → a single-member group, or a dedicated role.
4. **Create views** (one per secret, at its canonical level). Create roles
   and groups. The three level policies are estate-wide and exist once.
5. **Dynamic pointers:** rename engine roles to the `<env>[-<target>]`
   convention, keep a `$ref` entry only where a masked value is needed (§7).
6. **Pipelines:** workflows selecting on `DEPLOY_TO` also set `DEPLOY_ENV` on
   manual runs from a branch other than the environment's own. Merges that
   deploy one part add a `Deploy-To:` trailer.
7. **Cut over** the repo's endpoint and run its acceptance cases (§17.3).
8. **After a soak**, delete the repo's `kv/ci/...` subtree and its tier
   policies.

## 16. Open questions

1. **Refused login (§9.2):** is fail-on-explicit, fall-back-on-implicit
   right, or should every refusal fail?
2. **Branch-as-environment (§4.5 rule 2):** accept that implicit selection
   means env names equal branch names? The alternative is explicit-only,
   where pushes never reach an environment unless a `Deploy-Env:` trailer
   is added (not proposed here).
3. **More than one role per environment** (break-glass, per-team roles):
   `IRONBARK_JWT_ROLE` renders one name per env. Is that enough, or should a
   refused login try a second, suffixed role?
4. **Override lint:** only the audit-line list, or also an
   `ironbark lint` against a live tree that flags keys defined at more than
   one level?
5. **Image and event pins** without `custom_metadata`: drop them, or carry
   pins in the view mapping if voidstar can surface them?
6. **`vault_token` suppression** without `.config`: always return the token,
   or make suppression a role-level signal (for example, a
   `token_meta`-style field on the role that ironbark reads from the login
   response)?
7. **Repo rename protection** without `.identity`: bind `repo_id` in roles
   (per-repo roles, costly), put `{repo_id}` in the data path (unreadable
   paths), or accept the gap?
8. **Target prefixes:** is losing inheritance (`grp` → `grp/beta`) acceptable,
   or should targets split into up to N claims with one policy stanza per
   depth (the spike showed this works at a fixed depth)?
9. **Entity reaper:** ship an optional `ironbark reap-entities` (needs its own
   credential), or leave it to deployers?
10. **Part rule for `changed_files`:** first path segment (proposed) or a
    deeper, configurable depth?
11. **Group alias case:** do OpenBao group-alias names match
    case-sensitively for external groups? `esc()` makes the question moot
    for uppercase, but the lab should confirm.
12. **Voidstar views at escaped paths:** confirm voidstar accepts `%xx` in
    view names (`grp%2fbeta`) and lists them unchanged.

## 17. Testing

### 17.1 Unit

- Fact building per event from the recorded payload fixtures, including
  the promoted-PR trap (`ref` mismatch → `branch_protected=false`) and
  every `IRONBARK_ACTOR_FORGE` value.
- Env and target cascades: every rule, precedence, both grammars (including
  `.`/`..` segments), trailer parsing (none, one, two), `changed_files` one
  part, two parts, root files, empty.
- JWT claims: omission of absent claims, escaping of hostile values (`/`,
  `*`, `+`, `%`, `.`, `..`, uppercase), `sub` determinism and sensitivity
  (changes with env, target or team set; not with actor, event or pipeline).
- Role rendering (`ci-{env}` → `ci`), path-template validation, the level
  list, `render-policies` output.
- Walk: deepest wins, override records, unreadable levels skipped with the
  walk continuing, within-level clash, `$ref` classification.
- §9.2 decision table.

### 17.2 Integration (containerised OpenBao, and Vault before claiming it)

Each spike finding becomes a test: templated read at each level and 403
one level away; login refused by `bound_claims` (string, glob, list);
`groups_claim` to an external group granting a level; a forbidden character
in metadata building no ACL; the same-`sub` race (asserted absent with the
§5.4 derivation, present with a fixed `sub`); an empty mapped claim
matching nothing; per-login assertions against a role missing
`token_explicit_max_ttl` or set to `batch`; lease parenting and cascade
revocation of a `$ref` dynamic credential.

### 17.3 Acceptance: an end-to-end lab

An end-to-end acceptance lab (a Woodpecker + forge + OpenBao acceptance
catalogue of 45 cases, including a nine-step branch-as-environment UAT
scenario U1–U9) is rebuilt on this model. The lab applies its own fixture
data (views, JWT roles, templated policies, groups), because it is test
data with no reason to live anywhere else. Fixture shape:

- repo L: project level; environments `main` and `uat` (both protected;
  `uat` merge-only with an approvers whitelist); targets under `main`
  (`svc.alpha`, `grp%2fbeta`, `grp2`, `svc.gamma%2fsub`, …) with their
  `ci_deploy_root` markers; targets `partA`, `partB` under `uat`;
- repo O: project and `main`, for isolation;
- roles `ci`, `ci-main`, `ci-uat`; the `uat` target levels gated by group
  (Owners and uat-approvers per target, §6.4); teams via the fake or real
  forge.

In every rendered case, `delivered`/`denied` are re-derived for the new
paths, and the actor, team and conjunction canaries leave `delivered`
because those facts are now gates. That alone is not flagged below. A case is
flagged **changed** when its pipeline outcome or its stated intent changes.

| Case | Today | Under the grant model | Flag |
|---|---|---|---|
| M1 | manual, no target: manual tier + actor + team data | project + `main` (env from verified branch); actor/team deliver nothing, they only gate | **changed** (intent) |
| M2 | manual `svc.alpha`: target, target-actor, target-team prefixes | project + `main` + `main/svc.alpha`; conjunctions become group gates; kit-deploy success | **changed** (intent) |
| M3 | `svc.alpha/svc/gear`: inherits `svc.alpha` marker, success | opaque target, no level at `svc.alpha%2fsvc%2fgear` → marker missing → pipeline **error** (unless fixture adds the level) | **changed** (outcome) |
| M4 | `grp/beta`: success | `main/grp%2fbeta` marker, success | same |
| M5 | `grp`: no marker, error | no level, error | same |
| M6 | `grp2` rogue marker: guard refuses group | same | same |
| M7 | `svc.alpha/grouping`: inherited marker, guard refuses "no kit.yaml" | no level → marker missing → **error** at compile, before the guard | **changed** (outcome, still refused) |
| M8 | `svc.locked`: error | same | same |
| M9 | typo: error | same | same |
| M10–M14 | invalid target: error | `target_invalid`, walk stops at env, error | same (5 cases) |
| M15 | literal `%2f`: unknown segment, error | same | same |
| M16 | `svc.gamma/sub` rogue marker: guard refuses | only `svc.gamma%2fsub` level read, its marker mismatches, guard refuses | same |
| M17 | 8 segments: 17 team conjunctions dropped by the cap, success | no cap exists; opaque target has no level → **error**. Replace with a many-teams `groups_claim` case | **changed** (outcome; mechanism retired) |
| M18, M19 | guard refuses task missing / invalid | same | same |
| M20 | `svc.alpha/../svc.gamma`: guard refuses | `..` segment → `target_invalid` → **error** at compile | **changed** (outcome, still refused) |
| D1 | promote push to `svc.alpha`: deployment tier, no actor | env `main` from inherited verified branch; project + `main` + target; no event tier | **changed** (intent) |
| D2 | promote to `grp/beta`: guard reads deployment fields | target from `deploy_to`, variables ignored on deployment; success | same |
| D3, D4 | locked / invalid target: error | same | same |
| D5, D6 | guard refuses task | same | same |
| P1 | push `main`, member: push + `push/main` + actor + team | project + `main`; target from `changed_files` if one part | **changed** (intent) |
| P2 | push `main`, collaborator without team | identical to P1 unless `main` is team-gated in the fixture | **changed** (intent) |
| P3 | push branch `target`: branch tier must not meet `.target` | unprotected branch → no env → project only; the collision cannot exist | **changed** (intent) |
| P4 | outsider push refused by forge | same | same |
| R1 | PR: PR tier + PR actor data | role `ci` → project only (or nothing if PRs are excluded) | **changed** (intent) |
| C1 | cron: cron tier | env `main` if `ci-main` admits cron, else fallback to project | **changed** (intent) |
| O1 | other repo, approval: O's grants only | O's project + `main`; isolation by templated `repo` | same |
| X1 | Woodpecker fact pin | independent of ironbark | same |
| U1–U3 | forge refuses push / merge; approver merges | forge behaviour, unchanged | same (3 cases) |
| U4 | PR into `uat`: PR tier + `pull_request/uat`, none of `push/uat` | project only; the PR-per-base-branch tier has no equivalent; still none of `uat` | **changed** (intent) |
| U5 | merge push to `uat`: whole `push/uat` tier incl. partB (pinned leak) | env `uat`, target `partA` from `changed_files` (or a trailer) → project + `uat` + `uat/partA`; **partB not delivered**, leak closed | **changed** (intent) |
| U6 | direct push to `uat`, trigger file only: whole `push/uat` tier | project + `uat`; target `trigger` has no level; no part secrets | **changed** (intent) |
| U7 | push `uat-next`: nothing of `uat` | unprotected → project only | same |
| U8 | manual `uat/partA`, Owners: target + Owners conjunction | trigger becomes `DEPLOY_ENV=uat`, `DEPLOY_TO=partA`, branch `uat`; Owners group grants `uat/partA`; success | **changed** (trigger shape) |
| U9 | promote U8 to `uat/partA`: deployment tier + marker, success | no actor → no teams → gated `uat/partA` unreadable → marker missing → **error** | **changed** (outcome) |
| S1 | static: manual-matching workflows evaluate `DEPLOY_TO == ""` | same, extended to `DEPLOY_ENV` | same |
| S2 | static: repo settings | same, plus the per-repo extension endpoint | same |

Summary: 28 cases keep their expectation. 17 change: 5 in **outcome**
(M3, M7, M17, M20, U9. M7 and M20 are still refused, only earlier), and
12 in **intent** (M1, M2, D1, P1, P2, P3, R1, C1, U4, U5, U6, U8). U5 and
U6 are deliberate improvements (the pinned leak is closed). U9 is the
promote-has-no-actor limit, now enforced instead of merely noted.

New cases the model needs:

| Id | Case | Expect |
|---|---|---|
| G1 | manual `DEPLOY_ENV=uat` from unprotected branch | login refused, explicit → nothing, pipeline errors |
| G2 | push to unprotected branch named like an env | implicit env not selected, project only |
| G3 | promote of a PR pipeline | `ref` mismatch → `branch_protected=false` → no env |
| G4 | merge with `Deploy-To: partB` trailer touching `partA/` | trailer wins, target `partB` |
| G5 | push touching two parts | no target, env level only |
| G6 | same key at project and env | env value, override in audit line |
| G7 | two concurrent pipelines, same repo+env, different targets | each reads only its own target (race regression) |
| G8 | many teams (8+) | all reach `groups_claim`, no cap |
| G9 | tag pipeline | project only |

### 17.4 Failure-mode stack

Toy Forgejo, Woodpecker, OpenBao, voidstar and ironbark run in docker on a
disposable build VM, stood up per test run and torn down after, so
dependencies can be broken on purpose without touching production CI.
Each case asserts less or nothing, never more:

| Fault | Expect |
|---|---|
| forge down / slow (> timeout) | no implicit env, no teams; explicit env → nothing |
| OpenBao down | 502, nothing |
| JWT signed with a key not in `jwt_validation_pubkeys` | 502, nothing |
| JWT clock skew beyond leeway | 502, nothing |
| role missing (explicit / implicit) | nothing / project only |
| role with `token_type=batch` or no explicit max TTL | revoke, 502 |
| view missing | entry skipped |
| view quarantined / voidstar loopback broken | 502, nothing |
| group alias deleted mid-run | gated level unreadable on the next login |
| hostile values (`/`, `*`, `+`, `..`, uppercase) in branch, target, actor, team | escaped; no ACL failure; nothing extra |

## 18. Proposed decisions

Not recorded. Each would become one entry if accepted.

1. **Levels by value, gates by access.** Data is layered project → env →
   target. Team, actor, event and protected branch are OpenBao conditions,
   never path levels.
2. **ironbark signs facts; OpenBao decides.** Stock JWT auth, per-environment
   roles with `bound_claims` as the branch strategy, templated policies per
   level, teams as external groups via `groups_claim`. No plugin. No
   AppRole: the signing key is ironbark's only credential.
3. **Branch verification = forge `protected` AND `ref == refs/heads/<branch>`.**
4. **Selectors never entitle.** Env and target come from variables, promote
   fields, a trailer or changed files. OpenBao refuses what the facts do
   not allow.
5. **Env cascade:** explicit variable, then verified branch
   (branch-as-environment), then none.
6. **Target cascade:** manual variable, promote `deploy_to`, `Deploy-To:`
   trailer, single-part `changed_files`, none. One target per pipeline,
   escaped whole into one opaque level.
7. **Refused login:** fail when the environment was requested explicitly,
   fall back to the project level when it was inferred from the branch.
8. **`sub` = hash of every claim that feeds metadata or groups.**
9. **Deepest level wins; overrides are logged by name.**
10. **Dynamic credentials by naming convention, read with the pipeline's
    token.** `$ref` survives only for masked dynamic delivery.
11. **Four grant settings.** `IRONBARK_DATA_PATH`, `IRONBARK_ENV_VAR`,
    `IRONBARK_TARGET_VAR`, `IRONBARK_JWT_ROLE`, shared by `ib` through
    `~/.config/ib/config` (env wins).
12. **`ib` masks every value, with no length threshold, and checks no
    names.**
13. **Removed:** KV tier tree, attribute mount, per-tier policy names, dot
    directives, `custom_metadata` pins, the token-store mint and canary.
14. **Migration by per-repo extension endpoint.** Two deployments side by
    side, no dual-mode code.
15. **Acceptance:** the end-to-end acceptance lab applies its own fixtures, and
    failure modes run on an ephemeral docker stack.

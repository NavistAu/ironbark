# ironbark — design

> A [Woodpecker CI](https://woodpecker-ci.org) **secret extension** that
> federates pipeline identity to [OpenBao](https://openbao.org) (or
> [Vault](https://developer.hashicorp.com/vault)): for each pipeline it
> verifies Woodpecker's signed request, turns the payload into verified
> facts, signs those facts into a JWT, and logs in to OpenBao's `jwt` auth
> mount as the role for the selected environment. OpenBao decides what that
> login may read. ironbark walks the pipeline's levels of the secret tree
> under the login's own token and returns the values as ordinary **masked
> Woodpecker secrets**, plus an `ironbark_status` line. ironbark is
> stateless and holds no OpenBao credential: no rule tables, no path maps,
> no AppRole.

Status: M1 (the broker) is implemented on the grant model, released as
0.2.0. [`SPEC.md`](SPEC.md) is the normative interface and behaviour spec.
The [grant-model design](plans/2026-09-30-grant-model-design.md) carries
the full model: facts per event, claims, roles, policies, the walk, failure
behaviour and migration. This document covers architecture, rationale and
threat model. Where they overlap, SPEC governs, then the grant-model
design.

Revision note: this revision replaces the token-minting design of
2026-07-11 (ironbark held an AppRole, minted tokens through a token role,
derived tier policy names, and swept a KV tree shaped like those names).
That design is in git history and in the decisions of
[`docs/decisionlog/`](decisionlog/); §11 says which still stand.

## 1. Why this exists

Woodpecker has no pipeline-level identity token (no equivalent of GitHub
Actions' `id-token` or GitLab's `CI_JOB_JWT`), so a pipeline cannot present a
verifiable identity to a secrets manager and receive short-lived credentials.
(Confirmed against Woodpecker v3.15.0: issue #929 "Hashicorp vault as secret
storage integration" was closed *completed* by shipping the HTTP secret
extension — PR #6252 — not by adding Vault support. Upstream's answer to
"integrate Vault" is "write an extension.")

What Woodpecker *does* provide is the **secret extension**: on every pipeline
the server POSTs `{repo, pipeline}` to a configured HTTP endpoint, signed with
RFC-9421 HTTP Message Signatures (ed25519), and the endpoint returns the
secrets that pipeline may use. That server-signed payload — carrying repo
full-name, forge repo id, branch, event, commit, sender — *is* the pipeline
identity. ironbark is the endpoint that turns it into OpenBao-backed
secrets.

The obvious alternatives do not give a per-repo boundary:

- **Vault's Kubernetes auth.** Woodpecker lets a pipeline choose its own
  pod `serviceAccountName`, so a service-account identity is whatever the
  pipeline file says.
- **Woodpecker's native Kubernetes secret refs.** Instance-wide: any repo's
  pipeline can mount any secret in the build namespace.
- **A broker with its own read-everything credential.** A standing, silent
  decryption oracle.
- **A forge CI with OIDC (Forgejo Actions).** It has the identity token,
  but its Kubernetes runner needs a privileged Docker-in-Docker sidecar.
  Woodpecker's Kubernetes backend runs each step as an unprivileged pod.

### The metaphor

Woodpecker drills wood for grubs. Ironbark (*Eucalyptus* spp.) is a hardwood
whose dense, furrowed bark resists it. The broker is the bark: it decides, on a
per-peck basis, exactly how far in the woodpecker gets.

## 2. Core design: ironbark signs facts, OpenBao decides

Three decisions define the shape.

**ironbark establishes facts; it does not grant.** It reads the verified
payload, asks the forge two questions (is the branch protected, which teams
is the actor in), and signs the answers. It never names a policy and never
decides access. Access is OpenBao configuration, written as IaC: JWT roles
and their `bound_claims`, three templated level policies, external groups
for teams, and the views that exist. A branch strategy ("only protected
`main` deploys `prod`") has one home: the environment's role.

**Where a secret lives is decided by what changes its value.** Secrets sit
in a tree of levels: the repo, an environment under it, and one level per
target segment under that. A *level* fact (environment, target) becomes a
path segment. A *gate* fact (event, protected branch, actor, team) never
does; it is a condition in OpenBao. If two pipelines should see different
values, split a level. If they should see the same value or nothing, add a
gate. Each secret is stored once.

**It returns masked values, and the token only on request.** Woodpecker's
extension-returned secrets are native secrets — masked in logs, addressable
via `from_secret`, pinnable per-secret to images. So ironbark reads the
values itself, under the pipeline's own token, and returns them. The token
comes back as `vault_token` only where a level holds a metadata-only
`vault_token` marker (default off). Every read happens under a per-pipeline,
policy-scoped, short-TTL token that OpenBao issued for that login.

**It is stateless.** No rule table, no path map, no session. A constraint
forces this shape: the extension request carries only `{repo, pipeline}` —
Woodpecker never sends the `.woodpecker.yaml` or the secret names a pipeline
references — so job configuration cannot declare fetch lists to ironbark.
And a token's policies are not enumerable, so "return everything this token
can read" is impossible. A fixed level tree, read by one walk, is the
stateless way to know what to fetch. Onboarding a repo touches only OpenBao.

### Request flow

The normative sequence is SPEC §1.2. In outline:

1. **Verify** the RFC-9421 ed25519 signature, content digest and freshness
   against the configured Woodpecker public key. Refuse otherwise (§6).
2. **Build facts** from the payload: `org`, `repo`, `repo_key` (repo plus
   forge repo id), `event`, and per event `branch`, `ref`,
   `branch_protected`, `actor` and `target`. Branch protection is a forge
   lookup that fails closed.
3. **Select** the environment (`DEPLOY_ENV`, or a protected branch claimed
   by an environment level's `branches` metadata) and the target
   (`DEPLOY_TO` on manual runs, `deploy_to` on a promote, a `Deploy-To:`
   commit trailer on a push). Selection only chooses a path; it never
   entitles. An invalid explicit selector stops here.
4. **Discover**, only for a protected branch with no explicit environment:
   log in to the no-environment role `ci`, read level metadata, and find the
   one environment that claims the branch.
5. **Teams**: with an environment and an actor, resolve the actor's forge
   teams. A failed lookup sends `teams: []`.
6. **Sign and log in**: an RS256 JWT carrying the facts, posted to
   `auth/<mount>/login` with the rendered role (`ci-{env}`, or `ci`). A
   refused login is final; ironbark never retries with another role.
7. **Assert** the token is a service, orphan token with an explicit max TTL.
   A violation revokes it.
8. **Walk** the levels shallow to deep as that token: list each level, read
   each entry, deeper wins, unreadable levels and entries skipped.
9. **Respond** `200` with the secrets and `ironbark_status`. A response with
   nothing else revokes the token.

### Why JWT login

OpenBao's `jwt` auth method is a stock feature. A role binds claims
(`bound_claims`), maps claims into entity alias metadata (`claim_mappings`),
and maps a list claim to external groups (`groups_claim`). Templated ACL
policies then read that metadata. Together they express everything the old
design spread across Go code, policy names and KV layout:

- **Which pipelines may act for an environment** is the role's
  `bound_claims`: repos by `repo_key`, events, branch, protection, actor.
- **Which levels a login reads** is three templated policies, one per level
  kind (`ci-project`, `ci-env`, `ci-target`). They serve every repo,
  environment and target. `ironbark render-policies` prints them from
  `IRONBARK_DATA_PATH`, so the policy paths and the walk cannot drift.
- **Team conditions** are external groups whose policies add gated levels.

The signing key replaces the AppRole. JWT login is unauthenticated: the
signature is the credential, and OpenBao gates what each login may become.
No JWKS endpoint is hosted; the public key sits in the mount's
`jwt_validation_pubkeys` list, which also makes rotation a list edit.

## 3. Security model — the honest version

**ironbark's signing key is the CI secret estate.** Whoever holds it can
sign any claims — any repo, branch, protection, actor, teams — and log in
to any role. That is the same bound as the old design's token-create
capability, and the same as any broker. What the design buys, versus a
broker with a standing read credential:

- **No OpenBao credential exists at the broker** — at rest, in config, or
  in a secret store. There is nothing to steal that reads silently.
- **Every read chain starts with a login** that OpenBao audit-logs with its
  role and claims (`jti` correlates it with ironbark's audit line). Loud,
  not silent.
- **Values never rest in ironbark** — they transit memory per request, are
  never logged, never stored.
- **The ceiling is OpenBao data.** A forged login reaches at most the union
  of what the roles and groups grant. Nothing in ironbark's code can widen
  it.
- **Short TTLs bound every leaked artifact** — tokens and dynamic
  credentials expire on the role's explicit max TTL.
- **Every failure gives less, never more.** A refused login, a failed forge
  lookup, an unreadable level all shrink the result (grant-model design
  §9.3).

These are hardening and auditability properties, not a categorical
boundary; the design accepts that trade openly.

### Threat table

| Threat | Outcome |
|---|---|
| ironbark process compromised, or its signing key leaked | Attacker signs any claims and logs in to any role: the CI secret estate, bounded by the configured roles and groups. No silent path: every read chain starts with an audited login. Rotate by adding a new public key to `jwt_validation_pubkeys`, rolling ironbark, removing the old key. |
| A returned secret value leaked via CI logs | Masked by Woodpecker (extension secrets are native secrets). Residual: values written to artifacts or exfiltrated deliberately — masking is a log control, not DLP. |
| `vault_token` leaked | The login's policy set for the remaining TTL, then dead. Opt-in per level and image-pinned. It can read more than the walk did: literal group stanzas and convention-named engine paths the policies grant. |
| Malicious `.woodpecker.yaml` (PR branch) | Cannot forge `branch`, `event` or protection (forge-set). A PR has no `branch` fact at all, so it matches no role that binds one; it gets the repo level at most, or nothing if `ci` omits `pull_request`. The yaml has no channel to request anything from ironbark. |
| Selector abuse: `DEPLOY_ENV=prod` from an unprotected branch | The `ci-prod` role's `bound_claims` refuse the login. No secrets, only `ironbark_status` with `outcome=refused`. Never a fallback to the repo level. |
| Promote of a pull-request pipeline | Woodpecker copies the parent's `branch=main` and `ref=refs/pull/N/head`. ironbark requires `ref == refs/heads/<branch>` for `branch_protected=true`, so the promote is unprotected. |
| `event=manual` pipeline claims `branch=main` | Real: manual Branch is caller-supplied. It is verified against the forge's protection, but any user Woodpecker lets start a pipeline on a protected branch gets a verified branch. An environment that must not be reachable by all of them binds `actor` or a team gate as well. |
| Attacker pushes a branch literally named `Main` | `esc()` encodes uppercase instead of folding it (`Main` → `%4dain`), so it can never satisfy a role bound to `main`. Protection is looked up on the exact name (SPEC §2.2). |
| Claim value carrying `/`, `*` or `+` | `esc()` never emits them, so no claim can inject a path segment or a wildcard into a templated policy or a glob `bound_claims` (OpenBao would refuse the ACL and fail closed anyway). |
| Second login with the same `sub` rewrites an earlier token's grants | OpenBao overwrites alias metadata and group membership per login, and templates evaluate per request. `sub` is a hash of every value that feeds metadata or groups (env, target, teams), so two logins share a `sub` only when their grants are identical. |
| Someone with secret-tree write access plants a view or `resolve` mapping at a privileged path | The read happens under the pipeline's own token → 403, skipped. Mappings are convenience, not authority. |
| Role misconfigured as `batch`, non-orphan, or without an explicit max TTL | The per-login assertion revokes the token and reports `outcome=error`. |
| Spoofed request to ironbark | Refused at signature verification (§6). |
| Replayed request within the freshness window | Woodpecker signs a `created` timestamp but no nonce; ironbark enforces a `created` window (default 10s), and exact duplicates inside it are undetectable — bounded by window size, TLS, and network policy. Effect: a duplicate login for the same facts, not an identity change. |
| Repo renamed, or deleted and recreated under the same name | Every role lists repos by `repo_key` (`org/repo#<forge id>`). The new repo has a new id and cannot log in. An `org/repo#*` entry is unpinned by choice, and any wider glob in the same list silently undoes every pin beside it. |
| Forge down or slow | Protection fails closed (`branch_protected=false`: no discovery, repo level only); teams fail closed (`[]`: team-gated levels skipped). |
| ironbark down / DoS'd | Woodpecker is fail-open: pipelines run with DB-only secrets and a server-side warning. Steps referencing a missing `from_secret` fail at compile — the actual backstop. Pipelines depending only implicitly on extension secrets half-run. Not changeable from ironbark; documented loudly for adopters. |

### Honest limits

The full list is grant-model design §14. The ones that shape adoption:

- **Anything fetched via `vault_token` directly is not masked.** The masked
  path covers views and `resolve`d dynamic credentials; the escape hatch is
  curl territory (`set +x`, no echoing, `-no-color`).
- **Some providers have no STS.** A static API token in the tree gains
  rotation and audit, not ephemerality. Engines with dynamic credentials
  (AWS STS, databases) are delivered masked through `resolve` mappings.
- **The chain of trust stops at two keys.** Pipeline identity is
  Woodpecker's signature, trusted transitively; OpenBao sees ironbark's
  signature, not Woodpecker's. There is no cryptographic chain from git
  commit to OpenBao token beyond those keys (see §12).
- **TTL starts at login (pipeline compile time).** A pipeline that queues
  20 minutes arrives with 20 minutes less credential. Size
  `token_explicit_max_ttl` for queue plus run time (README, "TTL
  budgeting").
- **A promote has no actor.** Woodpecker copies the parent's sender, so no
  role or group can require an actor of a promote; team-gated levels are
  unreachable by promote.
- **One secret list per pipeline.** Woodpecker calls the extension before
  workflows exist. Every step sees the same list, filtered only by image
  pins. Split parts across runs.
- **ironbark never fails a pipeline, but Woodpecker can.** A step whose
  `from_secret` names a secret that was not returned errors the whole
  pipeline at compile, before any step reads `ironbark_status`.
- **`ironbark_status` is masked like every secret.** Woodpecker has no
  unmasked extension secret. Print it through a transform
  (`echo "$STATUS" | tr ' ' '\n'`).
- **Gate granularity is the environment.** Per-target team gates are
  literal group policies, one per gated level.
- **A branch strategy is written twice**: the level's `branches` (selector)
  and the role's `branch` binding (gate). If they disagree the result is
  less, never more. Write both from one IaC declaration.
- **Proven on OpenBao only.** Vault has the same JWT auth and templating,
  but the grant-model tests run on OpenBao; Vault results cover plain KV v2
  and are informational.

## 4. The Woodpecker secret-extension contract

Request (Woodpecker → ironbark), signed:

```json
{ "repo":     { "full_name": "acme/widgets", "forge_remote_id": "4711", ... },
  "pipeline": { "event": "push", "branch": "main", "ref": "refs/heads/main",
                "commit": "…", "sender": "…", "variables": { ... }, ... },
  "netrc":    { ... }   // only if WOODPECKER_SECRET_EXTENSION_NETRC=true
}
```

Response (ironbark → Woodpecker), always `200` for a verified request:

```json
{ "secrets": [
    { "name": "registry_password",  "value": "…",
      "images": ["registry.example.com/infra/toolbox"] },
    { "name": "aws_access_key",     "value": "…" },
    { "name": "aws_secret_key",     "value": "…" },
    { "name": "aws_security_token", "value": "…" },
    { "name": "vault_token",        "value": "…" },
    { "name": "ironbark_status",
      "value": "ironbark/v1 outcome=ok env=prod env_source=branch role=ci-prod" }
] }
```

- **Every verified request is `200` with `ironbark_status`.** `outcome` is
  `ok`, `refused`, `invalid`, `config_error` or `error`. The job reads it
  and decides whether to fail, warn or carry on; ironbark reports, the job
  decides. Only a bad signature (`401`), an over-size body (`413`) or a
  payload with no identity (`400`) answer otherwise, with no body.
- **No `events` field.** Event pins are role `bound_claims`. Image pins
  (`ironbark_images` on a mapping's `custom_metadata`) are relayed as
  `images`.
- `vault_token` appears only where a walked level holds the marker;
  `vault_addr` only when `IRONBARK_ADVERTISE_VAULT_ADDR` is set.

The service is *combined* with the DB store (`secret.NewCombined(NewDB,
NewHTTP)`), so extension secrets are additive and override DB secrets on an
exact-name collision; adoption is incremental. Woodpecker 3.x sets the
extension endpoint per repo, which is also how repos migrate between
ironbark deployments (§8).

ironbark ignores the `netrc` field; deployments should leave
`WOODPECKER_SECRET_EXTENSION_NETRC` off.

## 5. Levels, gates and the OpenBao side

ironbark's domain of authority is now a path template and a set of facts.
Everything else is OpenBao data. The operator checklist is the README
section "OpenBao operator contract (grant model)"; the full configuration,
with worked roles, policies and groups, is grant-model design §6.

**The level tree.** `IRONBARK_DATA_PATH` addresses it, for example
`vs/data/pipelines/{repo}/{env}/{target...}`:

```
vs/data/pipelines/acme/widgets/                  repo level
vs/data/pipelines/acme/widgets/prod/             environment level
vs/data/pipelines/acme/widgets/prod/web/         target level, depth 1
vs/data/pipelines/acme/widgets/prod/web/api/     target level, depth 2
```

Generic secrets sit high, customisations low. The walk reads only the
selected levels, shallow to deep, and the deepest readable value wins. A
nested target inherits its parents. Entries are normally
voidstar views — a mapping per
secret, resolving upstream — and a mapping is a record with its own
metadata: image pins, a `resolve` target, or nothing at all (the
`vault_token` marker). A plain KV v2 mount works too, without dynamic
pointers.

**Environments are named levels.** An entry named like the environment,
beside its folder, carries `branches` (comma-separated `path.Match`
patterns) in its `custom_metadata`. That is the whole branch-to-environment
mapping. Exactly one claimant selects the environment; two is a
`config_error`, never resolved by order or specificity.

**Dynamic credentials are `resolve` mappings.** Reading the mapping returns
the engine path, not the credential. ironbark then reads the path with the
pipeline token, so the lease parents to that token and dies with it. The
engine path is named after the levels (`aws/creds/<env>-<t1>`), so a
templated policy grants it and a mapping can only reach what the pipeline
could read anyway. One hop: a resolved response is never itself a pointer.

**The policies end every stanza in `/+`.** OpenBao's `*` is a prefix match
that crosses `/`, so a trailing `*` would grant every level below and
destroy the level separation. `+` is exactly one segment. A missing `env`
or `tN` claim renders an empty segment that matches nothing, so stanzas
deeper than the selected target grant nothing.

**Group policies are templated on `env`.** Identity policies apply to every
login of the entity, whatever the role, and a role cannot cap them. A group
policy templated on `env` matches nothing for a login without an
environment, so a group only adds levels below an environment the role
already admitted.

**The escape encoding must be injective.** Branch, actor, team and target
segments are attacker-chosen strings. Every claim that could reach a path
or a glob goes through `esc()` (SPEC §2.2): bytewise percent-encoding
outside `[a-z0-9._-]`, `%` always encoded, a leading `.` always encoded,
lowercase hex. Its output is a single segment, never dot-prefixed, never
contains `/`, `*` or `+`, and keeps distinct inputs distinct. `repo_key` is
built from escaped parts, so its `/` and `#` are always separators.

**Lowercase everywhere — except the branch, which is case-preserved.**
Org, repo and event are lowercased: forges enforce case-insensitive
owner/repo uniqueness, and Woodpecker's `from_secret` matching is
effectively lowercase while its store-merge dedup is case-sensitive, so
ironbark emits lowercase secret names. The branch is never folded: git refs
are case-sensitive and branch protection binds to the exact name, so
folding would collapse a branch `Main` onto protected `main`. `esc()`
encodes uppercase bytes instead (`Main` → `%4dain`). Team names get the
same treatment, because OpenBao matches group aliases case-insensitively;
aliases are written with the escaped name.

**Event facts the model encodes** (SPEC §2.1):

- `pull_request` has **no** `branch`: its base branch is not a trust
  signal. Tag and release have none either, so they never reach an
  environment.
- `manual` Branch is caller-supplied, `cron`'s is the cron creator's, and a
  promote (`deployment`) inherits its parent's. All are checked against the
  forge's protection and the `ref` before they count as protected.
- A promote has no actor. A push has an actor only when the operator
  declares a forge whose `sender` is a login (`IRONBARK_ACTOR_FORGE`).
- Unknown events pass through lowercased with no branch and no actor, so
  they match only roles that list them.

**Conventional policies are additive-only** — no `deny` stanzas. ACL
precedence is most-specific-wins regardless of allow/deny, and a `deny`
would also override the group grants that implement team gates.

## 6. Signature verification is load-bearing

This is the one part that cannot be thin.

- Woodpecker signs each request with ed25519 over `@request-target` and
  `content-digest` (RFC-9421 / `github.com/yaronf/httpsign`). The instance
  publishes its verification key at `GET /api/signature/public-key`.
- ironbark MUST verify the signature, the content digest and the `created`
  freshness window before acting on any payload. An unverified payload is
  attacker-controlled: without the check, any host that can reach ironbark
  can POST `{repo: "acme/widgets", branch: "main", event: "push"}`, and
  ironbark would sign those facts into a login that `ci-prod` accepts.
- The verification public key is configured out-of-band (never trusted from
  the request). Key rotation = config update and restart.
- Defence in depth: `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` on the Woodpecker
  side restricts which hosts the server will call; network policy restricts
  who can reach ironbark. Neither substitutes for the signature check.

A published tool that got this wrong would widen *adopters'* blast radius, so
it gets tests that assert: unsigned → refused; wrong key → refused; tampered
digest → refused; uncovered component → refused; missing, stale or future
`created` → refused; a byte-identical replay inside the window → accepted
and documented (SPEC §9.1).

## 7. Non-goals

- Not a secrets store. OpenBao is the store and voidstar the view layer;
  ironbark is a federation seam.
- Not a policy engine. ironbark carries no rules and names no policies;
  OpenBao's roles, policies and groups decide access.
- No GUI (DEC-260711061325). IaC is a form of UI; UI is not GUI. Today the
  control surface is hand-written OpenBao IaC plus
  `ironbark render-policies`. Still future: the M2 Terraform/OpenTofu
  module and `ironbark doctor`.
- Not multi-CI. Woodpecker-first. (Drone protocol kinship noted, not
  promised.)
- Not an OIDC issuer for pipelines. ironbark signs JWTs for exactly one
  audience, its own OpenBao mount, and hosts no JWKS. If Woodpecker ever
  ships pipeline id-tokens, ironbark's reason to exist shrinks and it
  should be reconsidered.
- No per-step or per-workflow secrets, and no knowledge of who promoted a
  deployment. Woodpecker does not provide either.

## 8. Deployment shape

- Container image, small Go binary, Kubernetes Deployment. Stateless —
  nothing to back up; replicas are trivial.
- Configuration (README, "Configuration reference"): the Woodpecker
  verification public key, the OpenBao address, the JWT signing key (PEM
  RSA, at least 3072 bits; `_FILE` variants suit External Secrets Operator
  mounts), the four grant settings (`IRONBARK_DATA_PATH`,
  `IRONBARK_ENV_VAR`, `IRONBARK_TARGET_VAR`, `IRONBARK_JWT_ROLE`), and
  optional forge access for protection and team lookups.
- ironbark holds **no OpenBao credential**. Its OpenBao footprint is a
  `jwt` auth mount trusting its public key, the roles, the three level
  policies, and any groups. Every read happens under the login's own token.
- Woodpecker server: `WOODPECKER_SECRET_EXTENSION_ENDPOINT` → ironbark's
  service URL; `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` widened to permit it
  (the default `MatchBuiltinExternal` blocks in-cluster/private addresses — a
  known gotcha). `WOODPECKER_SECRET_EXTENSION_NETRC` left off.
- **Migrating from 0.1.x** is two deployments side by side with the same
  Woodpecker public key. Repos move one at a time by changing their
  per-repo extension endpoint; rollback is the reverse change. There is no
  dual mode. Grant-model design §15 has the per-repo procedure.

## 9. Staged delivery

The broker is an *enhancement*, not a prerequisite. The value ladder:

1. OpenBao deployed → estate-wide value, no CI dependency.
2. A consuming repo holds a Woodpecker repo-secret credential and calls
   OpenBao directly → dynamic-cred CI with **no ironbark**, no new service
   to maintain.
3. ironbark replaces the static per-repo credential with signature-verified
   identity federation → "the repo declares nothing", central policy,
   added later.

ironbark's own repo bootstraps on stage 2 (its image build needs only a
registry token, not OpenBao) — no circular dependency.

## 10. Milestones

**M1 — the broker.** Verify → facts → select → (discover) → login → walk →
respond, on the grant model since 0.2.0. Signature test matrix (§6). Unit
tests per package; integration tests against containerised OpenBao with the
voidstar plugin, plus plain Vault over KV v2 (SPEC §9).

**M2 — the control surface** (DEC-260711061325). Still future: a generic
Terraform/OpenTofu module that writes roles, policies, groups, level
metadata and views from one declaration per repo, and `ironbark doctor`, a
read-only lint (role `branch` bindings against level `branches`, `repo_key`
lists free of wide globs, policies matching `IRONBARK_DATA_PATH`).

**M3 — the local client (`ib`)** was removed; the broker is the only
consumer of the secret tree.

## 11. Decisions

Decisions live in [`docs/decisionlog/`](decisionlog/) (MADR). The grant
model changes several; its own decisions are listed in grant-model design
§19 and are not yet recorded as entries.

| ID | Decision | Under the grant model |
|---|---|---|
| DEC-260711061322 | Return masked values plus the scoped token | Masked values stand; the token is opt-in per level (`vault_token` marker) |
| DEC-260711061323 | Stateless; no rule tables or path maps; yaml-declared fetch lists are protocol-impossible | Stands; the decisions moved from convention into OpenBao configuration |
| DEC-260711061324 | `$ref` pointer entries for dynamic engines | Superseded by `resolve` mappings |
| DEC-260711061325 | Control surface = IaC module + `ironbark doctor`; no GUI | Stands; both still future |
| DEC-260711114101 | Convention directives: `.identity`, `.config`, custom_metadata pins | Superseded: `repo_key` in `bound_claims`, the `vault_token` marker, `ironbark_images` on the mapping |
| DEC-260711114102 | Minted-token lifecycle: orphan non-renewable service tokens | Orphan service tokens with an explicit max TTL stand, now asserted per login |
| DEC-260711114103 | Identity encoding: branch case preserved injectively; event-tier mapping | Encoding stands; event tiers became role `event` bindings |
| DEC-260711114104 | Sweep/response semantics | Superseded by the walk; string-only values and deeper-wins stand |
| DEC-260711114105 | M1 runtime surface: 10s freshness, env-only config, dual audit shapes | Stands |

Earlier decisions still standing from the 2026-07-10 revision: Go
implementation (`woodpecker-ci/example-extensions` as reference for the
transport half); mandatory RFC-9421 verification; Woodpecker-first scope;
AGPL-3.0. AppRole for ironbark's own auth is gone.

## 12. Research notes

**JWT login — rejected 2026-07-11, adopted 2026-10.** The first research
pass turned down ironbark as a JWT issuer for OpenBao's `jwt` auth. Each
objection now has an answer:

- *A stateful key-holder (JWKS, rotation).* One RSA key, no JWKS; the
  mount's static `jwt_validation_pubkeys` list makes rotation an
  add-roll-remove edit.
- *Per-repo scoping needs per-repo roles or templated policies.* Templated
  policies, three for the whole estate; roles are per environment and list
  repos by `repo_key`.
- *Template injection: Vault allows `/` in substitutions, OpenBao drops the
  rule.* `esc()` never emits `/`, `*` or `+`, so no claim can carry one.
- *Alias-metadata authorization pitfalls.* The same-`sub` race was
  reproduced in a spike and closed by deriving `sub` from every value that
  feeds metadata or groups.

What tipped it: the old design spread access across Go code, policy names
and KV layout, and could only add grants, never gate them (grant-model
design §1).

**Custom Vault auth-method plugin.** ironbark forwards the Woodpecker-signed
request into OpenBao; a plugin verifies the ed25519 signature inside
OpenBao's trust boundary and issues the token natively. Buys: a
cryptographic chain from Woodpecker's signing key into OpenBao's audit log.
Costs: a binary plugin version-matched against both Vault and OpenBao
(plugin APIs drifting apart post-fork); managed Vault offerings disallow
custom plugins; sharply narrows adoption. Not roadmapped: OpenBao's audit
log records ironbark's JWT and its claims, not Woodpecker's signature.
**Revisit trigger:** that audit gap becomes a compliance requirement.

**Response wrapping.** Delivering `vault_token` cubbyhole-wrapped so only
the pipeline can unwrap it once. Interacts poorly with the walk (ironbark
uses the token first). Not evaluated.

## 13. Open questions

- **Vault parity.** The grant model is proven on OpenBao. Vault has the
  same JWT auth and templating, but ironbark should not claim it until the
  integration suite proves it.
- **Entity build-up.** Each distinct `sub` leaves an entity and alias that
  OpenBao never removes. Growth is bounded by distinct
  `(repo, env, target, team-set)` tuples. A reaper would need an identity
  credential ironbark does not hold. Roadmap only.
- **A step that tolerates a missing `from_secret`** would let every job,
  not only the careful ones, decide from `ironbark_status`. That is an
  upstream Woodpecker change.
- **The grant model's decision-log entries** (grant-model design §19) are
  proposed, not recorded.

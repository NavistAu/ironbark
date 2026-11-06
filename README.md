# ironbark

[![CI](https://github.com/navistau/ironbark/actions/workflows/ci.yml/badge.svg)](https://github.com/navistau/ironbark/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/navistau/ironbark)](https://github.com/navistau/ironbark/releases)

Per-pipeline secrets for [Woodpecker CI](https://woodpecker-ci.org) from
[HashiCorp Vault](https://developer.hashicorp.com/vault) or
[OpenBao](https://openbao.org): each pipeline gets exactly the secrets its
identity — repo, environment, target — is entitled to, and nothing else.

Without something in between, connecting Woodpecker to a secrets manager
is all-or-nothing. Woodpecker pipelines have no verifiable identity to
present to Vault, so whatever you wire up instead — a shared Vault token,
Kubernetes secrets mounted into the build namespace — is one pool that
every repo's pipelines can read alike. One repo's deploy credentials are
effectively every repo's deploy credentials.

ironbark is the piece in between: a Woodpecker
[secret extension](https://woodpecker-ci.org/docs/usage/extensions/secret-extension)
that brokers per-identity access.

- **Scoped by identity.** A pull-request build of `acme/widgets` gets that
  repo's repo-level secrets only; a push to protected `main` also gets the
  environment `main` selects; no pipeline ever sees another repo's secrets.
- **Short-lived.** Each pipeline logs in to OpenBao once and its token
  expires on the role's max TTL — including dynamic credentials (e.g. AWS
  STS) resolved at request time.
- **Delivered natively.** Values arrive as ordinary Woodpecker secrets:
  automatically masked in logs, `from_secret`-addressable, adoptable repo
  by repo alongside Woodpecker's built-in secrets.
- **Nothing to configure in the broker.** ironbark is stateless — no rule
  tables, no path maps. What a pipeline may read is decided entirely by
  OpenBao: the JWT roles and their `bound_claims`, the templated policies,
  and which entries exist; onboarding a repo is OpenBao-side IaC.

An aside for readers who know the OIDC id-token pattern from other CI
systems: Woodpecker has no pipeline id-tokens, but the seam it does have
turns out *stricter*, not weaker. The identity exchange is server-to-server,
signed, and finished before the build starts — pipeline code never holds an
identity credential it could exfiltrate — and ironbark holds no OpenBao
credential at all (only a JWT signing key, whose logins OpenBao gates), so
there is no standing OpenBao credential at the broker to steal either.

**How it works, in one breath:** Woodpecker calls ironbark for each
pipeline (a signed call — RFC-9421 ed25519 — so the identity is
verifiable); ironbark turns the payload into verified facts (repo, event,
branch and whether it is protected, actor, teams), signs a JWT carrying
them, and logs in to OpenBao with the role for the selected environment.
OpenBao's roles and templated policies decide what that token can read;
ironbark walks the repo, environment and target levels of the secret tree
under it, and returns the values (plus an `ironbark_status` line, and the
token itself where a level opts in). Architecture and threat
model: [`docs/DESIGN.md`](docs/DESIGN.md).

> Woodpecker drills wood; ironbark is the hardwood bark that decides, per peck,
> how far in it gets.

## Footguns

Known sharp edges, indexed so you hit them here first, not in production:

- [`WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` blocks in-cluster addresses by
  default](#deploying-pointing-woodpecker-at-ironbark) — the #1 deployment
  footgun.
- [ironbark down = fail-open, not
  fail-closed](#deploying-pointing-woodpecker-at-ironbark) — Woodpecker runs
  the pipeline anyway, on DB-only secrets.
- [Roles need `token_explicit_max_ttl`](#openbao-operator-contract-grant-model)
  — ironbark asserts it on every login.
- [`resolve` mappings are GET-only](docs/SPEC.md) (§4.3) — no PKI issuance
  via a mapping.
- [TTL must budget queue time, not just run time](#ttl-budgeting) — and one
  login covers every workflow of the run.
- [policy glob `*` crosses `/`](#openbao-operator-contract-grant-model) —
  the level policies end every stanza in `/+` for this reason; keep it.

## Status

M1 (the broker) is implemented: a Go
service (`cmd/ironbark` + `internal/…`),
unit-tested and integration-tested against OpenBao 2.7.0 with the voidstar
plugin (Vault 1.20 over plain KV v2 is informational). See [`docs/SPEC.md`](docs/SPEC.md) for the
broker's normative interface/behavior spec,
[`docs/DESIGN.md`](docs/DESIGN.md) for architecture and threat model, and
the decision log in [`docs/decisionlog/`](docs/decisionlog/). Still future:
the M2 Terraform module and `ironbark doctor` — onboarding a repo today
means hand-writing the OpenBao-side IaC described below.

## Install

From v0.1.0, ironbark publishes exactly two artifacts:

```sh
docker pull ghcr.io/navistau/ironbark
```

```sh
go install github.com/navistau/ironbark/cmd/ironbark@latest
```

## Why not just…

- **…a broker with its own read-everything credential?** A standing, silent
  decryption oracle. ironbark holds no OpenBao credential; every read chain
  starts with a per-role, audit-logged JWT login under the pipeline's own
  scoped token.
- **…Vault's Kubernetes auth?** Woodpecker lets a pipeline choose its own pod
  `serviceAccountName`, so k8s-SA identity is not a per-repo boundary.
- **…Woodpecker's native k8s secret refs?** Instance-wide: any repo's pipeline
  can mount any secret in the build namespace.
- **…Forgejo Actions (which has OIDC)?** Its Kubernetes runner still needs a
  privileged Docker-in-Docker sidecar; Woodpecker's k8s backend runs each step as
  an unprivileged pod. See the design doc's context section.

## Deploying: pointing Woodpecker at ironbark

Woodpecker's secret-extension flags (server-side, `cmd/server/flags.go`):

```
WOODPECKER_SECRET_EXTENSION_ENDPOINT=https://ironbark.internal/
WOODPECKER_SECRET_EXTENSION_NETRC=false
WOODPECKER_EXTENSIONS_ALLOWED_HOSTS=<see gotcha below>
```

Point `WOODPECKER_SECRET_EXTENSION_ENDPOINT` at ironbark's `/` route (the
only route Woodpecker calls; `/healthz`, `/readyz`, `/metrics` are for you).
The extension is *additive* to Woodpecker's own DB secrets — adoption can be
incremental, repo by repo, driven entirely by which OpenBao roles and
secret-tree entries exist for a given repo.

**Gotcha — `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` (the #1 deployment
footgun):** it defaults to `MatchBuiltinExternal`, which *blocks*
private/in-cluster addresses. An ironbark running in-cluster
(`*.svc.cluster.local`) is rejected outright unless you widen this flag to
permit ironbark's address. If the extension call is silently going nowhere,
check this first.

**Fail-open, loudly:** if ironbark is down, unreachable, or errors, Woodpecker
does **not** fail the pipeline. It logs a server-side warning and proceeds
with DB-only secrets — there is no fail-closed flag. A step referencing a
missing `from_secret` will then fail at compile (the real backstop), but a
pipeline that depends on ironbark only *implicitly* (e.g. reading
`vault_token` from the environment with no `from_secret` reference) can
half-run silently, using none of the secrets it expected. Do not assume
"the pipeline ran" means "ironbark answered."

**Leave `WOODPECKER_SECRET_EXTENSION_NETRC` off.** When enabled, Woodpecker
sends the repo *owner's* forge OAuth access token to the extension endpoint
on every pipeline call. ironbark never reads or logs the `netrc` field
regardless — there's simply no reason to send it.

## OpenBao operator contract (grant model)

> **Breaking.** ironbark now signs a JWT per request and logs in to OpenBao;
> it holds no AppRole and mints no token. Everything that decides access is
> OpenBao configuration. The full design is [`docs/plans/2026-09-30-grant-model-design.md`](docs/plans/2026-09-30-grant-model-design.md); this section is the
> checklist.

1. **Secret tree.** Views (voidstar mappings, or plain KV v2 entries) under
   `IRONBARK_DATA_PATH`, e.g. `vs/data/pipelines/{repo}/{env}/{target...}`:
   a repo level, an environment level per directory under it, and one level
   per target segment. `resolve` mappings hand out dynamic engine paths (leases
   parent to the pipeline token); a metadata-only mapping named `vault_token`
   opts a level in to returning the pipeline token; `ironbark_images` in a
   mapping's `custom_metadata` pins a secret to images. Level metadata
   `branches` (comma-separated `path.Match` patterns) on an environment
   directory lets a protected branch select it without `DEPLOY_ENV`.
2. **JWT auth mount** (default `jwt`): `bound_issuer=ironbark`,
   `jwt_validation_pubkeys` = the public half of `IRONBARK_JWT_SIGNING_KEY`
   (RSA, at least 3072 bits), and `groups_claim=teams` when team gates are
   used. ironbark always sends `teams` (`[]` when none).
3. **Roles.** One per environment (`IRONBARK_JWT_ROLE`, default `ci-{env}`)
   plus `ci` for runs with no environment. `bound_audiences=ironbark`,
   `user_claim=sub`, `claim_mappings` for `org`, `repo`, `env`, `t1`..`t8`, and
   `bound_claims` carrying the gates (`repo_key`, `branch`,
   `branch_protected`, `event`, ...). Every role must set `token_type=service`,
   `token_ttl` and `token_explicit_max_ttl` (size them; see TTL budgeting),
   and keep the default policy (revoke-self powers failure-path revocation).
   ironbark asserts service, orphan and a non-zero explicit max TTL on every
   login, and revokes and reports `outcome=error` if any fails.
4. **Policies.** Three templated level policies for the mount accessor;
   `ironbark render-policies -accessor auth_jwt_xxxx` prints them from
   `IRONBARK_DATA_PATH` with no OpenBao access (`ci-project`, `ci-env`,
   `ci-target`). Attach `ci-project` to `ci`, all three to environment roles.
5. **Groups.** External groups whose aliases are the escaped
   `org/team` names, for team-gated levels.

Every verified request returns `200` with an `ironbark_status` secret
(`outcome=ok|refused|invalid|config_error|error`); a response with nothing
else revokes the token it obtained. Gate a job on it:
`case "$STATUS" in *"outcome=ok"*) ;; *) exit 1 ;; esac`.

## TTL budgeting

the role's `token_explicit_max_ttl` is the entire lifetime of a pipeline's credentials,
so it must be sized to cover **queue time + run time**, not just run time.
The token is obtained once, at pipeline *compile* time — which is pipeline
creation, approval, or restart, not job start. A pipeline that sits queued
behind other work arrives at its first step with less TTL already spent.
Gated pipelines are the favourable case: they log in at *approval*, so
queue-delay TTL erosion only starts counting from the human approval click,
not from submission.

Dynamic-credential leases obtained through `resolve` mappings (e.g. database
credentials) are parented to the pipeline token and die when it does — so the token TTL must
outlive the whole pipeline run, including every workflow that shares it (one
login covers all workflows of a pipeline). ironbark never revokes a token
after a response that carries secrets; expiry is the only cleanup for a successful run, so
undersizing the TTL means credentials disappearing mid-run rather than being
proactively reclaimed.

## Configuration reference

Vars marked `/ _FILE` in the table have a `_FILE` suffix variant that
reads the value from a file path instead (for External Secrets Operator /
Kubernetes secret mounts). Setting both a var and its `_FILE` variant is a
configuration error. The four grant settings first, then plumbing; see
[`docs/plans/2026-09-30-grant-model-design.md`](docs/plans/2026-09-30-grant-model-design.md) §11.

| Var | Default | Required | Notes |
|---|---|---|---|
| `IRONBARK_DATA_PATH` | — | **yes** | path template: `<prefix>/data/.../{repo}/{env}/{target...}` (placeholders are whole segments; the last three, in that order) |
| `IRONBARK_ENV_VAR` | `DEPLOY_ENV` | no | pipeline variable naming the environment |
| `IRONBARK_TARGET_VAR` | `DEPLOY_TO` | no | manual-run variable naming the target; must differ from the env var |
| `IRONBARK_JWT_ROLE` | `ci-{env}` | no | login role template; `ci` when no environment |
| `IRONBARK_JWT_SIGNING_KEY` / `_FILE` | — | **yes** | PEM RSA private key, at least 3072 bits |
| `IRONBARK_JWT_MOUNT` | `jwt` | no | JWT auth mount path |
| `IRONBARK_LISTEN_ADDR` | `:8080` | no | |
| `IRONBARK_WOODPECKER_PUBLIC_KEY` / `_FILE` | — | **yes** | PEM ed25519, from `curl <woodpecker>/api/signature/public-key` |
| `IRONBARK_VAULT_ADDR` | — | **yes** | Vault/OpenBao URL |
| `IRONBARK_FRESHNESS_WINDOW` | `10s` | no | signature `created` freshness window |
| `IRONBARK_ADVERTISE_VAULT_ADDR` | unset | no | when set, echoed back as a `vault_addr` convenience secret (never keeps a token alive) |
| `IRONBARK_LOG_LEVEL` | `info` | no | |
| `IRONBARK_ACTOR_FORGE` | `none` | no | `none`, `gitea`, `github` or `bitbucket` (Cloud): the forge whose push-family sender is a login. With `IRONBARK_FORGE_PROVIDER=gitea`, only `gitea` or `none` |
| `IRONBARK_FORGE_PROVIDER` | `none` | no | `none` or `gitea` (Gitea, Forgejo): branch protection and teams. `none` makes `branch_protected` always `"false"` and logs a startup warning |
| `IRONBARK_FORGE_URL` | — | when provider ≠ `none` | forge base URL (`http`/`https`) |
| `IRONBARK_FORGE_TOKEN` / `_FILE` | — | when provider ≠ `none` | read scope on org teams and branch protection |
| `IRONBARK_FORGE_TIMEOUT` | `3s` | no | bounds each forge lookup (protection, teams); on failure the lookup fails closed |

Removed: `IRONBARK_VAULT_ROLE_ID`, `IRONBARK_VAULT_SECRET_ID`,
`IRONBARK_TOKEN_ROLE`, `IRONBARK_KV_MOUNT`, `IRONBARK_KV_PREFIX`,
`IRONBARK_POLICY_PREFIX`, `IRONBARK_ATTR_MOUNT`, `IRONBARK_MAX_POLICIES`.

No config file, no rule tables, no path maps — onboarding a repo is OpenBao
IaC (views, level metadata, roles), not broker configuration. TLS
termination is the deployment's concern (service mesh / ingress); ironbark
serves plain HTTP.

## License

[AGPL-3.0](LICENSE). It's a deployed service; the network-use clause keeps
hosted reuse open-source.

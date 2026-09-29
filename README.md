# ironbark

[![CI](https://github.com/navistau/ironbark/actions/workflows/ci.yml/badge.svg)](https://github.com/navistau/ironbark/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/navistau/ironbark)](https://github.com/navistau/ironbark/releases)

Per-pipeline secrets for [Woodpecker CI](https://woodpecker-ci.org) from
[HashiCorp Vault](https://developer.hashicorp.com/vault) or
[OpenBao](https://openbao.org): each pipeline gets exactly the secrets its
identity — repo, event, branch — is entitled to, and nothing else.

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
  repo's read-only tier; a push to `main` also gets that repo's `main`
  deploy tier; no pipeline ever sees another repo's secrets.
- **Short-lived.** Credentials are minted per pipeline run and expire in
  minutes — including dynamic credentials (e.g. AWS STS) resolved at
  request time.
- **Delivered natively.** Values arrive as ordinary Woodpecker secrets:
  automatically masked in logs, `from_secret`-addressable, adoptable repo
  by repo alongside Woodpecker's built-in secrets.
- **Nothing to configure in the broker.** ironbark is stateless — no rule
  tables, no path maps. What a pipeline may read is decided entirely by
  which Vault policies and KV entries exist; onboarding a repo is
  Vault-side IaC.

An aside for readers who know the OIDC id-token pattern from other CI
systems: Woodpecker has no pipeline id-tokens, but the seam it does have
turns out *stricter*, not weaker. The identity exchange is server-to-server,
signed, and finished before the build starts — pipeline code never holds an
identity credential it could exfiltrate — and ironbark itself can only mint
tokens, never read secrets, so there is no standing credential at the
broker to steal either.

**How it works, in one breath:** Woodpecker calls ironbark for each
pipeline (a signed call — RFC-9421 ed25519 — so the identity is
verifiable); ironbark derives conventional Vault policy names from the
pipeline's `(repo, event, branch)`, mints a short-lived token scoped to
exactly those policies — a policy set ironbark itself does not hold, so
the broker can never read secrets on its own — sweeps the repo's KV
subtree (`kv/ci/<org>/<repo>/…`) under that token, and returns the values,
plus the token itself for anything interactive. Architecture and threat
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
- [`token_ttl` on the role is a silent no-op](#token-role) — use
  `token_explicit_max_ttl`.
- [`$ref` is GET-only](#ref-dereference-limitation) — no PKI issuance via
  pointer.
- [TTL must budget queue time, not just run time](#ttl-budgeting) — and one
  mint covers every workflow of the run.
- [policy glob `*` crosses `/`](#tier-policies-example-acmewidgets) — scope
  each tier's paths to its own prefix, never a shared trailing wildcard.

## Status

M1 (the broker) and M3 (`ib`, the local client) are implemented: a Go
service (`cmd/ironbark` + `internal/{wpsign,identity,policy,broker,vaultx,httpapi}`)
and a CLI (`cmd/ib`), both unit-tested and integration-tested against both
Vault 1.20 and OpenBao 2.5.5. See [`docs/SPEC.md`](docs/SPEC.md) for the
broker's normative interface/behavior spec,
[`docs/CLIENT-SPEC.md`](docs/CLIENT-SPEC.md) for `ib`'s,
[`docs/DESIGN.md`](docs/DESIGN.md) for architecture and threat model, and
the decision log in [`docs/decisionlog/`](docs/decisionlog/). Still future:
the M2 Terraform module and `ironbark doctor` — onboarding a repo today
means hand-writing the Vault-side IaC described below.

## Install

From v0.1.0, ironbark publishes exactly two artifacts:

```sh
docker pull ghcr.io/navistau/ironbark
```

```sh
go install github.com/navistau/ironbark/cmd/ironbark@latest
```

## `ib`: the local client

`ib` gives a local run — your shell, an agent, a script — the same
repo/event/branch-tier secrets a CI run on the same repo and branch would
get (never attribute secrets, which need a signed pipeline payload), read from the same KV
layout the broker sweeps. It mints nothing and holds no credential of its
own: every read is made with your own Vault/OpenBao token, the one `ib
auth` (or `vault login`/`bao login` directly) already left at
`~/.vault-token`. Full behavior: [`docs/CLIENT-SPEC.md`](docs/CLIENT-SPEC.md).

```sh
go install github.com/navistau/ironbark/cmd/ib@latest
```

Four commands:

- `ib auth [args…]` — sugar over `bao login`/`vault login` (whichever CLI is
  on `PATH`, `bao` preferred); the token lands wherever that CLI's own token
  helper puts it.
- `ib get <name>` — one secret's value to stdout.
- `ib env` — every secret as `SECRET_<NAME>='<value>'` lines (break-glass —
  values land on disk if you redirect this to a file; `ib run` below is the
  normal path).
- `ib run -- <cmd> [args…]` — runs `<cmd>` with every secret set as
  `SECRET_<NAME>`, masking the values in its stdout/stderr; the way to use
  secrets without them touching disk. `--env-file <file>` instead sets only
  the `ironbark://<name>` references in that file (a subset, or your own
  variable names).

Example env file, for `ib run --env-file`:

```
API_TOKEN=ironbark://api_token
DB_PASSWORD=ironbark://db_password
DEBUG=true
```

`ironbark://<name>` is replaced by that secret's value from the sweep; any
other value (like `DEBUG=true` above) passes through unchanged.

**Security note:** `ib` reads exactly what your own Vault/OpenBao token can
read — since it never mints a token of its own, your policy is the only
bound on what comes back. `.identity` binding and `ironbark_images` pins
(SPEC §4.4, §4.6) are CI-only divergences: `ib` doesn't check `.identity`
(there's no forge-verified request to compare it against) and ignores image
pins (there's no step image locally). If you rely on either as hardening,
treat `ib` access as bypassing it — see
[CLIENT-SPEC.md §6](docs/CLIENT-SPEC.md#6-security-model).

## Why not just…

- **…a broker with its own read-everything credential?** A standing, silent
  decryption oracle. ironbark's Vault identity can only *create* tokens;
  every read chain starts with a per-role, audit-logged mint under the
  pipeline's own scoped token.
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
incremental, repo by repo, driven entirely by which Vault policies/KV paths
exist for a given repo.

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

## Vault/OpenBao operator contract

Setting up a repo (or the instance) requires Vault/OpenBao-side IaC — there
is no broker-side config for this. Three pieces: the token role ironbark
mints against, per-repo tier policies, and the AppRole ironbark itself logs
in with.

**Prerequisites** (once per Vault/OpenBao instance): a KV **v2** engine at
the configured mount, and AppRole auth enabled. Neither exists by default —
dev mode mounts kv-v2 at `secret/`, not the `kv/` this contract (and
ironbark's `IRONBARK_KV_MOUNT` default) assumes:

```
vault secrets enable -path=kv -version=2 kv
vault auth enable approle
```

Only if you use attribute policies (below): a second KV **v2** mount for
attribute data, at `IRONBARK_ATTR_MOUNT` (default `ironbark`). Until it
exists, attribute reads are skipped and nothing else changes.

```
vault secrets enable -path=ironbark -version=2 kv
```

### Token role

Create the role ironbark mints pipeline tokens from (default name `ci`,
`IRONBARK_TOKEN_ROLE`):

```hcl
allowed_policies_glob   = ["ci/*"]
token_type              = "service"
token_explicit_max_ttl  = "15m"
orphan                  = true
renewable               = false
token_no_default_policy = false
```

```
vault write auth/token/roles/ci \
  allowed_policies_glob="ci/*" \
  token_type=service \
  token_explicit_max_ttl=15m \
  orphan=true \
  renewable=false \
  token_no_default_policy=false
```

(Works identically against OpenBao as `bao write auth/token/roles/ci ...`.)

**Use `token_explicit_max_ttl`, not `token_ttl`.** This is integration-verified
(Vault 1.20 + OpenBao 2.5.5): the token-store role endpoint silently *drops*
a `token_ttl` field — no error, no warning — and a token minted with no
request TTL then inherits the token auth mount's `default_lease_ttl`, which
defaults to **32 days**. Setting `token_ttl` on the role is therefore a
no-op that quietly defeats the "dies in minutes" threat model. The field
that actually bounds a role-minted token's lifetime on both products is
`token_explicit_max_ttl`. Set it deliberately to however long a pipeline run
should be able to hold credentials — see TTL budgeting below.

`orphan=true` keeps pipeline tokens alive across ironbark's own AppRole
rotation/re-login. `renewable=false` makes the TTL an absolute lifetime —
Vault's `default` policy grants renew-self, so a renewable token could
outlive the "dies in minutes" intent. `token_no_default_policy=false` keeps
`default` attached, which is load-bearing: ironbark revokes every non-`200`
outcome via `auth/token/revoke-self`, authenticated *as* the minted token,
which requires `default`'s revoke-self grant.

### Tier policies (example: `acme/widgets`)

Policy names follow `ci/<org>/<repo>/<event>[/<branch>]`. A plan tier
(read-only, e.g. for `pull_request`):

```hcl
# ci/acme/widgets/pull_request   (repo-wide base tier + pull_request event tier)
path "kv/data/ci/acme/widgets/+"                 { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/"              { capabilities = ["list"] }
path "kv/data/ci/acme/widgets/pull_request/+"    { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/pull_request/" { capabilities = ["list"] }
```

A deploy tier (e.g. for `push` on `main`):

```hcl
# ci/acme/widgets/push/main      (branch tier only)
path "kv/data/ci/acme/widgets/push/main/+"       { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/push/main/"    { capabilities = ["list"] }
```

**Use exact paths under the tier, not a single trailing `*` at the repo
root shared across tiers.** In Vault's ACL glob, `*` crosses `/`
(integration-verified) — a policy path like `kv/data/ci/acme/widgets/*`
attached only to the *branch*-tier policy would also match the *event*-tier
and base-tier paths, leaking secrets meant for a broader (less trusted)
scope into a narrower one. Scope each policy's paths to its own tier prefix.
`+` matches exactly one path segment while `*` crosses `/`, so a tier
policy uses `+` for the key segment and grants `list` on the tier's exact
metadata path.

### Attribute policies (optional: target, actor, team)

Beyond repo/event/branch, ironbark requests policies for the pipeline's
**target** (a deployment's `deploy_to`, or the manual-run variable
`IRONBARK_TARGET_VAR`, default `DEPLOY_TO`), its **actor** (who started a
manual run; on push-family events the webhook sender, only when
`IRONBARK_ACTOR_FORGE` declares a forge whose sender is a login), the
actor's forge **teams** (optional, `IRONBARK_FORGE_PROVIDER`), and
conjunctions of a target with an actor or team. Names hang off the event
policy, e.g. `ci/acme/widgets/manual/.target/api`,
`…/.actor/<login>`, `…/.team/<team>`, `…/.target-actor/<target>/<login>`,
`…/.target-team/<target>/<team>`, with each value escaped as in
[`docs/SPEC.md` §2.2–§2.4](docs/SPEC.md) (a nested target `api/eu` is the
one segment `api%2feu`). Create only the ones you want; the rest grant
nothing. A deploy target `api`:

```hcl
# ci/acme/widgets/manual/.target/api
path "ironbark/data/acme/widgets/manual/.target/api/+"  { capabilities = ["read"] }
path "ironbark/metadata/acme/widgets/manual/.target/api/" { capabilities = ["list"] }
```

- Attribute data lives in the attribute mount, never under `kv/`, so no
  tier policy on `kv/` can reach it, whatever glob it uses.
- Attribute policies only grant. Never rely on them to deny: any
  attribute can be absent (no target, empty actor, a failed team lookup,
  or a name dropped by `IRONBARK_MAX_POLICIES`), which lifts the deny for
  exactly the pipelines it was meant to stop.
- A target-only policy scopes a secret away from other pipelines of the
  event, but anyone who can start a manual run or promote can name any
  target. To restrict *who*, use a conjunction (`.target-actor`,
  `.target-team`).
- Team membership is owned by the forge: whoever can edit a team there can
  widen what team policies grant. The forge token needs read scope only.
- The forge token must belong to a site admin or an org owner: Gitea-family
  forges hide team membership from anyone else (404, indistinguishable from
  "not a member"), so an ordinary user's token silently resolves no teams.
  Read-only scopes on an admin account still read every org and repo
  (SPEC §2.5).
- Writing attribute keys over raw HTTP: encode the `%` of an escaped
  segment as `%25` in the KV path (the `vault`/`bao` CLIs and API clients
  do this for you).

### ironbark's own AppRole

ironbark's Vault identity must be able to mint tokens against the role
above and nothing else — no KV read, no policy read:

```hcl
# ironbark-agent policy — the only grant ironbark's own identity holds
path "auth/token/create/ci" {
  capabilities = ["create", "update"]
}
```

Create the AppRole with that policy and read out the credentials that
become `IRONBARK_VAULT_ROLE_ID` / `IRONBARK_VAULT_SECRET_ID` (AppRole auth
must already be enabled — see prerequisites above):

```
vault policy write ironbark-agent ironbark-agent.hcl
vault write auth/approle/role/ironbark \
  token_policies=ironbark-agent \
  token_type=service token_ttl=1h token_max_ttl=4h
vault read auth/approle/role/ironbark/role-id
vault write -f auth/approle/role/ironbark/secret-id
```

### KV convention (brief — see [`docs/SPEC.md` §4](docs/SPEC.md) for detail)

```
kv/ci/<org>/<repo>/<key>                       # repo-wide, all events
kv/ci/<org>/<repo>/<event>/<key>                # event tier
kv/ci/<org>/<repo>/<event>/<branch>/<key>       # branch tier (branchful events only)
kv/ci/<org>/<repo>/.identity                    # optional: forge_remote_id binding
kv/ci/<org>/<repo>/.config                      # optional: repo directives (e.g. suppress vault_token)
```

Entries can be plain values, or `{"$ref": "<path>"}` pointers dereferenced
into dynamic engines at request time. KV v2 `custom_metadata` on an entry can
pin `ironbark_images` / `ironbark_events` to narrow which step images or
events the returned secret is valid for.

## `$ref` dereference limitation

`$ref` pointer entries are resolved with a bodiless `GET` against the
target path, using the pipeline's minted token. This means `$ref` targets
must be **GET-readable** dynamic-secret endpoints — `aws/creds/<role>`,
`database/creds/<role>`, `gcp/.../key`, `azure/creds/<role>`, or another KV
path. It does **not** work for engines that require a request body on a
write, notably `pki/issue/<role>`: that endpoint is POST-only and returns
405 on a bare GET (integration-verified on both products). Don't point
`$ref` at PKI issuance — there is no supported path to it in M1.

## TTL budgeting

`token_explicit_max_ttl` is the entire lifetime of a pipeline's credentials,
so it must be sized to cover **queue time + run time**, not just run time.
The token is minted once, at pipeline *compile* time — which is pipeline
creation, approval, or restart, not job start. A pipeline that sits queued
behind other work arrives at its first step with less TTL already spent.
Gated pipelines are the favourable case: they mint at *approval*, so
queue-delay TTL erosion only starts counting from the human approval click,
not from submission.

Dynamic-credential leases obtained via `$ref` (e.g. AWS STS creds) are
parented to the minted token and die when it does — so the token TTL must
outlive the whole pipeline run, including every workflow that shares it (one
mint covers all workflows of a pipeline). ironbark never revokes a token
after a `200` response; expiry is the only cleanup for a successful run, so
undersizing the TTL means credentials disappearing mid-run rather than being
proactively reclaimed.

## Configuration reference

Vars marked `/ _FILE` in the table have a `_FILE` suffix variant that
reads the value from a file path instead (for External Secrets Operator /
Kubernetes secret mounts). Setting both a var and its `_FILE` variant is a
configuration error.

| Var | Default | Required | Notes |
|---|---|---|---|
| `IRONBARK_LISTEN_ADDR` | `:8080` | no | |
| `IRONBARK_WOODPECKER_PUBLIC_KEY` / `_FILE` | — | **yes** | PEM ed25519, from `curl <woodpecker>/api/signature/public-key` |
| `IRONBARK_VAULT_ADDR` | — | **yes** | Vault/OpenBao URL |
| `IRONBARK_VAULT_ROLE_ID` / `_FILE` | — | **yes** | ironbark's AppRole |
| `IRONBARK_VAULT_SECRET_ID` / `_FILE` | — | **yes** | ironbark's AppRole |
| `IRONBARK_TOKEN_ROLE` | `ci` | no | token role name (§ above) |
| `IRONBARK_KV_MOUNT` | `kv` | no | KV v2 mount |
| `IRONBARK_KV_PREFIX` | `ci` | no | |
| `IRONBARK_POLICY_PREFIX` | `ci` | no | |
| `IRONBARK_FRESHNESS_WINDOW` | `10s` | no | signature `created` freshness window |
| `IRONBARK_ADVERTISE_VAULT_ADDR` | unset | no | when set, echoed back as a `vault_addr` convenience secret |
| `IRONBARK_LOG_LEVEL` | `info` | no | `debug` adds a per-request `payload attributes` line (variable names, never values) |
| `IRONBARK_ATTR_MOUNT` | `ironbark` | no | KV v2 mount for attribute data; must not equal, contain or sit inside `IRONBARK_KV_MOUNT` |
| `IRONBARK_TARGET_VAR` | `DEPLOY_TO` | no | manual-run variable naming the target |
| `IRONBARK_MAX_POLICIES` | `64` | no | cap on requested policies (≥ 3); attribute names are dropped first, never P1/P2 or the actor |
| `IRONBARK_ACTOR_FORGE` | `none` | no | `none`, `gitea`, `github` or `bitbucket` (Cloud): the forge whose push-family sender is a login. With `IRONBARK_FORGE_PROVIDER=gitea`, only `gitea` or `none` |
| `IRONBARK_FORGE_PROVIDER` | `none` | no | `none` or `gitea` (Gitea, Forgejo): resolve the actor's teams |
| `IRONBARK_FORGE_URL` | — | when provider ≠ `none` | forge base URL (`http`/`https`) |
| `IRONBARK_FORGE_TOKEN` / `_FILE` | — | when provider ≠ `none` | read scope on org teams |
| `IRONBARK_FORGE_TIMEOUT` | `3s` | no | bounds a whole team lookup; on failure team policies are skipped, never the request |

No config file, no rule tables, no path maps — onboarding a repo is Vault
IaC (policies + KV entries), not broker configuration. TLS termination is
the deployment's concern (service mesh / ingress); ironbark serves plain
HTTP.

## License

[AGPL-3.0](LICENSE). It's a deployed service; the network-use clause keeps
hosted reuse open-source.

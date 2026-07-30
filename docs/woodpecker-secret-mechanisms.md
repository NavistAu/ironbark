# Woodpecker secret mechanisms — facts read from v3.15.0 source (2026-07-11)

> Research doc predating publication; environment details below are the
> authors' own deployment and are illustrative only — examples elsewhere in
> this repo use generic hostnames/orgs.

Deployed: Woodpecker appVersion 3.15.0 (chart woodpecker-3.6.4, `dev/woodpecker`
kit in the authors' internal infrastructure). Forge: Forgejo at
forge.example.com. k8s backend, build namespace `woodpecker-builds`.

## 1. Native Kubernetes secret references — instance-wide, NOT per-repo

`pipeline/backend/kubernetes/backend_options.go`:

    type SecretRef struct {
        Name   string       `mapstructure:"name"`
        Key    string       `mapstructure:"key"`
        Target SecretTarget `mapstructure:"target"`
    }
    type SecretTarget struct {
        Env  string `mapstructure:"file"`   // (Env / File)
        File string `mapstructure:"file"`
    }

`pipeline/backend/kubernetes/secrets.go`:
- `secretReference(name)` returns `kube_core_v1.LocalObjectReference` →
  resolves ONLY in the pod's own namespace.
- `nativeSecretsProcessor.isEnabled()` returns `config.NativeSecretsAllowFromStep`,
  set from CLI flag `backend-k8s-allow-native-secrets`
  (`WOODPECKER_BACKEND_K8S_ALLOW_NATIVE_SECRETS`).
- Modes: simple (whole secret → envFrom), advanced (key → target.env),
  file (target.file → volume mount).

`pipeline/backend/kubernetes/kubernetes.go`:
- `config.Namespace` ← `backend-k8s-namespace`
- `config.EnableNamespacePerOrg` ← `backend-k8s-namespace-per-org`
- `GetNamespace(orgID)` → `<namespace>-<orgID>` when per-org enabled.
- `backend_options` has NO namespace field → a pipeline cannot choose its
  namespace.

CONSEQUENCE: enabling the flag lets ANY repo's pipeline mount ANY secret in the
build namespace. Finest k8s-side isolation available = per-ORG namespace.
A separate `ci` namespace does NOT work — LocalObjectReference is same-namespace.

## 2. Woodpecker DB secrets — repo + event + image scoped (server-enforced)

`server/model/secret.go`:

    type Secret struct {
        OrgID  int64
        RepoID int64
        Name   string
        Value  string
        Images []string       // only these step images may read it
        Events []WebhookEvent // only these events may read it
    }
    func (s Secret) IsGlobal() bool { return s.RepoID == 0 && s.OrgID == 0 }

Finer than any namespace scheme. `.woodpecker.yaml` cannot forge event/branch —
the forge sets them.

## 3. External secret extension — the GitLab+Vault analogue (KEY FINDING)

`cmd/server/flags.go`:
    WOODPECKER_SECRET_EXTENSION_ENDPOINT   ("secret-extension-endpoint")
    WOODPECKER_SECRET_EXTENSION_NETRC      ("secret-extension-netrc")
    WOODPECKER_EXTENSIONS_ALLOWED_HOSTS    ("extensions-allowed-hosts",
                                            default hostmatcher.MatchBuiltinExternal)

`server/services/setup.go`:
    if endpoint != "" {
        return secret.NewCombined(secret.NewDB(store), secret.NewHTTP(endpoint, client, includeNetrc))
    }
    return secret.NewDB(store)
→ extension is ADDITIVE to DB secrets; adoption can be incremental.

`server/services/secret/http.go`:
    type secretRequestStructure struct {
        Repo     *model.Repo     `json:"repo"`
        Pipeline *model.Pipeline `json:"pipeline"`
        Netrc    *model.Netrc    `json:"netrc,omitempty"`
    }
    type secretResponseStructure struct {
        Secrets []*model.Secret `json:"secrets"`
    }
POST per pipeline; 204 = no additional secrets; 200 = secret list.
Returned secrets carry their own Events/Images constraints.

`server/services/utils/http.go`:
- Requests signed with RFC-9421 HTTP Message Signatures via `github.com/yaronf/httpsign`,
  `httpsign.NewEd25519Signer(...)`, covering `@request-target` and `content-digest`.
- Verification key published by the instance:
      curl https://ci.example.com/api/signature/public-key
      -----BEGIN PUBLIC KEY-----
      MCowBQYDK2VwAyEAqy6P5owEoOz2Aq7ZbDBoVfyUk66bptDDc7sTWeZHEEg=
      -----END PUBLIC KEY-----

GOTCHA: `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` defaults to `MatchBuiltinExternal`,
which blocks private/internal addresses — an in-cluster broker
(`*.svc.cluster.local`) is rejected unless the flag is widened.

## 4. Identity model comparison

| GitLab + Vault                          | Woodpecker + broker                          |
|-----------------------------------------|----------------------------------------------|
| Job JWT with project/ref claims         | Signed request carrying repo + branch + event |
| Vault policy binds claims → secret paths| Broker maps (repo, branch, event) → secret set|
| Vault returns short-lived creds          | Broker returns per-pipeline values; never stored in Woodpecker DB |
| Repo declares the Vault role             | Repo declares NOTHING                         |

Woodpecker has no native Vault integration → Vault would still need a broker in
front. 1Password Connect already runs in-cluster; Connect tokens are vault-scoped.

## Open questions handed to deep research
- Existing OSS implementations of a Woodpecker secret extension?
- Any OIDC/JWT id-token support for pipelines (issue/PR status)?
- Does 1P Connect/Service Accounts support per-vault scoping + short-lived creds?
- Forgejo Actions (act_runner) OIDC support as an alternative?
- Prior art + maintenance experience for (repo, branch, event) → secret policy tables.

---

# Second source pass — 2026-07-11, adversarially verified

Facts below answered by parallel source-reading agents against the v3.15.0
tag, each finding re-checked by an independent verifier agent that re-fetched
every citation and attempted refutation. All items CONFIRMED unless noted.

## 5. Extension failure mode: FAIL-OPEN

`server/services/secret/combined.go`:

    extensionSecrets, err := c.extension.SecretListPipeline(ctx, repo, pipeline, netrc)
    if err != nil {
        // Log the error but don't fail - use base secrets only
        log.Warn().Err(err).Msg("failed to fetch secrets from extension")
        return baseSecrets, nil
    }

An unreachable or non-2xx extension is swallowed with a server-side warning;
the pipeline compiles and runs with DB-only secrets. No fail-closed flag
exists (`cmd/server/flags.go` checked — only `secret-extension-endpoint` and
`secret-extension-netrc`). The error branch in `server/pipeline/items.go
parsePipeline` is reachable only via DB failure.

Also found: `server/services/manager.go SecretServiceFromRepo` supports a
per-repo `repo.SecretExtensionEndpoint` override; it too is wrapped in
`NewCombined` — every extension route is fail-open.

CONSEQUENCE for ironbark: Woodpecker will not fail a pipeline when ironbark
is down or refuses (bad signature, stale). Steps then fail on missing
`from_secret` references (secret not found at compile), which is the actual
backstop — but a pipeline with no `from_secret` references and an implicit
dependency (e.g. only `vault_token` via env) would half-run. ironbark cannot
change this server-side; it is a documented property adopters must know.

## 6. `pipeline.Branch` per event type — NOT a uniform source-branch field

| Event | Branch contains | Source |
|---|---|---|
| push | source branch (`TrimPrefix(hook.Ref, "refs/heads/")`) | gitea/forgejo `helper.go pipelineFromPush` |
| pull_request, pull_request_closed | **TARGET/base branch** (`hook.PullRequest.Base.Ref`) — source branch only in `Refspec`/`Ref` | gitea+forgejo `helper.go pipelineFromPullRequest` |
| tag | **empty string** — never set (`Ref` = `refs/tags/<tag>`) | `pipelineFromTag` |
| release | release target branch (`hook.Release.Target`) | `pipelineFromRelease` |
| deployment | gitea/forgejo have NO deployment webhook parser; deploy = `PostPipeline` restart with `event=deploy` override, Branch **inherited unchanged** from the restarted pipeline (`server/pipeline/restart.go` mutates only Parent/RerunCount/Version) | `server/api/pipeline.go` |
| cron | `cron.Branch`, falling back to repo default branch | `server/cron/cron.go` |
| manual | **caller-supplied** `opts.Branch`, whatever the user requested | `server/api/pipeline.go createTmpPipeline` |

CONSEQUENCES for ironbark's convention:
- `event=pull_request, branch=main` means "PR *targeting* main" — every PR
  against main carries `branch=main`. Tiering MUST gate on event first;
  branch only meaningfully narrows `push` (and release/cron).
- `event=manual` Branch is user-chosen: a `manual/main` policy tier is
  grantable to anyone who can press "run pipeline" on the repo. Treat manual
  (and deploy, which inherits) as their own trust tiers, not as
  branch-verified.
- `tag` events have no branch at all; the convention needs a defined
  placeholder or must scope tag secrets at event level only.

## 7. `forge_remote_id` IS in the extension payload

`server/model/repo.go`:

    ForgeRemoteID ForgeRemoteID `json:"forge_remote_id" xorm:"UNIQUE(forge) forge_remote_id"`

No `omitempty`, no custom marshaller; `secretRequestStructure` carries
`Repo *model.Repo` (named field), so the payload has
`repo.forge_remote_id`. The `.identity` rename-binding proposal is viable.

## 8. RFC-9421 replay material: `created` yes, nonce/expires no

`server/services/utils/http.go`:

    signer, err := httpsign.NewEd25519Signer(ed25519Key, httpsign.NewSignConfig(),
        httpsign.Headers("@request-target", "content-digest"))

`yaronf/httpsign v0.5.1` (pinned) `NewSignConfig()` defaults `signCreated:
true` → every request carries a signed `created` (Unix time). No nonce, no
expires (defaults 0/empty, no setters called; verifier confirmed the emit
conditionals in the library's `signatures.go`). Library default
`NewVerifyConfig()`: `notNewerThan: 2s, notOlderThan: 10s`. Library doc:
"Without nonce validation, this is the only replay defense, signatures can
be replayed within the window."

CONSEQUENCE: ironbark MUST enforce a `created` freshness window (the
§11 DESIGN.md replay question is answered: timestamp yes, nonce no); exact
duplicates within the window are undetectable — mitigations are the window
size and TLS/network policy.

## 9. Secret names: no validation, case-insensitive matching, one precedence trap

- `model.Secret.Validate()` checks only non-empty Name/Value; extension
  response secrets are returned without any Validate call
  (`server/services/secret/http.go` → `return response.Secrets, nil`).
- `from_secret` matching lowercases BOTH sides
  (`compiler.secrets[strings.ToLower(secret.Name)]` in
  `pipeline/frontend/yaml/compiler/option.go`; `name = strings.ToLower(name)`
  in `convert.go`).
- TRAP (verifier-found): the combined-store dedup is **case-sensitive** on
  raw names, but the compiler map is lowercased last-write-wins with
  extension secrets inserted FIRST — so a DB secret differing only in case
  from an extension secret survives dedup and silently WINS in the compiler.
  CONSEQUENCE: ironbark must emit lowercase names so collisions are exact
  and extension priority (see §10) actually holds.

## 10. Combined-store merge: extension wins on exact name collision

`server/services/secret/combined.go SecretListPipeline`: build name-set from
extension secrets, append all extension secrets, then append only base (DB)
secrets whose name is not in the set — DB collisions silently dropped.
Only `SecretListPipeline` merges; all other Service methods delegate to base.

## 11. netrc payload = repo OWNER's forge OAuth token

`forge.Netrc(user, repo)` is called with the repo owner
(`_store.GetUser(repo.UserID)`, `server/pipeline/create.go`); the GitHub impl
sets `Login = u.AccessToken, Password = "x-oauth-basic",
Machine = <clone-URL host>`. Enabling `WOODPECKER_SECRET_EXTENSION_NETRC`
therefore sends the repo owner's forge OAuth access token to the extension
endpoint on every pipeline. CONSEQUENCE: ironbark documents "leave it off"
and ignores the field (already the design position; now with teeth).

## 12. Extension call cadence: once per pipeline lifecycle event, no caching

Exactly one production call site for `SecretListPipeline`
(`server/pipeline/items.go:52`, inside `parsePipeline`), confirmed exhaustive
by repo-wide grep of the v3.15.0 tarball. `parsePipeline` runs once per
`createPipelineItems`, which has exactly three callers:

- `server/pipeline/create.go:96` — pipeline creation
- `server/pipeline/approve.go:60` — approval of a gated pipeline
- `server/pipeline/restart.go:92` — restart (including deploy-via-restart)

Each is a fresh HTTP POST to the extension; no memoization anywhere in the
chain (`combined.go` re-invokes both stores live; `manager.go
SecretServiceFromRepo` constructs a fresh wrapper per call). One call covers
ALL workflows in the pipeline — multi-YAML pipelines still get exactly one
call, and every workflow shares the one secret set.

CONSEQUENCES for ironbark:
- One mint per create/approve/restart; restarts and approvals re-mint fresh
  tokens (good — no stale-token reuse), and a deploy-via-restart re-mints
  under the ORIGINAL pipeline's inherited Branch (§6).
- The minted token and swept values are shared across all workflows of the
  pipeline; TTL budgeting is per-pipeline, not per-workflow.
- Gated pipelines mint at approval time, not submission time — queue-delay
  TTL erosion starts at approve, which is the favourable case.

# Woodpecker secret mechanisms — facts read from v3.15.0 source (2026-07-11)

Deployed: Woodpecker appVersion 3.15.0 (chart woodpecker-3.6.4, `dev/woodpecker`
kit in the authors' internal infrastructure). Forge: Forgejo at forge.example.com. k8s backend, build namespace
`woodpecker-builds`.

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

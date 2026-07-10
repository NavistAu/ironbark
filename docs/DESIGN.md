# ironbark — design

> A [Woodpecker CI](https://woodpecker-ci.org) **secret extension** that
> federates pipeline identity to [Vault](https://developer.hashicorp.com/vault)
> or [OpenBao](https://openbao.org): for each pipeline it verifies Woodpecker's
> signed request, maps `(repo, branch, event)` to a policy, and mints a
> short-lived, narrowly-scoped Vault/OpenBao **token** — which it returns to the
> pipeline. It never reads a secret value itself.

Status: design. Nothing built yet.

## 1. Why this exists

Woodpecker has no pipeline-level identity token (no equivalent of GitHub
Actions' `id-token` or GitLab's `CI_JOB_JWT`), so a pipeline cannot present a
verifiable identity to a secrets manager and receive short-lived credentials.
(Confirmed against Woodpecker v3.15.0: issue #929 "Hashicorp vault as secret
storage integration" was closed *completed* by shipping the HTTP secret
extension — PR #6252 — not by adding Vault support. Upstream's answer to
"integrate Vault" is "write an extension.")

What Woodpecker *does* provide is the **secret extension**: on every pipeline the
server POSTs `{repo, pipeline}` to a configured HTTP endpoint, signed with
RFC-9421 HTTP Message Signatures (ed25519), and the endpoint returns the secrets
that pipeline may use. That server-signed payload — carrying repo full-name,
branch, event, commit — *is* the pipeline identity. ironbark is the endpoint
that turns it into a Vault/OpenBao credential.

### The metaphor

Woodpecker drills wood for grubs. Ironbark (*Eucalyptus* spp.) is a hardwood
whose dense, furrowed bark resists it. The broker is the bark: it decides, on a
per-peck basis, exactly how far in the woodpecker gets.

## 2. Core design decision: return a token, not a value

ironbark returns a Vault/OpenBao **token**, not secret values. This is the
single decision everything else follows from.

Vault token *roles* (`auth/token/roles/:role`) support `allowed_policies` /
`allowed_policies_glob`, documented as:

> "tokens can be created with any subset of the policies in this list, rather
> than the normal semantics of tokens being a subset of the calling token's
> policies"

So ironbark, holding a token that can *create* against role `ci-<repo>`, can mint
a child token bearing policy `widgets-plan` **without itself holding that
policy** — i.e. without any ability to read the secrets that policy grants. The
pipeline then talks to Vault directly with the minted token.

Consequences, each a reason this shape was chosen over a value-returning broker:

- **ironbark never sees a secret value.** No secret transits its memory, logs, or
  the extension response beyond the scoped token. A value-returning broker is a
  standing decryption oracle for everything it can read; ironbark is not.
- **Blast radius is bounded by construction.** ironbark compromised → attacker
  mints scoped, short-TTL tokens for the roles it can create against, nothing
  more. A pipeline's returned token leaked → that repo's policy set for the
  token's TTL (minutes), then dead.
- **Vault/OpenBao owns everything hard** — the policy→secret mapping, dynamic
  credential engines (e.g. AWS STS), audit log, TTL, revocation. ironbark owns
  only `(repo, branch, event) → token-role`.
- **Masking is partially recovered.** The token is delivered as a Woodpecker
  secret (`from_secret`), so Woodpecker masks it in logs. (Values the pipeline
  then fetches over HTTP are *not* masked — see §7.)

## 3. Decisions log

| Decision | Choice | Why |
|---|---|---|
| What the extension returns | A Vault/OpenBao **token** | Broker never reads secrets; token-role `allowed_policies` delegates without escalation; short TTL bounds leak |
| Target secrets managers | Vault **and** OpenBao | The mint path is one API call (`token create`), byte-identical between them; only the address differs |
| Identity source | Woodpecker's signed `{repo, pipeline}` payload | It is the only pipeline identity Woodpecker offers; forge sets `branch`/`event`, so a `.woodpecker.yaml` cannot forge them |
| Signature verification | Mandatory, RFC-9421 ed25519 against the instance public key | The one load-bearing control; skipping it turns any reachable host into a token minter (§6) |
| Implementation language | Go | RFC-9421 verification is error-prone in shell; official `woodpecker-ci/example-extensions` (Go) to fork for the transport half; a published security tool needs to be auditable |
| Policy expression | Config table `(repo, branch, event) → token-role (+ optional explicit policies/TTL)` | Onboarding a repo is config, not code; `allowed_policies_glob` lets convention (`ci-*` → `<repo>-*`) avoid per-repo edits |
| ironbark's own Vault auth | AppRole, minimal capability: `create` against the `ci-*` token roles only | Pod-identity, not pipeline-identity — the case ESO handles well; ironbark cannot read secrets or mint arbitrary policies |
| Scope | Woodpecker-first | Drone's extension protocol is an ancestor; Drone-compat is a possible later note, not a v1 goal |
| License | AGPL-3.0 | Deployed service; §13 network clause is the only thing that discourages closed SaaS reuse while keeping it OSS |

## 4. The Woodpecker secret-extension contract

Request (Woodpecker → ironbark), signed:

```json
{ "repo":     { "full_name": "acme/widgets", "private": true, ... },
  "pipeline": { "event": "push", "branch": "main", "commit": "…", ... },
  "netrc":    { ... }   // only if WOODPECKER_SECRET_EXTENSION_NETRC=true
}
```

Response (ironbark → Woodpecker):

```json
{ "secrets": [
    { "name": "vault_token", "value": "<minted token>",
      "events": ["push"], "images": ["forge.example.com/infra/iac-toolbox"] }
] }
```

`HTTP 204` = "no additional secrets" (leave Woodpecker's own DB secrets intact).
The service is *combined* with the DB store (`secret.NewCombined(NewDB, NewHTTP)`),
so extension secrets are additive and take priority; adoption is incremental.

Each returned secret carries its own `events`/`images` constraints — ironbark
SHOULD pin the token to the toolbox image and the event it was minted for, so a
later step running a different image cannot read it.

## 5. Policy model

A declarative table, ironbark's entire domain of authority:

```yaml
# ironbark policy (illustrative)
rules:
  - repo: acme/widgets
    match: { event: [pull_request, push] }      # any non-main work
    token_role: ci-widgets
    policies: [widgets-plan]                     # read-only CF + read-only state
    ttl: 15m
  - repo: acme/widgets
    match: { event: [push], branch: [main] }    # post-merge on protected main
    token_role: ci-widgets
    policies: [widgets-deploy]                   # read/write CF + dynamic AWS STS
    ttl: 15m
```

Notes:
- `branch`/`event` come from the *forge-set* payload, not the repo — a pipeline
  cannot claim `branch: main` from a feature branch.
- `token_role`'s `allowed_policies`/`allowed_policies_glob` in Vault is the
  backstop: even a bug in ironbark's table cannot grant a policy the role
  disallows.
- Convention option: one role `ci-*` with `allowed_policies_glob: "<repo>-*"`
  makes onboarding a new repo a Vault policy file, no ironbark change.

## 6. Signature verification is load-bearing

This is the one part that cannot be thin.

- Woodpecker signs each request with ed25519 over `@request-target` and
  `content-digest` (RFC-9421 / `github.com/yaronf/httpsign`). The instance
  publishes its verification key at `GET /api/signature/public-key`.
- ironbark MUST verify the signature and the content digest before acting on any
  payload. An unverified payload is attacker-controlled: without the check, any
  host that can reach ironbark can POST `{repo: "…/widgets", branch: "main",
  event: "push"}` and be handed a deploy token.
- The verification public key is configured out-of-band (not trusted from the
  request). Key rotation = config update.
- Defence in depth: `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` on the Woodpecker side
  restricts which hosts the server will call; network policy restricts who can
  reach ironbark. Neither substitutes for the signature check.

A published tool that got this wrong would widen *adopters'* blast radius, so it
gets tests that assert: unsigned → refused; wrong key → refused; tampered digest
→ refused; replayed/stale → refused (bounded by digest+target scope; consider a
freshness window if the payload carries a timestamp).

## 7. Security model / threat model

| Threat | Outcome |
|---|---|
| ironbark process compromised | Mints scoped, short-TTL tokens for `ci-*` roles only. Cannot read secrets; cannot mint disallowed policies (Vault role backstop). |
| A repo's returned `vault_token` leaked in logs | That repo's policy set, for the token TTL (minutes), then expires. Woodpecker masks the token (`from_secret`); downstream fetched *values* are NOT masked. |
| Malicious `.woodpecker.yaml` (PR from a branch) | Cannot forge `branch`/`event` (forge-set); policy table gates PR events to the read-only tier. Deploy tier requires `event=push, branch=main`, which a PR pipeline structurally is not. |
| ironbark's AppRole `secret_id` leaked (from k8s) | Can request token creation against `ci-*` roles = same as ironbark compromise. Bounded to token-create capability; no secret read, no policy escalation. ESO-managed, rotatable. |
| Spoofed request to ironbark | Refused at signature verification (§6). |

Honest limits stated up front:
- **Cloudflare has no STS.** The CF API token is a static value in Vault KV;
  Vault buys rotation + audit there, not ephemerality. AWS state-backend creds
  *are* dynamic (Vault AWS secrets engine → STS), which is the real upgrade.
- **AppRole is a bootstrap credential, not attestation.** ironbark authenticating
  to Vault is pod-identity; the pipeline identity attestation is Woodpecker's
  signature, which ironbark trusts transitively. There is no cryptographic chain
  from the git commit to the Vault token beyond Woodpecker's signing key.
- **Runtime-fetched values lose Woodpecker's log masking.** The token is masked;
  values fetched with it are not. Pipelines must `set +x`, avoid echoing, and use
  `-no-color`; this is a real tradeoff against the value-returning alternative.

## 8. Non-goals

- Not a secrets store. Vault/OpenBao is the store; ironbark is a federation seam.
- Not a Vault replacement or a policy engine — the policy *table* is a routing
  map, not an ACL system; Vault enforces the actual ACLs.
- Not multi-CI in v1. Woodpecker-first. (Drone protocol kinship noted, not
  promised.)
- Not an OIDC issuer. If Woodpecker ever ships pipeline id-tokens, ironbark's
  reason to exist shrinks to policy-routing and it should be reconsidered.

## 9. Deployment shape

- Container image, small Go binary. Runs as a k8s Deployment.
- Its AppRole `role_id`/`secret_id` supplied by ESO from the estate's secrets
  manager (pod-identity — ESO's sweet spot).
- Config: the policy table (ConfigMap), the Woodpecker verification public key,
  the Vault/OpenBao address.
- Woodpecker server: `WOODPECKER_SECRET_EXTENSION_ENDPOINT` → ironbark's service
  URL; `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` widened to permit it (the default
  `MatchBuiltinExternal` blocks in-cluster/private addresses — a known gotcha).

## 10. Staged delivery

The broker is an *enhancement*, not a prerequisite. The value ladder:

1. Vault/OpenBao deployed → estate-wide value, no CI dependency.
2. A consuming repo holds a Woodpecker repo-secret AppRole and calls Vault
   directly → dynamic-cred CI with **no ironbark**, no new service to maintain.
3. ironbark replaces the static per-repo AppRole with signature-verified identity
   federation → "the repo declares nothing," central policy, added later.

ironbark's own repo bootstraps on stage 2 (its image build needs only a registry
token, not Vault) — no circular dependency.

## 11. Open questions

- Freshness/replay: does the signed payload carry a timestamp or nonce ironbark
  can bound? (Confirm against the Woodpecker signing implementation.)
- Token use-limit vs TTL: cap uses (`num_uses`) as well as TTL?
- Whether to emit an audit line per mint (repo, branch, event, role, TTL) in
  addition to Vault's own audit — useful when correlating a CI run to a Vault
  token.
- Publishing home: mirror from the private forge to a public one; which.

# ironbark — design

> A [Woodpecker CI](https://woodpecker-ci.org) **secret extension** that
> federates pipeline identity to [Vault](https://developer.hashicorp.com/vault)
> or [OpenBao](https://openbao.org): for each pipeline it verifies Woodpecker's
> signed request, derives the pipeline's entitlements **by convention** from
> the forge-set `(repo, event, branch)`, mints a short-lived scoped token, and
> uses that token — the pipeline's own — to sweep a conventional KV subtree,
> returning the values as ordinary **masked Woodpecker secrets** plus the
> token itself. ironbark is stateless: no rule tables, no path maps, no
> standing read credential.

Status: design. Nothing built yet.

Revision note: this document supersedes the 2026-07-10 token-only,
config-table design (see git history). The changes are recorded in
[`docs/decisionlog/`](decisionlog/) as DEC-0001 … DEC-0005.

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
full-name, branch, event, commit — *is* the pipeline identity. ironbark is the
endpoint that turns it into Vault/OpenBao-backed secrets.

### The metaphor

Woodpecker drills wood for grubs. Ironbark (*Eucalyptus* spp.) is a hardwood
whose dense, furrowed bark resists it. The broker is the bark: it decides, on a
per-peck basis, exactly how far in the woodpecker gets.

## 2. Core design: stateless convention broker

Two decisions define the shape:

**It returns masked values *and* a scoped token** (DEC-0001). Woodpecker's
extension-returned secrets are native secrets — automatically masked in logs,
addressable via `from_secret`, pinnable per-secret to events and images. So
ironbark mints the pipeline's token, then *uses that token itself* to read the
pipeline's conventional KV subtree and returns the values through the
extension response, plus the token (`vault_token`) as the escape hatch for
interactive uses. No standing read credential exists anywhere: ironbark's own
Vault identity can only create tokens; every read happens under a
per-pipeline, policy-scoped, short-TTL token.

**It is stateless** (DEC-0002). No rule table, no path maps. Everything is
derived from the signed payload by fixed convention; *which* policies and
secrets exist is Vault-side data. Onboarding a repo touches only Vault.
(A constraint forces this shape: the extension request carries only
`{repo, pipeline}` — Woodpecker never sends the `.woodpecker.yaml` or the
secret names a pipeline references, so job configuration *cannot* declare
fetch lists to ironbark. And Vault policies are not enumerable from a token,
so "return everything this token can read" is impossible; a conventional
location is the only stateless way to know what to fetch.)

### Request flow

1. **Verify** the RFC-9421 ed25519 signature and content digest against the
   configured Woodpecker public key. Refuse otherwise (§6).
2. **Extract identity** from the forge-set payload: `org`/`repo` from
   `repo.full_name`, `event` and `branch` from the pipeline.
3. **Derive conventional policy names**, e.g. `ci/<org>/<repo>/<event>` and
   `ci/<org>/<repo>/<event>/<branch>` (encoding: §5). Request all of them
   unconditionally — attaching a nonexistent policy grants nothing, so which
   tiers exist is decided entirely by which policies the admin created.
4. **Mint** a child token against a single token-role (working name `ci`)
   whose `allowed_policies_glob` backstops the grantable set; TTL from the
   role's `token_ttl`.
5. **Sweep** the conventional KV v2 subtree `kv/ci/<org>/<repo>/…` with the
   minted token (§5), tolerating partial denials — the 403s *are* the tiering
   mechanism.
6. **Dereference pointer entries** (`$ref`, DEC-0003) with the same token;
   policy gates every deref; denied pointers are skipped.
7. **Respond** with each value as a Woodpecker secret (masked), events pinned
   to the minting event, plus `vault_token`.
8. **Token lifecycle**: the token is returned to the pipeline and its TTL must
   cover queue + runtime; dereference leases parent to it, so ironbark never
   revokes after fetch. Expiry is the cleanup.

### Why token-role minting still matters

Vault token *roles* (`auth/token/roles/:role`) support `allowed_policies` /
`allowed_policies_glob`, documented as:

> "tokens can be created with any subset of the policies in this list, rather
> than the normal semantics of tokens being a subset of the calling token's
> policies"

So ironbark, holding only `create` against the role, mints tokens bearing
policies **it does not itself hold**. The role's glob is a backstop
independent of ironbark's code: even a bug cannot mint a policy outside the
conventional namespace.

## 3. Security model — the honest version

An earlier revision framed the token design as oracle/no-oracle. That
overstated it: **ironbark's token-create capability is transitive read
capability for an active attacker** — mint a token bearing the target policy,
read with it. Compromising ironbark exposes the union of policies the `ci`
role can grant, i.e. the CI secret estate — the same as any broker. What the
design actually buys, versus a broker with a standing read credential:

- **No standing read credential exists** — at rest, in config, or in ESO.
  There is nothing to steal that reads silently.
- **Every attacker read requires a mint**, which Vault audit-logs per-role
  with metadata. Loud, not silent.
- **Values never rest in ironbark** — they transit memory transiently per
  pipeline, are never logged, never stored.
- **The role glob backstops** the maximum grantable policy set regardless of
  ironbark bugs.
- **Short TTLs bound every leaked artifact** — tokens and dynamic creds
  expire in minutes.

These are hardening and auditability properties, not a categorical boundary;
the design accepts that trade openly (DEC-0001).

### Threat table

| Threat | Outcome |
|---|---|
| ironbark process compromised | Attacker mints tokens for conventionally-named policies and reads with them — the CI secret estate, bounded by the role glob. No silent path: every read chain starts with an audited mint. |
| A returned secret value leaked via CI logs | Masked by Woodpecker (extension secrets are native secrets). Residual: values written to artifacts or exfiltrated deliberately — masking is a log control, not DLP. |
| `vault_token` leaked | That pipeline's policy set for the remaining TTL, then dead. Masked in logs. |
| Malicious `.woodpecker.yaml` (PR branch) | Cannot forge `branch`/`event` (forge-set); PR-tier policies gate what the sweep can see; deploy tier requires `event=push, branch=main`, which a PR pipeline structurally is not. The yaml has no channel to request anything from ironbark at all. |
| Someone with KV-subtree write access plants a `$ref` at a privileged path | Deref happens under the pipeline's own token → 403, skipped. Pointers are convenience, not authority. |
| ironbark's AppRole `secret_id` leaked | Equivalent to ironbark compromise; same bounds. ESO-managed, rotatable. |
| Spoofed request to ironbark | Refused at signature verification (§6). |
| Repo renamed / deleted-and-recreated under the same name | Convention keys on `full_name`, so a new repo inherits the old name's subtree. Mitigation proposed: `.identity` binding (§5, open). |

### Honest limits

- **Anything fetched via `vault_token` directly is not masked.** The masked
  path now covers conventional KV values and dereferenced dynamic creds; the
  escape hatch remains curl territory (`set +x`, no echoing, `-no-color`).
- **Cloudflare has no STS.** The CF API token is a static value in KV; Vault
  buys rotation + audit there, not ephemerality. AWS state-backend creds *are*
  dynamic (Vault AWS engine → STS), now deliverable masked via pointer.
- **AppRole is a bootstrap credential, not attestation.** The pipeline
  identity attestation is Woodpecker's signature, trusted transitively. No
  cryptographic chain from git commit to Vault token beyond Woodpecker's
  signing key (see research note, §12).
- **TTL starts at mint (pipeline compile time).** A pipeline that queues 20
  minutes arrives with 20 minutes less credential. TTL guidance must budget
  queue + runtime — a documentation obligation (§13).

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
    { "name": "cf_api_token",       "value": "…", "events": ["push"],
      "images": ["forge.example.com/infra/iac-toolbox"] },
    { "name": "aws_access_key",     "value": "…", "events": ["push"] },
    { "name": "aws_secret_key",     "value": "…", "events": ["push"] },
    { "name": "aws_security_token", "value": "…", "events": ["push"] },
    { "name": "vault_token",        "value": "…", "events": ["push"] }
] }
```

`HTTP 204` = "no additional secrets" (an un-onboarded repo's sweep finds
nothing → 204; Woodpecker's own DB secrets remain intact). The service is
*combined* with the DB store (`secret.NewCombined(NewDB, NewHTTP)`), so
extension secrets are additive and take priority; adoption is incremental.

ironbark ignores the `netrc` field; deployments should leave
`WOODPECKER_SECRET_EXTENSION_NETRC` off.

## 5. The convention

ironbark's entire domain of authority is a naming convention. Illustrative
(exact encodings are M1 build territory — see open questions):

**Policy names** — `ci/<org>/<repo>/<event>` and
`ci/<org>/<repo>/<event>/<branch>`. Which exist is the admin's tiering
decision, e.g. for widgets: `ci/acme/widgets/pull_request` (plan tier)
and `ci/acme/widgets/push/main` (deploy tier). Policies grant
`read` on `kv/data/ci/<org>/<repo>/<tier-scope>` and `list` on the
corresponding `kv/metadata/…` paths (KV v2 splits data/metadata).

**KV layout mirrors the policy tiers** — this is load-bearing: the sweep
reads what the token can see, so tiering only works if tiers are separate
path prefixes:

```
kv/ci/<org>/<repo>/<key>                      # all events, all branches
kv/ci/<org>/<repo>/<event>/<key>              # event-scoped
kv/ci/<org>/<repo>/<event>/<branch>/<key>     # branch-scoped (main = prod)
```

**Sweep algorithm** — LIST `kv/metadata/ci/<org>/<repo>/`; read plain
entries; descend *only* into `<event>/`, then only into `<branch-escaped>/`.
Tolerate 403/404 at every level (partial visibility is the mechanism —
never fail the response on a denied subtree). Entries whose name begins with
`.` are ironbark directives, never returned as secrets.

**Pointer entries** (DEC-0003) — an entry valued
`{"$ref": "aws/creds/widgets-deploy"}` is dereferenced with the minted token;
multi-field results flatten as `<entry>_<field>`.

**Branch/name encoding must be injective.** Branch names are
attacker-chosen strings containing `-` and `/`; naive concatenation lets
`(repo=a, branch=b-x)` collide with `(repo=a-b, branch=x)` constructions.
Fixed field order plus a reversible escape (percent-encoding the branch into
a single path segment is the working candidate) — and the DEC-0004 IaC module
generates all names, so humans never hand-write them.

**Proposed, not yet decided:**

- **Per-secret pins via KV v2 `custom_metadata`** — e.g.
  `images: forge.example.com/infra/iac-toolbox` on an entry becomes the returned
  secret's `images` constraint. Replaces the old config-table pinning;
  stays in Vault, stays stateless. Costs one metadata read per entry.
- **`.identity` binding** — a reserved entry recording the forge's stable
  repo ID (`repo.forge_remote_id`); ironbark refuses when the payload's ID
  mismatches. Closes the rename/recreate inheritance hole with a forge-set
  verifiable value (a "salt" has no transport channel in the protocol — the
  payload is entirely forge/server-set). Written by the IaC module at
  onboarding; a rename is a deliberate re-onboard.
- **`.config` directives** — repo-level opts, e.g. suppressing the
  `vault_token` secret for repos that never need the escape hatch (which
  also re-enables revoke-after-response when no leases exist).

## 6. Signature verification is load-bearing

This is the one part that cannot be thin.

- Woodpecker signs each request with ed25519 over `@request-target` and
  `content-digest` (RFC-9421 / `github.com/yaronf/httpsign`). The instance
  publishes its verification key at `GET /api/signature/public-key`.
- ironbark MUST verify the signature and the content digest before acting on
  any payload. An unverified payload is attacker-controlled: without the
  check, any host that can reach ironbark can POST
  `{repo: "…/widgets", branch: "main", event: "push"}` and be handed deploy
  credentials.
- The verification public key is configured out-of-band (not trusted from the
  request). Key rotation = config update.
- Defence in depth: `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` on the Woodpecker
  side restricts which hosts the server will call; network policy restricts
  who can reach ironbark. Neither substitutes for the signature check.

A published tool that got this wrong would widen *adopters'* blast radius, so
it gets tests that assert: unsigned → refused; wrong key → refused; tampered
digest → refused; replayed/stale → refused (bounded by digest+target scope;
freshness window pending the replay investigation, §13).

## 7. Non-goals

- Not a secrets store. Vault/OpenBao is the store; ironbark is a federation
  seam.
- Not a policy engine — ironbark carries no rules at all (DEC-0002); Vault
  enforces the ACLs and the convention names them.
- No GUI (DEC-0004). IaC is a form of UI; UI is not GUI. The control surface
  is the Terraform/OpenTofu module plus `ironbark doctor`.
- Not multi-CI in v1. Woodpecker-first. (Drone protocol kinship noted, not
  promised.)
- Not an OIDC issuer. If Woodpecker ever ships pipeline id-tokens, ironbark's
  reason to exist shrinks and it should be reconsidered.

## 8. Deployment shape

- Container image, small Go binary, k8s Deployment. Stateless — nothing to
  back up; replicas are trivial.
- Config, in full: Woodpecker verification public key; Vault/OpenBao address;
  its own AppRole `role_id`/`secret_id` (supplied by ESO — pod-identity,
  ESO's sweet spot); convention template overrides (optional); listen
  address.
- ironbark's AppRole grants exactly: `create` against the `ci` token role.
  Nothing else — no KV read, no policy read. (Sweep reads happen under the
  minted pipeline token, not the AppRole token.)
- Woodpecker server: `WOODPECKER_SECRET_EXTENSION_ENDPOINT` → ironbark's
  service URL; `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` widened to permit it
  (the default `MatchBuiltinExternal` blocks in-cluster/private addresses — a
  known gotcha). `WOODPECKER_SECRET_EXTENSION_NETRC` left off.

## 9. Staged delivery

The broker is an *enhancement*, not a prerequisite. The value ladder:

1. Vault/OpenBao deployed → estate-wide value, no CI dependency.
2. A consuming repo holds a Woodpecker repo-secret AppRole and calls Vault
   directly → dynamic-cred CI with **no ironbark**, no new service to
   maintain.
3. ironbark replaces the static per-repo AppRole with signature-verified
   identity federation → "the repo declares nothing," central policy, added
   later.

ironbark's own repo bootstraps on stage 2 (its image build needs only a
registry token, not Vault) — no circular dependency.

Related project split (recorded in the widgets design session, 2026-07-10):
ironbark is a generic, publishable project; the example.com-internal specs for
standing up Vault/OpenBao and for wiring vault+ironbark+Woodpecker live
elsewhere and consume ironbark's generic artifacts.

## 10. Milestones

**M1 — the broker.** Verify → derive → mint → sweep → deref → respond.
Signature test matrix (§6). Integration tests against real Vault *and*
OpenBao (containerized), with a fake-Woodpecker signing harness. Encoding
and naming conventions locked by end of M1 iteration (expected to evolve
during build — accepted 2026-07-11).

**M2 — the control surface** (DEC-0004). Generic `ironbark-repo`
Terraform/OpenTofu module (policies, KV skeleton, pointer entries,
`.identity` binding) shipping in this repo; `ironbark doctor` read-only
convention lint (separate admin-ish credential at invocation).

## 11. Decisions

Current decisions live in [`docs/decisionlog/`](decisionlog/) (MADR):

| ID | Decision |
|---|---|
| DEC-0001 | Return masked values (KV sweep under the minted token) *plus* the scoped token — supersedes the token-only response |
| DEC-0002 | Stateless: convention over Vault; no rule tables or path maps; yaml-declared fetch lists are protocol-impossible |
| DEC-0003 | `$ref` pointer entries dereference dynamic engines into the masked path |
| DEC-0004 | Control surface = IaC module + `ironbark doctor`; no GUI |
| DEC-0005 | Custom Vault auth-method plugin: research note only, with revisit trigger |

Earlier decisions still standing from the 2026-07-10 revision: Go
implementation (fork `woodpecker-ci/example-extensions` for the transport
half); Vault **and** OpenBao as targets; mandatory RFC-9421 verification;
AppRole via ESO for ironbark's own auth; Woodpecker-first scope; AGPL-3.0.

## 12. Research notes

**Custom Vault auth-method plugin** (DEC-0005). ironbark forwards the
Woodpecker-signed request into Vault; a plugin verifies the ed25519 signature
inside Vault's trust boundary and issues the token natively. Buys: a
cryptographic chain from Woodpecker's signing key into Vault's audit log;
structured route config instead of convention-encoded policy names. Costs:
binary plugin build/registration version-matched against both Vault and
OpenBao (plugin APIs drifting apart post-fork); managed Vault offerings
disallow custom plugins; sharply narrows adoption of a published tool.
**Revisit trigger:** the convention encoding proves too brittle in practice.

## 13. Open questions

Verification items (source reads against Woodpecker, per the standard set in
`woodpecker-secret-mechanisms.md`):

- **Fail posture** — when the extension returns non-2xx, does Woodpecker
  fail the pipeline or proceed with DB secrets only? Load-bearing: decides
  whether an ironbark outage/DoS fails closed. Could force a design change.
- **`pipeline.Branch` semantics per event type** — source vs target branch
  on `pull_request`; what `tag`, `deployment`, `cron`, `manual` carry. The
  convention's branch tier depends on this.
- **Payload fields** — confirm `repo.forge_remote_id` is present in the
  extension payload (needed for the `.identity` binding).
- **Replay/freshness** — does Woodpecker's RFC-9421 signature include the
  `created` parameter (httpsign default?); pick a freshness window
  accordingly.

Design/parity items:

- **OpenBao parity check** for every feature leaned on: token-role
  `allowed_policies_glob`, KV v2 `custom_metadata`, `+` policy-path
  wildcards, policy-name charset (also determines whether `/` in policy
  names is legal, else fall back to a flat escaped encoding).
- **Role strategy** — single glob role `ci` (M1 working choice) vs per-repo
  roles stamped by the IaC module (stronger per-repo backstop). Revisit at
  M2.
- **`num_uses`** — a use-capped token conflicts with ironbark's own sweep
  reads and with returning the token; likely uncapped + short TTL. Confirm.
- **Name normalization** — Woodpecker secret-name charset/case rules; KV
  key → secret-name mapping; collision with DB secrets (extension wins —
  document as intentional). Expected to evolve during M1 build; lock before
  v1 (accepted 2026-07-11).

Operational items:

- **TTL guidance** — documentation must state the queue+runtime budgeting
  rule and the lease-parenting consequence (no revoke when derefs occur).
- **Per-mint audit line** — emit `(repo, branch, event, policies, TTL)` per
  mint in addition to Vault's audit; format TBD.
- **Rate limiting** — whether to bound mint rate per repo/instance.
- **Health/readiness/metrics** — endpoints and what readiness means (Vault
  reachable? role present?).
- **Publishing home** — mirror from the private forge to a public one;
  which.

Proposed-pending-acceptance (see §5): `custom_metadata` pins, `.identity`
binding, `.config` directives.

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

Status: M1 (the broker) is implemented — see [`SPEC.md`](SPEC.md) for the
accepted, normative interface/behavior spec. This document covers
architecture, rationale, and threat model; where the two overlap, SPEC
governs.

Revision note: this document supersedes the 2026-07-10 token-only,
config-table design (see git history). The changes are recorded in
[`docs/decisionlog/`](decisionlog/) as DEC-260711061322 … DEC-260711061325
(a fifth item from that batch, the custom Vault auth-method plugin, is
recorded as a research note below rather than as a decision).

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

**It returns masked values *and* a scoped token** (DEC-260711061322). Woodpecker's
extension-returned secrets are native secrets — automatically masked in logs,
addressable via `from_secret`, pinnable per-secret to events and images. So
ironbark mints the pipeline's token, then *uses that token itself* to read the
pipeline's conventional KV subtree and returns the values through the
extension response, plus the token (`vault_token`) as the escape hatch for
interactive uses. No standing read credential exists anywhere: ironbark's own
Vault identity can only create tokens; every read happens under a
per-pipeline, policy-scoped, short-TTL token.

**It is stateless** (DEC-260711061323). No rule table, no path maps. Everything is
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
   `ci/<org>/<repo>/<event>/<branch>` (encoding: §5; always lowercase —
   Vault normalizes policy names to lowercase anyway). Request all of them
   unconditionally and **always explicitly** — attaching a nonexistent
   policy mints fine with a warning and grants nothing (source-confirmed,
   research §7.1), so which tiers exist is decided entirely by which
   policies the admin created. (An *empty* policy request falls back to the
   role's literal `allowed_policies` list — never send one.)
4. **Mint** a child token against a single token-role (working name `ci`)
   with `token_type=service` **forced on the role** — service, not batch,
   is a hard requirement: batch-token leases parent to the batch's parent,
   which would bind pipeline STS leases to ironbark's own AppRole token.
   The role's `allowed_policies_glob` bounds the grantable set — and note
   it is availability-critical, not just a backstop: a requested policy
   outside the glob ERRORS the whole mint rather than being filtered
   (research §7.6). TTL from the role's `token_ttl`. Expect and swallow the
   per-mint "Policy %q does not exist" warnings (surface them in the audit
   line, not as errors).
5. **Sweep** the conventional KV v2 subtree `kv/ci/<org>/<repo>/…` with the
   minted token (§5), tolerating partial denials — the 403s *are* the tiering
   mechanism.
6. **Dereference pointer entries** (`$ref`, DEC-260711061324) with the same token;
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
the design accepts that trade openly (DEC-260711061322).

### Threat table

| Threat | Outcome |
|---|---|
| ironbark process compromised | Attacker mints tokens for conventionally-named policies and reads with them — the CI secret estate, bounded by the role glob. No silent path: every read chain starts with an audited mint. |
| A returned secret value leaked via CI logs | Masked by Woodpecker (extension secrets are native secrets). Residual: values written to artifacts or exfiltrated deliberately — masking is a log control, not DLP. |
| `vault_token` leaked | That pipeline's policy set for the remaining TTL, then dead. Masked in logs. |
| Malicious `.woodpecker.yaml` (PR branch) | Cannot forge `branch`/`event` (forge-set); PR-tier policies gate what the sweep can see; deploy tier requires `event=push, branch=main`, which a PR pipeline structurally is not. The yaml has no channel to request anything from ironbark at all. |
| Someone with KV-subtree write access plants a `$ref` at a privileged path | Deref happens under the pipeline's own token → 403, skipped. Pointers are convenience, not authority. |
| ironbark's AppRole `secret_id` leaked | Equivalent to ironbark compromise; same bounds. ESO-managed, rotatable. |
| Compromised ironbark attempts `root` escalation | Impossible: the root-policy guard survives token roles — a `root`-bearing token cannot be minted unless the *parent* token holds root, which ironbark's AppRole never does (source-verified, research §7.6). |
| Spoofed request to ironbark | Refused at signature verification (§6). |
| Replayed request within the freshness window | Woodpecker signs a `created` timestamp but no nonce (mechanisms §8); ironbark MUST enforce a `created` window, and exact duplicates inside it are undetectable — bounded by window size, TLS, and network policy. Effect of a replay: a duplicate mint for the same identity, not an identity change. |
| `event=manual` pipeline claims `branch=main` | Real: manual-event Branch is caller-supplied (mechanisms §6). The convention must treat `manual` (and `deploy`, which inherits Branch from the restarted pipeline) as their own trust tiers — grantable to anyone with run-pipeline access — never as branch-verified. |
| Attacker pushes a branch literally named `Main` (or other case variant of a protected branch) | Would reach the protected branch's tier if branch names were case-folded. Prevented: the convention never case-folds branches; case is preserved injectively through the escape encoding (SPEC §2.2, found in cross-AI review cycle 2). |
| ironbark down / DoS'd | Woodpecker is fail-open (mechanisms §5): pipelines run with DB-only secrets and a server-side warning. Steps referencing missing `from_secret` fail at compile — the actual backstop. Pipelines depending only implicitly on extension secrets half-run. Not changeable from ironbark; documented loudly for adopters. |
| Repo renamed / deleted-and-recreated under the same name | Convention keys on `full_name`, so a new repo inherits the old name's subtree. Mitigation proposed: `.identity` binding against `repo.forge_remote_id`, which is confirmed present in the payload (mechanisms §7). |

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
      "images": ["registry.example.com/infra/toolbox"] },
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

**Pointer entries** (DEC-260711061324) — an entry valued
`{"$ref": "aws/creds/widgets-deploy"}` is dereferenced with the minted token;
multi-field results flatten as `<entry>_<field>`.

**Branch/name encoding must be injective.** Branch names are
attacker-chosen strings containing `-` and `/`; naive concatenation lets
`(repo=a, branch=b-x)` collide with `(repo=a-b, branch=x)` constructions.
Fixed field order plus a reversible escape (percent-encoding the branch into
a single path segment is the working candidate) — and the DEC-260711061325 IaC module
generates all names, so humans never hand-write them. `/` itself is legal in
policy names (route regex `.+`, both products) but `/`-named policies do not
appear in a flat `LIST sys/policies/acl` — a doctor concern, not a blocker.

**Lowercase everywhere — except the branch, which is case-PRESERVED.**
Vault lowercases policy names on every read/write, and Woodpecker's
`from_secret` matching lowercases both sides while its store-merge dedup is
case-sensitive (mechanisms §9) — so ironbark derives lowercase policy names
and emits lowercase secret names. Org/repo/event are case-folded (forges
enforce case-insensitive owner/repo uniqueness; the IaC module and doctor
flag collisions). The branch is NOT case-folded: git refs are
case-sensitive and branch protection binds to the exact name, so folding
would collapse an attacker's branch `Main` onto protected `main`'s tier.
Instead the escape encoding percent-encodes uppercase bytes (`Main` →
`%4dain`) — output stays lowercase, distinctness survives (SPEC §2.2).

**Event-tier facts the convention must encode** (from mechanisms §6):
- `pull_request` Branch is the TARGET branch — every PR against main carries
  `branch=main`. Tiering gates on event first; branch only meaningfully
  narrows `push` (and `release`/`cron`).
- `tag` events carry no branch at all — tag secrets scope at event level.
- `manual` Branch is caller-supplied and `deploy` inherits it from the
  restarted pipeline — both are their own trust tiers ("anyone with
  run-pipeline access"), never branch-verified.

**Conventional policies are additive-only** — no `deny` stanzas. ACL
precedence is most-specific-wins regardless of allow/deny (research §7.3),
which is subtle enough that the convention simply refuses to depend on it.

**The role glob must cover the convention's whole output space.** A
requested policy outside `allowed_policies_glob` errors the mint outright
(research §7.6) — the glob (e.g. `ci/*`) is load-bearing for availability.
Doctor check: convention templates ⊆ role glob.

**Accepted 2026-07-11 (DEC-260711114101; specified in SPEC.md §4.4–§4.6):**

- **Per-secret pins via KV v2 `custom_metadata`** — e.g.
  `images: registry.example.com/infra/toolbox` on an entry becomes the returned
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
- Not a policy engine — ironbark carries no rules at all (DEC-260711061323); Vault
  enforces the ACLs and the convention names them.
- No GUI (DEC-260711061325). IaC is a form of UI; UI is not GUI. The control surface
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

Related project split: ironbark is a generic, publishable project; the
specs for standing up Vault/OpenBao and for wiring vault+ironbark+Woodpecker
in the authors' own deployment live in the authors' internal infrastructure
and consume ironbark's generic artifacts.

## 10. Milestones

**M1 — the broker.** Verify → derive → mint → sweep → deref → respond.
Signature test matrix (§6). Integration tests against real Vault *and*
OpenBao (containerized), with a fake-Woodpecker signing harness. Encoding
and naming conventions locked by end of M1 iteration (expected to evolve
during build — accepted 2026-07-11).

**M2 — the control surface** (DEC-260711061325). Generic `ironbark-repo`
Terraform/OpenTofu module (policies, KV skeleton, pointer entries,
`.identity` binding) shipping in this repo; `ironbark doctor` read-only
convention lint (separate admin-ish credential at invocation).

## 11. Decisions

Current decisions live in [`docs/decisionlog/`](decisionlog/) (MADR):

| ID | Decision |
|---|---|
| DEC-260711061322 | Return masked values (KV sweep under the minted token) *plus* the scoped token — supersedes the token-only response |
| DEC-260711061323 | Stateless: convention over Vault; no rule tables or path maps; yaml-declared fetch lists are protocol-impossible |
| DEC-260711061324 | `$ref` pointer entries dereference dynamic engines into the masked path |
| DEC-260711061325 | Control surface = IaC module + `ironbark doctor`; no GUI |
| DEC-260711114101 | Convention directives graduated: `.identity`, `.config`, custom_metadata pins |
| DEC-260711114102 | Minted-token lifecycle: orphan non-renewable service tokens, canary-gated |
| DEC-260711114103 | Identity encoding: branch case preserved injectively; event-tier mapping |
| DEC-260711114104 | Sweep/response semantics: independent tiers, specific-wins, string-only |
| DEC-260711114105 | M1 runtime surface: 10s freshness, env-only config, dual audit shapes |

Earlier decisions still standing from the 2026-07-10 revision: Go
implementation (fork `woodpecker-ci/example-extensions` for the transport
half); Vault **and** OpenBao as targets; mandatory RFC-9421 verification;
AppRole via ESO for ironbark's own auth; Woodpecker-first scope; AGPL-3.0.

## 12. Research notes

**Custom Vault auth-method plugin.** ironbark forwards the
Woodpecker-signed request into Vault; a plugin verifies the ed25519 signature
inside Vault's trust boundary and issues the token natively. Buys: a
cryptographic chain from Woodpecker's signing key into Vault's audit log;
structured route config instead of convention-encoded policy names. Costs:
binary plugin build/registration version-matched against both Vault and
OpenBao (plugin APIs drifting apart post-fork); managed Vault offerings
disallow custom plugins; sharply narrows adoption of a published tool. Not
roadmapped: stock-Vault/OpenBao compatibility stays intact, at the cost of a
weaker audit chain meanwhile — Vault's audit log records ironbark's mint,
not Woodpecker's signature; that trust is attested only in ironbark's own
logs. **Revisit trigger:** the convention encoding proves too brittle in
practice.

**JWT-issuer alternative — evaluated 2026-07-11, not adopted** (research
§3/§7.7/§8). ironbark as an OIDC/JWT issuer consumed by Vault's `jwt` auth
method (GitLab/SPIFFE-style `bound_claims`) is mature and well-precedented,
but: it makes ironbark a stateful key-holder (JWKS, rotation); per-repo
scoping still needs per-repo roles or templated policies; and the templating
shortcut is undermined by a real divergence — Vault allows `/` in templated
substitutions by default (a metadata value like `org/repo` injects path
segments), OpenBao blocks it by default (the rule is silently dropped) —
plus a history of alias-metadata authorization CVEs. With the token-role
linchpin source-confirmed, the alternative loses on both security and
simplicity. **Revisit triggers:** Woodpecker ships native id-tokens
(discussion #2285, dormant since 2022 — "There is no eta"), or token-role
minting fails operationally.

**Response wrapping** (unverified lead from bedag/vault-secret-broker):
delivering the minted token cubbyhole-wrapped so only the pipeline can
unwrap it once. Possible M2+ hardening; interacts poorly with the sweep
(ironbark itself must use the token first). Not evaluated.

**Forgejo v16.0 (due mid-July 2026)** ships scoped short-lived JWT tokens at
the forge level. Does not give Woodpecker pipelines an identity, but worth
tracking for the estate.

## 13. Open questions

RESOLVED by the 2026-07-11 research pass (facts in
`woodpecker-secret-mechanisms.md` §5–§12 and
`research/2026-07-11-pre-implementation-research.md`):

- ~~Fail posture~~ → **fail-open**, no fail-closed flag exists; documented
  property + threat-table row (§3).
- ~~`pipeline.Branch` semantics~~ → per-event table; PR = target branch,
  tag = empty, manual = caller-supplied, deploy = inherited. Folded into §5.
- ~~`forge_remote_id` in payload~~ → yes; `.identity` binding viable.
- ~~Replay/freshness~~ → `created` is signed (httpsign default), no nonce.
  ironbark enforces a `created` window; replays inside it are undetectable
  (threat row, §3). Window size itself is an M1 knob (library verify
  default is −2s/+10s; extension calls are server-to-server so a tight
  window is viable).
- ~~`num_uses`~~ → not used: every API request decrements (sweep and deref
  reads included), and use-caps are illegal on batch and hostile to the
  returned token. TTL is the bound.
- ~~Policy-name charset~~ → `/` legal, lowercased, no length cap; folded
  into §5.
- ~~Extension call cadence~~ → once per create/approve/restart, covers all
  workflows in the pipeline; no caching.
- ~~OpenBao parity (mostly)~~ → no divergence on: token/lease mechanics,
  nonexistent-policy behavior, allowed_policies_glob logic, wildcard
  matching. Real divergences found and accounted for: `default-ceiling`
  and `control-group` are Vault-only (cosmetic for us); Vault-only List-op
  precedence CVE fix (our sweep LISTs — test both products); policy
  templating slash defaults differ (moot — templating not adopted, §12).

Still open:

- **OpenBao KV v2 `custom_metadata` parity** — last unconfirmed parity
  item; M1 integration tests exercise it directly.
- **Role strategy** — single glob role `ci` (M1 working choice) vs per-repo
  roles stamped by the IaC module (narrower per-repo glob = tighter
  availability *and* security backstop). Revisit at M2.
- **TTL merge semantics** (role-vs-request) — verifier refuted a claimed
  Vault/OpenBao divergence; treat role values as caps and pin exact
  behavior via M1 integration tests against both products.
- **Freshness window size** — pick during M1 (see above).
- **Name normalization details** — injective branch escape, KV key →
  secret-name mapping. Expected to evolve during M1 build; lock before v1
  (accepted 2026-07-11). Both must produce lowercase output (§5).
- **TTL guidance docs** — queue+runtime budgeting; no-revoke-when-derefs;
  mint happens at create/approve/restart so gated pipelines mint at
  approval (favourable).
- **Per-mint audit line** — emit `(repo, branch, event, policies, TTL)` +
  any mint warnings; format TBD.
- **Rate limiting** — whether to bound mint rate per repo/instance.
- **Health/readiness/metrics** — endpoints and what readiness means (Vault
  reachable? role present?).
- **Publishing home** — mirror from the private forge to a public one;
  which.

(The former §5 proposals — `custom_metadata` pins, `.identity` binding,
`.config` directives — were accepted 2026-07-11 as DEC-260711114101.)

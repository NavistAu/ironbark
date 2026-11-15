# ironbark M1 — implementation specification

**Grant model (2026-10):** this spec describes the grant model
([design](plans/2026-09-30-grant-model-design.md)); §2.3–§2.5, §3, §4.1,
§4.4–§4.6 and §7 are reduced to pointers at the design. Breaking; see the
CHANGELOG. The §12 decisions and the cross-AI review record below are
history of the pre-grant M1 spec.

Status: ACCEPTED 2026-07-11, after a 4-cycle adversarial cross-AI review
(codex + gemini, zero remaining HIGH concerns —
[`reviews/SPEC-REVIEWS.md`](reviews/SPEC-REVIEWS.md)). The §12 decisions
are logged as [DEC-260711114101…DEC-260711114105](decisionlog/).
Sources of truth: [`DESIGN.md`](DESIGN.md) (architecture + threat model),
[`decisionlog/`](decisionlog/) (DEC-260711061322…260711061325; a fifth item
from that batch is a DESIGN.md §12 research note, not a decision),
[`woodpecker-secret-mechanisms.md`](woodpecker-secret-mechanisms.md)
(source-verified Woodpecker facts, cited as **[WP§n]**),
[`research/2026-07-11-pre-implementation-research.md`](research/2026-07-11-pre-implementation-research.md)
(verified Vault/OpenBao facts, cited as **[R§n]**).
This spec defines interfaces, behaviors, encodings, and verification
criteria — not implementations.

## 0. Scope

M1 delivers the broker: one Go binary implementing the Woodpecker secret
extension against Vault or OpenBao, its test suite, and a container image.
Out of scope for M1: the Terraform module and `ironbark doctor` (M2,
DEC-260711061325), Drone compatibility, any UI.

## 1. Runtime behavior

### 1.1 HTTP surface

| Route | Method | Purpose |
|---|---|---|
| `/` | POST | The secret-extension endpoint Woodpecker calls |
| `/healthz` | GET | Liveness: process up. Always 200 when serving. |
| `/readyz` | GET | Readiness: OpenBao answers `sys/health` initialised and unsealed (a standby counts). 200/503. |
| `/metrics` | GET | Prometheus. Counters: requests by outcome (`ok\|refused\|invalid\|config_error\|error\|refused_signature`), mints (tokens obtained by the final login of a request), signature failures by reason. |

Anything else: 404. Non-POST on `/`: 405.

### 1.2 Request processing sequence (normative)

1. **Read body**, limit 1 MiB; over-limit → `413`.
2. **Verify** (§5). Any failure → `401`, structured log with reason
   category, response body empty. No payload field may be trusted or
   logged before this step succeeds (log only remote addr + reason).
3. **Parse and build facts** (design §4). The `netrc` field is ignored
   entirely — never read, never logged [WP§11]. Malformed JSON, a missing
   `repo`, `pipeline`, `repo.forge_remote_id` or `pipeline.event`, or a
   `repo.full_name` without exactly one `/` → `400`. The forge lookup for
   branch protection is bounded by `IRONBARK_FORGE_TIMEOUT` and fails
   closed (`branch_protected=false`).
4. **Select** the environment (`IRONBARK_ENV_VAR`) and the target (design
   §4.6). An invalid explicit selector → status only, before any login.
5. **Discover** (design §4.5): only with no explicit environment and a
   protected branch — the discovery login to `ci` and the level-metadata
   read (§3). No claimant keeps the discovery token; one claimant revokes
   it and selects that environment; two → status only (`config_error`).
6. **Teams** (§2.5): only with an environment and an actor.
7. **Login** (§3): sign the JWT and log in with the rendered role. A
   refusal → status only. Per-login assertions (§3) follow.
8. **Walk** (§4.1): read the levels as the login's token.
9. **Build response** (§6): `200` with the walk's secrets and
   `ironbark_status`. If nothing but `ironbark_status` (and `vault_addr`)
   is returned, the token the request obtained is revoked.

Every verified request is `200`; only steps 1–3 answer otherwise. A
non-200 makes Woodpecker proceed fail-open without extension secrets
[WP§5]; the job reads `ironbark_status` to decide what to do. Target:
complete within 5s under normal conditions; hard request timeout 30s →
`200` with `outcome=error reason=timeout`.

### 1.3 OpenBao session

ironbark holds no OpenBao credential and keeps no session: no AppRole, no
renewal, no startup login. Each request's own login yields the token every
read and the revoke-self use (§3).

## 2. Identity and naming (normative encodings)

### 2.1 Identity extraction

From the verified payload:

| Field | Source | Normalization |
|---|---|---|
| `org`, `repo` | `repo.full_name` split at its single `/` | lowercase |
| `event` | `pipeline.event` | lowercase (unknown values allowed — see below) |
| `branch` | `pipeline.branch` | **VERBATIM bytes — never case-folded** (see §2.2); may be empty (tag events) [WP§6] |
| `forge_remote_id` | `repo.forge_remote_id` [WP§7] | verbatim string |

Org/repo/event are lowercased because Vault lowercases policy names and
Woodpecker's `from_secret` matching is effectively lowercase
[R§7.2][WP§9]; forges enforce case-insensitive uniqueness for owner/repo
names, and case-colliding repo names are additionally a documented
operator concern (DESIGN §5). The branch is NOT lowercased: branch names
are attacker-chosen and git refs are case-sensitive, so case-folding
would collapse a branch literally named `Main` onto the protected
`main`'s tier — a privilege escalation. Case is preserved injectively
through `esc()` instead.

**Facts per event** (design §4.1). `forge_remote_id` is required and
reaches the JWT only inside `repo_key`
(`esc(org)/esc(repo)#esc(forge_remote_id)`). Three more facts, filled per
event:

| Event | `branch` / `ref` | `actor` | `target` from |
|---|---|---|---|
| `push` | payload | `pipeline.sender` iff `IRONBARK_ACTOR_FORGE` ≠ `none` | `Deploy-To:` trailer of the head commit message |
| `pull_request`, `tag`, `release` | absent | as `push` | — |
| `manual` | payload | `pipeline.author` | `pipeline.variables[IRONBARK_TARGET_VAR]` (exact key) |
| `deployment` | payload (the parent's) | empty | `pipeline.deploy_to` |
| `cron` | payload | empty | — |
| any other event | absent | empty | — |

`actor` is verbatim (never case-folded). A deployment has no actor: a
Woodpecker promotion carries the parent pipeline's `sender`, a GitHub
deployment webhook its creator's, and the payload cannot tell which.
`target` grammar: split on `/`; every segment non-empty (no leading,
trailing or doubled `/`); at most 8 segments and 256 bytes; case kept;
segments exactly `.` or `..` refused; every segment is escaped with `esc()`
(§2.2). A value violating the grammar is no target and the request is
`outcome=invalid` (`target_invalid` in the audit line). `Variables` are read
for `manual`, `deployment` and `cron` only.

Known events (Woodpecker v3.15.0): `push`, `pull_request`,
`pull_request_closed`, `tag`, `release`, `deployment`, `cron`, `manual`.
Event values outside the ones in the table above, `pull_request_closed`
included, are accepted (forward compatibility) and lowercased, but carry no
branch and no actor, so they match only roles that list them in `event`.

### 2.2 Escape function

`esc(s)`: RFC-3986-style percent-encoding, applied bytewise to the
ORIGINAL branch bytes: every byte outside `[a-z0-9._-]` is encoded as `%`
+ two lowercase hex digits; `%` itself is always encoded; and a LEADING
`.` is always encoded (cycle-3 G3-1: output can therefore never be `.`,
`..`, or any dot-prefixed name — no path-special segments, no collision
with the dot-directive namespace; git forbids such ref names anyway, but
ironbark does not rely on forge-side validation). Uppercase bytes are
*encoded, not folded*: `Main` → `%4dain`, which cannot collide with
`main`. Output is all-lowercase by construction (so Vault's policy-name
lowercasing [R§7.2] is a no-op on it), a single path segment (never
contains `/`), never dot-prefixed, injective, and stable — all
property-tested (§9.2).

### 2.3 Policy names

**Replaced by the grant model** ([grant-model design](plans/2026-09-30-grant-model-design.md) §6.3). ironbark requests no policies
and derives no policy names. Access is three OpenBao-side templated policies
(`ci-project`, `ci-env`, `ci-target`, printed by `ironbark render-policies`)
attached to JWT roles; the login's claims decide which paths a token can
read. The tier/attribute policy derivation, `IRONBARK_POLICY_PREFIX` and
`IRONBARK_MAX_POLICIES` are gone.

### 2.5 Teams

**Changed** ([grant-model design](plans/2026-09-30-grant-model-design.md) §4.4). Teams are still resolved on the forge, fail closed,
and only when an actor exists **and** an environment is selected. They reach
OpenBao as the JWT `teams` claim (always sent, `[]` when none), each entry
`esc(org)/esc(team)`, through the mount's `groups_claim` to external groups.
They no longer produce policy names.

### 2.4 KV layout

**Replaced** ([grant-model design](plans/2026-09-30-grant-model-design.md) §8.1). The secret tree is addressed by
`IRONBARK_DATA_PATH`, for example `vs/data/pipelines/{repo}/{env}/{target...}`:
a repo level, an environment level, and one level per target segment. There
are no event or branch tiers, no `.identity`/`.config` directives and no
attribute mount.

## 3. Login (was: Minting)

**Replaced** ([grant-model design](plans/2026-09-30-grant-model-design.md) §5, §9). ironbark holds no OpenBao credential, mints no
token and runs no startup canary.

- Per request it signs an RS256 JWT (`IRONBARK_JWT_SIGNING_KEY`; the
  OpenBao `jwt` mount trusts the public key) and logs in
  (`POST auth/<IRONBARK_JWT_MOUNT>/login`) with the role rendered from
  `IRONBARK_JWT_ROLE` (`ci-{env}`, or `ci` with no environment). A refused
  login is never retried with another role.
- The role must issue a service, orphan token with an explicit max TTL. Each
  login asserts this (`token_type`, `orphan`, `lookup-self`
  `explicit_max_ttl`); a violation revokes and reports `outcome=error`.
- The only other login is the metadata-only discovery login to `ci` before
  an environment chosen by level metadata; it is revoked before the
  environment login unless no level claims the branch.
- **Revocation by outcome.** A response carrying only `ironbark_status`
  (and possibly `vault_addr`) revokes any token the request obtained; a
  response carrying any other secret never does.
- Every verified request is `200` with `ironbark_status`
  (`outcome=ok|refused|invalid|config_error|error`); `204` and `502` are
  gone. An invalid signature is still `401` with nothing.

## 4. Sweep

### 4.1 Read set

**Replaced by the walk** ([grant-model design](plans/2026-09-30-grant-model-design.md) §8.2). Levels (repo, environment, one per
target segment) are read shallow to deep as the login's token: `LIST` each
level, `GET` each entry, deeper level wins, unreadable levels and entries
skipped. Entries are voidstar views: `fetch` (default), `resolve`
(dynamic engine paths, one hop, leases parent to the pipeline token) and
`metadata` (the `vault_token` marker). `ironbark_status` is a reserved name.

### 4.2 Entry forms and secret naming

For a level entry named `E` (a voidstar view or a plain KV v2 entry) whose
`data` map is `D`:

- **Single-field shorthand**: `D` is exactly `{"value": v}` → one secret
  named `E`.
- **General**: each field `f` in `D`, in sorted order → secret named `E_f`.
- **`vault_token`**: an entry named `vault_token` with a `metadata`-mode
  view, or no data, → the secret `vault_token` carrying the pipeline token;
  one carrying data is skipped with a warning.
- **`resolve` view**: the entry's data is what its target path returns
  (§4.3), always flattened as `E_f` unless KV v2-shaped.

**Values must be JSON strings** (C4): a non-string field value (number,
bool, array, object) is skipped with a warning — never coerced — in every
form and in resolved results. (Woodpecker's secret `value` is a string;
emitting anything else risks a response-decode failure and silent fail-open
on the CI side.)

Names are lowercased with `-` mapped to `_`; ironbark validates final names
against `[a-z0-9_]+` (anything else → entry skipped + warning log).
`ironbark_status` is reserved: an entry producing it is skipped with a
warning. Collisions: a deeper level's secret replaces a shallower level's
of the same name (§4.1); within one level the first key in bytewise order
wins and the clash is logged. Emitting lowercase is required so
Woodpecker's case-sensitive store-merge and case-insensitive compiler agree
[WP§9].

### 4.3 Resolve mappings

A `resolve` view names an engine path; the walk does a bodiless `GET` of it
with the pipeline token, so any lease parents to that token and is revoked
with it. Response `.data` fields flatten as `E_f` per §4.2 (string-only
rule applies). `403`/`404` on the resolve target: skip entry, log. Any
other failure (5xx, timeout, malformed response): the walk fails, the
request is `outcome=error reason=walk`, the token is revoked and the
cascade revokes leases already taken. A view that cannot be read (a
voidstar quarantine or loopback `502`, or an undecodable answer) is the
same failure but names the entry: `outcome=error reason=view:<level>/<key>`,
and the audit line carries `entry`. Leases only survive when the response
carries secrets. The hop is one level: a resolved response is never itself
treated as a pointer or view (no chains, no cycles). Which paths a mapping
may name is the voidstar mount's concern, and which it may read is the
token's policy.

**KV v2-shaped resolve targets.** A target whose response is itself KV v2
wire-shaped — KV v2 read directly, or a KV v2-wire-compatible view — is
detected by shape, never by path: the response's `.data` is treated as KV
v2-shaped only when it contains BOTH a nested `data` object AND a
`metadata` object. Only then is it unwrapped to the inner field map and
classified like a level entry (§4.2: single `{"value": v}` → secret named
`E` alone; otherwise `E_f`). A flat response — including one that happens
to carry a field literally named `data` or `metadata` without the paired
object shape — keeps flattening unconditionally as `E_f`.

**Limitation — GET-only resolve (integration-verified, 2026-07-16):** the
read is a bodiless HTTP GET, so targets must be **GET-readable**
dynamic-secret endpoints: `aws/creds/<role>` (DEC-260711061324's motivating STS
example), `database/creds/<role>`, `gcp/.../key`, `azure/creds/<role>`,
and KV reads. It does NOT support engines that require request-body
parameters on a write — notably `pki/issue/<role>`, which is POST-only
(`GET` returns 405 on both Vault and OpenBao). Supporting POST-with-body
would mean carrying a request body into a privileged write — a deliberate
trust-surface exclusion, not a bug.

### 4.4 `.identity` binding and 4.5 `.config` directives

**Removed** ([grant-model design](plans/2026-09-30-grant-model-design.md) §13). Repo identity is bound by the role's `repo_key`
claim (`esc(org)/esc(repo)#esc(forge_remote_id)`). `vault_token` is returned
only where a metadata-only `vault_token` mapping exists at a walked level
(§8.5); there is no suppression or `vault_token_images` directive.

### 4.6 Per-secret pins

**Changed** ([grant-model design](plans/2026-09-30-grant-model-design.md) §8.4). Image pins live on the voidstar mapping as
`ironbark_images` in its `custom_metadata`, relayed as the secret's
`images`. Event pins are gone: they are role `bound_claims`. An entry still
carrying `ironbark_events` is logged as ignored. No `events` field is
emitted in the response.

## 5. Signature verification (load-bearing; DESIGN §6)

- Library: `github.com/yaronf/httpsign` (same library Woodpecker signs
  with [WP§8]).
- Required coverage: the signature MUST cover `@request-target` and
  `content-digest`; the `Content-Digest` header MUST validate against the
  received body; the key MUST be the configured ed25519 public key
  (PEM, from file or env; rotation requires a restart — SIGHUP reload is
  optional, not a v1 requirement; cycle-2 G2-4).
- Freshness: the signature's `created` parameter is REQUIRED (Woodpecker
  always sends it [WP§8]); reject when
  `|now − created| > FRESHNESS_WINDOW` (default 10s — the call is a
  synchronous server-to-server request; G4). Replays inside the window
  are accepted and documented (DESIGN §3 threat table) — no nonce exists
  in the protocol [WP§8].
- No payload-derived data (including the key) is ever used for
  verification; the key is out-of-band config only.

Failure taxonomy (each its own metrics label + log reason): missing
signature header, unparseable signature, wrong key, digest mismatch,
uncovered required component, missing `created`, stale/future `created`.

## 6. Response construction

`200` body:

```json
{ "secrets": [
    { "name": "<per §4.2>", "value": "<...>", "images": ["<pin or absent>"] },
    { "name": "vault_token", "value": "<pipeline token>" },
    { "name": "vault_addr",  "value": "<ADVERTISE_VAULT_ADDR>" },
    { "name": "ironbark_status", "value": "ironbark/v1 outcome=ok ..." }
] }
```

- No `events` field is emitted: event pins are role `bound_claims` (§4.6).
  Extension secrets override DB secrets on exact-name collision [WP§10].
- `vault_token` only where a metadata-only `vault_token` mapping exists at
  a walked level (§4.4).
- `vault_addr` only when `ADVERTISE_VAULT_ADDR` is configured (convenience
  so pipelines need no hardcoded address). It never counts toward the
  empty-response decision (§3): a response of `ironbark_status` plus
  `vault_addr` still revokes the token.
- `ironbark_status` is on every `200`: `ironbark/v1` followed by
  `key=value` pairs in fixed order, empty keys omitted — `outcome`, `env`,
  `env_source`, `target`, `role`, `reason`, `levels` (the environments
  claiming the branch, on `config_error`), `skipped` (levels the walk
  skipped). Values are percent-encoded so they cannot add a field; secret
  values never appear.
- Non-`200` answers carry no body: `401` (§5), `400` (payload yields no
  identity, §1.2), `413`.

## 7. Configuration (complete surface)

Env vars (a `_FILE` suffix variant reads the value from a file path, for
ESO/k8s mounts). The grant settings are defined in [grant-model design](plans/2026-09-30-grant-model-design.md) §11.

| Var | Default | Notes |
|---|---|---|
| `IRONBARK_DATA_PATH` | — (required) | path template with `{repo}`, `{env}`, `{target...}` as the last three segments; second segment `data` |
| `IRONBARK_ENV_VAR` | `DEPLOY_ENV` | pipeline variable naming the environment |
| `IRONBARK_TARGET_VAR` | `DEPLOY_TO` | manual-run variable naming the target (must differ from the env var) |
| `IRONBARK_JWT_ROLE` | `ci-{env}` | login role template; renders `ci` with no environment |
| `IRONBARK_JWT_SIGNING_KEY` / `_FILE` | — (required) | PEM RSA private key, at least 3072 bits |
| `IRONBARK_JWT_MOUNT` | `jwt` | auth mount path |
| `IRONBARK_LISTEN_ADDR` | `:8080` | |
| `IRONBARK_WOODPECKER_PUBLIC_KEY` / `_FILE` | — (required) | PEM ed25519 |
| `IRONBARK_VAULT_ADDR` | — (required) | Vault/OpenBao URL |
| `IRONBARK_FRESHNESS_WINDOW` | `10s` | §5 |
| `IRONBARK_ADVERTISE_VAULT_ADDR` | unset | §6 |
| `IRONBARK_LOG_LEVEL` | `info` | |
| `IRONBARK_ACTOR_FORGE` | `none` | `none` \| `gitea` \| `github` \| `bitbucket`: the forge whose push-family `sender` is a login. With `IRONBARK_FORGE_PROVIDER=gitea` only `gitea` or `none` |
| `IRONBARK_FORGE_PROVIDER` | `none` | `none` \| `gitea` (Gitea, Forgejo): branch protection and teams. `none` makes `branch_protected` always `"false"` (startup warning) |
| `IRONBARK_FORGE_URL` | — | required when provider ≠ `none` |
| `IRONBARK_FORGE_TOKEN` / `_FILE` | — | required when provider ≠ `none` |
| `IRONBARK_FORGE_TIMEOUT` | `3s` | Go duration > 0; bounds each forge lookup (protection, teams) |

Removed: `IRONBARK_VAULT_ROLE_ID`, `IRONBARK_VAULT_SECRET_ID`,
`IRONBARK_TOKEN_ROLE`, `IRONBARK_KV_MOUNT`, `IRONBARK_KV_PREFIX`,
`IRONBARK_POLICY_PREFIX`, `IRONBARK_ATTR_MOUNT`, `IRONBARK_MAX_POLICIES`.
`/readyz` reports 200 while OpenBao answers `sys/health` unsealed.

No config file, no rule tables, no path maps (DEC-260711061323). TLS termination
is the deployment's concern (in-cluster service mesh / ingress); ironbark
serves plain HTTP.

## 8. Observability

### 8.1 Audit line

One structured JSON log line per POST at info level. Two shapes (cycle-2
C2-4 — payload fields are untrusted until the signature verifies and must
never appear in the refused-signature line):

- **Refused signature**: `ts, remote_addr, reason (failure taxonomy §5),
  outcome=refused_signature` — nothing derived from the payload.
- **Verified request**: `org, repo, repo_key, event, branch, ref,
  branch_protected, actor, teams, teams_error, env, env_source
  (variable|branch), env_claimants, env_invalid, env_refused, target,
  target_source (variable|deploy_to|trailer), target_invalid,
  discovery_login, role, sub, jti, levels (label →
  read|skipped_403|skipped_404), secrets_returned (names only),
  images_relayed (names), vault_token_issued, token_accessor, token_ttl,
  entry (the entry whose view broke, `error` only),
  outcome (ok|refused|invalid|config_error|error)`; fields with no value
  are omitted. Payload values that are not facts (variables other than the
  two selectors, message text) are never logged. Warnings from the walk,
  an error line for a config or availability fault, and a failed
  best-effort revoke each log a separate line. At debug level a
  `payload attributes` line lists the pipeline facts behind the audit
  fields (event, sender, author, actor, branch) and the variable *names*,
  never their values or the message text.

NEVER log: secret values, the token itself, netrc. The token *accessor*
is safe and correlates with Vault's own audit log (DESIGN §13 audit
question: resolved thus).

## 9. Testing (normative — these gate M1 completion)

### 9.1 Signature matrix (unit, fake signer harness)

Built with `httpsign` acting as Woodpecker [WP§8]:

| Case | Expect |
|---|---|
| valid signature, fresh `created` | 200 path |
| no signature header | 401 |
| signed with a different key | 401 |
| body tampered after signing (digest mismatch) | 401 |
| `Content-Digest` header absent | 401 |
| signature not covering `@request-target` or `content-digest` | 401 |
| `created` absent | 401 |
| `created` older than window | 401 |
| `created` in the future beyond window | 401 |
| byte-identical replay inside window | accepted (documented) |

### 9.2 Unit

- `esc()` injectivity: property/fuzz test over pairs (`FuzzEscInjective`) —
  distinct inputs never collide; output never contains `/` and never begins
  with `.`; reserved segments never equal `esc` output
  (`TestAttrSegmentsNeverEscOutput`, `FuzzEscNeverAttrSegment`); `main` vs
  `Main` stay distinct (`TestEsc`).
- Facts (`internal/facts`): per-event fixtures (`TestBuildFixtures`),
  `pull_request_closed` has no branch, a promoted-PR ref never looks up
  protection, forge error/unprotected/no forge → `"false"`, actor per
  `IRONBARK_ACTOR_FORGE`, malformed payloads, team resolution and its
  fail-closed error.
- Selectors (`internal/selector`): environment and target grammar, the
  target cascade per event, trailer parsing, invalid never falls through,
  branch-pattern claimants.
- JWT (`internal/jwtsign`): key validation, signature verifies, full claims,
  absent facts omitted, hostile values escaped, `sub`, discovery claims.
- Levels and policies (`internal/levels`): level derivation per template,
  rendered policies (golden; no stanza ends in `*`).
- Walk (`internal/walk`): unreadable levels skipped and deeper ones read,
  bytewise order, deepest wins, entry errors, naming/flattening incl.
  non-string skip, `vault_token` marker, ignored `ironbark_events`, resolve
  hook; discovery incl. two claimants and an unreadable level.
- Status (`internal/status`): golden status line, values cannot break the
  line, `ShouldRevoke`, audit JSON omits absent fields.
- Config (`internal/grantcfg`): defaults, required vars, `_FILE` variants,
  selector-variable clash, role template, forge vars.
- Broker and HTTP (`internal/broker`, `internal/httpapi`): every outcome
  row of design §9.2, revocation by outcome, revoke failure flagged,
  malformed payload → 400, 413, timeout → 200 `outcome=error`, `/readyz`
  tracks OpenBao, routes and metrics.

### 9.3 Integration (containerized OpenBao 2.7.0 with voidstar, plus Vault 1.20)

Fixture (`test/integration`): OpenBao with the voidstar plugin mounted, a
`jwt` auth mount trusting the test key, the templated level policies, and a
plain Vault 1.20 with KV v2 only. The grant tests run on OpenBao; Vault
results are informational.

- Login (`TestGrantLogin`): event lists, globs, string claims, `repo_key`
  with a changed forge id, a missing bound claim and a missing role are
  refused; a bad signature is an error, not a refusal; a role without
  explicit max TTL or a `batch` role fails the per-login assertion and the
  token is revoked.
- Discovery (`TestGrantDiscovery`): the `ci` token reads every environment
  level's `branches` and no environment data; none/one/two claimants; another
  repo's levels are unreadable so discovery errors.
- Walk (`TestGrantWalk`, `TestGrantWalkPlainKV`): nested targets read their
  parents and not a sibling; another environment or repo is skipped on 403;
  a target below an unreadable environment is still read; pins come from
  the mapping; plain KV v2 entries and the `vault_token` marker.
- Dynamic credentials (`TestGrantDynamic`): a `resolve` mapping yields the
  engine's credentials with the lease parented to the pipeline token.
- Spike findings (`TestGrantSpike`, both products) and `esc()` never
  emitting a policy-template metacharacter
  (`TestEscNeverEmitsPolicyMetacharacters`).

### 9.4 End-to-end smoke

`TestGrantE2E`: a fake-Woodpecker signer POSTs realistic payloads through
`httpapi`, `broker` and `walk` against OpenBao — discovery then
environment, manual and promote with targets, `resolve`, PR and tag
(repo level only), an explicit environment refused from an unprotected
branch, invalid selectors, two claimants, status-only revocation, the audit
line carrying the design §10 fields and no values. Run in CI.

## 10. Implementation shape (Go)

- Module path: `github.com/navistau/ironbark`. Go ≥1.22, stdlib `net/http`.
- Dependencies (deliberately few): `github.com/yaronf/httpsign`,
  `github.com/hashicorp/vault/api` (client; works against OpenBao),
  `github.com/prometheus/client_golang`. Logging: stdlib `log/slog`.
- Packages:
  - `cmd/ironbark` — main, wiring, `render-policies`.
  - `internal/wpsign` — §5. `Verify` + failure-reason typed errors.
  - `internal/identity` — §2.2. `Esc`, git remote parsing, `ErrMalformed`.
  - `internal/facts` — §2.1, §2.5. Verified facts and team resolution.
  - `internal/selector` — environment and target selection, branch claimants.
  - `internal/grantcfg`, `internal/levels` — §7 configuration; level and
    policy derivation from `IRONBARK_DATA_PATH`.
  - `internal/jwtsign` — the JWT (§3).
  - `internal/vaultx` — OpenBao client: `LoginJWT` with its assertions,
    reads, `RevokeSelf`, `Healthy`.
  - `internal/walk` — discovery and the walk (§4).
  - `internal/status` — `ironbark_status` and the audit record.
  - `internal/broker` — orchestrates §1.2 steps 3–9.
  - `internal/httpapi` — routes (§1.1), handler, metrics.
  - `internal/forge` — the forge lookups (branch protection, teams); Gitea
    family implementation.
- The fork-reference: `woodpecker-ci/example-extensions` (Apache-2.0) is
  reference material for the transport half; ironbark's verification is
  written against `httpsign` directly with the §9.1 matrix.

## 11. Delivery

- `Dockerfile`: static build, distroless/nonroot, `USER` nonzero.
- ironbark's own CI (its Woodpecker pipeline) needs only a registry
  token — stage-2 bootstrap, no Vault dependency (DESIGN §9).
- README gains: deployment walkthrough (Woodpecker env vars incl.
  `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` gotcha [WP§3], the fail-open
  property [WP§5], netrc-off requirement [WP§11]), the OpenBao operator
  contract (grant model), and TTL budgeting guidance (queue+runtime;
  login-at-approval for gated pipelines [WP§12]).

## 12. Decisions this spec introduces (log as DECs on acceptance)

1. Orphan service tokens (§3.3) — pipeline tokens survive ironbark's own
   credential rotation.
2. Revocation by outcome: every non-200 revokes (cascading leases on
   failure paths); a 200 never revokes (§3.4).
3. Un-onboarded detection via all-policies-warned → 204 (§1.2.6).
4. Event tier mapping: manual/deployment/tag never branchful; unknown
   events accepted P1-only (§2.1/§2.3).
5. Entry forms + naming scheme, string-only values, most-specific-wins
   collisions (§4.2); single-level deref only (§4.3).
6. Graduation of the three DESIGN §5 proposals: `.identity` (§4.4, with
   fail-closed malformation rules), `.config` (§4.5), custom_metadata
   pins (§4.6, no fallback read).
7. Freshness window default 10s (§5).
8. Config surface (§7); no TLS in-process.
9. `vault_addr` convenience secret, excluded from empty-response
   decision (§6).
10. Startup canary self-check enforcing the role contract without
    widening the AppRole, and acting as a HARD GATE on minting (§3.5);
    per-mint `token_type` assertion (§1.2.6).
11. Independent per-tier LISTs, most-specific-first sweep order (§4.1).
12. `renewable=false` in the role contract — TTL is the absolute token
    lifetime (§3.1).
13. Branch case is preserved injectively through `esc()` — org/repo/event
    lowercase, branch never case-folded; leading `.` always encoded so no
    output is path-special or dot-prefixed (§2.1/§2.2).
14. Two audit-line shapes; refused-signature lines carry no
    payload-derived fields (§8.1).

Cross-AI review dispositions (all cycles): [`reviews/SPEC-REVIEWS.md`](reviews/SPEC-REVIEWS.md).

# ironbark M1 — implementation specification

**Grant model (2026-10):** §2.3–§2.5, §3, §4.1, §4.4–§4.6 and §7 are
replaced or reduced to pointers at the [grant-model design](plans/2026-09-30-grant-model-design.md);
the remaining sections (notably §1.1 `/readyz` and §1.2, §4.2–§4.3, §6,
§8.1, §9) still describe the pre-grant model until updated. Breaking; see
the CHANGELOG.

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
| `/readyz` | GET | Readiness: Vault reachable AND AppRole session valid AND startup canary passed (§3.5). 200/503. |
| `/metrics` | GET | Prometheus. Minimum counters: requests by outcome, mints, mint warnings, sweep reads, deref reads, signature failures by reason. |

Anything else: 404. Non-POST on `/`: 405.

### 1.2 Request processing sequence (normative)

1. **Read body**, limit 1 MiB; over-limit → `413`.
2. **Verify** (§5). Any failure → `401`, structured log with reason
   category, response body empty. No payload field may be trusted or
   logged before this step succeeds (log only remote addr + reason).
3. **Parse** payload `{repo, pipeline, netrc?}` [WP§3]. The `netrc` field
   is ignored entirely — never read, never logged [WP§11]. Malformed
   JSON / missing `repo.full_name` or `pipeline.event` → `400`.
4. **Extract and normalize identity** (§2.1). Invalid identity (e.g.
   `full_name` without exactly one `/`) → `400`.
5. **Derive the policy set** (§2.2).
6. **Mint** (§3). Requires PASSING canary state (§3.5) — failed/unknown →
   `502` without minting. Vault unreachable / login failure / mint error
   → `502`.
   - Assert the mint response's `token_type` is `service`; anything else →
     revoke best-effort, `502`, error log (misconfigured role — see §3.5).
   - If the mint response's `"Policy %q does not exist"` warnings
     [R§7.1] cover **every** requested policy, the repo is not
     onboarded: revoke the minted token (§3.4) and respond `204`.
7. **Read repo directives** with the minted token (cycle-3 G3-2):
   - `.identity` (§4.4): mismatch OR malformed → revoke, log at error
     level with both IDs (or the malformation), respond `204`.
     Non-403/404 read error → revoke, `502`.
   - `.config` (§4.5): malformed OR non-403/404 read error → revoke,
     `502`. Absent/unreadable → defaults apply.
8. **Sweep** (§4). Vault errors other than 403/404 during sweep →
   revoke, `502`.
9. **Dereference pointers** (§4.3). Non-403/404 deref failure → revoke,
   `502` (§3.4: failure paths always revoke; the cascade cleans any leases
   already created).
10. **Build response** (§6). If no swept/deref secrets AND `vault_token`
    is suppressed (§4.5) → revoke, `204` — `vault_addr` never counts
    toward "non-empty"; address-only `200` responses are forbidden.
    Otherwise `200`.

Woodpecker treats any non-200/204 as "no extension secrets" and proceeds
fail-open [WP§5]; ironbark's status codes are therefore for operators and
logs, not flow control on the CI side. Target: complete within 5s under
normal conditions; hard request timeout 30s → `502`.

### 1.3 Vault session (ironbark's own)

- AppRole login at startup (`role_id` + `secret_id` from config/files).
- Renew own token at ~half TTL; on renewal failure, re-login; on re-login
  failure, `/readyz` goes 503 and mints fail `502`.
- **AppRole token contract** (cycle-3 C3-1): the AppRole's token must be
  renewable and retain the `default` policy (renew-self and lookup-self
  power the session management above). Its ONE attached ACL policy grants
  exactly `create` (update) on `auth/token/create/<TOKEN_ROLE>` — no KV
  read, no policy read, no arbitrary revoke (DESIGN §8). If an operator
  strips `default`, ironbark degrades safely: renewal fails → re-login
  path takes over (login is always possible with valid AppRole creds). All KV/deref reads use the minted
  pipeline token; revocation uses `auth/token/revoke-self` *as* the
  minted token (§3.4).

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

**Pipeline attributes** (design
[`plans/2026-09-30-pipeline-attributes-design.md`](plans/2026-09-30-pipeline-attributes-design.md),
"the attributes design"; `D1`–`D8` below cite the decisions recorded in
[`plans/2026-09-30-pipeline-attributes-plan.md`](plans/2026-09-30-pipeline-attributes-plan.md)).
Three more fields, filled per event; the push
family is `push`, `tag`, `pull_request`, `pull_request_closed`, `release`:

| Event | `actor` | `target` from | `code_author` |
|---|---|---|---|
| push family | `pipeline.sender` iff `IRONBARK_ACTOR_FORGE` ≠ `none`, else empty | — | `pipeline.sender` |
| `manual` | `pipeline.author` | `pipeline.variables[IRONBARK_TARGET_VAR]` (exact key; none when the var is empty) | empty |
| `deployment` | empty | `pipeline.deploy_to` | empty |
| `cron`, unknown events | empty | — | empty |

`actor` and `code_author` are verbatim (never case-folded); `author` is
never used outside `manual`. A deployment has no actor: a Woodpecker
promotion carries the parent pipeline's `sender`, a GitHub deployment
webhook its creator's, and the payload cannot tell which. `code_author` is
recorded for audit only and is never a policy input. `target` grammar:
split on `/`; every segment non-empty (no leading, trailing or doubled
`/`); at most 8 segments and 256 bytes; case, `.` and `..` kept (§2.2
makes every value a safe segment). A value violating the grammar is no
target, and the audit line records `target_invalid`.

Known events (Woodpecker v3.15.0): `push`, `pull_request`,
`pull_request_closed`, `tag`, `release`, `deployment`, `cron`, `manual`.
Event values outside this set are accepted (forward compatibility): they
are lowercased, derive P1 only (never branchful), are echoed unchanged in
the response's `events` pins, and are logged at info.

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

For a KV entry named `E` with data map `D`:

- **Pointer**: `D` is exactly `{"$ref": "<path>"}` → §4.3.
- **Single-field shorthand**: `D` is exactly `{"value": v}` → one secret
  named `E`.
- **General**: each field `f` in `D` → secret named `E_f`.

**Values must be JSON strings** (C4): a non-string field value (number,
bool, array, object) is skipped with a warning — never coerced — in all
three entry forms and in deref results. (Woodpecker's secret `value` is a
string; emitting anything else risks a response-decode failure and silent
fail-open on the CI side.)

Secret names are lowercased; ironbark validates final names against
`[a-z0-9_]+` (KV keys with `-` map to `_`; anything else invalid →
entry skipped + warning log). Name collisions within one response: first
writer wins, and because the sweep runs most-specific-first (§4.1:
branch, then event, then base; lexicographic within a level), the MOST
specific secret wins deterministically (G2). Collisions are logged.
Emitting lowercase is required so Woodpecker's case-sensitive store-merge
and case-insensitive compiler agree [WP§9].

### 4.3 Pointer dereference

`GET <path>` (any mount) with the minted token. Response `.data` fields
flatten as `E_f` per §4.2 (string-only rule applies). `403`/`404` on
deref: skip entry, log. Any other deref failure (5xx, timeout, malformed
response): revoke + `502` — per §3.4 a failed request always revokes, and
the service-token cascade cleans up any leases earlier derefs created
(C3). Leases only survive when the response is a `200`. Pointers are
followed exactly one level — a deref result is never re-examined for
`$ref` (no chains, no cycles). A pointer found in any tier or attribute
prefix is dereferenced with the minted token, so it reaches attribute
data only if that pipeline's token already holds the attribute policy — a
pointer in an ordinary tier cannot lift attribute-gated data into a
pipeline without it.

**KV v2-shaped deref targets.** A `$ref` may point at a target whose
response is itself KV v2 wire-shaped — KV v2 read directly, or a
KV v2-wire-compatible view (e.g. a voidstar view: `vs/data/...`) — rather
than a flat dynamic-engine response (`aws/sts/*` etc.). Detection is
shape-based, never path-based: the response's `.data` is treated as KV
v2-shaped only when it contains BOTH a nested `data` object AND a
`metadata` object (mirroring the envelope §4.1's own KV v2 data-GET
already unwraps). Only then is it unwrapped to the inner field map and
classified exactly like a swept entry (§4.2: single `{"value": v}` →
secret named `E` alone; otherwise general form, `E_f`) — pointer-form
(`$ref`) classification is never applied to a deref result, preserving
the no-chain rule above. A flat response — including one that happens to
carry a field literally named `data` or `metadata` without the paired
object shape — is unaffected and keeps flattening unconditionally as
`E_f`, byte-identical to prior behavior.

**Limitation — GET-only deref (integration-verified, 2026-07-16):** the
deref is a bodiless HTTP GET, so `$ref` targets must be **GET-readable**
dynamic-secret endpoints: `aws/creds/<role>` (DEC-260711061324's motivating STS
example), `database/creds/<role>`, `gcp/.../key`, `azure/creds/<role>`,
and KV reads. It does NOT support engines that require request-body
parameters on a write — notably `pki/issue/<role>`, which is POST-only
(`GET` returns 405 on both Vault and OpenBao). Supporting POST-with-body
derefs would require the KV pointer entry to carry an attacker-writable
request body into a privileged write — out of scope for M1 and a
deliberate trust-surface exclusion. If PKI issuance via `$ref` is ever
needed, that is a post-M1 design change, not a bug.

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
    { "name": "<per §4.2>", "value": "<...>",
      "events": ["<event>"], "images": ["<pin or absent>"] },
    { "name": "vault_token", "value": "<minted>", "events": ["<event>"] },
    { "name": "vault_addr",  "value": "<ADVERTISE_VAULT_ADDR>", "events": ["<event>"] }
] }
```

- Every secret's `events` defaults to exactly the minting event
  (`ironbark_events` may override, §4.6). Extension secrets override DB
  secrets on exact-name collision [WP§10].
- `vault_token` included unless suppressed (§4.5).
- `vault_addr` included only when `ADVERTISE_VAULT_ADDR` is configured
  (convenience so pipelines need no hardcoded address). It never counts
  toward the empty-response decision (C7) — a response containing only
  `vault_addr` is forbidden; that case is revoke + `204`.
- `204` (no body): un-onboarded repo, identity mismatch, or
  empty-and-suppressed (§1.2).

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
- **Verified request**: `ts, org, repo, event, branch, pipeline_number,
  policies_requested, policy_warnings (names), secrets_returned (names
  only), token_accessor, token_ttl, actor, target, target_invalid,
  code_author, teams, teams_error, policies_dropped,
  policies_requested_count, policy_warnings_count (D5),
  outcome (ok|unonboarded|identity_mismatch|error)`.

At debug level only (off by default), a second line `payload attributes`
follows a successful parse (D8): `event, sender, author, deploy_to,
deploy_task, variable_names, reviewed_by, actor, target, target_invalid,
code_author`. It carries manual-run variable *names* only, never their
values.

NEVER log: secret values, the token itself, netrc. The token *accessor*
is safe and correlates with Vault's own audit log (DESIGN §13 audit
question: resolved thus).

## 9. Testing (normative — these gate M1 completion)

### 9.1 Signature matrix (unit, fake signer harness)

Built with `httpsign` acting as Woodpecker [WP§8]:

| Case | Expect |
|---|---|
| valid signature, fresh `created` | 200/204 path |
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

- `esc()` injectivity: property/fuzz test over pairs — distinct inputs
  never collide; output never contains `/` and never begins with `.`
  (inputs `.`, `..`, `.foo` produce encoded, non-path-special segments —
  cycle-3 G3-1); explicit case pair `main` vs `Main` derives distinct P2
  policies and KV paths (cycle-2 C2-3).
- Policy derivation table: every event type × branch present/empty/
  slash-containing/uppercase → exact expected policy lists (incl. manual/
  deploy/tag producing P1 only).
- Naming/flattening: shorthand, general, pointer detection, `-`→`_`,
  invalid-name skip, collision most-specific-wins (branch beats event
  beats base), non-string value skip (all entry forms + deref).
- Payload parsing: netrc present-and-ignored; missing fields → 400;
  unknown event → P1-only processing.
- Pipeline attributes: extraction per event × `IRONBARK_ACTOR_FORGE` from
  payload fixtures (`TestParseAttributes`); target grammar
  (`TestParseTarget`); reserved segments never equal `esc` output
  (`TestAttrSegmentsNeverEscOutput`, `FuzzEscNeverAttrSegment`); config
  validation incl. the actor-forge/provider rule and mount overlap
  (`TestLoadAttributeVars`, `TestLoadForgeVars`); attribute names, order,
  hostile-value escaping and no prefix nesting (`TestAttributes_*`); the
  cap's drop order (`TestCap`); team resolution incl. fail-closed errors
  and timeout (`TestGiteaTeams_*`); attribute sweep order, cross-mount
  first-writer-wins and wire encoding (`TestSweepWithAttributes_*`);
  broker request list, lookup gating and audit (`TestHandleAttr_*`); audit
  and debug lines (`TestAttr_*`).

### 9.3 Integration (containerized Vault AND OpenBao, both must pass)

Fixture: mount KV v2, create tier policies for a test repo, token role
per §3.1, AppRole for ironbark.

- Startup canary: passes against the documented role; fails loudly
  (`/readyz` 503, and POSTs return 502 WITHOUT minting — assert no token
  is created, cycle-2 C2-2) when the role is misconfigured to
  `token_type=batch`, `renewable=true`, non-orphan,
  `token_no_default_policy=true`, or a glob not covering the prefix —
  one test per misconfiguration (G1/C5/C2-1).
- Privileged-client assertions on a normally-minted token: type is
  service, orphan, renewable=false (the definitive orphan check —
  cycle-2 G2-3).
- Un-onboarded repo (no policies exist) → all-warnings mint → 204, token
  revoked (verify via accessor lookup by a root test client).
- Revoke-self works for the documented role (C5); failure-path revocation
  cascades deref leases (C3: force a deref then a later 5xx → assert the
  pki lease is revoked).
- Least-privilege tier: a policy granting list/read ONLY on the branch
  tier (no base/event grants) still yields that tier's secrets (C2).
- Precedence: same-named secret at base and branch tier → branch value
  returned (G2).
- Non-string KV value (number/bool/object) → skipped with warning, valid
  siblings still returned (C4).
- Malformed `.identity` (missing/non-string field) → 204 + revoke;
  malformed `.config` → 502 + revoke (C1).
- Tier isolation: PR-tier token sweeps only PR-visible entries; deploy
  subtree yields 403s that are skipped; response contains exactly the
  expected names.
- Glob coverage: role glob narrowed below the convention → mint errors →
  502 (and the failure is observable) [R§7.6].
- Nonexistent branch-tier policy → warning, P1 still effective.
- `.identity` match, mismatch, absent.
- `.config` vault_token suppression → 204 when sweep empty; token revoked.
- Pointer deref with lease: use the `pki` secrets engine (cheap
  lease-producing engine) — deref returns fields, lease created, token
  NOT revoked, lease dies when token TTL expires (assert with short TTL).
- custom_metadata pins surface as `images`/`events`, AND the named
  assertion that `custom_metadata` arrives in the data-GET response on
  both products (§4.6 depends on it; no fallback exists) [R§7.8, G3].
- TTL merge pinning: role `token_ttl` vs request-supplied ttl (we send
  none, but the test documents actual behavior on both products) [R§7.4].
- LIST behavior parity on both products (List-op precedence divergence,
  R§7.3): the sweep's 403-tolerant LISTs behave identically.
- Pipeline attributes (`TestAttributes`): dot-prefixed and `%2f` policy
  names accepted verbatim; a target-only policy grants any manual run
  naming the target while a conjunction does not; teams via a fake forge;
  team lookup timeout/500 fail closed; overflow drops only attribute
  names; a signed manual payload end to end.
- Attribute isolation (`TestAttributeIsolation`, `TestAttrMountStartup`):
  ordinary tier policies — the README examples verbatim, repo-root,
  `ci/*`, `kv/*` and `+` variants — get 403 on every attribute LIST/GET
  and the sweep returns no attribute secret; one attribute policy, `+` and
  trailing-`*` forms, reads exactly its own prefix; the README tiers
  (`TestReadmeTierPolicies`) are isolated per tier; overlapping mounts fail
  startup; a missing attribute mount leaves the sweep as before.
(An earlier draft said ironbark "does not preflight the role" — superseded
by the §3.5 canary, which preflights it via a mint, not a role read.)

### 9.4 End-to-end smoke

Fake-Woodpecker signer POSTs a realistic payload → response secrets used
to read KV directly → values match. Run in CI for both products.

## 10. Implementation shape (Go)

- Module path: decided at publishing-home decision (DESIGN §13); build as
  `ironbark` until then. Go ≥1.22, stdlib `net/http`.
- Dependencies (deliberately few): `github.com/yaronf/httpsign`,
  `github.com/hashicorp/vault/api` (client; works against OpenBao),
  `github.com/prometheus/client_golang`. Logging: stdlib `log/slog`.
- Packages:
  - `cmd/ironbark` — main, config loading, wiring.
  - `internal/wpsign` — §5. `Verify(r *http.Request, key ed25519.PublicKey, window time.Duration) (err error)` + failure-reason typed errors.
  - `internal/identity` — §2.1–2.2. `Parse(body []byte, opts Options) (Identity, error)`, `ParseTarget`, `Esc(string) string`. (`Identity` also carries `Commit`/`PipelineNumber` for the §3.2 mint metadata and §8.1 audit line.)
  - `internal/policy` — §2.3. `Derive(Identity, Prefix) []string`;
    `Attributes`, `Cap`, `AttrKVPath` for attribute names.
  - `internal/broker` — orchestrates §1.2 steps 5–10; owns interfaces:
    `Minter`, `Sweeper`, `Dereferencer` (implemented in `internal/vaultx`).
  - `internal/vaultx` — Vault API client wrapper: AppRole session (§1.3),
    `Mint`, `Sweep`, `Deref`, `RevokeSelf`.
  - `internal/httpapi` — routes (§1.1), handler, metrics.
  - `internal/forge` — §2.5. `TeamResolver` interface and the Gitea-family
    implementation.
- The fork-reference: `woodpecker-ci/example-extensions` (Apache-2.0) is
  reference material for the transport half; ironbark's verification is
  written against `httpsign` directly with the §9.1 matrix.

## 11. Delivery

- `Dockerfile`: static build, distroless/nonroot, `USER` nonzero.
- ironbark's own CI (its Woodpecker pipeline) needs only a registry
  token — stage-2 bootstrap, no Vault dependency (DESIGN §9).
- README gains: deployment walkthrough (Woodpecker env vars incl.
  `WOODPECKER_EXTENSIONS_ALLOWED_HOSTS` gotcha [WP§3], the fail-open
  property [WP§5], netrc-off requirement [WP§11]), the Vault operator
  contract (§3.1 + tier policy examples), and TTL budgeting guidance
  (queue+runtime; mint-at-approval for gated pipelines [WP§12]).

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

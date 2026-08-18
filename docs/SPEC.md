# ironbark M1 — implementation specification

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

Base prefix `POLICY_PREFIX` (default `ci`). For every request derive:

- `P1 = <prefix>/<org>/<repo>/<event>`
- `P2 = <prefix>/<org>/<repo>/<event>/<esc(branch)>` — only for
  **branchful events**: `push`, `pull_request`, `pull_request_closed`,
  `release`, `cron`, and only when branch is non-empty.

`manual` and `deployment` are NEVER branchful — their branch fields are
caller-supplied or inherited, not forge-verified [WP§6]; they get P1
only. `tag` has no branch [WP§6]; P1 only.

`/` in policy names is legal in both products [R§7.2]. Both policies are
requested explicitly on every mint (never an empty list) [R§7.6];
nonexistent ones warn and grant nothing [R§7.1].

### 2.4 KV layout

Mount `KV_MOUNT` (default `kv`, KV v2), prefix `KV_PREFIX` (default
`ci`), base `B = <KV_PREFIX>/<org>/<repo>`:

```
B/<key>                      # all events of the repo
B/<event>/<key>              # event tier
B/<event>/<esc(branch)>/<key># branch tier (branchful events only)
B/.identity                  # reserved: identity binding (§4.4)
B/.config                    # reserved: repo directives (§4.5)
```

Entries whose name begins with `.` are directives, never returned as
secrets, and only recognized at the base level.

## 3. Minting

### 3.1 Token role contract (documented prerequisite, enforced by tests)

The Vault/OpenBao operator provides token role `TOKEN_ROLE` (default
`ci`) with, at minimum:

```
allowed_policies_glob   = ["<POLICY_PREFIX>/*"]   # must cover §2.3 output space
token_type              = "service"               # hard requirement, R§7.4; batch
                                                  # leases would parent to ironbark's
                                                  # own token (research §4)
token_explicit_max_ttl  = <operator choice, e.g. 15m>  # THE lifetime bound — see note
orphan                  = true                    # see §3.3
renewable               = false                   # TTL is the lifetime, full stop:
                                                  # default policy grants renew-self,
                                                  # so a renewable token could outlive
                                                  # the threat model's "dies in minutes"
token_no_default_policy = false                   # default policy is load-bearing:
                                                  # revoke-self powers §3.4
```

**Note on the lifetime bound (integration-verified, 2026-07-16, Vault
1.20 + OpenBao 2.5.5):** the token-store role endpoint
(`auth/token/roles/:name`) does **not** honor a `token_ttl` field — it is
silently dropped (no warning), and a token minted with no request TTL then
inherits the token auth mount's `default_lease_ttl` (32 days by default).
So `token_ttl` on the role is a NO-OP and would leave CI tokens alive for
32 days, defeating the threat model's "dies in minutes." The field that
actually bounds a role-minted token's lifetime is
`token_explicit_max_ttl` (a hard, unrenewable expiry cap the role backend
does honor on both products). ironbark still sends no `ttl` at mint (§3.2);
`token_explicit_max_ttl` is what makes "TTL is the bound" (DEC-260711114102) real.
Operators MUST set it; the M1 integration suite asserts a minted token's
TTL is bounded by it on both products. (Alternatively/additionally the
operator may lower the token mount's `default_lease_ttl` via
`sys/auth/token/tune`, but that is instance-wide; the per-role
`token_explicit_max_ttl` is the correct, scoped control.)

Note on the glob: `allowed_policies_glob` uses plain substring globbing
(`ryanuber/go-glob` — `*` matches ANY characters including `/`; there are
no path-segment semantics) [R§7.6], so the single pattern
`<POLICY_PREFIX>/*` covers every multi-level name §2.3 can derive.

A requested policy outside the glob ERRORS the mint [R§7.6] — the glob is
availability-critical. (M2's doctor verifies template ⊆ glob; M1
documents it and integration-tests it.)

### 3.2 Mint call

`POST auth/token/create/<TOKEN_ROLE>` with:

| Param | Value |
|---|---|
| `policies` | `[P1, P2?]` — always explicit (§2.3) |
| `meta` | `org`, `repo`, `event`, `branch`, `pipeline_number`, `commit` — lands in Vault's audit log |
| `display_name` | `ironbark-<org>-<repo>` |
| `ttl`, `num_uses`, `type` | NOT sent — role config governs; `num_uses` is deliberately unused [R§7.4] |

The `default` policy remains attached (lookup-self, renew-self,
revoke-self — the last is load-bearing for §3.4) [R§7.6].

### 3.3 Orphan vs child

Decision: tokens are minted against the role with `orphan = true` set on
the role, so pipeline tokens do NOT die when ironbark's own AppRole token
rotates or is revoked mid-pipeline. TTL is then the only lifetime bound.
(Without orphan, ironbark's routine re-login could cascade-revoke live
pipeline tokens and their STS leases.)

### 3.4 Revocation

Where this spec says "revoke": call `auth/token/revoke-self`
authenticated as the *minted* token (powered by the `default` policy —
§3.1). The rule is by outcome:

- **Every path that does not return a `200`** — un-onboarded `204`,
  identity mismatch, empty-and-suppressed `204`, and ALL failure paths
  (`502`) — revokes the minted token, even if dereferences already
  created leases: the service-token cascade revokes those leases too,
  which is the desired cleanup since nothing was delivered.
- **A `200` never revokes** — returned dereferenced leases and/or the
  returned `vault_token` must outlive the response (DEC-260711061324); TTL is
  the cleanup.

Revoke failures are logged and do not change the response code
(best-effort; TTL is the backstop).

### 3.5 Startup canary (self-check)

At startup (and after every AppRole re-login), ironbark performs one
canary mint against `TOKEN_ROLE` requesting the single policy
`<POLICY_PREFIX>/ironbark-selftest` (conventional prefix, nonexistent —
warning expected):

- Mint must succeed → proves AppRole capability and that the role glob
  covers the convention prefix [R§7.6].
- Response `token_type` must be `service` → catches the silent
  misconfiguration (G1) without granting ironbark any read on the role.
- Response `renewable` must be `false` (cycle-2 C2-1).
- Orphan status: asserted from the mint response IF the products expose
  it there (cycle-2 G2-3: exposure unverified either way); the privileged
  integration test (§9.3) is the definitive orphan check regardless.
- `auth/token/revoke-self` with the canary token must succeed → proves
  the `default` policy survived role config (C5).

**Canary state is a hard gate on minting** (cycle-2 C2-2): while the
canary state is failed or unknown (startup, or after a re-login whose
canary hasn't passed yet), POST requests return `502` without minting —
a role misconfigured in ways the per-mint assertion cannot see
(non-orphan, renewable, stripped default) must not produce tokens.
Canary failure: log at error with the specific violated expectation;
`/readyz` serves 503.

## 4. Sweep

### 4.1 Read set

All sweep prefixes are derived from the identity a priori — no LIST-based
discovery or descent. Using the minted token, ironbark LISTs each
applicable prefix **independently** (so a least-privilege policy granting
only one tier still works — C2), in this order (most specific first, G2):

1. `LIST <mount>/metadata/<B>/<event>/<esc(branch)>` — branchful events
   with non-empty branch only.
2. `LIST <mount>/metadata/<B>/<event>`
3. `LIST <mount>/metadata/<B>`

From each LIST result, only plain keys at that level are taken —
directory entries are never descended (deeper nesting is NOT swept; v1
constraint, documented). Keys beginning with `.` are NEVER treated as
secret entries at any level (cycle-3 G3-3): at the base level they are
the directive namespace (§2.4); everywhere they are skipped by the
sweep. Every LIST/GET tolerates `403` and `404` by
skipping that level/entry — partial visibility IS the tiering mechanism
(DESIGN §5). Any other status: revoke + `502` (§1.2 step 8). Plain keys
are read via `GET <mount>/data/...`.

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
`$ref` (no chains, no cycles).

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

### 4.4 `.identity` binding

If `GET <mount>/data/<B>/.identity` succeeds and yields
`{"forge_remote_id": <string>}`: compare against the payload's
`forge_remote_id`; mismatch → §1.2 step 7. If the entry is absent (404)
or unreadable (403), the binding is not enforced (opt-in hardening,
written by the M2 module; conventional policies SHOULD grant read on it).
**Fail-closed rules (C1):** if the entry exists but is malformed —
`forge_remote_id` missing, non-string, or empty — treat as a mismatch
(revoke, error log naming the malformation, `204`); a non-403/404 read
error (5xx, timeout) → revoke + `502`. A broken binding must never
silently degrade to "not enforced". This closes the
repo-rename/recreate inheritance hole (DESIGN §3) when enabled.

### 4.5 `.config` directives

`GET <mount>/data/<B>/.config`, optional, all fields optional:

| Key | Type | Effect |
|---|---|---|
| `vault_token` | `"false"` | Suppress returning the minted token |
| `vault_token_images` | comma-separated string | `images` pin on the `vault_token` secret |

Unknown keys ignored (logged at debug). **Fail-closed rules (C1):** a
non-403/404 read error → revoke + `502`; an entry that exists but cannot
be parsed as a flat string map → revoke + `502` with an error log (a
broken directive must never silently fall back to defaults — it may be an
operator's suppression attempt).

### 4.6 Per-secret pins via custom_metadata

If a swept entry's KV v2 `custom_metadata` contains:

| Key | Effect |
|---|---|
| `ironbark_images` | comma-separated → the returned secret's `images` list |
| `ironbark_events` | comma-separated → REPLACES the default event pin (rare; e.g. a secret valid for `push` and `cron`) |

`custom_metadata` is read from the KV v2 data-GET response's metadata
block — no fallback metadata-GET (G3). That the data-GET carries
`custom_metadata` on BOTH products is a named integration-test assertion
(§9.3); if that assertion ever fails, this section is the thing to
re-design, not silently work around.

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
ESO/k8s mounts):

| Var | Default | Notes |
|---|---|---|
| `IRONBARK_LISTEN_ADDR` | `:8080` | |
| `IRONBARK_WOODPECKER_PUBLIC_KEY` / `_FILE` | — (required) | PEM ed25519 |
| `IRONBARK_VAULT_ADDR` | — (required) | Vault/OpenBao URL |
| `IRONBARK_VAULT_ROLE_ID` / `_FILE` | — (required) | AppRole |
| `IRONBARK_VAULT_SECRET_ID` / `_FILE` | — (required) | AppRole |
| `IRONBARK_TOKEN_ROLE` | `ci` | token role name |
| `IRONBARK_KV_MOUNT` | `kv` | KV v2 mount |
| `IRONBARK_KV_PREFIX` | `ci` | |
| `IRONBARK_POLICY_PREFIX` | `ci` | |
| `IRONBARK_FRESHNESS_WINDOW` | `10s` | §5 |
| `IRONBARK_ADVERTISE_VAULT_ADDR` | unset | §6 |
| `IRONBARK_LOG_LEVEL` | `info` | |

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
  only), token_accessor, token_ttl,
  outcome (ok|unonboarded|identity_mismatch|error)`.

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
  - `internal/identity` — §2.1–2.2. `Parse(body []byte) (Identity, error)`, `Esc(string) string`. (`Identity` also carries `Commit`/`PipelineNumber` for the §3.2 mint metadata and §8.1 audit line.)
  - `internal/policy` — §2.3. `Derive(Identity, Prefix) []string`.
  - `internal/broker` — orchestrates §1.2 steps 5–10; owns interfaces:
    `Minter`, `Sweeper`, `Dereferencer` (implemented in `internal/vaultx`).
  - `internal/vaultx` — Vault API client wrapper: AppRole session (§1.3),
    `Mint`, `Sweep`, `Deref`, `RevokeSelf`.
  - `internal/httpapi` — routes (§1.1), handler, metrics.
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

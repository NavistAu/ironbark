# Pre-implementation deep research — 2026-07-11

Method: multi-agent deep-research harness (6 search angles, 24 sources
fetched, 112 claims extracted, top 25 adversarially verified by 3-vote
panels: 22 confirmed, 3 refuted) plus two source-verification workflows
(Woodpecker v3.15.0 — results in `woodpecker-secret-mechanisms.md` §5–§12;
Vault/OpenBao — in flight at time of writing, results to be appended).
Confidence markers reflect the verification votes, not authorial optimism.

## 1. Prior art: effectively none — we are first

- The only concrete OSS CI→Vault broker precedent found,
  **bedag/vault-secret-broker**, is dead: archived 2021, single commit, zero
  stars/forks/releases, GitLab-CI-focused (Concourse/Bamboo roadmap), never
  targeted Woodpecker or Drone. [3-0]
- No OSS Woodpecker secret-extension implementation beyond upstream's
  `example-extensions` was found at all.
- Graveyard lesson: brokers built against one CI's plugin API historically
  did not survive. ironbark's mitigations: the extension protocol is now a
  stable documented contract (below), the broker is deliberately thin
  (stateless, convention), and it solves a live gap upstream has explicitly
  declined to close (issue #929 → "write an extension").
- Unverified lead worth noting: bedag's README describes using Vault
  **response wrapping** so the broker never sees values. Response-wrapping
  the minted token (cubbyhole wrap → pipeline unwraps) is a potential
  hardening for ironbark's token delivery; not evaluated this pass.
- REFUTED [0-3, do not rely on]: two hypotheses about drone-vault's auth
  model (static bearer secret; AppRole with 72h/24h TTL/renewal). Its actual
  mechanism remains unestablished; no comparison to RFC-9421 signing should
  be drawn from it.

## 2. The extension protocol is stable and our premise is validated

- Documented contract: signed POST `{repo, pipeline, netrc?}` → `204` or
  `{secrets: [{name, value, images?, events?}]}`; extension secrets merge
  with and take priority over DB secrets; fail-open on extension
  unreachability (docs agree with our source read). [3-0]
- Signing history: shared-secret HMAC (pre-1.0) → ed25519 per-request
  signing (1.0.0) → formalized as RFC-9421 (3.0.0+). Source-verified at
  v3.15.0: `httpsign` Ed25519Signer over `@request-target` +
  `content-digest`. One stale upstream doc still links draft-cavage; the
  implementation is genuinely RFC-9421. [3-0]
- Woodpecker-native OIDC id-tokens (which would obsolete ironbark's
  verification half): no surviving claim either way this pass — moved to the
  follow-up workflow (discussion #2285 is the lead).

## 3. The JWT-issuer alternative is real and mature — decision pending Track 3

Vault's `jwt` auth method is a credible alternative shape: ironbark would
verify Woodpecker's signature, then issue its own short-lived JWT with
repo/branch/event claims; Vault (configured to trust ironbark's JWKS) does
the token issuance natively via `bound_claims`/`bound_audiences` roles.

Verified mechanics that would govern that design [all 3-0]:
- `role_type: jwt` verifies bearer JWTs against local keys/JWKS/OIDC
  discovery; `bound_claims` = exact match by default, list-OR, optional glob.
- **Vault ≥1.17 gotcha**: if the JWT carries `aud`, the role MUST set
  `bound_audiences` or login fails outright (bit real deployments during
  upgrades).
- `bound_issuer` is single-valued per auth mount — multi-issuer needs
  parallel mounts or per-role claim checks.
- Reusable templates exist: GitLab id_tokens (`aud` +
  `project_path`/`namespace_path`/`ref`/`pipeline_source` bound claims) and
  SPIFFE/SPIRE (Vault trusts SPIRE's OIDC discovery endpoint,
  `bound_subject` per role). ironbark's claims would mirror GitLab's.

What it would buy: Vault-native issuance and audit of the login; policy
binding via claims instead of convention-derived policy names; possibly a
single templated ACL policy (`{{identity.entity.aliases.<accessor>.metadata.repo}}`
in policy paths + `claim_mappings`) replacing per-repo policies entirely —
templating viability is in the follow-up workflow.
What it would cost: ironbark becomes a stateful key-holding issuer (JWKS
endpoint, key rotation); per-repo Vault roles (or templating) still needed;
the pipeline must still exchange the JWT for a token (an extra hop the
sweep currently hides). Decision deferred until the follow-up workflow's
token-role facts land — if `allowed_policies_glob`/nonexistent-policy
minting behave as designed, the current shape stands (DEC-0001/0002); if
not, the JWT route is the fallback with production precedent.

## 4. Token/lease mechanics — one hard requirement found

Verified [3-0], no Vault/OpenBao divergence on this mechanic:
- **Batch tokens are always leaves** (cannot create child tokens) and their
  leases are capped at the batch token's remaining TTL and tracked by the
  batch token's PARENT.
- Service-token leases (incl. children's) revoke in cascade with the token.

**Design consequence (hard): ironbark MUST mint service tokens, not batch.**
A batch-token mint would parent any `$ref`-dereferenced dynamic-secret lease
(AWS STS) to ironbark's own AppRole token — binding pipeline credential
lifetime to ironbark's process credential, exactly the coupling the design
exists to avoid. Service-token cascade is instead the desired behavior:
token expires → its STS leases die with it. (Role `token_type` confirmation
is in the follow-up workflow.)

## 5. KV v2 custom_metadata: confirmed in Vault, OpenBao parity pending

Arbitrary per-secret custom key/value metadata, independent of secret data,
via `vault kv metadata put -custom-metadata k=v` or the metadata API; present
since Vault 1.9, current. [3-0] Supports the proposed per-secret
`events`/`images` pins (§5 of DESIGN.md). OpenBao cross-check was NOT done
this pass — in the follow-up workflow.

## 6. Refuted claims register (do not build on these)

| Refuted claim | Vote |
|---|---|
| drone-vault uses a static pre-shared bearer secret, not signing | 0-3 |
| drone-vault uses AppRole with 72h TTL / 24h renewal | 0-3 |
| Non-root callers can only assign policies from their parent token's policy set (root exempt) | 0-3 |

The third refutation matters: the *actual* rule constraining which policies
a child token may carry is precisely what the follow-up workflow must
establish from `token_store.go` — the folk version of the rule is wrong.

## 7. Follow-up source workflow results (Vault + OpenBao source, adversarially verified)

Method: per-question source-reading agents against `hashicorp/vault` and
`openbao/openbao` main branches (2026-07-11 snapshots), each finding
re-verified by an agent re-fetching every citation. Verifier verdicts noted;
where the verifier CORRECTED the finding, the corrected version is what is
stated here.

### 7.1 Nonexistent policies: the linchpin HOLDS [CONFIRMED, divergence: none]

Token creation performs **no policy-existence validation**. Requested names
pass through `policyutil.SanitizePolicies` (dedupe/lowercase/sort) and a
small `nonAssignablePolicies` blocklist (`response-wrapping`, Vault also
`control-group`); the token persists with whatever names were given, and only
*after* persistence does the create handler loop policies and
`resp.AddWarning("Policy %q does not exist")` — the mint **succeeds**. At
request evaluation, `PolicyStore.ACL()` silently skips names with no stored
policy; they contribute zero grants. Identical control flow in both products
(`vault/token_store.go handleCreateCommon`; OpenBao relocated the policy code
to `vault/policy/`). DEC-0002's "request the full conventional set
unconditionally" mechanism is therefore sound. Implementation note: ironbark
should expect and swallow the per-mint warnings (or surface them in its audit
line), not treat them as errors.

### 7.2 Policy names: `/` legal, always lowercased, two Vault-only reserved names [CORRECTED]

- The CRUD route pattern is `policies/acl/(?P<name>.+)` — `.+` admits `/`,
  so `ci/<org>/<repo>/<event>` **is a legal policy name** in both products.
  Caveat (mechanical inference): `/`-containing names nest in storage, so a
  flat `LIST sys/policies/acl` does not enumerate them — `ironbark doctor`
  and admins must account for that.
- Names are `strings.ToLower(strings.TrimSpace(...))`-normalized on every
  read and write. CONSEQUENCE: the convention must lowercase derived names,
  and two forge repos differing only in case would collide onto one policy
  set — the `.identity` binding and IaC module should reject/flag
  case-colliding repo names.
- No length limit in either product.
- Reserved: `root`, `response-wrapping` (both); Vault-only: `control-group`
  and the entire `default-ceiling` concept (verifier established OpenBao has
  no `default-ceiling` at all — zero occurrences). `default` is
  delete-protected but overwritable in both.

### 7.3 ACL path wildcards [CORRECTED on precedence]

- `+` is a wildcard only as a WHOLE segment (`+/`, `/+`, or bare `+`);
  embedded `+` is literal. Matches exactly one segment.
- Trailing `*` = prefix match; the literal substring `+*` is forbidden;
  combining `+` segments with a trailing `*` elsewhere is legal
  (`secret/+/data*` valid).
- Precedence (verifier-corrected): **most-specific match wins regardless of
  allow/deny** — "deny always wins" is folk wisdom and is only true within a
  single rule's capability set or when multiple policies define the
  *identical* pattern string. CONSEQUENCE: keep conventional policies purely
  additive (no `deny` stanzas) so precedence subtleties can never matter.
- Real divergence: Vault main carries a List-operation precedence CVE fix
  (`resolveACLPermsForListOp`) that OpenBao lacks. Our sweep LISTs
  `kv/metadata/...` paths — integration tests must cover List behavior on
  BOTH products.

### 7.4 Token-role type/TTL/num_uses [CORRECTED on TTL divergence claim]

- **A token role can hard-force `token_type=service`** (role values
  `service`/`batch` force; `default*` are soft). This makes the §4
  service-token requirement *enforceable in Vault config*, not just ironbark
  behavior. Batch requests with `num_uses`/`period`/`explicit_max_ttl` are
  rejected outright.
- `num_uses`: role acts as a cap (min of role/request), and a "use" is
  **every API request** routed with the token — sweep reads, deref reads,
  and every pipeline call each consume one. CONSEQUENCE: `num_uses` is
  unsuitable for ironbark's tokens; resolve the DESIGN.md open question as
  "uncapped, TTL is the bound".
- Renewable: role can force non-renewable.
- TTL merge when role and request both specify: the investigating agent
  claimed Vault does unconditional role-override vs OpenBao lesser-of; the
  verifier REFUTED the divergence (evidence both products do
  lesser-of-with-warning, and the period-requires-sudo gate is long-standing
  shared behavior, hashicorp/vault#3874). Treat as: role value caps, exact
  merge semantics to be pinned by M1 integration tests rather than source
  archaeology.

### 7.5 Woodpecker OIDC trajectory: dormant; ironbark's reason-to-exist is durable [CONFIRMED]

Discussion #2285 ("Add and expose job/trigger context as a JWT") is the sole
thread: open since 2022-08-24, no assignee/milestone/PR ever, maintainer
position "There is no eta. If a dev pick it up and it got reviewed nd
merged, it's done" (6543, 2023). Community workaround
`sloonz/woodpecker-signed-env` (env plugin minting signed JWTs — additional
prior art for the JWT-issuer alternative) is archived. Notable estate-level
item: a commenter notes **Forgejo v16.0 (mid-July 2026) ships scoped
short-lived JWT tokens** — forge-level, does not give Woodpecker pipelines
an identity, but worth tracking for the example.com estate.

### 7.6 `allowed_policies` / `allowed_policies_glob` enforcement [self-verified re-run, divergence: none]

Source: `handleCreateCommon` (Vault, inline) / `resolveTokenPolicies`
(OpenBao, extracted — mechanically identical, byte-diffed).

- **Glob semantics: full glob**, not trailing-prefix — `ryanuber/go-glob`
  via `strutil.StrListContainsGlob`: `*` matches anywhere, any number of
  times (`team-*-readonly`, `*-prod` valid); only `*` is special (no `?`,
  no classes).
- **Violation ERRORS the mint** — `"token policies (%q) must be subset of
  the role's allowed policies (%q) or glob policies (%q)"` /
  `"token policy %q is disallowed by this role"`, both
  `logical.ErrInvalidRequest`. Nothing is silently filtered.
  **CONSEQUENCE (design-shifting):** the role's glob is not merely a
  backstop — it is load-bearing for mint *success*. ironbark requests the
  full conventional name set unconditionally, so the role glob (e.g.
  `ci/*`) MUST cover every name the convention can generate, including
  arbitrary branch-derived names; a too-narrow glob fails the mint outright
  rather than degrading. `ironbark doctor` should verify
  convention-template ⊆ role-glob coverage.
- **Empty policy request** → token gets the role's literal
  `allowed_policies` list (glob entries are NOT expanded; a glob-only role
  yields just `default`). ironbark always requests explicit names, so this
  path must never be taken — send explicit policies on every mint.
- **`default` policy**: added unless the request sets `no_default_policy`,
  the role sets `token_no_default_policy`, or the role disallows it.
  Keeping `default` on minted tokens is useful (lookup-self, renew-self,
  cubbyhole) — working choice: keep it.
- **The role is a complete escape from the child-⊆-parent rule** (the
  subset check branch is never reached when the role defines
  allowed/disallowed lists) with ONE guard that survives: a `root` policy
  cannot be minted unless the parent itself holds root — so a compromised
  ironbark cannot use any glob to reach `root`.

### 7.7 ACL policy templating (JWT-alternative enabler) [self-verified re-run — real divergence found]

- Templating in policy paths works:
  `{{identity.entity.aliases.<mount_accessor>.metadata.<key>}}` is valid in
  paths, and jwt-auth `claim_mappings` populate exactly that alias metadata
  per login (`vault-plugin-auth-jwt/path_login.go`). `role` is a reserved
  mapping key. KV v2 paths are not special-cased. Lookups are
  case-sensitive.
- Missing metadata key → the entire `path` stanza is **silently dropped**
  from the compiled ACL (fail-closed by omission, no error). Wildcards in a
  *resolved* value are always rejected (same silent drop).
- **DIVERGENCE (security-relevant): slash handling in substituted values.**
  Vault: `DenySlashInTemplatedPaths` defaults FALSE — a metadata value
  `org/repo` inserts a literal `/`, extending path depth; a crafted value
  can inject extra segments. OpenBao: blocked-substitution defaults block
  `/` — the same policy silently drops the rule and denies. Same template,
  opposite out-of-the-box behavior.
- History: HCSEC-2021-30 and HCSEC-2022-18 were real alias-metadata
  authorization bugs (fixed) — this mechanism has hurt people before.

### 7.8 OpenBao `custom_metadata` parity

Not independently source-confirmed this pass (deep research confirmed Vault;
OpenBao forked at a version including it, and no removal is documented).
Residual verification item for M1 integration tests, which exercise it
directly anyway.

## 8. Synthesis: verdict on the design

The token-role minting design (DEC-0001/0002/0003) survives the full research
pass intact, and the JWT-issuer alternative is **evaluated and not adopted**:

- The linchpin (nonexistent policies mint clean and grant nothing) is
  source-confirmed in both products (§7.1).
- The role mechanism is *stronger* than assumed: it can hard-force service
  tokens, and the root-escalation guard survives roles — a compromised
  ironbark cannot reach `root` via any glob (§7.4, §7.6).
- The JWT alternative's best feature — one templated policy replacing
  per-repo policies — is undermined by the slash-substitution divergence
  (§7.7): the exact `org/repo`-shaped values ironbark deals in behave
  opposite by default on Vault vs OpenBao, with Vault's default being a
  segment-injection surface and OpenBao's being silent denial. Add the
  statefulness cost (JWKS key management) and the alias-metadata CVE
  history, and the alternative loses on both security and simplicity.
- Revisit triggers: Woodpecker ships native id-tokens (#2285 — dormant), or
  the token-role convention fails operationally in practice.

New obligations the research imposes on the design (folded into DESIGN.md):
role glob coverage is availability-critical (mint errors on gap, §7.6);
always request explicit policies; expect and swallow mint warnings; emit
lowercase secret and policy names; policies additive-only; enforce a
`created` freshness window; treat manual/deploy events as their own trust
tiers; document fail-open loudly; integration tests must run against BOTH
products (List-op precedence and slash-default divergences).

## Sources

Primary: developer.hashicorp.com/vault (auth/jwt, concepts/tokens,
concepts/policies, kv-v2 custom-metadata cookbook), woodpecker-ci.org
(secret-extension docs, extensions overview, migrations), docs.gitlab.com
(id-token conversion, hashicorp_vault), spiffe.io (Vault integration),
HashiCorp Well-Architected Framework (GitLab CI/CD secrets),
github.com/bedag/vault-secret-broker, github.com/drone/drone-vault,
hashicorp/vault issues #2201/#3682/#27343, woodpecker discussion #2285.
Secondary (blog): HashiCorp SPIFFE workload-identity post, DigitalOcean
GitHub-Actions RBAC post, jorijn.com Vault-vs-OpenBao comparison,
dev.to Vault-sprawl governance post.

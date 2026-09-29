# Pipeline attributes — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build [`2026-09-30-pipeline-attributes-design.md`](2026-09-30-pipeline-attributes-design.md)
(the "design"): policies and KV reads for the actor, target and teams of a
pipeline, on top of today's repo/event/branch tiers. The design is the
source of truth and this plan puts it in order. Where the two disagree, stop
and report. Do not pick one.

**Architecture:** `identity.Parse` extracts Actor, Target and CodeAuthor
from the signed payload. A new `internal/forge` package resolves teams
(Gitea-family only). `internal/policy` derives the attribute names in sweep
order and applies the `IRONBARK_MAX_POLICIES` cap. The broker requests
P1/P2 plus the kept attribute names, and `vaultx` sweeps the kept attribute
prefixes in the ironbark-owned attribute mount before today's tiers.
Nothing about P1/P2 or the `kv/` layout changes.

**Tech stack:** Go (module `go` version, mise-managed), stdlib `net/http`,
`log/slog`, `github.com/hashicorp/vault/api`. No new module dependencies.
Integration uses the existing docker-compose Vault 1.20 + OpenBao 2.5.5
fixture (`test/integration/docker-compose.yml`).

**Plan style:** this plan is a spec, not a diff. Steps give signatures,
behaviours, test cases with expected values, and commands. The implementer
writes the code. "Write the failing test" steps list the exact cases and
assertions. They do not paste test bodies.

**Conventions for every task:**
- TDD: failing test → confirm it fails → implement → confirm it passes → commit.
- Unit: `go test ./internal/<pkg> -run <Name> -v`. Before every commit run
  the full `go test ./...` and `go vet ./...` too. The broker's and `ib`'s
  existing tests stay green after every task.
- Integration: `docker compose -f test/integration/docker-compose.yml up -d --wait`,
  then `go test -tags integration ./test/integration/... -run <Name> -v`.
  Every integration case runs against **both** products (loop over
  `products`, as `TestBrokerSuite` does).
- Commit prefixes: `feat:` `fix:` `test:` `docs:` `chore:`.
- Published repo: every example, fixture and test value is generic
  (`acme/widgets`, `itest/*`, `alice`, `ops`, `example.test`). There must be
  no estate hostnames, logins, team names or registry paths anywhere
  (DEC-260723134044).
- Nothing is pushed or posted (git push, `gh pr`, comments) without the
  operator's explicit confirmation for that specific action.

---

## Maintainer rulings

**Pending confirmation. These are implemented as written and flagged:**
1. **`IRONBARK_ACTOR_FORGE` defaults to `none`**, unconditionally. This
   **differs from design §2/§7**, which default it to `gitea` when
   `IRONBARK_FORGE_PROVIDER=gitea`. The validation rule stays: with provider
   `gitea`, only `gitea` or `none` is accepted. Task 20 updates the design
   text once the ruling is confirmed.
2. **Dot-prefixed reserved segments:** `.target`, `.actor`, `.team`,
   `.target-actor`, `.target-team` (design §3).

**Fixed:** actor, target and teams are all in scope. A team lookup fails
closed and drops only the team policies. Attribute policies only grant.
Attribute data lives in an ironbark-owned KV mount. Only development images
are built until the payload facts are verified on real pipelines (Phase 7).
After that comes the release (Phase 8).

## Decisions this plan makes where the design is silent

Each of these is recorded in the code comment at the point of use and in the SPEC delta (Task 18):

- **D1 — Request order:** `[P1, P2?]` first, then the kept attribute names
  in sweep order (design §4 list).
- **D2 — Drop tie-break:** within one drop class, entries with the same
  target depth drop in *reverse* byte order of `esc(team)`. Team policies
  also drop in reverse `esc(team)` order. Across all classes the entry
  dropped first is the one swept last.
- **D3 — Only kept prefixes are swept.** Dropped attribute prefixes would
  403 anyway, so they are not LISTed.
- **D4 — Case:** actor and team values are escaped verbatim, so uppercase
  bytes encode as `%xx` (design §8 "uppercase"). They are never folded. An
  admin names policies with the forge's exact case.
- **D5 — Audit counts:** design §6's "count of requested and
  existing-policy warnings" becomes `policies_requested_count` and
  `policy_warnings_count`.
- **D6 — Repo-teams non-200** (including 404 for a user-owned repo) is a
  lookup failure. It is recorded as `teams_error` and the lookup fails
  closed. The outcome is the same as "no teams", but the operator can see
  it.
- **D7 — Team lookup runs after the canary gate**, so a failed canary never
  makes a forge call. The canary-failed audit line lists only P1/P2.
- **D8 — Payload debug line:** it is kept permanently at debug level (off
  by default). It logs variable *names* only and never variable values.

---

## File structure

```
internal/config/config.go            — §7 vars + validation (modify)
internal/identity/identity.go        — Options, new Identity fields, per-event extraction (modify)
internal/identity/target.go          — target grammar (create)
internal/identity/testdata/payloads/ — recorded/constructed payload fixtures (create)
internal/policy/attributes.go        — Attr, TargetPrefixes, Attributes, Cap, AttrKVPath (create)
internal/forge/forge.go              — TeamResolver interface (create)
internal/forge/gitea.go              — Gitea/Forgejo resolver (create)
internal/vaultx/client.go            — Config.AttrMount (modify)
internal/vaultx/sweep.go             — SweepWithAttributes, mount-parametrised tier helpers (modify)
internal/broker/broker.go            — Options, team lookup, cap, attr sweep, audit fields (modify)
internal/httpapi/server.go           — Parse options, audit fields, debug line (modify)
cmd/ironbark/main.go                 — wiring (modify)
test/integration/readme_policies_test.go — README tier examples, verbatim (create; Task 1)
test/integration/attr_fixture.go     — attribute mount, seed, policies, fake forge (create)
test/integration/attr_test.go        — TestAttributes, TestAttributeIsolation, TestAttrMountStartup (create)
README.md, docs/SPEC.md, docs/CLIENT-SPEC.md, docs/DESIGN.md, CHANGELOG.md, docs/decisionlog/ (modify/create)
```

---

## Phase 0 — README tier-policy fix (independent, ships first)

### Task 1: Correct the README tier examples

The published `pull_request` example grants `kv/data/ci/acme/widgets/*`.
That also reads the `push/main` tier (design §4, §9). The fix does not
depend on anything else in this plan and merges to `develop` on its own,
before any attribute work.

**Branch:** this repo has no worktree task, so create it by hand:
`git worktree add .worktrees/readme-tier-policies -b docs/readme-tier-policies develop`.

**Files:** Modify `README.md` (the "Tier policies" section). Create
`test/integration/readme_policies_test.go`. Modify `CHANGELOG.md`
(`[Unreleased]` → `### Fixed`).

Corrected examples. These are load-bearing, so copy them exactly (`+` is
one segment; the metadata grant is the exact LIST path):

```hcl
# ci/acme/widgets/pull_request   (repo-wide base tier + pull_request event tier)
path "kv/data/ci/acme/widgets/+"                 { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/"              { capabilities = ["list"] }
path "kv/data/ci/acme/widgets/pull_request/+"    { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/pull_request/" { capabilities = ["list"] }

# ci/acme/widgets/push/main      (branch tier only)
path "kv/data/ci/acme/widgets/push/main/+"       { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/push/main/"    { capabilities = ["list"] }
```

Keep the existing "Use exact paths under the tier" paragraph and extend it
by one sentence: `+` matches one segment and `*` crosses `/`, so a tier
policy uses `+` for the key segment.

- [ ] **Step 1: Write the failing test** `TestReadmeTierPolicies` (build
  tag `integration`). It runs per product:
  - A drift guard: the test holds the two HCL blocks as string constants and
    asserts that `../../README.md` contains each one byte-for-byte.
  - Seed `kv/ci/acme/widgets/{base_key, pull_request/pr_key, push/push_key, push/main/main_key}`.
  - Install both policies verbatim (`sys/policies/acl`). Mint one root-created token per policy.
  - pull_request token: GET `base_key` and `pr_key` → 200. GET `push_key`
    and `main_key` → 403. LIST `ci/acme/widgets/push/main` → 403.
  - push/main token: GET `main_key` → 200. GET `base_key`, `pr_key` and
    `push_key` → 403.
  - Regression witness: the *old* example text (kept as a constant in the
    test only) *does* read `main_key`. This proves the test would have
    caught the defect.
- [ ] **Step 2:** Run it → FAIL, because the README still has the old
  text, so the drift guard fails.
- [ ] **Step 3:** Edit `README.md` to the corrected blocks. Add the
  CHANGELOG `Fixed` entry: "README tier-policy example for `pull_request`
  also read the `push/main` tier; examples now scope each tier with `+`
  and an exact metadata path."
- [ ] **Step 4:** Run `TestReadmeTierPolicies` → PASS on vault and openbao.
- [ ] **Step 5:** Commit `fix(docs): README tier policies scoped per tier`.
- [ ] **Step 6:** **Operator gate.** Ask whether to merge
  `docs/readme-tier-policies` into `develop` and push, and whether it also
  goes to `main` now as a docs-only release PR, or rides the next release.
  Do not push or open a PR without that confirmation. After the merge, run
  `git-wt-close docs/readme-tier-policies`.

**Implementation branch for Tasks 2–17:** after Task 1 and this plan's
branch (`docs/pipeline-attributes`) are both on `develop`, run
`git worktree add .worktrees/pipeline-attributes -b feat/pipeline-attributes develop`.
Until Phase 8 this branch is **not** merged to `develop`. That keeps
`develop` releasable while the payload facts are still unverified.

---

## Phase 1 — Configuration and identity

### Task 2: Config — attribute mount, target variable, policy cap

**Files:** Modify `internal/config/config.go` and `internal/config/config_test.go`.

New `Config` fields: `AttrMount string`, `TargetVar string`, `MaxPolicies int`.

| Var | Default | Rule |
|---|---|---|
| `IRONBARK_ATTR_MOUNT` | `ironbark` | Stored with leading and trailing `/` trimmed. Empty after the trim → error. After trimming both, it must not equal `IRONBARK_KV_MOUNT`, and neither may be a `/`-prefix of the other (`a == b`, `strings.HasPrefix(a, b+"/")`, `strings.HasPrefix(b, a+"/")`) → error naming `IRONBARK_ATTR_MOUNT` |
| `IRONBARK_TARGET_VAR` | `DEPLOY_TO` | taken verbatim |
| `IRONBARK_MAX_POLICIES` | `64` | `strconv.Atoi`. Not an integer, or `< 3` → error naming the var |

- [ ] **Step 1: Failing tests** (extend `TestLoad`'s table style):
  - defaults → `AttrMount=ironbark`, `TargetVar=DEPLOY_TO`, `MaxPolicies=64`.
  - `ATTR_MOUNT` = `kv` (the KV default) → error. `kv/attrs` → error. With
    `KV_MOUNT=kv/ci`, `ATTR_MOUNT=kv` → error. `/kv/` → error (trimmed).
    `kvx` → OK. `/ironbark/` → OK, stored as `ironbark`. `/` → error (empty).
  - `MAX_POLICIES` = `3` → OK. `2` → error. `abc` → error. `0` → error.
  - `TARGET_VAR=TARGET` → stored.
- [ ] **Step 2:** `go test ./internal/config -run TestLoad -v` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS. Commit `feat(config): attribute mount, target var, policy cap`.

### Task 3: Config — forge provider and actor forge

**Files:** same as Task 2.

New fields: `ActorForge string`, `ForgeProvider string`, `ForgeURL string`,
`ForgeToken string`, `ForgeTimeout time.Duration`.

| Var | Default | Rule |
|---|---|---|
| `IRONBARK_FORGE_PROVIDER` | `none` | `none` \| `gitea`; anything else → error |
| `IRONBARK_FORGE_URL` | — | required when provider ≠ `none`; must parse (`url.Parse`) as absolute `http`/`https` with a host |
| `IRONBARK_FORGE_TOKEN` / `_FILE` | — | required when provider ≠ `none`, via the existing `requiredSecret` (both set → error). Not read when provider is `none` |
| `IRONBARK_FORGE_TIMEOUT` | `3s` | `time.ParseDuration`, must be `> 0` |
| `IRONBARK_ACTOR_FORGE` | **`none`** (ruling 1, pending) | `none` \| `gitea` \| `github` \| `bitbucket`; anything else → error. With provider `gitea`, only `gitea`/`none` are accepted; `github` or `bitbucket` → error naming both vars |

- [ ] **Step 1: Failing tests:**
  - defaults → provider `none`, actor forge `none`, timeout 3s, no URL/token required.
  - provider `gitea` with no URL → error. With no token → error. Token and
    `_FILE` both set → error. `_FILE` read and trimmed → stored.
  - provider `gitea` with actor forge unset → `none` (ruling 1; the design
    would say `gitea`, so add a comment pointing at this plan's ruling
    note). `gitea` → OK. `github` → error. `bitbucket` → error.
  - provider `none` with actor forge `github` → OK; `bitbucket` → OK;
    `gitlab` → error; `GITEA` → error (values are exact).
  - provider `github` → error. Timeout `0s` → error; `abc` → error.
  - `FORGE_URL=ftp://x` → error. `example.test` (no scheme) → error.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(config): forge provider and actor forge`.

### Task 4: Target grammar

**Files:** Create `internal/identity/target.go` and `internal/identity/target_test.go`.

Signature: `func ParseTarget(s string) (target string, invalid bool)`.
- `""` → `("", false)`, meaning no target. This is not invalid.
- Otherwise the target is valid when: it has at most 256 bytes; splitting
  on `/` gives at most 8 segments; and every segment is non-empty (no
  leading, trailing or doubled `/`). Valid → `(s, false)`. Invalid → `("", true)`.

- [ ] **Step 1: Failing table test** `TestParseTarget`:
  | input | target | invalid |
  |---|---|---|
  | `` | `` | false |
  | `api` | `api` | false |
  | `a/b/c` | `a/b/c` | false |
  | `a/b/c/d/e/f/g/h` (8) | same | false |
  | `a/b/c/d/e/f/g/h/i` (9) | `` | true |
  | `/a` | `` | true |
  | `a/` | `` | true |
  | `a//b` | `` | true |
  | `/` | `` | true |
  | 256 × `x` | same | false |
  | 257 × `x` | `` | true |
  | `.` / `..` / `a/..` | same | false (escaping handles them, design §3) |
  | `Prod/EU` | same | false (case is kept) |
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(identity): target grammar`.

### Task 5: Payload fixtures

**Files:** Create `internal/identity/testdata/payloads/*.json`.

Each fixture is a whole secret-extension body, `{repo, pipeline}`, with
generic values (`acme/widgets`, `forge_remote_id` `"42"`). Build the fields
from Woodpecker v3.18.0 `server/model/pipeline.go` JSON tags: `sender`,
`author`, `deploy_to`, `deploy_task`, `variables` (object of strings),
`reviewed_by`. Put provenance in the Go test file's comment, which says
"constructed from source, Task 23 replaces the rows verified on real
pipelines".

| File | event | sender | author | other |
|---|---|---|---|---|
| `gitea-push.json` | push | `alice` | `alice` | branch `main` |
| `gitea-tag.json` | tag | `alice` | `alice` | |
| `gitea-pull-request.json` | pull_request | `bob` | `bob` | |
| `gitea-manual.json` | manual | `` | `carol` | `variables: {"DEPLOY_TO":"api/eu","OTHER":"x"}` |
| `gitea-manual-no-target.json` | manual | `` | `carol` | no `variables` |
| `gitea-promotion.json` | deployment | `alice` (parent's) | `alice` | `deploy_to:"prod"`, `deploy_task:"migrate"`, parent `variables` |
| `github-deployment.json` | deployment | `dave` | `dave` | `deploy_to:"production"` |
| `gitlab-release.json` | release | `Jane Doe` (display name) | `Jane Doe` | |
| `gitlab-push.json` | push | `` | `jane` | |
| `cron.json` | cron | `` | `` | branch `main` |
| `unknown-event.json` | someday_event | `alice` | `alice` | |

- [ ] **Step 1:** Create the files. `go vet ./...` stays clean.
- [ ] **Step 2:** Commit `test(identity): pipeline payload fixtures`.

### Task 6: Parse — options and attribute extraction

**Files:** Modify `internal/identity/identity.go`,
`internal/identity/parse_test.go`, `internal/identity/esc_test.go`, and
Parse's only non-test caller, `internal/httpapi/server.go`. For that caller
pass `identity.Options{}` for now; Task 12 wires the real options.

API change:

```go
type Options struct {
    ActorForge string // "none" | "gitea" | "github" | "bitbucket"; "" == "none"
    TargetVar  string // manual-run variable naming the target; "" == no manual target
}
func Parse(body []byte, opts Options) (Identity, error)
```

New `Identity` fields: `Actor string`, `Target string`, `TargetInvalid bool`,
`CodeAuthor string`, and `Payload PayloadFacts`.
`PayloadFacts{Sender, Author, DeployTo, DeployTask, ReviewedBy string; VariableNames []string}`
is raw data for the debug line only (Task 12). It is never an input to
policy. `VariableNames` is sorted.

Extraction (design §1). The push family is `push`, `tag`, `pull_request`,
`pull_request_closed`, `release`:

| event | Actor | Target source | CodeAuthor |
|---|---|---|---|
| push family | `sender` iff `ActorForge ∉ {"", "none"}` | none | `sender` |
| `manual` | `author` | `variables[TargetVar]` (exact key) when `TargetVar != ""` | `` |
| `deployment` | `` | `deploy_to` | `` |
| `cron` | `` | none | `` |
| unknown events | `` | none | `` |

The target source passes through `ParseTarget`, which sets
`Target`/`TargetInvalid`. Actor is verbatim (D4). `author` is never used
outside `manual`.

- [ ] **Step 1: Failing tests:**
  - A fixture table (`TestParseAttributes`): every Task 5 fixture ×
    `ActorForge ∈ {none, gitea, github, bitbucket}`, with
    `TargetVar=DEPLOY_TO`, gives the exact `(Actor, Target, TargetInvalid, CodeAuthor)`:
    - `gitea-push` → actor `alice` for gitea/github/bitbucket and `` for
      none. CodeAuthor `alice` in every case.
    - `gitea-manual` → actor `carol` and target `api/eu` for every actor-forge value.
    - `gitea-manual-no-target` → target ``, not invalid.
    - `gitea-promotion` → actor ``, target `prod`, CodeAuthor ``.
    - `github-deployment` → actor ``, target `production`.
    - `gitlab-release` + `none` → actor ``, CodeAuthor `Jane Doe` (verbatim).
    - `gitlab-push` + `none` → actor ``, CodeAuthor ``.
    - `cron` → all empty. `unknown-event` → all empty.
  - `TargetVar=TARGET` on `gitea-manual` → no target. `TargetVar=""` → no target.
  - A manual run whose `DEPLOY_TO` is `a//b` → `TargetInvalid=true`, `Target=""`.
  - `PayloadFacts` on `gitea-promotion` → `DeployTask=migrate`,
    `VariableNames` sorted, `ReviewedBy` as in the fixture.
  - Existing `TestParse` cases still pass once they call `Parse(body, Options{})`.
  - A collision property test (`esc_test.go`, `TestAttrSegmentsNeverEscOutput`):
    for inputs `target`, `actor`, `team`, `target-actor`, `target-team`,
    `.target`, `.actor`, `.team`, `.target-actor`, `.target-team`, `Esc(x)`
    never equals any of the five reserved segments. `Esc(".target") == "%2etarget"`.
    Extend `FuzzEscInjective` (or add a fuzz test) with the assertion
    "output ∉ reserved-segment set".
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS, and the
  full `go test ./...` passes (httpapi still compiles).
- [ ] **Step 5:** Commit `feat(identity): actor, target and code author per event`.

---

## Phase 2 — Attribute names

### Task 7: Attribute derivation in sweep order

**Files:** Create `internal/policy/attributes.go` and `internal/policy/attributes_test.go`.

```go
type AttrKind int // KindTargetActor, KindTargetTeam, KindTarget, KindActor, KindTeam
type Attr struct {
    Kind  AttrKind
    Depth int    // target depth in segments; 0 for actor/team
    Team  string // esc(team); "" unless a team kind
    Rel   string // e.g. ".target-team/a%2fb/ops"
}
func TargetPrefixes(target string) []string              // "a/b/c" → ["a","a/b","a/b/c"]; "" → nil
func Attributes(id identity.Identity, teams []string) []Attr
func AttrKVPath(id identity.Identity, rel string) string // "<org>/<repo>/<event>/<rel>"
```

Behaviour of `Attributes`:
- It uses `id.Target` (empty or `TargetInvalid` means no target
  prefixes), `id.Actor`, and `teams`.
- Teams are escaped. Empty names are dropped, duplicates (after
  escaping) are removed, and the rest are sorted by `esc(team)` byte order.
- Each target prefix `T` is escaped **whole**: `esc("a/b") == "a%2fb"`.
- It returns the design §4 sweep order. For each `T`, deepest first:
  `.target-actor/<esc T>/<esc actor>` (only when the actor is non-empty),
  then `.target-team/<esc T>/<esc team>` for each team. Then
  `.target/<esc T>`, deepest first. Then `.actor/<esc actor>`. Then
  `.team/<esc team>` in team order.
- Teams are only meaningful with an actor. The broker only resolves teams
  when Actor ≠ "", so `Attributes` does not re-check that.

The policy name is `P1 + "/" + Rel`, where P1 is `Derive(...)[0]`.

- [ ] **Step 1: Failing tests:**
  - `TestTargetPrefixes`: `""`→nil, `a`→[a], `a/b/c`→[a a/b a/b/c].
  - `TestAttributes_Order`: manual, target `a/b`, actor `alice`, teams
    `[ops, dev]` → Rels exactly, in order:
    `.target-actor/a%2fb/alice`, `.target-team/a%2fb/dev`, `.target-team/a%2fb/ops`,
    `.target-actor/a/alice`, `.target-team/a/dev`, `.target-team/a/ops`,
    `.target/a%2fb`, `.target/a`, `.actor/alice`, `.team/dev`, `.team/ops`.
  - Target only (deployment `prod`) → `[.target/prod]`. Actor only → `[.actor/alice]`. Neither → empty.
  - `TargetInvalid=true` with an actor → `[.actor/alice]` only.
  - Hostile values are escaped in both the Rel and `AttrKVPath`: actor
    `../x` → `.actor/%2e.%2fx`; team `Ops` → `.team/%4fps`; team `a%b` →
    `.team/a%25b`; target `.target` → `.target/%2etarget`; target `a/.actor/x`
    → one segment, `.target/a%2f.actor%2fx` (and its prefixes `a`, `a/.actor`).
    None of them yield a Rel with more segments than its shape.
  - Teams `[ops, ops, ""]` → one `ops`.
  - Structural property (`TestAttributes_NoPrefixNesting`): over a
    generated set (targets `a`, `a/b`, `target`, `.target`; actors
    `alice`, `target`; teams `ops`, `actor`), no `P1/Rel` is a `/`-prefix
    of another `P1/Rel` or of `P2 = P1/esc(branch)` for branches `target`,
    `actor`, `team`, `.target`, `main`. The segment count per Kind is
    fixed: target 2, actor 2, team 2, target-actor 3, target-team 3.
  - `AttrKVPath(id{org acme, repo widgets, event manual}, ".target/a")` → `acme/widgets/manual/.target/a`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(policy): attribute names in sweep order`.

### Task 8: Policy cap and drop order

**Files:** same as Task 7.

`func Cap(base []string, attrs []Attr, max int) (kept, dropped []Attr)`
- `base` is P1/P2 and is never dropped. `KindActor` is never dropped.
- While `len(base)+len(kept) > max`, drop in this order:
  1. `KindTargetTeam`, deepest `Depth` first, then reverse `Team` order (D2).
  2. `KindTargetActor`, deepest first.
  3. `KindTeam`, reverse `Team` order.
  4. `KindTarget`, deepest first.
- `kept` keeps sweep order. `dropped` is in drop order.

- [ ] **Step 1: Failing tests** use Task 7's 11-attr example (manual, so base = [P1], total 12):
  - `max=64` and `max=12` → nothing dropped.
  - `max=11` → dropped `[.target-team/a%2fb/ops]`.
  - `max=9` → dropped `[.target-team/a%2fb/ops, .target-team/a%2fb/dev, .target-team/a/ops]`.
  - `max=5` → dropped are the 4 target-teams, then `.target-actor/a%2fb/alice`,
    `.target-actor/a/alice`, then `.team/ops`. Kept =
    `[.target/a%2fb, .target/a, .actor/alice, .team/dev]`.
  - `max=3` → kept `[.target/a, .actor/alice]`, 9 dropped, the last of them
    `.target/a%2fb`.
  - Branchful base of 2 (push/main, actor only) with `max=3` → nothing dropped.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(policy): IRONBARK_MAX_POLICIES drop order`.

---

## Phase 3 — Team resolution

### Task 9: `forge.TeamResolver` and the Gitea implementation

**Files:** Create `internal/forge/forge.go`, `internal/forge/gitea.go` and `internal/forge/gitea_test.go`.

```go
type TeamResolver interface {
    Teams(ctx context.Context, org, repo, login string) ([]string, error)
}
func NewGitea(baseURL, token string, timeout time.Duration, hc *http.Client) *Gitea // hc nil → a default client
```

Behaviour. Everything runs under `context.WithTimeout(ctx, timeout)`, which
bounds the *whole* lookup, not each call:
1. `GET {base}/api/v1/repos/{org}/{repo}/teams`, with each segment
   `url.PathEscape`d. Headers: `Authorization: token <token>` and
   `Accept: application/json`. 200 → decode `[{"id":int64,"name":string}]`.
   Any other status → error (D6). The endpoint is unpaginated in Gitea
   and Forgejo; the dev run confirms this (Task 22 checklist).
2. For each team: `GET {base}/api/v1/teams/{id}/members/{PathEscape(login)}`.
   200 → member, 404 → not a member, anything else → error for the whole
   lookup. It never returns a partial list.
3. Return the member teams' names, verbatim.
- Response bodies are read through `io.LimitReader` (1 MiB).
- Error strings name the endpoint shape and the status. They never contain
  the token. A timeout error wraps `context.DeadlineExceeded`.
- There is no caching (design §2).

- [ ] **Step 1: Failing tests** use an `httptest.Server` fake forge:
  - Member of `ops` and not of `dev` → `[ops]`. Assert the auth header,
    both paths, and `url.PathEscape` of a login containing `/`.
  - Repo teams 404 → error. 500 → error. Malformed JSON → error.
  - A membership 500 on one team → error with nil teams, never a partial list.
  - The server sleeps past a 50 ms timeout → error; `errors.Is(err, context.DeadlineExceeded)`; returns in < 1 s.
  - No error string contains the token value.
  - Zero teams → empty, nil error.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(forge): Gitea-family team resolver`.

---

## Phase 4 — Sweep

### Task 10: `vaultx` attribute sweep

**Files:** Modify `internal/vaultx/client.go` (`Config.AttrMount string`),
`internal/vaultx/sweep.go` and `internal/vaultx/sweep_test.go`.

```go
func (c *Client) SweepWithAttributes(ctx context.Context, token string, id identity.Identity,
    branchful bool, attrPaths []string) (SweepResult, error)
```
- `attrPaths` are paths relative to `AttrMount` (from `policy.AttrKVPath`),
  already in sweep order. Each one is swept first, in the given order, as
  `LIST {AttrMount}/metadata/<path>` followed by per-key `GET {AttrMount}/data/<path>/<key>`.
  After that come today's tiers in `KVMount`, unchanged. All of it goes
  through one `sweepAccumulator`, so first-writer-wins spans both mounts.
- The rules are the same as today: plain keys only, no descent, dot-keys
  skipped, 403/404 skipped (a missing mount counts), any other status
  aborts with a plain error, and the partial result is returned.
- Non-empty `attrPaths` with an empty `AttrMount` returns an error. That is
  a wiring bug.
- `Sweep(ctx, token, id, branchful)` becomes
  `SweepWithAttributes(..., nil)`. `cmd/ib` is not touched (design §4:
  `ib` never reads the attribute mount).
- Refactor `sweepTier`/`listTierKeys`/`sweepEntry` to take a `mount string`.
  Do not duplicate them.

- [ ] **Step 1: Failing tests** (the `fakeKV` harness; add a
  `RequestURI` recorder if needed):
  - The attribute LIST precedes every tier LIST. Two attr paths are LISTed
    in the given order.
  - Key `dup` exists at attr `.target/a` and at the branch tier → the
    attribute value wins. At two attr prefixes → the first given wins.
  - Attr LIST 403 → skipped and the tiers are still returned. Attr LIST
    404 (missing mount) → the same.
  - Attr LIST 500 → an error, and no tier LIST follows.
  - A dot-key and a `dir/` entry under an attr prefix → neither read.
  - Wire encoding: attr path `acme/widgets/manual/.target/a%2fb` reaches
    the server with `URL.Path` containing the literal `.target/a%2fb` and
    `RequestURI` containing `%252f`. This is the same encoding the branch
    tier's `feature%2ffoo` already gets. Assert the branch case in the same
    test, so both are pinned.
  - `Sweep` (the old entry point) sends no request to the attr mount.
  - Non-empty `attrPaths` with `AttrMount=""` → an error.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS, including
  every existing `TestSweep_*` and `cmd/ib` test.
- [ ] **Step 5:** Commit `feat(vaultx): sweep attribute prefixes in the attribute mount`.

---

## Phase 5 — Broker, HTTP, wiring

### Task 11: Broker — teams, cap, attribute sweep, audit

**Files:** Modify `internal/broker/broker.go` and `internal/broker/broker_test.go` (mockVault).

- `Vault` interface: replace `Sweep` with `SweepWithAttributes` (same
  signature as Task 10). `*vaultx.Client` must still satisfy it (the
  existing compile-time assertion).
- Options: `type Option func(*Broker)`; `WithTeamResolver(forge.TeamResolver)`;
  `WithMaxPolicies(int)` (default 64). The signature becomes
  `New(v, policyPrefix, advertiseVaultAddr string, opts ...Option)`, so the
  existing call sites compile unchanged.
- `AuditFields` gains `Teams []string`, `TeamsError string` and
  `PoliciesDropped []string` (full policy names).
- The `Handle` sequence changes only before the mint and at the sweep:
  1. `base := policy.Derive(...)`. Canary gate as today (D7).
  2. If `id.Actor != ""` and a resolver is set, call
     `resolver.Teams(ctx, id.Org, id.Repo, id.Actor)`. On error, teams is
     nil and `TeamsError = err.Error()`. The request continues; a lookup
     never fails it.
  3. `attrs := policy.Attributes(id, teams)`, then `kept, dropped := policy.Cap(base, attrs, max)`.
  4. `policies = base ++ [base[0]+"/"+a.Rel for a in kept]` (D1).
     `PoliciesRequested = policies`.
  5. Mint, token-type check, un-onboarded check (`allWarned` over all
     requested names — unchanged), `.identity`, `.config` — all as today.
  6. `SweepWithAttributes(ctx, token, id, branchful, [policy.AttrKVPath(id, a.Rel) for a in kept])`.
     It gets nil when there are no attributes (D3).

- [ ] **Step 1: Failing tests:**
  - Backwards compatibility: push/main with no actor/target → policies ==
    `Derive` output; `attrPaths` is empty; there are no new audit values.
    All existing `TestHandle_*` tests pass with the mock renamed.
  - Manual, target `a/b`, actor `alice`, no resolver → requested = P1 +
    6 names in Task 7 order (no team kinds). `attrPaths` are the
    matching `acme/widgets/manual/...` paths in the same order.
  - A resolver returning `[ops]` is called once with `(org, repo, "alice")`
    and the team names appear. `Audit.Teams == [ops]`.
  - Deployment (actor empty) → the resolver is not called.
  - Resolver error → status 200, no `.team`/`.target-team` names,
    `TeamsError` is set, and the target/actor names are still requested.
  - Canary failed → the resolver is not called (D7).
  - `WithMaxPolicies(3)` on the manual example → requested = `[P1, …/.target/a, …/.actor/alice]`.
    `PoliciesDropped` holds the 9 full names in drop order. `attrPaths` has 2 entries.
  - Every requested name warned → 204 unonboarded. Only P1 warned (an
    attribute policy exists) → the request proceeds.
  - `TargetInvalid` → no target names.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(broker): request and sweep attribute policies`.

### Task 12: HTTP — parse options, audit line, debug line

**Files:** Modify `internal/httpapi/server.go`, `internal/httpapi/server_test.go`,
and `test/integration/e2e_test.go` (constructor call only).

- `httpapi.New` gains a final parameter, `parseOpts identity.Options`,
  which is passed to `identity.Parse`.
- The verified-request audit line (design §6) adds `actor`, `target`,
  `target_invalid`, `code_author`, `teams`, `teams_error`,
  `policies_dropped`, `policies_requested_count` and `policy_warnings_count`
  (D5). The refused-signature line is unchanged: no payload fields.
- The debug line `"payload attributes"` is emitted at debug level after a
  successful parse. It carries `event`, `sender`, `author`, `deploy_to`,
  `deploy_task`, `variable_names`, `reviewed_by`, `actor`, `target`,
  `target_invalid` and `code_author` (D8). There are never variable values.

- [ ] **Step 1: Failing tests** use a captured JSON log buffer:
  - A signed `gitea-manual.json` body with `Options{TargetVar:"DEPLOY_TO"}`
    reaches the handler with `Target == "api/eu"` and `Actor == "carol"`.
  - The audit line has every new key and the correct counts.
  - At debug level the payload line has `variable_names ["DEPLOY_TO","OTHER"]`,
    and the string `"x"` (OTHER's value) appears nowhere in the log. At
    info level there is no payload line.
  - A refused signature → the log has none of the new keys.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(httpapi): attribute audit fields and payload debug line`.

### Task 13: Wiring

**Files:** Modify `cmd/ironbark/main.go`.

- `vaultx.Config.AttrMount = cfg.AttrMount`.
- `identity.Options{ActorForge: cfg.ActorForge, TargetVar: cfg.TargetVar}` → `httpapi.New`.
- Broker options: `WithMaxPolicies(cfg.MaxPolicies)`. When
  `cfg.ForgeProvider == "gitea"`, also
  `WithTeamResolver(forge.NewGitea(cfg.ForgeURL, cfg.ForgeToken, cfg.ForgeTimeout, nil))`.
- The startup log line adds `attr_mount`, `actor_forge` and
  `forge_provider`. It never logs the token.

- [ ] **Step 1:** Implement (wiring has no unit test).
- [ ] **Step 2:** `go build ./cmd/ironbark && go test ./... && go vet ./...`, and `golangci-lint run` (v2.12, as in CI) → clean.
- [ ] **Step 3:** Commit `feat(cmd): wire pipeline attributes`.

---

## Phase 6 — Integration (Vault and OpenBao)

### Task 14: Attribute fixture

**Files:** Create `test/integration/attr_fixture.go`.

`setupAttrFixture(t, ctx, root *api.Client)` must be idempotent: use
`ensureMount` and overwrite writes. Layout, with org `itest`, repo `attrs`
(`RepoAttrs`) and event `manual`:
- It mounts KV v2 at `ironbark`. `kv` already exists.
- Ordinary tiers in `kv`: `ci/itest/attrs/tier_base = {value}` and `ci/itest/attrs/manual/tier_event = {value}`.
- Attribute data in `ironbark/itest/attrs/manual/`, one key per shape. The
  key names are unique, so a leak is identifiable:
  `.target/a/k_target_a`, `.target/a%2fb/k_target_ab`,
  `.target-actor/a/alice/k_ta_a_alice`, `.target-team/a/ops/k_tt_a_ops`,
  `.target-actor/a%2fb/alice/k_ta_ab_alice`, `.actor/alice/k_actor`,
  `.team/ops/k_team`, and `.actor/bob/k_actor_bob`.
  Collision key: `dup` at `.target/a` (`attr-dup`) and at `kv` base
  (`tier-dup`). Unswept nested key: `.target/a/nested/deep`.
- Policies in `+` form, one per prefix above, named `ci/itest/attrs/manual/<rel>`
  (read `ironbark/data/itest/attrs/manual/<rel>/+`, list `ironbark/metadata/itest/attrs/manual/<rel>/`).
  Plus `ci/itest/attrs/manual` (P1) granting only the two ordinary tiers in `+` form.
- `attrShapes`: an exported-in-package table of `{rel, key, policyName}`
  that the isolation tests iterate.
- `fakeForge`: an `httptest.Server` for the two Gitea endpoints, with
  settable membership (`alice ∈ ops`) and a settable response delay.
- The seed and policy writes go through the vault `api` client, so `%` in
  paths travels as `%25` (Task 10's pinned encoding).

- [ ] **Step 1:** Implement, plus a smoke test `TestAttrFixture` that
  asserts LIST of `ironbark/metadata/itest/attrs/manual/.target/` returns
  exactly `a/` and `a%2fb/` as two entries — not a nested `a/b/`. It must
  pass on both products.
- [ ] **Step 2:** Commit `test(integration): attribute fixture`.

### Task 15: Names, grants and overflow through the broker

**Files:** Create `test/integration/attr_test.go` (`TestAttributes`).
The broker is built as in `TestBrokerSuite`, with `AttrMount: "ironbark"`.

- [ ] **Step 1: Write the failing cases** (per product):
  - `dot_and_pct_accepted`: `sys/policies/acl/ci/itest/attrs/manual/.target/a%2fb`
    reads back with exactly that name. A root-minted token with that
    policy lists it verbatim in `policies`.
  - `target_only_grant`: a manual run with target `a` and actor `bob`
    returns `k_target_a` and `dup`, with `dup`'s value `attr-dup`
    (attribute beats tier). It returns neither `k_ta_a_alice` nor `k_tt_a_ops`.
  - `conjunction_needs_actor`: target `a/b`, actor `alice` →
    `k_ta_ab_alice`, `k_ta_a_alice`, `k_target_ab`, `k_target_a`,
    `k_actor`, `tier_base`, `tier_event`. There is no `k_actor_bob` and no
    team key (no resolver).
  - `teams_via_fake_forge`: a resolver on `fakeForge` → `k_tt_a_ops` and `k_team` added. `Audit.Teams == [ops]`.
  - `overflow_drops_only_attributes`: `WithMaxPolicies(3)` for target
    `a/b`, actor `alice`, team `ops` → the mint succeeds with 3 policies (P1,
    `.target/a`, `.actor/alice`). The secrets are exactly `k_target_a`,
    `k_actor`, `tier_*` and `dup`. `Audit.PoliciesDropped` is non-empty and
    holds no P1 and no actor name.
  - `e2e_manual_payload`: a signed manual payload with
    `variables.DEPLOY_TO="a"` goes through the `httpapi` stack (the e2e
    helpers, parse options set) → `k_target_a` is in the response.
- [ ] **Step 2:** FAIL until Tasks 14 and earlier are in. If it fails for
  any other reason, debug it (superpowers:systematic-debugging).
- [ ] **Step 3:** PASS on vault and openbao. Commit `test(integration): attribute grants and overflow`.

### Task 16: Team lookup fails closed

**Files:** `test/integration/attr_test.go`.

- [ ] **Step 1: Case** `team_timeout_fails_closed`: the `fakeForge` delay
  is 2 s and the resolver timeout 200 ms. Target `a`, actor `alice` →
  status 200, `Audit.TeamsError` is non-empty, there is no `k_tt_a_ops` or
  `k_team`, `k_target_a` and `k_actor` are present, and `Handle` returns
  in < 1.5 s. Case `team_500_fails_closed` is the same with a 500 response.
- [ ] **Step 2:** Run → PASS on both products. Commit `test(integration): team lookup fails closed`.

### Task 17: Attribute isolation

**Files:** Create `test/integration/attr_isolation_test.go` (`TestAttributeIsolation`).
Tokens are created by root via `auth/token/create` with explicit
`policies`. Every assertion runs on both products.

- [ ] **Step 1: Ordinary-tier tokens reach no attribute data.** For each
  of these policies (installed under `iso-*` names):
  - the corrected README blocks from Task 1, verbatim
  - the *old* README `pull_request` block, verbatim
  - `kv/data/ci/itest/attrs/*` and `kv/metadata/ci/itest/attrs/*` (read, list)
  - `kv/data/ci/*` and `kv/metadata/ci/*`
  - `kv/*` (read, list)
  - `kv/+/ci/itest/attrs/*`, and `kv/data/+/+/+/*` with `kv/metadata/+/+/+/*`

  Assert: 403 on LIST of every `attrShapes` prefix, and on GET of every
  attribute key including `nested/deep`. `SweepWithAttributes` with all
  attribute paths returns no `k_*` attribute key name.
- [ ] **Step 2: A single attribute policy reaches exactly its own prefix.**
  For each shape, in both the `+` form (the fixture policy) and a
  trailing-`*` form (`iso-star-<shape>`: read `…/<rel>/*`, list `…/<rel>/*`
  and `…/<rel>/`):
  - It reads its own key(s): a 200 GET, and its LIST includes the key.
  - It gets 403 on every other shape's LIST and GET. Explicitly: the
    target-`a` policy on `.target/a%2fb` and on both conjunctions on `a`;
    the `.actor/alice` policy on `.target-actor/a/alice` and
    `.target-actor/a%2fb/alice`; the `.team/ops` policy on `.target-team/a/ops`.
  - `*` form only: GET `.target/a/nested/deep` → 200 (documented design
    §4). The sweep with that token does **not** return `deep`.
- [ ] **Step 3: The corrected README tiers stay isolated.** Re-assert
  Task 1's per-tier 200/403 matrix inside this test, so the isolation suite
  is complete on its own.
- [ ] **Step 4: Startup and a missing mount** (`TestAttrMountStartup`):
  - Build `./cmd/ironbark` into `t.TempDir()` (the same pattern as
    `buildIBBinary`). Run it with valid required env (e2e key, dummy
    Vault address) and `IRONBARK_ATTR_MOUNT` ∈ {`kv`, `kv/attrs`, `/kv/`}.
    Expect exit code 1 and stderr naming `IRONBARK_ATTR_MOUNT`. Also
    `IRONBARK_KV_MOUNT=kv/ci` with `IRONBARK_ATTR_MOUNT=kv` → exit 1.
  - A broker built with `AttrMount: "ironbark-absent"`, for target `a` and
    actor `alice` → 200, and the secrets equal the no-attribute baseline
    (`tier_base`, `tier_event`, `dup`=`tier-dup`).
- [ ] **Step 5:** PASS on both products. Also run
  `go test -tags integration ./test/integration/...` (whole suite) → green.
  Commit `test(integration): attribute isolation`.

---

## Phase 6b — Documentation

### Task 18: SPEC deltas

**Files:** Modify `docs/SPEC.md`.

- [ ] Change these sections: §2.1 (the new Identity fields and the
  extraction table from Task 6); §2.3 (attribute names, conjunctions,
  reserved dot segments, whole-prefix `esc(T)`, request order D1,
  `IRONBARK_MAX_POLICIES` and the drop order with D2); §2.4 and §4.1 (the
  attribute mount, the five KV shapes, the read order, D3, 403/404 incl. a
  missing mount); §4.3 (the pointer note from design §4); §7 (the eight
  vars, `IRONBARK_ACTOR_FORGE` default `none` per ruling 1); §8.1 (the
  audit fields, D5, the debug line D8); §9.2/§9.3 (the unit and
  integration lists from design §8, pointing at the test names added
  here); §10 (the `internal/forge` package).
- [ ] State the grant-only rule and the team-trust paragraph (design §2, §3) normatively.
- [ ] Commit `docs(spec): pipeline attributes`.

### Task 19: README, CLIENT-SPEC, DESIGN, CHANGELOG

**Files:** Modify `README.md`, `docs/CLIENT-SPEC.md`, `docs/DESIGN.md` and `CHANGELOG.md`.

- [ ] README "operator contract": add the attribute-mount prerequisite
  `vault secrets enable -path=ironbark -version=2 kv`. Add one policy
  example (generic):
  ```hcl
  # ci/acme/widgets/manual/.target/api
  path "ironbark/data/acme/widgets/manual/.target/api/+"  { capabilities = ["read"] }
  path "ironbark/metadata/acme/widgets/manual/.target/api/" { capabilities = ["list"] }
  ```
  Also state:
  - attribute data is never under `kv/`, so tier policies cannot reach it
  - attribute policies only grant; never rely on them to deny
  - a target-only policy scopes but does not restrict *who*; use a conjunction for that
  - team membership is forge-owned
  - raw-HTTP writers must encode `%` as `%25` in KV paths
- [ ] README config table: add the eight rows from design §7, with
  `IRONBARK_ACTOR_FORGE` default `none`.
- [ ] CLIENT-SPEC §0: qualify "same secrets as a CI run" to the
  repo/event/branch tiers, and say that `ib` never reads the attribute
  mount (design §4).
- [ ] DESIGN §5 (the convention): one paragraph and a link to the design doc.
- [ ] CHANGELOG `[Unreleased] → Added`: pipeline attributes, the new
  config vars, and the audit fields.
- [ ] Re-run `TestReadmeTierPolicies` (the drift guard) → PASS.
- [ ] Commit `docs: pipeline attributes in README, CLIENT-SPEC, DESIGN`.

### Task 20: Decision log and design status

**Files:** Create entries in `docs/decisionlog/` (MADR, the existing
front-matter shape, id `YYMMDDHHMMSS`). Modify the design doc's status line
and, if ruling 1 is confirmed, its §2/§7 default text.

- [ ] **Operator gate:** confirm rulings 1 and 2, and D1–D8. If ruling 1
  is reversed, change Task 3's default and test, SPEC §7, and the README
  row before continuing.
- [ ] Use the decision-log skill to write one entry per item in design
  "Decisions to log on acceptance" (7 entries). Ruling 1 goes inside the
  actor-source entry. Each entry lists the rejected alternatives the
  design names.
- [ ] Commit `docs(decisionlog): pipeline attributes`.

---

## Phase 7 — Development image and payload verification

No release until this phase passes. Every command and value in the
published repo stays generic. The operator supplies the registry and the
deployment.

### Task 21: Build and deploy a development image

- [ ] Version stamp: `DEV_VERSION="$(cat VERSION)-attrs.$(git rev-parse --short HEAD)"`.
- [ ] Build to the operator's registry, never `ghcr.io/navistau/ironbark`:
  `VERSION="$DEV_VERSION" KO_DOCKER_REPO=<registry>/<path> ko build ./cmd/ironbark --bare --tags "$DEV_VERSION"`.
  Use ko v0.18.0 (see `.woodpecker.yaml`) and
  `KO_DEFAULTBASEIMAGE=gcr.io/distroless/static-debian12:nonroot`.
  Record the image digest.
- [ ] **Operator step** (their deployment, their IaC; the agent does not
  change the host state):
  - Deploy the digest with `IRONBARK_LOG_LEVEL=debug` and
    `IRONBARK_ACTOR_FORGE` set for the forge.
  - Optionally set `IRONBARK_FORGE_PROVIDER=gitea` with its URL and a
    read-scope token.
  - Create the `ironbark` KV v2 mount.
  - For one test repo, create one `.target/<t>` policy and key, one
    `.actor/<login>` policy and key, and (if teams are on) one
    `.team/<team>` policy and key.
- [ ] Confirm the startup log reports `version=$DEV_VERSION`, `attr_mount`,
  `actor_forge` and `forge_provider`, and that `/readyz` is 200.

### Task 22: Verification runs

Capture the debug `"payload attributes"` line and the audit line for each
run. Tick a row only with that evidence.

- [ ] **Push** to a branch: `sender` = the pusher's login. `actor` =
  `sender` (or empty with actor forge `none`). `code_author` = `sender`.
  `target` is empty. With teams on, `teams` lists the pusher's teams and
  the forge accepted the unpaginated repo-teams call.
- [ ] **Manual run with a target variable** (`DEPLOY_TO=<t>`): `sender`
  is empty. `author` = the login of whoever started the run, and
  `actor = author`. `target = <t>`. `variable_names` includes `DEPLOY_TO`.
  The `.target/<t>` key is present in the pipeline's secrets.
- [ ] **Deployment promotion** (promote a finished pipeline with
  `deploy_to=<t>` and `deploy_task=<k>`):
  - `deploy_to` and `deploy_task` are present.
  - `sender`/`author` equal the *parent's* values. Record them as seen.
  - `actor` is empty. `code_author` is empty.
  - `variable_names` equal the parent's; the promotion's other query
    parameters do not appear.
  - The `.target/<t>` key is present.
- [ ] **Approval-gated run** (a repo that requires approval): the extension
  call fires on approval, and `reviewed_by` is **empty** at call time.
- [ ] Any row that disagrees with design §Payload facts → **stop**. Amend
  the design (it goes back through review) before any more work. Do not
  paper over it in code.

### Task 23: Replace constructed fixtures with captured payloads

**Files:** `internal/identity/testdata/payloads/`, `internal/identity/parse_test.go`.

- [ ] For each verified run, redact the captured body to generic values.
  Keep every field shape and emptiness exactly as captured; change only
  the identifying strings (`acme/widgets`, `alice`, …). Then replace the
  matching constructed fixture: `gitea-push`, `gitea-manual`,
  `gitea-promotion`, and an approval case `gitea-approved.json`.
- [ ] Update the provenance comment: which fixtures are captured (with
  the Woodpecker version) and which are still constructed from source
  (`github-deployment`, `gitlab-*`, `cron`).
- [ ] `go test ./internal/identity -v` → PASS. Commit `test(identity): payload fixtures captured from real pipelines`.

---

## Phase 8 — Release (per `docs/releasing.md`)

### Task 24: Integrate

- [ ] Rebase `feat/pipeline-attributes` on `develop`. Then run
  `go test -race ./...`, `go vet ./...`, `golangci-lint run`, and the
  integration suite (both products). All must be green.
- [ ] **Operator gate:** confirm the merge. Then, from a checkout that is
  on `develop`, run `git merge --no-ff feat/pipeline-attributes`, then
  `git-wt-close feat/pipeline-attributes`.

### Task 25: Cut the release

- [ ] releasing.md §1: set `VERSION` to the next minor (e.g. `0.1.2` → `0.2.0`; this adds features).
- [ ] §2: `CHANGELOG.md` — move `[Unreleased]` into `## [0.2.0] - <date>`.
  That includes `ib` if it is still unreleased, the README fix if it has
  not shipped, and the attributes.
- [ ] §3: docs currency check — README Status, config reference and
  Install; SPEC; DESIGN; decisionlog — against each other.
- [ ] Commit `chore(release): v0.2.0` on `develop`.
- [ ] §4: **Operator gate for each action:** `git push origin develop`,
  then `gh pr create --base main --head develop --title "Release v0.2.0" --fill`.
  Posting the PR needs explicit confirmation. Merge only when all CI jobs
  are green (vet, race tests, lint, the Vault + OpenBao integration). The
  merge is the release (§5).
- [ ] §6: verify the publish — anonymous pull, `go install …@v0.2.0`,
  `cosign verify`, the release page, the version in the startup log, and
  the package page README.
- [ ] Replace the development image in the operator's deployment with
  the release digest (their IaC). Drop `IRONBARK_LOG_LEVEL=debug` unless
  they want it.

---

## Self-review against the design

| Design § | Tasks |
|---|---|
| Payload facts | 5, 6, 22, 23 |
| §1 attributes, target grammar | 4, 6 |
| §2 teams, fail-closed, config coupling | 3, 9, 11, 16 |
| §3 names, conjunctions, dot segments, cap | 6 (collision), 7, 8, 11, 15 |
| §4 attribute mount, layout, sweep order, pointer note, `ib` exclusion | 2, 10, 14, 17, 18, 19 |
| §5 no directives | nothing to build; stated in SPEC (18) |
| §6 audit line | 11, 12 |
| §7 configuration | 2, 3, 13, 19 |
| §8 verification (unit, integration, isolation, pre-release runs) | 4–12, 14–17, 21–23 |
| §9 documentation, README fix first | 1, 18, 19 |
| Decisions to log | 20 |

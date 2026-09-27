# ib — the ironbark local client (M3)

Status: draft for review. Roadmap: [DESIGN §10 M3](DESIGN.md#10-milestones).
Normative companion to [SPEC.md](SPEC.md) (the broker). Section references
of the form "SPEC §n" point there.

## 0. Scope

`ib` gives a local run — an operator's shell, an agent, a script — the same
secrets a CI run on the same repository and environment would get, read
from the same KV layout (SPEC §2.4) the broker sweeps, subject to the
divergences named in §6. One layout, one resolution algorithm, two
callers: the broker for CI, `ib` for everything else.

In scope: resolving secrets for a local checkout; delivering them as a
single value, an env file, or a child process environment.

Out of scope: minting tokens, signature verification, Woodpecker, writing
to Vault, managing policies. `ib` never grants anything: every read is made
with the caller's own token, so the caller's Vault policy is the only
bound on what `ib` returns (§6).

## 1. Commands

`get`, `env`, and `run` each also accept a global `--branch <name>` (or
`IB_BRANCH=<name>`) override, §3 rule 1; omitted from the synopses below
for brevity. `auth` takes no such flag — it has no environment to select.

### 1.1 `ib auth [args…]`

Convenience wrapper over the Vault/OpenBao CLI login. Runs `bao login
[args…]` if `bao` is on `PATH`, else `vault login [args…]`, else fails
with a message naming both. Arguments pass through unchanged (method,
path, username). The token lands wherever that CLI's token helper puts
it, but `ib` itself only reads it back from the default location,
`~/.vault-token` (§5.1) — a `bao`/`vault` config pointing `token_helper`
elsewhere breaks the `ib auth` → `ib get` handoff. `ib auth` adds nothing
else — no token storage of its own.

### 1.2 `ib get <name>`

Resolves the checkout's environment (§3), sweeps it (§4) and writes the
value of secret `<name>` to stdout. `<name>` is the final secret name as
the sweep produces it (SPEC §4.2 naming: lowercase, `[a-z0-9_]+`, general
entries as `E_f`). A trailing newline is written only when stdout is a
terminal. Unknown name → exit 3 (§7).

### 1.3 `ib env`

Resolves and sweeps as `get`, then writes every secret to stdout as one
line per secret:

```
SECRET_<NAME>=<quoted value>
```

`<NAME>` is the secret name upper-cased. `<quoted value>` is
single-quoted; an embedded `'` is written as `'\''`; newlines are kept
literally inside the quotes. The output is valid for POSIX `sh` `.`/
`source` and for `ib run --env-file`. Values are on disk if redirected to
a file — `ib env` is the break-glass path; `ib run` is the normal one.

### 1.4 `ib run [--env-file <file>]… [--no-masking] -- <cmd> [args…]`

Runs `<cmd>` with an environment built from:

1. the caller's environment, then
2. each `--env-file` in order (later files override earlier ones), where
   a value of the exact form `ironbark://<name>` is replaced by secret
   `<name>` from the sweep, and any other value is passed through as is.

Env file syntax: `KEY=value` entries, one per logical line; blank lines
and lines starting with `#` outside any open quote are ignored; `KEY` must
match `[A-Za-z_][A-Za-z0-9_]*`; a value may be single- or double-quoted
(quotes stripped, no escape processing beyond `'\''` in single quotes).
Parsing is quote-aware: a quoted value's closing quote, not end-of-line,
ends the entry, so a literal newline inside an open quote (as `ib env`,
§1.3, emits) is part of the value, not a line break. A file written by
`ib env` is valid input.

A reference to a name the sweep did not produce → exit 3 before `<cmd>`
starts; `ib run` never starts a command with a half-resolved environment.

The sweep runs once per `ib run`, and only if at least one value is an
`ironbark://` reference.

**Masking** (default on): every resolved value of length ≥ 4 is replaced
by `<concealed by ib>` in the child's stdout and stderr, which `ib` pipes
through, scanning as a byte stream rather than line-by-line (so a match
split across two reads is still caught) and matching longest-value-first
(so one resolved value that is a substring of another is never left
partially exposed). `--no-masking` passes the child's stdio through
untouched (use for interactive commands). Masking is a guard against
accidental logging, not a security boundary — the child holds the values.

Exit status is the child's. Signals received by `ib` are forwarded to the
child.

**Leases.** If any resolved secret came from a lease-bearing deref
(SPEC §4.3, e.g. a dynamic-engine credential), `ib run` revokes each such
lease after the child exits by its `lease_id` (`PUT sys/leases/revoke`),
authenticated with the caller's own token — never
`auth/token/revoke-self`, which would revoke the caller's actual Vault
session, not a lease. This is every lease the sweep created, referenced
or not — not only the leases behind values actually substituted into the
child's environment. This needs the caller's policy to grant `update` on
`sys/leases/revoke` (or the lease's own prefix); a revoke failure is
logged to stderr and does not change `ib run`'s exit status (best-effort,
matching SPEC §3.4's revoke philosophy — the lease's TTL is the backstop).
`get` and `env` leave leases to expire on their TTL, and say so on stderr.

## 2. Identity

`ib` builds the same identity shape as the broker (SPEC §2.1) from the
checkout, never from flags:

- **Org / repo:** from the `origin` remote URL (`git remote get-url
  origin`). Accepted forms: `https://host[:port]/org/repo[.git]`,
  `ssh://[user@]host[:port]/org/repo[.git]`, `[user@]host:org/repo[.git]`.
  The last two path segments are org and repo, lowercased (SPEC §2.1).
  The host is not part of the identity. No `origin`, or a URL that does
  not parse → exit 2.
- **Event:** always `push`. A local run reads what a push to the chosen
  branch reads.
- **Branch:** chosen by §3.

The checkout is located with `git rev-parse` (so linked worktrees, whose
`.git` is a file, work unchanged). A detached `HEAD` is valid.

`.identity` (SPEC §4.4) is not checked: `ib` has no forge-verified remote
id to compare against — see §6 for the security implication where an
operator relies on `.identity` hardening. `.config` (SPEC §4.5) is not
read: `vault_token` suppression concerns tokens handed to pipelines, and
`ib` hands out none — but its fail-closed enforcement (§4.5) is skipped
too; see §6.

## 3. Environment (branch) selection

Which branch's tiers to read is an **environment choice, not access
control**. The checkout is local and editable; nothing in this section is
trusted for authorization — the caller's policy is (§6).

**Tracked branches** are the branch directories under
`<mount>/metadata/<B>/push/` that the caller's token can LIST (SPEC §2.4
layout). They are matched against `T`, the short name of each
remote-tracking branch (`origin/T` with the `origin/` remote prefix
stripped — never the full ref), by escaping `T` with SPEC §2.2 `Esc` and
comparing — no unescaping. `origin/T`, ref intact, is used only for the
ancestry and freshness checks below.

Selection, in order; the first rule that yields one branch wins:

1. **Override.** `--branch <name>` or `IB_BRANCH=<name>` → that branch.
   It must be tracked, else exit 4.
2. **Direct match.** The checked-out branch is tracked → it.
3. **Nearest ancestor.** For each tracked branch `T` with a remote-tracking
   ref `origin/T`: `d(T)` = number of commits in `HEAD` not in `origin/T`
   (`git rev-list --count origin/T..HEAD`). Branches with no common
   ancestor with `HEAD` are dropped. Lowest `d` wins.
4. **Tie → reflog.** If the checked-out branch's reflog creation entry
   (`branch: Created from <ref>`) names one of the tied branches (as `T`
   or `origin/T`), it wins. In a detached `HEAD` there is no checked-out
   branch and therefore no branch reflog entry to consult — this rule is
   skipped and rule 5 applies directly.
5. **Tie → cascade.** The first tied branch in the cascade list wins.
   Built-in list, least to most production-like, so an unresolved guess
   lands on a lower environment: `dev`, `develop`, `development`, `test`,
   `testing`, `qa`, `uat`, `stage`, `staging`, `preprod`, `trunk`, `main`,
   `master`, `prod`, `production`, `live`. Exact names only. `release*` is
   deliberately absent: release branches are temporary curation branches,
   not environments.
6. **Fail.** Exit 4, listing the candidates and their distances, asking
   for `--branch`. `ib` never guesses past this point, and never falls back
   to the default branch on its own.

**No branch tiers at all.** If the caller can see no branch directory under
`<B>/push/` (the repository keeps its secrets only in the event and base
tiers, which the broker serves to every push), selection is skipped: `ib`
sweeps `<B>/push` and `<B>` only, as a CI push to a branch with no branch
tier does, and says so on stderr (`ib: no branch tiers; event and base tiers
only`). An override naming a branch is then an error (exit 4). If branch
tiers exist but none shares history with `HEAD`, rule 6 applies (exit 4).

**Stale refs.** Before rule 3, `ib` runs `git ls-remote origin` once and
compares each tracked `origin/T` with the forge. Any difference → a
warning on stderr naming the branch (`ib: origin/develop differs from the
forge; git fetch`). The run continues. If `ls-remote` fails (offline), a
single warning says freshness is unknown.

**Visibility.** The chosen branch and the rule that chose it are always
printed to stderr: `ib: env develop (nearest ancestor, 3 commits)`.

## 4. Sweep

SPEC §4.1–§4.3 and §4.6 with identity (§2) and branch (§3), made with the
caller's token, via the **same code** the broker uses (§8) — except the
`.identity`/`.config`/image-pin divergences noted in §6:

- Tiers `<B>/push/<esc(branch)>`, `<B>/push`, `<B>`, most specific first;
  plain keys only; dot-keys skipped; 403/404 skip that tier or entry.
- Entry forms, naming, string-only values, most-specific-wins collisions:
  SPEC §4.2.
- Pointers dereferenced one level with the caller's token: SPEC §4.3,
  including KV v2-shaped targets. A pointer entry the caller can list/read
  but whose `$ref` target 403/404s is still skipped silently in the sweep
  result (SPEC §4.3's partial-visibility rule, unchanged) — but named
  afterwards on stderr: `ib: skipped N entries: no read on their targets
  (name1, name2, …)`, so a shorter-than-expected `ib env` has a hint
  instead of a silent gap.
- Per-secret pins (SPEC §4.6): `ironbark_events` is applied with event
  `push` (a secret pinned away from `push` is not returned).
  `ironbark_images` is ignored — there is no step image locally; this is
  the one place `ib` returns more than a CI step would, and it is bounded
  by the caller's policy like everything else.
- Any non-403/404 failure → exit 5, nothing written, leases created so far
  revoked.

## 5. Configuration

### 5.1 Vault connection

Address: `BAO_ADDR`, else `VAULT_ADDR`; neither → exit 2. Token:
`BAO_TOKEN`, else `VAULT_TOKEN`, else the token helper file
`~/.vault-token` — the default Vault/OpenBao CLI token-helper path only;
`ib` does not shell out to a custom `token_helper` program a CLI config
may point at instead; none → exit 2 with a hint to run `ib auth`. CA and
TLS settings follow the standard `VAULT_CACERT`/`BAO_CACERT` variables:
`VAULT_CACERT` (and the other `VAULT_*` TLS vars) are picked up for free
by the underlying Vault API client; `BAO_CACERT` and its siblings are not
— the client library only recognizes `VAULT_*` names, so `ib` maps any set
`BAO_*` TLS variable onto the same config fields itself (§8), the same
precedence pattern as `BAO_ADDR`/`BAO_TOKEN`.

### 5.2 Layout

`IB_KV_MOUNT` (default `kv`) and `IB_KV_PREFIX` (default `ci`) — the
same meaning and defaults as the broker's `IRONBARK_KV_MOUNT` /
`IRONBARK_KV_PREFIX` (SPEC §7). They must match the broker serving the
repository.

### 5.3 Later (not in M3)

An in-repo config file for: a remote other than `origin`, a custom
cascade (replacing the built-in list), layout overrides. Not designed
until needed.

## 6. Security model

- `ib` holds no credential of its own and mints nothing. Every Vault call
  uses the caller's token.
- Access control is the caller's Vault policy: which map tiers
  (`<prefix>/<org>/<repo>/push/<branch>/…`) and which dereference targets
  it may read. An operator should grant a human or agent only the tiers
  and targets of the environments they may use — typically mirroring the
  branch policies their push access implies.
- Branch selection (§3) reads untrusted local state; tampering with it can
  only change which *permitted* set is returned.
- Values never touch disk except via `ib env` redirected by the caller.
  `ib` itself writes no cache.
- `ib` does not evaluate `.identity` (§4.4) or `.config` (§4.5) — see §2.
  Where an operator has enabled `.identity` binding as hardening against a
  forge repo-rename/recreate inheriting an old repo's KV tree (SPEC §4.4,
  DESIGN §3), that hardening is CI-only: a binding mismatch that makes the
  broker fail closed (204, no secrets) does not stop `ib` from returning
  the full sweep to whoever holds a token scoped to that tier. Operators
  relying on `.identity` for that protection should treat `ib` access as
  bypassing it — the caller's Vault policy remains the only bound, the
  same model as the `ironbark_images` divergence (§4).
- Likewise, a malformed `.config` entry (§4.5) makes the broker fail
  closed for every CI run against that repo (502, no secrets, until
  fixed); `ib` never reads `.config`, so it is unaffected and keeps
  returning secrets normally in that state. Accepted for M3 — `.config`'s
  only fields concern the minted `vault_token` `ib` never hands out — not
  a bug to fix silently.

## 7. Exit codes

| Code | Meaning |
|---|---|
| 0 | success (`run`: the child's status instead) |
| 1 | usage error |
| 2 | configuration: no git checkout, unparseable `origin`, no Vault address or token |
| 3 | a requested secret name was not produced by the sweep |
| 4 | environment selection failed (§3) |
| 5 | Vault error other than 403/404 during the sweep |

## 8. Implementation shape

- `cmd/ib` — a second binary in the same Go module.
- Shared, not copied: the sweep, entry classification, naming, pin
  handling and dereference in `internal/vaultx` are refactored so they
  take a token and an address and do not depend on the broker's AppRole
  session (`vaultx.Config` today carries `RoleID`/`SecretID`). `Sweep`
  already reads under a caller-supplied token; the remaining gap is
  `SweepResult`, which today reports only a `LeasesCreated bool` — `ib
  run`'s lease revocation (§1.4) needs each deref's `lease_id` itself, so
  `SweepResult`/`SweptSecret` gain a `LeaseID` field. The broker and `ib`
  call the same functions; SPEC §9.2–9.3 sweep tests cover both.
- `internal/identity` — `Esc` reused as is. Remote-URL parsing is new and
  lives there.
- `internal/gitenv` (new) — §2 checkout discovery and §3 selection,
  shelling out to `git`. Unit-tested against scripted fixture repos
  (branch, worktree, detached, orphan, tie cases).
- A new `ib`-specific config loader for §5's env vars — distinct from
  `internal/config`, which is the broker's own surface (SPEC §7) and
  requires broker-only fields (`IRONBARK_WOODPECKER_PUBLIC_KEY`,
  `IRONBARK_VAULT_ROLE_ID`/`_SECRET_ID`, …) `ib` has no reason to supply.
  It also maps any set `BAO_*` TLS variable (§5.1) onto the `api.Config`
  `vaultx.New` builds, since the underlying client only reads `VAULT_*`
  names for that.
- Integration: the SPEC §9.3 containerized Vault and OpenBao harness,
  plus a test asserting `ib env` and a broker response agree on the same
  layout and branch.

## 9. Delivery

Dogfood from source (`go install ./cmd/ib`) before any release. Adding a
published `ib` artifact changes the release-artifact set (DEC-260723140246,
the current accepted decision, lists exactly two) and needs its own
decision record at that point.

## 10. Roadmap (not M3)

- Nested map entries: the sweep descends subdirectories and joins the
  path into the secret name (e.g. `group/leaf` → `group_leaf`). A change
  to the shared sweep, so broker and `ib` move together.
- Configurable cascade and remote (§5.3).

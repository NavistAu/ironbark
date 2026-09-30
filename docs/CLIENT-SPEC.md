# ib — the ironbark local client (M3)

Status: rewritten for the grant model (plans/2026-09-30-grant-model-design.md,
§12 is the source for §3–§5 here). Normative companion to [SPEC.md](SPEC.md)
(the broker). Section references of the form "SPEC §n" point there; where
this file and the grant-model design disagree, the design wins.

## 0. Scope

`ib` gives a local run — an operator's shell, an agent, a script — the
secrets a CI run on the same repository, environment and target would get:
the same levels (project, environment, nested target), read by the same
walk (`internal/walk`, design §8.2), made with the caller's own OpenBao
login instead of a pipeline JWT. One walk, two callers: the broker for CI,
`ib` for everything else.

In scope: resolving secrets for a local checkout; delivering them as a
single value, an env file, or a child process environment.

Out of scope: minting tokens, signature verification, Woodpecker, writing
to Vault, managing policies. `ib` never grants anything: every read is made
with the caller's own token, so the caller's Vault policy is the only
bound on what `ib` returns (§6).

## 1. Commands

`get`, `env`, and `run` each also accept `--env <name>` and
`--target <path>` (or `IB_ENV` / `IB_TARGET`), §3; omitted from the
synopses below for brevity. `auth` takes no such flags — it has nothing to
select. There is no `--branch`.

### 1.1 `ib auth [args…]`

Convenience wrapper over the Vault/OpenBao CLI login. Runs `bao login
[args…]` if `bao` is on `PATH`, else `vault login [args…]`, else fails
with a message naming both. Arguments pass through unchanged (method,
path, username). The token lands wherever that CLI's token helper puts
it, but `ib` itself only reads it back from the default location,
`~/.vault-token` (§5.1) — a `bao`/`vault` config pointing `token_helper`
elsewhere breaks the `ib auth` → `ib get` handoff. `ib auth` adds nothing
else — no token storage of its own.

### 1.2 `ib get [--output raw|json] <name>`

Resolves the checkout's environment (§3), walks it (§4) and writes the
value of secret `<name>` to stdout. `<name>` is the final secret name as
the walk produces it (SPEC §4.2 naming: lowercase, `[a-z0-9_]+`, general
entries as `E_f`). Unknown name → exit 3 (§7).

`--output` (default `raw`) selects the stdout shape:

- `raw` (default): the value alone. A trailing newline is written only
  when stdout is a terminal.
- `json`: one line, `{"name": "<name>", "value": "<value>"}`.

`--output`, like `--env` and `--target`, is recognized wherever it appears among the
command's arguments (§3). An unrecognized `--output`
value is a usage error (exit 1). In every mode, stdout carries only the
value (or the JSON object) — every status/diagnostic line (selection,
skipped entries, warnings, lease notes) stays on stderr, unchanged by
`--output`; an error prints its message to stderr and nothing to stdout.

### 1.3 `ib env [--output env|json]`

Resolves and walks as `get`, then writes every secret to stdout.
`--output` (default `env`) selects the shape:

- `env` (default): one line per secret,
  ```
  SECRET_<NAME>=<quoted value>
  ```
  `<NAME>` is the secret name upper-cased. `<quoted value>` is
  single-quoted; an embedded `'` is written as `'\''`; newlines are kept
  literally inside the quotes. The output is valid for POSIX `sh` `.`/
  `source` and for `ib run --env-file`. Values are on disk if redirected
  to a file — `ib env` is the break-glass path; `ib run` is the normal
  one.
- `json`: one JSON object,
  ```
  {"env": "<chosen or empty>", "rule": "<selection rule>", "secrets": {"<name>": "<value>", …}}
  ```
  `env`/`rule` are the §3 selection outcome (`rule` is `explicit`, `branch`
  or `none`; `env` is `""` for `none`).
  `secrets` is keyed by the walk's own lowercase names (not the
  `SECRET_<NAME>` form `env` output uses), with keys sorted.

`--output`, like `--env` and `--target`, is recognized wherever it appears among the
command's (otherwise empty) argument list. An unrecognized `--output`
value is a usage error (exit 1). In every mode, stdout carries only the
env lines or the JSON object — every status/diagnostic line (selection,
skipped entries, warnings, lease notes) stays on stderr, unchanged by
`--output`; an error prints its message to stderr and nothing to stdout.

### 1.4 `ib run [--env-file <file>]… [--no-masking] -- <cmd> [args…]`

Runs `<cmd>` with an environment built from the caller's environment,
plus one of two modes:

- **No `--env-file` (the normal way to invoke `ib run`).** The walk
  always runs, and every secret it produces is injected as
  `SECRET_<NAME>` — `<NAME>` upper-cased, exactly the naming `ib env`
  (§1.3) uses. A caller env var already named `SECRET_<NAME>` is
  overwritten by the swept value. This is the default: no file to write
  or keep in sync, and nothing to name per secret — just run the command.
- **One or more `--env-file` (to use a subset, or your own names).**
  Each file is applied in order (later files override earlier ones): a
  value of the exact form `ironbark://<name>` is replaced by secret
  `<name>` from the walk, and any other value is passed through as is.
  Reach for this when `<cmd>` expects specific variable names, only some
  secrets should reach it, or it needs literal values (like `DEBUG=true`)
  alongside secrets. Since a reference file holds only `ironbark://`
  names, never values, it's safe to commit to the repo. The walk runs
  once per `ib run`, and only if at least one value across the given
  files is an `ironbark://` reference — a file with no reference at all
  never touches Vault.

Env file syntax: `KEY=value` entries, one per logical line; blank lines
and lines starting with `#` outside any open quote are ignored; `KEY` must
match `[A-Za-z_][A-Za-z0-9_]*`; a value may be single- or double-quoted
(quotes stripped, no escape processing beyond `'\''` in single quotes).
Parsing is quote-aware: a quoted value's closing quote, not end-of-line,
ends the entry, so a literal newline inside an open quote (as `ib env`,
§1.3, emits) is part of the value, not a line break. A file written by
`ib env` is valid input.

A `--env-file` reference to a name the walk did not produce leaves that
variable **unset** in the child (even one the caller's environment already
had), with one stderr line naming it (`ib: <VAR> left unset: no secret
"<name>" was produced`); `ib run` still starts the command. `ib` does not
check that expected names arrived — the wrapped tool validates its own
inputs (design §12.4). Exit 3 remains only for `ib get <name>`, where
there is nothing to print.

**Masking** (default on): every injected or resolved value, whatever its
length (no exemption for short values: a short value that masks noise is an
identifier stored as a secret, and the fix is on the data side) — every
walked secret in the no-file mode, every value substituted for an
`ironbark://` reference in `--env-file` mode — is replaced by
`<concealed by ib>` in the child's stdout and stderr, which `ib` pipes
through, scanning as a byte stream rather than line-by-line (so a match
split across two reads is still caught) and matching longest-value-first
(so one resolved value that is a substring of another is never left
partially exposed). `--no-masking` passes the child's stdio through
untouched (use for interactive commands). Masking is a guard against
accidental logging, not a security boundary — the child holds the values.

Exit status is the child's. Signals received by `ib` are forwarded to the
child.

**Leases.** If any injected or resolved secret came from a lease-bearing
deref (design §7, a resolve mapping to a dynamic engine), `ib run` revokes each
such lease after the child exits by its `lease_id` (`PUT
sys/leases/revoke`), authenticated with the caller's own token — never
`auth/token/revoke-self`, which would revoke the caller's actual Vault
session, not a lease. This is every lease the walk took, referenced
or not — not only the leases behind values actually substituted into the
child's environment. This needs the caller's policy to grant `update` on
`sys/leases/revoke` (or the lease's own prefix); a revoke failure is
logged to stderr and does not change `ib run`'s exit status (best-effort,
matching SPEC §3.4's revoke philosophy — the lease's TTL is the backstop).
`get` and `env` leave leases to expire on their TTL, and say so on stderr.
Applies to both modes above.

## 2. Identity

`ib` takes the repository from the checkout, never from flags:

- **Org / repo:** from the `origin` remote URL (`git remote get-url
  origin`). Accepted forms: `https://host[:port]/org/repo[.git]`,
  `ssh://[user@]host[:port]/org/repo[.git]`, `[user@]host:org/repo[.git]`.
  The last two path segments are org and repo, lowercased, then escaped
  (`identity.Esc`) into path segments as the broker does. The host is not
  part of the identity. No `origin`, or a URL that does not parse → exit 2.
- **Branch:** the checked-out branch, used only by §3's discovery; empty in
  a detached `HEAD`.

The checkout is located with `git rev-parse` (so linked worktrees, whose
`.git` is a file, work unchanged). A detached `HEAD` is valid.

There is no event and no `.identity`/`.config`: the grant model has neither
(design §13). Repo-rename protection is the JWT role's `repo_key` bound
claim, which a human login does not pass through; see §6.

## 3. Selection

Which environment and target to read is a **choice, not access control**.
The checkout and the flags are local and editable; nothing here is trusted
for authorization — the caller's policies are (§6).

- **Environment.** `--env <name>` / `IB_ENV` (flag wins) names the
  environment level directly; it must match the environment grammar
  (design §4.5: `^[a-z0-9][a-z0-9_-]{0,62}$`), else exit 4. Otherwise `ib`
  runs the level-metadata rule (design §4.5 rule 2) for the current local
  branch, over the environment levels the caller can read: it LISTs the
  repo level, reads each directory's level metadata (`GET` on its metadata
  path with a trailing slash) with the caller's token, and matches the
  branch against each `branches` list (`path.Match` patterns, bytewise,
  design §4.5). One claimant → that environment. None → the repo level
  only (not an error). Several → exit 4 naming them; pass `--env`. A
  detached `HEAD` has no branch, so it selects nothing. There is **no
  protection check**: the caller's own policies are the gate.
- **Fail closed.** Any failure reading a level's metadata other than 404
  (a 403 included) ends discovery with exit 5 (exit 2 if OpenBao rejects
  the token itself): a claimant the caller cannot see must not let another
  level win. The human policy therefore needs `read` on level metadata for
  every environment directory (§6).
- **Target.** `--target <path>` / `IB_TARGET` (flag wins), the target
  grammar of design §4.6 (≤ 8 segments, no empty or dot segments), else
  exit 4. Without it the walk stops at the environment level: `ib` never
  derives a target from the working tree and has no `Deploy-To:`/cascade.
  A nested target walks every segment (design §8.1). A target with no
  environment selected is exit 4.

**Visibility.** The choice is always printed to stderr: `ib: env staging
(explicit)`, `ib: env staging (branch), target web/api`, or `ib: no
environment; repo level only`.

## 4. Walk

The design §8.2 walk over the levels selected in §3, by the same code the
broker runs (`internal/walk`), with the caller's token:

- Levels, shallow to deep: the repo level, the environment, one level per
  target segment. Each is LISTed; 403/404 skips the level and the walk
  continues deeper (an unreadable environment does not hide a readable
  target). Sub-directories other than the selected environment or target
  segment are never read. Entries are read in bytewise key order; a 403/404
  entry is skipped.
- Naming, string-only values, `-` → `_`, `[a-z0-9_]+`, clash rules (deepest
  level wins; within a level the first key wins, logged): design §8.2 /
  SPEC §4.2.
- **Resolve mappings** (design §7) are read with the caller's token, so a
  dynamic credential's lease belongs to the caller; `ib run` revokes it
  afterwards (§1.4). One hop only. A 403/404 on the target skips the entry.
- `ironbark_status` (reserved) and `vault_token` are **never produced**:
  `ib` hands out no token, and the caller's own is never given to the child.
  Both are dropped even if present. A reserved-name or invalid-name key is
  skipped with a warning.
- Image pins (`ironbark_images`) are ignored — there is no step image
  locally. `ironbark_events` is not read; an entry still carrying it is
  named on stderr as ignored.
- Skipped entries are named once on stderr: `ib: skipped N entries: no read
  on them or their targets (level/key, …)`. Warnings print as `ib: warning:
  …`.
- All levels answering 403 is checked against `auth/token/lookup-self`: a
  rejected token is exit 2 with a hint to run `ib auth`, never an empty
  success.
- Any other failure → exit 5, nothing written, leases taken so far revoked.

## 5. Configuration

### 5.1 OpenBao connection

Address: `BAO_ADDR`, else `VAULT_ADDR`; neither → exit 2. Token:
`BAO_TOKEN`, else `VAULT_TOKEN`, else the token helper file
`~/.vault-token` — the default Vault/OpenBao CLI token-helper path only;
`ib` does not shell out to a custom `token_helper` program; none → exit 2
with a hint to run `ib auth`. A token is never read from the config file.
TLS settings follow `VAULT_CACERT`/`BAO_CACERT` and siblings (`CAPATH`,
`CLIENT_CERT`, `CLIENT_KEY`, `TLS_SERVER_NAME`, `SKIP_VERIFY`), `BAO_*`
before `VAULT_*`.

### 5.2 Layout and selection

`ib` reads the same four settings as ironbark, under the same names
(design §11.1): `IRONBARK_DATA_PATH` (required, no default; the template
must be the one the broker serving the repository uses), `IRONBARK_ENV_VAR`
(default `DEPLOY_ENV`), `IRONBARK_TARGET_VAR` (default `DEPLOY_TO`) and
`IRONBARK_JWT_ROLE` (default `ci-{env}`). Only the data path shapes what `ib`
reads; the other three are accepted so one file serves both. `IB_ENV` and
`IB_TARGET` are §3's fallbacks.

`IB_KV_MOUNT`, `IB_KV_PREFIX` and `IB_BRANCH` no longer exist. Setting one
(in the environment or the file) is a configuration error (exit 2) naming
its replacement: `IRONBARK_DATA_PATH` for the first two, `IB_ENV`
(or `--env`) for the last.

### 5.3 The config file

`~/.config/ib/config` is a `KEY=value` file in `ib run --env-file` syntax
(quotes, `#` comments, blank lines) holding any of the names above, TLS
included; unknown keys are ignored. **Environment variables win over the
file**, per name (for the `BAO_*`/`VAULT_*` pairs, the environment's pair is
consulted before the file's). A missing file is fine; a malformed one is
exit 2 naming its line.

## 6. Security model

- `ib` holds no credential of its own and mints nothing. Every Vault call
  uses the caller's token.
- Access control is the caller's OpenBao policy. The templated CI policies
  key on JWT alias metadata and do nothing for a human token: people get
  static policies (design §12.2), e.g. `read` on
  `vs/data/pipelines/acme/+/staging/*` and `read` on
  `vs/metadata/pipelines/acme/+/+/` for level metadata, plus `read` on the
  dynamic-engine paths they may resolve and `update` on `sys/leases/revoke`.
  Personal policies are the gate.
- Policy gotcha: the most specific matching path wins and capabilities are
  not merged. A subtree rule such as `vs/metadata/…/staging/*` shadows the
  `+/` level-metadata rule for that environment, so it must itself carry
  `read` (and `list`), or discovery fails closed with a 403.
- Selection (§3) reads untrusted local state and flags; tampering with them
  can only change which *permitted* set is returned.
- Values never touch disk except via `ib env` redirected by the caller.
  `ib` itself writes no cache.
- The `repo_key` guard against a forge repo rename or recreate inheriting an
  old repo's secrets is a JWT role bound claim, checked at CI login. A human
  login does not pass through it: the caller's policy remains the only
  bound, and `ib` reads `org/repo` from the local `origin` URL.
- `ib` never returns `vault_token`, and drops `ironbark_status` (§4).

## 7. Exit codes

| Code | Meaning |
|---|---|
| 0 | success (`run`: the child's status instead) |
| 1 | usage error |
| 2 | configuration: no git checkout, unparseable `origin`, no address, token or `IRONBARK_DATA_PATH`, a removed variable, a malformed config file, a rejected token |
| 3 | `ib get`: the requested secret name was not produced by the walk |
| 4 | selection failed (§3): several claimants, invalid `--env`/`--target`, target without an environment |
| 5 | OpenBao error other than 403/404 during selection or the walk |

## 8. Implementation shape

- `cmd/ib` — a second binary in the same Go module.
- Shared, not copied: the walk, naming, pin handling, resolve mappings
  and environment discovery are `internal/walk` (design §8.2, §4.5), over
  a small client interface the broker and `ib` both satisfy;
  `internal/levels` builds the level list from the data-path template,
  `internal/selector` holds the env/target grammars and branch patterns.
  `ib` reads through `vaultx.Conn.As(token)` with the caller's token and
  does its own lease revocation and token check (`cmd/ib/leases.go`).
- `internal/identity` — `Esc` and remote-URL parsing.
- `internal/gitenv` — §2 checkout discovery (shelling out to `git`) and §3
  selection (`gitenv.Select`).
- `internal/ibcfg` — §5's loader (environment over `~/.config/ib/config`),
  distinct from `internal/grantcfg`, the broker's own surface, which
  requires broker-only fields (JWT signing key, Woodpecker public key, …).
- `internal/mask` — §1.4 masking.
- Integration: `test/integration/ib_grant_test.go` runs the real binary
  against the grant-model fixture (OpenBao + voidstar) under a static human
  policy: nested-target walk, discovery from the local branch, several
  claimants, a level whose metadata is unreadable, lease revocation after
  `ib run`, masking of short values, an unproduced reference.

## 9. Delivery

Dogfood from source (`go install ./cmd/ib`) before any release. Adding a
published `ib` artifact changes the release-artifact set (DEC-260723140246,
the current accepted decision, lists exactly two) and needs its own
decision record at that point.

## 10. Roadmap (not M3)

- A remote other than `origin`.

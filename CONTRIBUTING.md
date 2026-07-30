# Contributing to ironbark

Thanks for your interest in contributing! ironbark is a Go service that
benefits from contributions of all kinds — bug reports, documentation
improvements, test coverage, and code.

## Getting Started

```sh
git clone https://github.com/navistau/ironbark.git
cd ironbark
mise install    # installs Go 1.24 (see mise.toml)
go build ./cmd/ironbark
go vet ./...
go test ./...
```

## Development

### Prerequisites

- Go 1.24 (see `mise.toml` for the exact version; `mise install` provides it)
- Docker + Docker Compose, for the integration suite only

### Running Tests

There are two test suites:

```sh
go test ./...                                  # unit suite — no external services
go test -tags integration ./test/integration/...  # integration suite
```

The integration suite exercises the real broker flow against both Vault
and OpenBao, and needs the services in `test/integration/docker-compose.yml`
running first:

```sh
docker compose -f test/integration/docker-compose.yml up -d
go test -tags integration ./test/integration/...
docker compose -f test/integration/docker-compose.yml down
```

### Project Structure

- `cmd/ironbark` — entry point; wiring only, no business logic
- `internal/wpsign` — Woodpecker RFC-9421 signature verification
- `internal/identity` — request payload parsing/normalization
- `internal/policy` — policy-name derivation from identity
- `internal/broker` — verify → derive → mint → sweep → deref orchestration
- `internal/vaultx` — Vault/OpenBao client (mint, sweep, canary)
- `internal/httpapi` — the Woodpecker secret-extension HTTP surface
- `test/integration` — the dual-product (Vault + OpenBao) integration suite

See [`docs/SPEC.md`](docs/SPEC.md) for the normative interface/behavior
spec and [`docs/DESIGN.md`](docs/DESIGN.md) for architecture and threat
model. Design decisions are recorded as MADRs in
[`docs/decisionlog/`](docs/decisionlog/) — `docs/SPEC.md` and the decision
log are the normative sources; other docs defer to them.

## Branch Workflow

ironbark uses a two-branch model:

- **`develop`** is the default branch and the integration target. Branch
  your feature/fix work off `develop` and open PRs **back into `develop`**.
  This is where day-to-day development lands.
- **`main`** is the release branch. It only advances via a PR from
  `develop` → `main`, and that PR is the **release gate**: `main` is
  protected so a PR cannot merge until all CI checks pass (no direct
  pushes to `main`).
- **Releases** are cut from `main`: merging a `develop` → `main` PR *is*
  the release. `release.yml` triggers on push to `main`, reads the version
  from the root `VERSION` file, tags `vX.Y.Z` on the merge commit, and
  publishes. No manual tagging. See [`docs/releasing.md`](docs/releasing.md).

CI runs on pushes to and PRs targeting both `develop` and `main`, so your
PR into `develop` is fully checked before it lands.

## Pull Requests

- **Target `develop`** (the default branch), not `main` — only release
  PRs go `develop` → `main`
- One logical change per PR
- Include tests for new functionality (unit, and integration where the
  change touches the Vault/OpenBao interaction)
- Run `go vet ./...` and `gofmt -l .` before submitting
- Update docs if you change user-facing or operator-facing behavior

## Reporting Bugs

Please use the bug report issue template — it asks for the Woodpecker
version, Vault/OpenBao product and version, and ironbark version, which
are usually needed to diagnose anything.

## Security

Do not open a public issue for a security vulnerability — see
[`SECURITY.md`](SECURITY.md).

## Code of Conduct

Be kind, be constructive, assume good intent.

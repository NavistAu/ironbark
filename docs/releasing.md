# Release Checklist

Step-by-step process for cutting a new ironbark release.

> **Branch model:** `develop` is the default/integration branch; `main` is the release branch.
> Releases are prepared on `develop` and promoted to `main` via a PR (the release gate — `main` is
> protected and requires green CI to merge). **Merging that PR is the release:** `release.yml`
> triggers on push to `main`, reads the version from the root `VERSION` file, tags `vX.Y.Z` on the
> merge commit, and publishes. No manual tagging. See `CONTRIBUTING.md` → "Branch Workflow".

## Prerequisites

- All feature work for the release merged to `develop`, and `develop` is green
- No outstanding feature branches or worktrees (`git worktree list`, `git branch -a`)
- Version bump and changelog (steps 1–2) are done **on `develop`**

## 1. Version Bump

Edit the root `VERSION` file to the new `X.Y.Z` (no `v` prefix, no trailing
content besides the newline). This is the single source the release
workflow, the Dockerfile build stage, and `.woodpecker.yaml` all read via
`-ldflags "-X main.version=$(cat VERSION)"`.

## 2. Changelog

Add a new `## [X.Y.Z] - YYYY-MM-DD` section at the top of `CHANGELOG.md`,
above `[Unreleased]`, following Keep a Changelog format (Added / Changed /
Fixed / Removed as applicable) — move the relevant `[Unreleased]` entries
into it rather than duplicating them.

## 3. Documentation Currency Check

Verify docs reflect the new version's features and are internally
consistent (README ↔ `docs/SPEC.md` ↔ `docs/DESIGN.md` — SPEC is
normative, others defer to it):

- `README.md` — Status section, config reference, Install section
- `docs/SPEC.md` — normative interface/behavior spec
- `docs/DESIGN.md` — architecture and threat model
- `docs/decisionlog/` — any decisions made since the last release recorded

## 4. Release PR (`develop` → `main`) — the release gate

Commit steps 1–3 to `develop` and push it. Then open a PR from `develop`
into `main`:

```sh
git push origin develop
gh pr create --base main --head develop --title "Release vX.Y.Z" --fill
```

`main` is protected: the PR cannot merge until **all CI jobs** pass — vet,
unit tests (race detector), lint, and the integration job (Vault +
OpenBao). Do not merge until CI is fully green. **Merging the PR is the
release** — there is nothing to do by hand afterwards (see step 5).

## 5. Release fires automatically on merge

`release.yml` triggers on **push to `main`** (i.e. the merge in step 4). A
`gate` job reads `VERSION`, and unless `vX.Y.Z` already exists as a tag,
runs the full pipeline — creating the `vX.Y.Z` tag on the merge commit
itself (via the default `GITHUB_TOKEN`; no PAT or App token, because the
tag is no longer the trigger).

The gate also **disarms releases while the repository is private**: during
the pre-publish bring-up phase, pushes to `main` skip the publish job
entirely (flipping the repo public arms releases with no other change). A
deliberate private rehearsal is possible via workflow_dispatch with
`force: true` — clean up its tag/package afterwards.

There is **no manual `git tag` step.** Merge the green release PR and walk
away.

The workflow:

1. Builds `./cmd/ironbark` with `ko`, multi-platform
   (`linux/amd64,linux/arm64`), version-stamped via the same `-ldflags -X
   main.version=...` injection, SPDX SBOM attached, and pushes
   `ghcr.io/navistau/ironbark:{vX.Y.Z,latest}` — auth is the workflow's
   own `GITHUB_TOKEN` (`packages: write`), no registry secrets needed.
2. Signs the image with `cosign` (keyless, GitHub OIDC).
3. Creates a GitHub Release from the CHANGELOG section for the version.

- **Re-run / recover** (a publish job hiccupped): re-run the failed job
  from the Actions UI, or re-run the whole workflow via **Actions →
  Release → Run workflow** with `force: true` to bypass the
  already-tagged check.
- **Skip behaviour:** a push to `main` whose `VERSION` is already tagged
  is a no-op (the gate short-circuits and every downstream job skips), so
  a hotfix that doesn't bump the version won't re-publish.

## 6. Verify Publish

**First release only:** the workflow's first push creates the GHCR
package **private** — package visibility is independent of repo
visibility. Make it public before continuing (Package settings → Change
visibility → Public); every subsequent release reuses the same, now-public,
package.

After the release workflow completes, verify from a clean machine:

- **Anonymous pull** (proves the package is public):
  `docker run ghcr.io/navistau/ironbark:vX.Y.Z` — starts and fails clean
  on missing config.
- **`go install`:** `go install github.com/navistau/ironbark/cmd/ironbark@vX.Y.Z`
  resolves and builds.
- **`cosign verify`:**
  `cosign verify ghcr.io/navistau/ironbark:vX.Y.Z --certificate-identity-regexp='.*' --certificate-oidc-issuer=https://token.actions.githubusercontent.com`
  passes. On success, add this invocation to README.md and SECURITY.md
  (both currently note it's "documented at first release").
- **Release page:** `gh release view vX.Y.Z --repo navistau/ironbark` shows
  the CHANGELOG section.
- **Version reporting:** the running container's startup log (or
  `--version`, once added) reports `X.Y.Z`.
- **Package page:** shows the README (the `org.opencontainers.image.source`
  image label linked it to the repo -- confirmed against GitHub's packages
  docs that this is a Docker/OCI image **label**, not a manifest
  annotation; `release.yml` sets it via `ko build --image-label`).

## 7. Post-Release

- W5 announcements (awesome-woodpecker PR, Woodpecker docs, OpenBao
  community, etc.) are separate, user-confirmed, per-item steps — see the
  publish spec's W5 — not part of this checklist.

---
id: "DEC-0017"
title: "Release artifacts: Go module + GHCR image only, signed, with SBOM"
status: accepted
date: 2026-07-23
y-statement: >-
  In the context of what a public ironbark release ships, facing the
  discovery that the maintainer's legacy Docker Hub org is slugged
  navistautomatum and cannot be renamed to navistau while a new org would
  hit current Docker Hub org pricing, we decided for exactly two release
  artifacts — the tagged Go module (github.com/navistau/ironbark) and a
  multi-arch ghcr.io/navistau/ironbark image built with ko on the
  distroless nonroot base, cosign-signed keylessly with SPDX SBOMs,
  pushed with the workflow's own GITHUB_TOKEN — and against Docker Hub
  under a mismatched or paid org name, prebuilt binaries, OS packages,
  and a Helm chart, to achieve a minimal, zero-cost, zero-external-secret
  artifact surface with signed provenance, accepting the full ghcr.io
  pull path in docs and a one-time make-package-public step at first
  release.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "artifacts", "supply-chain"]
supersedes: ["DEC-0013"]
---

# Release artifacts: Go module + GHCR image only, signed, with SBOM

## Context and Problem Statement

DEC-0013 chose Docker Hub (`docker.io/navistau/ironbark`) pending org
registration, with GHCR named as the fallback if registration proved
unacceptable. It did: the maintainer's existing pre-pricing-change Docker
Hub org has the slug `navistautomatum`, Docker Hub does not allow renaming
it to `navistau`, and creating a fresh `navistau` org falls under current
org pricing. The namespace mismatch with the GitHub org (and the cost)
triggers the fallback. The artifact set itself (module + image, no
binaries) is unchanged from DEC-0013.

## Decision Drivers

* Registry namespace should match the GitHub org (`navistau`) — a
  `navistautomatum` image name contradicts the project's naming.
* Zero recurring cost and zero external credentials preferred.
* GHCR authenticates release workflows with the built-in `GITHUB_TOKEN`
  (`packages: write`) — no registry secrets to provision or rotate.
* GHCR has no meaningful anonymous pull rate limits, removing the need
  for a Docker-Sponsored Open Source application.
* A credential-custody tool must ship verifiable provenance (unchanged).

## Considered Options

* GHCR (`ghcr.io/navistau/ironbark`)
* Docker Hub under the legacy `navistautomatum` org
* Docker Hub under a newly registered paid `navistau` org

## Decision Outcome

Chosen option: "GHCR", because it matches the org namespace exactly,
costs nothing, and removes external secrets from the release pipeline.

Per release, exactly two artifacts: the `vX.Y.Z` module tag (the Go
module IS the tag) and `ghcr.io/navistau/ironbark:{vX.Y.Z,latest}` —
ko-built, linux/amd64+arm64, `KO_DEFAULTBASEIMAGE` pinned to the
distroless static nonroot base in lockstep with the Dockerfile, ko SPDX
SBOMs on, cosign keyless (GitHub OIDC) signature documented in README and
SECURITY.md, `org.opencontainers.image.source` annotation linking the
package to the repo. GHCR specifics: the first push creates the package
**private** (package visibility is independent of repo visibility) — the
v0.1.0 verify-publish checklist makes it public before the anonymous-pull
check; all documented pull commands use the full `ghcr.io/` path.

### Consequences

* Good, because registry namespace equals org namespace.
* Good, because the release pipeline holds zero external credentials.
* Good, because no consumer pull-rate-limit mitigation is needed (DSOS
  application dropped from the announce workstream).
* Bad, because operators who default to Docker Hub search won't find it
  there — accepted; docs always give the full pull path.
* Bad, because a forgotten make-package-public step would break anonymous
  pulls — mitigated by the explicit checklist item and verify step.

## Pros and Cons of the Options

### GHCR

* Good, because free, namespace-correct, GITHUB_TOKEN-authenticated.
* Good, because package page links to the repo and README.
* Bad, because less discoverable than Docker Hub for casual search.

### Docker Hub under `navistautomatum`

* Good, because the org already exists at no cost.
* Bad, because the image name would permanently contradict the
  `navistau` project namespace; rejected.

### Docker Hub under a new paid `navistau` org

* Good, because namespace-correct and maximally discoverable.
* Bad, because recurring cost plus external credentials for a niche
  operator tool; rejected.

## More Information

Supersedes DEC-0013 (Docker Hub as primary registry; its artifact set,
signing, and SBOM requirements carry over unchanged). See publish plan
docs/plans/2026-07-23-publish.md D6/W3, and DEC-0012 for the release.yml
that produces these artifacts.

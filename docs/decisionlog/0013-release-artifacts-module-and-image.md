---
id: "DEC-0013"
title: "Release artifacts: Go module + Docker Hub image only, signed, with SBOM"
status: accepted
date: 2026-07-23
y-statement: >-
  In the context of what a public ironbark release ships, facing a
  container-first server whose consumers deploy an image or build from
  source, we decided for exactly two artifacts — the tagged Go module
  (go-installable as github.com/navistau/ironbark) and a multi-arch
  docker.io/navistau/ironbark image built with ko on the distroless
  nonroot base, cosign-signed keylessly with SPDX SBOMs — and against
  prebuilt release binaries, OS packages, a Helm chart, and GHCR as
  primary registry, to achieve a minimal artifact surface with signed
  provenance appropriate to a credential-custody tool, accepting that
  binary-wanting users must go install and that Docker Hub org
  registration (and its pricing) is a prerequisite.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "artifacts", "supply-chain"]
supersedes: []
---

# Release artifacts: Go module + Docker Hub image only, signed, with SBOM

## Context and Problem Statement

ironbark is a stateless server deployed as a container behind a Woodpecker
instance. Publishing (DEC-0011) forces the question of what a release
actually ships and to which registry, and how much of the beachcomber
packaging matrix (deb/rpm/AUR/nix/brew, SDK publishes, installer shims)
transfers to a server-shaped project.

## Decision Drivers

* Consumers are Woodpecker+Vault operators: they pull an image or
  `go install`; nobody has asked for tarballs.
* Every artifact is a standing maintenance commitment.
* A tool whose job is credential custody must ship verifiable provenance.
* The maintainer chose Docker Hub under the org name over GHCR.

## Considered Options

* Go module + Docker Hub image, signed + SBOM
* The above plus prebuilt binaries (GoReleaser matrix)
* GHCR as the primary registry

## Decision Outcome

Chosen option: "Go module + Docker Hub image, signed + SBOM", because two
artifacts cover the real consumption paths with nothing left to rot.

Per release: the `vX.Y.Z` module tag (the Go module IS the tag; nothing
extra to publish) and `docker.io/navistau/ironbark:{vX.Y.Z,latest}` —
ko-built, linux/amd64+arm64, `KO_DEFAULTBASEIMAGE` pinned to the distroless
static nonroot base in lockstep with the Dockerfile, ko SPDX SBOMs on,
cosign keyless (GitHub OIDC) signature, `cosign verify` documented in
README and SECURITY.md. Prerequisites: register the `navistau` Docker Hub
org (verify current org pricing at signup; GHCR is the free fallback if
unacceptable) and, once public, apply to Docker-Sponsored Open Source to
lift consumer pull limits.

### Consequences

* Good, because two artifacts, one workflow, minimal rot surface.
* Good, because image provenance is verifiable end to end.
* Bad, because there is no curl-a-binary path — accepted; `go install`
  covers it.
* Bad, because Docker Hub org registration may carry a cost and pull rate
  limits apply to anonymous consumers until DSOS is granted.

## Pros and Cons of the Options

### Go module + Docker Hub image, signed + SBOM

* Good, because it matches how a server is actually consumed.
* Good, because Docker Hub is where operators look first.
* Bad, because Docker Hub org pricing and rate limits are outside our
  control.

### Plus prebuilt binaries

* Good, because non-Go users get a download.
* Bad, because it adds a build matrix, checksums, and archive naming to
  maintain for a hypothetical audience.

### GHCR primary

* Good, because free, org-linked, GITHUB_TOKEN-authenticated.
* Bad, because less discoverable to the operator audience; the maintainer
  chose Docker Hub.

## More Information

DEC-0012 (the release.yml that produces these), DEC-0010 (runtime surface
the image must respect), publish plan W3. The distroless base pin and its
lockstep constraint with the Dockerfile predate this decision (see
.woodpecker.yaml history).

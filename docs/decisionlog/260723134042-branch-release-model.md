---
id: "DEC-260723134042"
title: "Branch/release model: develop→main gate, VERSION file, SemVer from v0.1.0"
status: accepted
date: 2026-07-23
y-statement: >-
  In the context of ironbark's public release process, facing tag-driven
  releases versus the org's proven develop-main gate, we decided for the
  develop-main gate with a VERSION file and SemVer from v0.1.0, against tag-
  driven releases, to achieve cross-project consistency.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "release-process", "versioning"]
supersedes: []
---

# Branch/release model: develop→main gate, VERSION file, SemVer from v0.1.0

## Context and Problem Statement

ironbark is moving to a public GitHub home (DEC-260723134041) and needs a release
process. The publish plan initially recommended tag-driven releases as
lighter ceremony for a single-maintainer repo; the maintainer preferred
consistency with beachcomber's proven develop→main model. Go adds one
wrinkle: there is no manifest version field (no Cargo.toml equivalent), so
a release gate needs an explicit version source.

## Decision Drivers

* One release model across NavistAu projects: one set of habits, one
  releasing.md shape, transferable muscle memory.
* A protected, always-releasable `main` gives a CI-enforced gate — merging
  the release PR **is** the release.
* The gate job must be able to read "the version" from the tree.

## Considered Options

* develop→main gate, beachcomber-shaped
* Tag-driven (pushing vX.Y.Z triggers release)

## Decision Outcome

Chosen option: "develop→main gate, beachcomber-shaped", because
cross-project consistency outweighs per-project ceremony optimization.

`develop` is the default branch; `main` is protected and only advances via
the release PR. `release.yml` fires on push to `main`: a gate job reads the
root `VERSION` file, skips if `vX.Y.Z` is already tagged, otherwise tags
the merge commit in-run (default `GITHUB_TOKEN`; nothing triggers off the
tag) and publishes. The binary reports the same version via `-ldflags -X`
injection. Versioning is SemVer; the first public release is v0.1.0 — the
operator contract is specified but young, and pre-1.0 signals it.

### Consequences

* Good, because releasing is identical across the org's projects.
* Good, because red CI physically blocks a release at the PR gate.
* Good, because no PAT/App token is needed — the tag is created inside the
  run, not used as a trigger.
* Bad, because solo hotfixes pay PR ceremony — accepted for consistency.

## Pros and Cons of the Options

### develop→main gate, beachcomber-shaped

* Good, because the release gate is enforced by branch protection, not
  discipline.
* Good, because it matches beachcomber exactly — shared releasing.md shape.
* Bad, because two long-lived branches are more state than trunk-based.

### Tag-driven

* Good, because minimal ceremony for a single maintainer.
* Bad, because nothing structurally prevents tagging a red commit.
* Bad, because it diverges from the org's established release model.

## More Information

DEC-260723134041 (publish home), DEC-260723134043 (what the release publishes). Process
detail lives in docs/plans/2026-07-23-publish.md (W3) and, once written,
docs/releasing.md. Mirrors NavistAu/beachcomber's release.yml gate design.

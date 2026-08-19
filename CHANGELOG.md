# Changelog

All notable changes to ironbark will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-08-19

### Fixed

- KV v2-shaped `$ref` deref now applies the single-field convention:
  an unwrapped target carrying a string `value` field yields ONE secret
  named for the entry, ignoring metadata siblings (id/title/staleness
  fields that 1P-style field-engine views return alongside the value).
  The strict exactly-one-key shorthand test flattened such views into
  `E_id`/`E_title`/… general-form names, so the expected secret never
  existed (first production deref, 2026-08-19). Multi-field targets
  without a `value` field flatten general-form, unchanged.


## [0.1.1] - 2026-08-19

### Added

- `$ref` pointer dereference (SPEC §4.3) now recognizes KV v2-shaped
  targets — KV v2 itself, or a KV v2-wire-compatible view — by response
  shape (a nested `data`+`metadata` object pairing), and unwraps them to
  apply the same single-field-shorthand/general-form classification as a
  swept entry. Flat dynamic-engine deref targets (`aws/sts/*` etc.) are
  unaffected — unchanged, general-form-only flattening.

## [0.1.0] - 2026-08-01

First public release.

### Added

- **M1: the broker.** ironbark's core is implemented: a Go service
  (`cmd/ironbark` + `internal/{wpsign,identity,policy,broker,vaultx,httpapi}`)
  that verifies each Woodpecker secret-extension request's RFC-9421
  ed25519 signature, derives conventional Vault/OpenBao policy names from
  the forge-set `(org, repo, event, branch)`, mints a short-lived,
  narrowly-scoped token via a Vault token-role, sweeps the repo's
  conventional KV subtree under that token, dereferences `$ref` pointer
  entries into dynamic engines, and returns the result as masked
  Woodpecker secrets.
- Unit-tested and integration-tested against both Vault 1.20 and OpenBao
  2.5.5.
- Container image `ghcr.io/navistau/ironbark` (linux/amd64 + linux/arm64,
  distroless nonroot, SPDX SBOM, cosign keyless signature).

[Unreleased]: https://github.com/navistau/ironbark/compare/main...develop
[0.1.0]: https://github.com/navistau/ironbark/releases/tag/v0.1.0

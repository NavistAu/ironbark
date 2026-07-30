# Changelog

All notable changes to ironbark will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/navistau/ironbark/compare/main...develop

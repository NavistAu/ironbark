---
id: "DEC-0005"
title: "Custom Vault plugin is a research note, not a roadmap item"
status: accepted
date: 2026-07-11
y-statement: >-
  In the context of moving ironbark's identity mapping inside Vault's trust
  boundary via a custom auth-method plugin that verifies Woodpecker's ed25519
  signature natively, facing the operational and adoption cost of binary
  plugin registration version-matched against both Vault and OpenBao, we
  decided for keeping stock-Vault/OpenBao compatibility and recording the
  plugin as a research note with an explicit revisit trigger, and against
  putting the plugin on the roadmap, to achieve broad adoptability of a
  published tool, accepting a weaker audit chain (signature verified outside
  Vault) and convention-encoded policy names instead of structured route
  config.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["scope", "vault", "research"]
supersedes: []
---

# Custom Vault plugin is a research note, not a roadmap item

## Context and Problem Statement

The compelling version of an "ironbark engine" is a Vault *auth method*
plugin: ironbark forwards Woodpecker's RFC-9421-signed request into Vault,
the plugin verifies the ed25519 signature inside Vault's boundary and issues
the token itself. That would give a cryptographic chain from Woodpecker's
signing key into Vault's audit log, and structured route configuration
instead of convention-encoded policy names. The question is whether it earns
a place on the roadmap of a published tool.

## Decision Drivers

* Custom plugins mean building, registering, and version-matching binary
  plugins against both Vault and OpenBao, whose plugin APIs are drifting
  apart post-fork.
* "Requires a custom Vault plugin" sharply cuts who will adopt a published
  security tool; managed Vault offerings disallow custom plugins.
* Stock-Vault/OpenBao compatibility is one of ironbark's quiet selling
  points.
* The convention encoding (DEC-0002) has not yet been proven brittle.

## Considered Options

* Roadmap the auth-method plugin
* Record as a research note with a revisit trigger (chosen)
* Discard the idea entirely

## Decision Outcome

Chosen option: "research note with revisit trigger". The design is captured
in DESIGN.md's research-notes section. Explicit trigger to revisit: the
convention encoding proves too brittle in practice (naming collisions,
un-encodable identities, or operational drift that DEC-0004 tooling cannot
contain).

### Consequences

* Good, because M1/M2 stay shippable against any stock Vault/OpenBao.
* Good, because the idea and its rationale are preserved with a concrete
  reopening condition rather than relitigated ad hoc.
* Bad, because the audit chain ends at ironbark: Vault's audit log records
  ironbark's mint, not Woodpecker's signature; Woodpecker→ironbark trust is
  attested only in ironbark's own logs.

## Pros and Cons of the Options

### Roadmap the plugin

* Good, because strongest audit story and structured config.
* Bad, because double plugin-API maintenance (Vault + OpenBao) and a large
  adoption tax on a published tool.

### Research note with trigger

* Good, because preserves optionality at zero build cost.
* Bad, because the weaker audit chain persists meanwhile.

### Discard entirely

* Good, because least to document.
* Bad, because the analysis would be re-derived from scratch if convention
  encoding fails.

## More Information

Depends on the convention model of DEC-0002. See DESIGN.md research notes.

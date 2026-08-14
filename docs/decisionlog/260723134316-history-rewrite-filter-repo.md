---
id: "DEC-260723134316"
title: "Publish full git history rewritten with filter-repo to remove internal references"
status: accepted
date: 2026-07-23
y-statement: >-
  In the context of taking ironbark's repo public, facing history whose old file
  versions and messages name internal infrastructure, we decided for a filter-
  repo rewrite before the first push, against publishing history as-is or
  squashing fresh, accepting hash churn.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "git", "hygiene"]
supersedes: []
---

# Publish full git history rewritten with filter-repo to remove internal references

## Context and Problem Statement

DEC-260723134044 guarantees no internal-infrastructure references in published
content, and the genericization sweep cleans HEAD — but git history
retains every old file version, and several commit messages name the
internal registry. The references are audited-benign (worked examples, no
secrets), but once public they are greppable forever. The publish plan
surfaced three options; the maintainer chose the rewrite.

## Decision Drivers

* The no-internal-references guarantee is hollow if `git log -p` defeats
  it.
* Commit provenance and the decision-log narrative have real value for a
  project whose docs lean on its own history.
* Nothing external references the current hashes yet — a rewrite is free
  today and impossible later.

## Considered Options

* filter-repo rewrite of full history
* Publish full history as-is (scrub HEAD only)
* Squash to a fresh initial commit

## Decision Outcome

Chosen option: "filter-repo rewrite of full history", because it is the
only option delivering both provenance and a zero-internal-strings
repository, and the one-time cost is lowest at exactly this moment.

Mechanics: on a fresh clone, after the W1 genericization sweep lands (so
HEAD and history converge on the same generic exemplars), run
`git filter-repo` with `--replace-text` (blob contents) and
`--replace-message` (commit messages) mapping every internal identifier to
its generic exemplar. Push the rewritten repo as the initial content of
the private GitHub repository — GitHub never sees a pre-rewrite object.
The original repository is retained only as an internal archive. Verify:
case-insensitive grep for the internal identifiers over
`git log -p --all` of the rewritten clone returns zero hits.

### Consequences

* Good, because history-level guarantee matches the HEAD-level one, gated
  by the same mechanical grep.
* Good, because MADR/spec provenance survives for public readers.
* Bad, because all hashes change — existing local clones and the internal
  mirror relationship must restart from the rewritten repo.
* Bad, because filter-repo is a sharp tool — mitigated by operating on a
  throwaway fresh clone with the original untouched.

## Pros and Cons of the Options

### filter-repo rewrite

* Good, because provenance plus zero internal strings, including messages.
* Bad, because most effort and hash churn of the three options.

### Full history as-is

* Good, because zero effort and stable hashes.
* Bad, because contradicts the maintainer's literal no-references
  requirement at the `git log -p` level.

### Squash fresh

* Good, because trivially zero-history exposure.
* Bad, because discards commit provenance the docs narrative benefits
  from.

## More Information

DEC-260723134044 (the reference policy this extends to history), DEC-260723134041 (the
private-first flip this precedes), publish plan W2.1 and pre-flight gate.

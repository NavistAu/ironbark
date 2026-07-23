---
id: "DEC-0014"
title: "No internal-infrastructure references; generic exemplars; parameterized Woodpecker example"
status: accepted
date: 2026-07-23
y-statement: >-
  In the context of publishing a repository developed against the authors'
  private infrastructure, facing docs, CI config, and test fixtures that
  name internal hostnames, registries, and personal repositories as worked
  examples, we decided for a full genericization sweep — every published
  file uses generic exemplar identifiers, the retained .woodpecker.yaml
  becomes an example pipeline whose publish step takes registry host,
  repository, and credentials entirely from Woodpecker secrets, and a
  mechanical zero-hit grep gate blocks the public flip — and against
  scoping the scrub to a single document or deleting the Woodpecker file,
  to achieve published content with no internal references that still
  dogfoods a runnable Woodpecker pipeline, accepting churn in test
  fixtures and historical docs.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "documentation", "hygiene"]
supersedes: []
---

# No internal-infrastructure references; generic exemplars; parameterized Woodpecker example

## Context and Problem Statement

Development used the authors' real forge, CI host, and registry as worked
examples throughout README, DESIGN, research docs, CI config, and test
fixtures. The published project must stand alone: no internal hostnames,
registry paths, or personal repository names anywhere in published
content. The publish plan's original D8 scoped this to one research doc;
the maintainer widened it to everything, and directed that any retained
Woodpecker files be "example generic".

## Decision Drivers

* Published examples should be copy-pasteable without leaking anyone's
  infrastructure layout.
* A Woodpecker secret extension should keep a Woodpecker pipeline in its
  own repo — as a generic example and working dogfood, while project CI
  moves to GitHub Actions.
* Docs quality: one consistent exemplar org/repo lets a reader follow a
  single thread across README, SPEC, DESIGN, tests, and website.
* Enforcement must be mechanical, not a judgment call at flip time.

## Considered Options

* Full sweep + parameterized Woodpecker example + grep gate
* Scrub only the obviously internal doc(s)
* Drop .woodpecker.yaml from the public repo

## Decision Outcome

Chosen option: "Full sweep + parameterized Woodpecker example + grep
gate", because partial scrubs rot and the Woodpecker file has example
value precisely because it is real.

All published files are genericized: hosts become `*.example.com` forms;
the worked org/repo example becomes one consistent generic identity reused
everywhere, docs and test fixtures alike. `.woodpecker.yaml` stays as a
labelled example/dogfood pipeline: build/test steps unchanged; the publish
step reads registry host, repo path, and credentials from Woodpecker
secrets, so it contains no infrastructure identifiers yet runs unmodified
on any instance that supplies them. Enforcement: a case-insensitive grep
for the internal identifiers over the tracked tree must return zero hits
before the repository is flipped public (git authorship metadata exempt).
Whether pre-publish *history* is also scrubbed is a separate open decision
(publish plan D2).

### Consequences

* Good, because nothing about the authors' environment is inferable from
  published content, and the gate is a command, not a judgment call.
* Good, because the Woodpecker file demonstrates real-world usage of the
  very extension mechanism ironbark implements.
* Bad, because test fixtures and historical plan/research docs get renamed
  churn with no functional change — accepted, one-time cost.

## Pros and Cons of the Options

### Full sweep + parameterized Woodpecker example + grep gate

* Good, because complete and mechanically verifiable.
* Good, because the example pipeline stays genuinely runnable.
* Bad, because it touches many files that never needed functional change.

### Scrub only the obviously internal doc(s)

* Good, because minimal churn.
* Bad, because references live in CI config, DESIGN payload examples, and
  test fixtures too — a partial scrub misses them and rots.

### Drop .woodpecker.yaml

* Good, because zero risk of stale internal config.
* Bad, because it discards the project's best self-demonstration — a
  Woodpecker pipeline in a Woodpecker-extension repo.

## More Information

DEC-0011 (private-first flip this gates), publish plan
docs/plans/2026-07-23-publish.md (W1.2 lists known sites; the grep gate is
in the pre-flight checklist). History scrub question tracked as plan D2.

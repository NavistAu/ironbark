---
id: "DEC-260801002907"
title: "README-first documentation: no website at launch"
status: accepted
date: 2026-07-30
y-statement: >-
  In the context of launching ironbark's docs, facing whether a docusaurus site
  is worth building, we decided for README-first with no website at launch,
  against building the site DEC-260723134317 had planned, to achieve doc investment
  where the audience reads.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "documentation", "website"]
supersedes: ["DEC-260723134317"]
---

# README-first documentation: no website at launch

## Context and Problem Statement

DEC-260723134317 chose a docusaurus site on GitHub Pages at
`ironbark.foss.navist.au`. During publish execution the maintainer
reopened the premise: is a multi-page documentation site worth the effort
versus a good comprehensive README? The audience is Woodpecker+Vault
operators; the README already carries the full pitch, deploy guide, and
operator contract; SPEC, DESIGN, and the decision log all render natively
on GitHub.

## Decision Drivers

* Effort should go where the audience reads — for a niche operator tool,
  that is the repository itself.
* A docusaurus site adds a node toolchain to a Go repo, a second doc
  surface that can drift, and mandatory analytics + DNS obligations.
* Beachcomber's site is justified by breadth (SDKs, CLI reference,
  general audience) that ironbark does not have.
* The domain/namespace idea (`*.foss.navist.au`) loses nothing by
  waiting; it can be revived on a post-launch demand signal.

## Considered Options

* README-first, no website at launch
* Build the docusaurus site pre-flip (DEC-260723134317 as ratified)

## Decision Outcome

Chosen option: "README-first, no website at launch", because the site's
audience-reach benefit does not cover its toolchain, drift, and
maintenance costs for this tool today.

The W6 docs-quality gate absorbs the effort as a higher bar on the README
and in-repo docs (value-first framing, walkthrough-tested commands,
cross-doc consistency with SPEC normative). The website plan is shelved,
not deleted: DEC-260723134317's mechanics (docusaurus scaffold reuse, GitHub
Pages, `ironbark.foss.navist.au` CNAME, org domain verification) remain
the blueprint if revived, and revival carries two standing conditions
recorded from the maintainer: the site must be a tracked property in the
maintainer's analytics stack (Umami), and its DNS must be declared
through the maintainer's DNS IaC.

### Consequences

* Good, because one documentation surface, one quality bar, zero added
  toolchains.
* Good, because launch is not gated on site content, DNS, or analytics
  wiring.
* Bad, because no branded docs home and no pageview signal — accepted;
  GitHub traffic insights partially substitute.
* Bad, because if demand appears, the site is a from-scratch effort at a
  busier time — mitigated by DEC-260723134317 remaining as the blueprint.

## Pros and Cons of the Options

### README-first, no website at launch

* Good, because the README is already the project's best document and
  the audience's first stop.
* Good, because in-repo docs cannot drift from a second rendering layer.
* Bad, because long-form navigation (sidebar, search) is worse than a
  docs site.

### Build the docusaurus site pre-flip

* Good, because branded home and structured navigation from day one.
* Bad, because node toolchain + content re-projection + analytics + DNS
  for an audience that reads repos; rejected as premature.

## More Information

Supersedes DEC-260723134317 (website: docusaurus at ironbark.foss.navist.au) —
its status is updated to superseded; its mechanics remain the revival
blueprint. See publish plan docs/plans/2026-07-23-publish.md W4/W6.

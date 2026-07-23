---
id: "DEC-0016"
title: "Website: docusaurus on GitHub Pages at ironbark.foss.navist.au"
status: accepted
date: 2026-07-23
y-statement: >-
  In the context of giving published ironbark implementer-grade docs in
  all forms, facing the constraint of not buying a domain and the org's
  existing beachcomber docusaurus/GitHub Pages setup, we decided for a
  docusaurus site reusing the beachcomber scaffold, deployed to GitHub
  Pages under ironbark.foss.navist.au (CNAME to navistau.github.io on
  DNS the maintainer already controls, establishing a reusable
  *.foss.navist.au namespace for future FOSS tools) and against a
  purchased apex domain, a bare navistau.github.io/ironbark path, or the
  shorter ironbark.navist.au, to achieve a zero-cost branded docs home
  consistent with the org's tooling, accepting docusaurus maintenance and
  that the site re-projects existing docs rather than being a launch
  blocker.
decision-makers: ["Joshua Hogendorn", "Claude"]
tags: ["publishing", "documentation", "website"]
supersedes: []
---

# Website: docusaurus on GitHub Pages at ironbark.foss.navist.au

## Context and Problem Statement

The maintainer wants docs "in all forms" at implementer grade, is open to
a website, but explicitly does not want to buy a domain for it (unlike
beachcomber's purchased beachcomber.sh). The org already runs one
docusaurus/GitHub Pages/custom-domain site, so scaffold, workflow shape,
and operational knowledge exist.

## Decision Drivers

* Zero domain purchase; DNS for navist.au is already in hand.
* Reuse over invention: the beachcomber website stack is proven in-org.
* A namespace pattern that scales to future FOSS tools without
  per-project domain decisions.
* Website must not gate v0.1.0 — content is a re-projection of the
  README/SPEC/DESIGN corpus, which is the normative source.

## Considered Options

* docusaurus + GitHub Pages + ironbark.foss.navist.au
* Same stack at ironbark.navist.au
* No custom domain (navistau.github.io/ironbark)
* Purchased apex domain (beachcomber pattern)

## Decision Outcome

Chosen option: "docusaurus + GitHub Pages + ironbark.foss.navist.au",
because it costs nothing, reuses the proven stack, and the `foss.`
layer reserves first-level navist.au subdomains while giving every future
tool an obvious home (`<tool>.foss.navist.au`).

Mechanics: `website/` scaffold cloned from beachcomber's layout;
deploy-website workflow on push to main; `CNAME` file in the site;
DNS CNAME `ironbark.foss.navist.au → navistau.github.io`; verify
`navist.au` on the GitHub org (subdomain-takeover guard); HTTPS enforced
once the certificate issues. Content: landing (README pitch + "why not
just…"), deploy guide, operator contract, reference, SPEC/DESIGN,
rendered decision log.

### Consequences

* Good, because branded docs home at zero recurring cost.
* Good, because the namespace decision is made once for all future tools.
* Bad, because docusaurus/node is a second toolchain in a Go repo —
  accepted, already carried by beachcomber.
* Bad, because two doc surfaces (repo + site) can drift — mitigated by
  the W6 rule that SPEC is normative and the site is a projection.

## Pros and Cons of the Options

### ironbark.foss.navist.au

* Good, because reusable pattern, no purchase, commercial namespace kept
  clean.
* Bad, because a longer hostname than the alternatives.

### ironbark.navist.au

* Good, because shorter.
* Bad, because spends first-level subdomains of the brand apex on each
  tool.

### No custom domain

* Good, because zero DNS work.
* Bad, because unbranded, and moving to a domain later churns links.

### Purchased apex (beachcomber pattern)

* Good, because maximum brandability.
* Bad, because explicitly ruled out — recurring cost for a niche
  operator tool.

## More Information

Publish plan W4 (site build) and W6 (docs quality gate). Precedent:
NavistAu/beachcomber website/ + deploy-website.yml + beachcomber.sh.

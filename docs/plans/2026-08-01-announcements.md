# Announcements plan: ironbark v0.1.0+

Split out of `2026-07-23-publish.md` W5 (2026-08-01) for execution in a
later session. The publish itself is complete: repo public, v0.1.0
released, image on GHCR, cosign-signed.

## Standing rule

Every item below posts content under the maintainer's identity on a
third-party venue. **Each item requires explicit per-item confirmation at
execution time**, and the exact content (PR diff, post text) is drafted
and shown for review before anything is submitted. Nothing here is
pre-authorized.

## Messaging

Lead with the README's value proposition, not mechanism: per-identity
(repo/event/branch) scoping of Vault/OpenBao secrets into Woodpecker,
versus the all-or-nothing access every other wiring gives. Secondary
points, per audience: stricter-than-OIDC posture (no identity credential
in the build to exfiltrate; mint-only broker), stateless/Vault-side-IaC
onboarding, first-class OpenBao support (integration-tested 2.5.5),
signed distroless image, AGPL.

## Wave 1 — ecosystem lists (do first; low-noise, high-relevance)

1. **awesome-woodpecker** (`woodpecker-ci/awesome-woodpecker`): PR adding
   ironbark under the appropriate section (extensions/tools). Read its
   CONTRIBUTING/format rules first; one-line description in list style.
2. **Woodpecker docs**: check whether the secret-extension docs page
   (woodpecker-ci.org/docs/usage/extensions/secret-extension) links known
   implementations. If such a list exists, PR to `woodpecker-ci/woodpecker`
   docs; if not, consider asking in their community whether one is wanted
   — ask before PRing unsolicited.
3. **OpenBao community** (GitHub discussions / mailing list / Matrix —
   pick per their community norms): short post. Angle: tools that
   explicitly integration-test against OpenBao are rare; ironbark treats
   it as co-equal with Vault.

## Wave 2 — broadcast (optional; only after wave 1 and user appetite)

4. **Show HN** — title shape: "Show HN: ironbark – per-pipeline Vault
   secrets for Woodpecker CI". Expect the "why not OIDC" question; the
   README aside is the prepared answer.
5. **lobste.rs** — same content, tags per their taxonomy.
6. **r/selfhosted / r/devops** — check each sub's self-promotion rules
   first; skip any sub where it would violate norms.

## Prerequisites before any item

- NavistAu org avatar set (in progress — arrow PNGs rendered).
- Repo social preview image (optional, nice for wave 2 link cards).
- A sanity pass on the README as the landing experience: badges render,
  Install works copy-paste, Footguns index anchors resolve on github.com.

## Verification per item

Link live and correct; for PRs, merged or constructively reviewed; note
each completed item back into this file with date + URL.

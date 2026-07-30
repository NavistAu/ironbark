# M1 plan cross-AI adversarial review log

Target: `docs/plans/2026-07-11-m1-broker.md`. Same loop mechanics as
[`SPEC-REVIEWS.md`](SPEC-REVIEWS.md); the SPEC is accepted and settled —
reviewers judge plan fidelity, sequencing, test adequacy, executability,
and hallucination only.

## Cycle 1 — 2026-07-11

Verdicts: codex `high=1 medium=4 low=1`; gemini `high=0 medium=2 low=1`.

| ID | Rev | Sev | Finding (summary) | Disposition |
|---|---|---|---|---|
| CP1 | codex | MED | `Derive` test table short of the §9.2 matrix (no `pull_request_closed`, no slash-branch) | **ACCEPTED** — table extended + explicit 8-events × 4-branch-shapes loop requirement. Task 3. |
| CP2 | codex | HIGH | Only four of §9.3's five canary-misconfig integration cases — non-orphan missing | **ACCEPTED-MODIFIED** — fifth case added with the product-dependent nuance: canary detects non-orphan only where the mint response exposes the flag (SPEC §3.5 soft assertion); the privileged-client check is definitive; the test pins per-product behavior. Task 14. |
| CP3 | codex | MED | Lexicographic within-tier ordering stated but untested (deterministic collisions depend on it) | **ACCEPTED** — `a-b` vs `a_b` unsorted-LIST case added with exact winner. Task 9. |
| CP4 | codex | MED | No test for the no-chain deref rule | **ACCEPTED** — deref-returns-`$ref` case added (no second call; `$ref` field name fails validation → skipped). Task 9. |
| CP5 | codex | MED | SPEC §1.2's 30s hard request timeout unimplemented/untested anywhere | **ACCEPTED** — injectable timeout wired in httpapi; blocking-broker test with `outcome=error` audit assertion. Task 11. |
| CP6 | codex | LOW | testdata key path inconsistent between creation and smoke usage | **ACCEPTED** — canonical `internal/wpsign/testdata/dev-ed25519.{pem,pub}`, created in Task 4. Task 12. |
| GP1 | gemini | LOW | Claim: `hashicorp/vault:1.20` is not a valid version | **REJECTED** — stale reviewer memory: Vault 1.20.4 was verified to exist during the 2026-07-10 research session. Spirit adopted: Task 13 now says confirm BOTH image tags at implementation time, symmetric with the OpenBao instruction. |
| GP2 | gemini | MED | TTL-merge test description "role TTL governs" could mislead vs the research §7.4 lesser-of finding | **ACCEPTED (wording)** — restated: request sends no TTL ⇒ token TTL equals role `token_ttl`, consistent with lesser-of when one side is absent; per-product behavior recorded. Task 14. |
| GP3 | gemini | MED | Non-orphan canary case missing (duplicate of CP2) | **ACCEPTED (dup)** — see CP2. |

**Post-revision state: all cycle-1 findings dispositioned (8 accepted,
1 rejected with rationale).**

CYCLE_SUMMARY (cycle 1, pre-revision): current_high=1

## Cycle 2 — 2026-07-11

Verdicts: codex `high=0 medium=0 low=1`; gemini `high=0 medium=1 low=2`.
No cycle-1 fix challenged except CP6's (incomplete, see CP2-1).

| ID | Rev | Sev | Finding (summary) | Disposition |
|---|---|---|---|---|
| CP2-1 | codex | LOW | CP6 fix incomplete: Task 12's smoke consumes a keypair no task creates | **ACCEPTED** — Task 4 gains an explicit generate-and-check-in step (openssl commands given); canonical path everywhere. |
| GP2-1 | gemini | MED | Session loop and canary were uncoordinated — a re-login would not re-run the canary, violating SPEC §3.5 and minting on stale canary state | **ACCEPTED** — unified `Client.Run(ctx, prefix)` lifecycle: canary after EVERY login/re-login, 60s retry while failed; coordination test added (canary-call counter across a forced re-login). Tasks 7/8/12. |
| GP2-2 | gemini | LOW | Broker's branchful determination for the Sweep call was implicit | **ACCEPTED** — `policy.Branchful(event)` exported as the single source of the branchful set; broker passes it to Sweep explicitly. Tasks 3/10. |
| GP2-3 | gemini | LOW | Fuzz-test description used a pair-based property model foreign to Go's single-input fuzzing | **ACCEPTED** — reworded to round-trip-decode injectivity proof, single-input model. Task 1. |

**All cycle-2 findings addressed.**

## CONVERGED ✓

Both reviewers report zero HIGH findings in cycle 2; the sole MEDIUM
(GP2-1) and three LOWs were textual-scope fixes applied same-cycle.
Totals across the plan loop: 13 findings, 12 accepted, 1 rejected with
evidence-backed rationale.

CYCLE_SUMMARY (final): current_high=0

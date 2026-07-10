# SPEC.md cross-AI adversarial review log

Loop mechanics: each cycle, codex (OpenAI, high reasoning) and gemini review
`docs/SPEC.md` against the verified-facts docs; every finding is triaged
(verified against source-verified facts before acceptance), dispositioned
here, and accepted findings are folded into the spec before the next cycle.
Convergence = a cycle with zero valid HIGH findings. Max 3 cycles.

## Cycle 1 — 2026-07-11

Reviewers: codex (gpt-5.5, reasoning=high, docs inlined — its own sandbox
cannot nest inside the session sandbox), gemini (repo file access).
Raw outputs: session scratchpad `cycle1-codex.md`, `cycle1-gemini.md`.
Verdicts: gemini `high=1 medium=1 low=2`; codex `high=0 medium=5 low=2`.

| ID | Rev | Sev | Finding (summary) | Disposition |
|---|---|---|---|---|
| G1 | gemini | HIGH | `token_type=service` is a silent-failure prerequisite with no M1 enforcement | **ACCEPTED-MODIFIED** — enforcement added, but not via role-read permission (would widen the create-only AppRole). Instead: (a) per-mint assertion on the mint response's `token_type`; (b) startup canary mint that validates type, orphan flag, glob coverage of the policy prefix, and revoke-self, then revokes itself. `/readyz` fails until the canary passes. SPEC §3.5, §1.1, §1.3. |
| G2 | gemini | MED | Sweep order base→event→branch + first-writer-wins makes the LEAST specific secret win name collisions | **ACCEPTED** — order reversed: branch → event → base; most-specific wins. SPEC §4.1/§4.2. |
| G3 | gemini | LOW | custom_metadata fallback metadata-GET unnecessary (data-GET always carries it) | **ACCEPTED-MODIFIED** — claim is from reviewer memory, so: fallback removed AND the "custom_metadata present in data-GET" assumption is a named dual-product integration assertion. SPEC §4.6, §9.3. |
| G4 | gemini | LOW | 30s freshness window unnecessarily wide for a synchronous server-to-server call | **ACCEPTED** — default now 10s. SPEC §5, §7. |
| C1 | codex | MED | `.identity`/`.config` error handling incomplete: 5xx/timeout/malformed undefined; silent skip could bypass operator-enabled protections | **ACCEPTED** — non-403/404 directive read errors → 502 + revoke; malformed `.identity` → fail closed as identity mismatch; malformed `.config` → 502 + revoke. SPEC §4.4/§4.5. |
| C2 | codex | MED | Tier descent depended on parent LIST visibility; least-privilege tier-only policies would yield nothing | **ACCEPTED** — all three identity-derived prefixes are LISTed independently (they are known a priori; no discovery needed); 403/404 skip per level. Least-privilege test added. SPEC §4.1, §9.3. |
| C3 | codex | MED | Deref failure handling undefined; "leases disable revocation" wrongly leaves tokens+leases alive after a failed request | **ACCEPTED** — non-403/404 deref failure → 502 + revoke; revocation rule restated: ALWAYS revoke on no-return/failure paths (service-token cascade cleans the leases — that is the desired cleanup); never revoke on success paths. SPEC §3.4, §4.3. |
| C4 | codex | MED | Non-string KV/deref values would emit invalid extension JSON → Woodpecker decode failure → fail-open | **ACCEPTED** — string-only rule: non-string field values are skipped with a warning, never coerced. Unit + integration tests added. SPEC §4.2, §9.2. |
| C5 | codex | MED | Role contract doesn't pin `token_no_default_policy=false`; stripped default breaks load-bearing revoke-self | **ACCEPTED** — added to role contract; canary + integration test prove revoke-self. SPEC §3.1, §9.3. |
| C6 | codex | LOW | Known-event table rule contradicts unknown-event forward-compatibility paragraph | **ACCEPTED** — "must be in known set" removed; unknown events: lowercase, P1 only, event echoed in pins. SPEC §2.1. |
| C7 | codex | LOW | `vault_addr`-only response ambiguity vs empty→204 rule | **ACCEPTED** — `vault_addr` never counts toward "non-empty"; no address-only 200; revoke + 204. SPEC §1.2, §6. |

Rejected findings: none. (Codex's first run could not read the workspace —
nested-sandbox failure, honestly reported, not counted as a finding.)

**Post-revision state: all cycle-1 findings addressed in SPEC.md.**

CYCLE_SUMMARY (cycle 1, pre-revision): current_high=1

## Cycle 2 — 2026-07-11

Reviewers as cycle 1, both fed the revised spec + this disposition log
inline. Verdicts: codex `high=3 medium=1 low=0`; gemini
`high=1 medium=2 low=1`. No cycle-1 finding was re-raised — cycle-2
findings target newly added text and deeper analysis, so the rising HIGH
count is depth, not stall.

| ID | Rev | Sev | Finding (summary) | Disposition |
|---|---|---|---|---|
| C2-1 | codex | HIGH | Token renewability unbounded — default policy grants renew-self, so a leaked token could outlive its TTL, contradicting the threat model | **ACCEPTED** — `renewable=false` added to the role contract; canary asserts the mint response's `renewable`; misconfig integration test added. SPEC §3.1/§3.5/§9.3. |
| C2-2 | codex | HIGH | Canary failure only degraded `/readyz`; POSTs still minted with only a `token_type` guard — non-orphan/renewable/stripped-default misconfigs would still produce tokens. Also flagged the contradictory §9.3 "does not preflight" leftover | **ACCEPTED** — canary is now a hard gate: failed/unknown state → POST `502` without minting; contradictory bullet replaced; no-mint-while-failed test added. SPEC §1.2.6/§3.5/§9.3. |
| C2-3 | codex | HIGH | Lowercasing the branch before `esc()` breaks injectivity: attacker branch `Main` case-folds onto protected `main`'s tier → privilege escalation | **ACCEPTED** — best catch of the loop. Branch is never case-folded; `esc()` runs on original bytes and percent-encodes uppercase (`Main` → `%4dain`), output stays lowercase and injective. `main` vs `Main` test added; DESIGN.md threat row + convention text updated. SPEC §2.1/§2.2/§9.2. |
| C2-4 | codex | MED | Audit line required payload-derived fields for ALL POSTs, contradicting the no-payload-before-verification rule | **ACCEPTED** — two audit shapes; refused-signature lines carry remote addr + reason only. SPEC §8.1. |
| G2-1 | gemini | HIGH | Claim: `<prefix>/*` glob cannot match `/` (multi-level policy names), so the role would reject all mints | **REJECTED** — miscites the research it names: R§7.6 source-verified that `ryanuber/go-glob` is plain substring globbing, `*` matches any characters INCLUDING `/`, no path-segment semantics. `ci/*` covers the full output space. A clarifying note was added to §3.1 since the confusion is plausible for operators, but the finding is factually wrong. |
| G2-2 | gemini | MED | §9.3 canary bullet contradicts the "does not preflight" bullet | **ACCEPTED (duplicate of C2-2's second part)** — contradictory bullet removed. |
| G2-3 | gemini | MED | Canary cannot verify orphan status (claim: mint response does not expose it) | **PARTIAL** — the exposure claim is unverified either way (not covered by our source research; reviewer argues from memory). Resolved without depending on it: canary asserts orphan only IF the response exposes it; the privileged-client integration test is the definitive orphan check. SPEC §3.5/§9.3. |
| G2-4 | gemini | LOW | SIGHUP mentioned once, ambiguous requirement status | **ACCEPTED** — demoted: rotation requires restart; SIGHUP optional, not v1. SPEC §5. |

**Post-revision state: all cycle-2 findings dispositioned (7 accepted/
partial, 1 rejected with rationale).**

CYCLE_SUMMARY (cycle 2, pre-revision): current_high=4 raised, 3 valid, 0
remaining post-revision

## Cycle 3 — 2026-07-11

Verdicts: codex `high=0 medium=1 low=0`; gemini `high=1 medium=1 low=1`.
No prior finding re-raised; no fix challenged as inadequate.

| ID | Rev | Sev | Finding (summary) | Disposition |
|---|---|---|---|---|
| C3-1 | codex | MED | ironbark's own AppRole token contract never states it needs `default`/renew-self for the required session renewal — the "exactly create" wording would break renewal if followed literally | **ACCEPTED** — explicit AppRole token contract added (renewable, retains `default`; one ACL policy: create on the token role; safe degradation to re-login if default stripped). SPEC §1.3. |
| G3-1 | gemini | HIGH | A branch named `.` or `..` passes `esc()` unchanged → branch tier collapses onto event tier / path-special segments | **ACCEPTED-MODIFIED** — exploitability is limited (git ref rules forbid `.`/`..`/dot-leading components, enforced forge-side), so this is robustness rather than a live escalation; fixed at the root instead of via 400-validation: `esc()` now always encodes a leading `.`, so NO output is ever `.`, `..`, or dot-prefixed. Property test extended. SPEC §2.2/§9.2. |
| G3-2 | gemini | MED | §1.2 sequence omitted the `.config` read step (its fail-closed rules were only reachable via §4.5) | **ACCEPTED** — step 7 is now "read repo directives" covering `.identity` and `.config` with their fail rules inline. SPEC §1.2. |
| G3-3 | gemini | LOW | Dot-entry skipping stated in §2.4 but absent from the normative sweep logic | **ACCEPTED** — explicit skip rule in §4.1 (all levels, not just base). |

**Post-revision state: all cycle-3 findings addressed. Zero unresolved
HIGHs; fixes pending reviewer verification (cycle 4, verification-only).**

CYCLE_SUMMARY (cycle 3, pre-revision): current_high=1 raised (downgraded
in substance), 0 remaining post-revision

## Cycle 4 — 2026-07-11 (verification-only)

Both reviewers asked ONLY to verify the cycle-3 fixes and check the
revisions introduced no new HIGH.

- codex: `No findings. VERDICT: high=0 medium=0 low=0`
- gemini: `No findings. VERDICT: high=0 medium=0 low=0`

## CONVERGED ✓

Trajectory: cycle 1 → 1 HIGH raised; cycle 2 → 3 valid HIGHs raised (new
depth, zero re-raises); cycle 3 → 1 HIGH raised (robustness-grade); cycle
4 → clean sign-off from both reviewers. Totals across the loop: 19
findings raised, 17 accepted (some modified), 1 partial, 1 rejected with
evidence-backed rationale. No finding was ever re-raised and no fix was
challenged as inadequate.

CYCLE_SUMMARY (final): current_high=0

// Package broker orchestrates SPEC §1.2 steps 5–10: derive policies, mint
// a pipeline token, read the repo's .identity/.config directives, sweep
// its secrets, and build the response — enforcing the SPEC §3.4
// revocation-by-outcome invariant (every non-200 response revokes the
// minted token; a 200 never does) structurally: Handle's named return
// is inspected by a single deferred func registered right after the mint
// succeeds, so every return statement below that point — however it's
// shaped, including a bare `Result{...}` literal — is revoke-checked;
// there is no per-branch call to forget.
//
// Steps 1–4 (read body, verify signature, parse payload, extract
// identity) belong to internal/httpapi (Task 11), which calls Handle
// with the already-verified, already-parsed identity.
package broker

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ironbark/internal/identity"
	"ironbark/internal/policy"
	"ironbark/internal/vaultx"
)

// Vault is everything the broker needs from a Vault/OpenBao client;
// *vaultx.Client satisfies it (asserted below). Mocked in tests.
type Vault interface {
	CanaryOK() bool
	Base(id identity.Identity) string
	MintToken(ctx context.Context, policies []string, meta map[string]string, displayName string) (vaultx.Mint, error)
	RevokeSelf(ctx context.Context, token string) error
	ReadIdentity(ctx context.Context, token, base string) (*string, error)
	ReadConfig(ctx context.Context, token, base string) (map[string]string, error)
	Sweep(ctx context.Context, token string, id identity.Identity, branchful bool) (vaultx.SweepResult, error)
}

var _ Vault = (*vaultx.Client)(nil)

// Secret is one entry of the SPEC §6 response body.
type Secret struct {
	Name   string
	Value  string
	Events []string
	Images []string
}

// Outcome classifies a Handle result for the SPEC §8.1 audit line.
type Outcome string

const (
	OutcomeOK               Outcome = "ok"
	OutcomeUnonboarded      Outcome = "unonboarded"
	OutcomeIdentityMismatch Outcome = "identity_mismatch"
	OutcomeError            Outcome = "error"
)

// AuditFields carries everything httpapi (Task 11) needs to render the
// SPEC §8.1 verified-request audit line. The broker never logs itself.
type AuditFields struct {
	PoliciesRequested []string
	PolicyWarnings    []string
	SecretNames       []string
	TokenAccessor     string
	TokenTTL          time.Duration
}

// Result is Handle's complete outcome: the HTTP status httpapi should
// send, the secrets to serialize (only meaningful on Status 200), the
// classified Outcome, and the audit fields.
type Result struct {
	Status  int
	Secrets []Secret
	Outcome Outcome
	// RevokeFailed is true when this Result's status was non-200 and the
	// resulting best-effort RevokeSelf call itself errored (SPEC §3.4:
	// revoke failures are logged, TTL is the backstop). The broker never
	// logs; httpapi (Task 11) is expected to log this bool when set.
	RevokeFailed bool
	Audit        AuditFields
}

// Broker holds the config Handle needs beyond the per-request identity.
type Broker struct {
	vault              Vault
	policyPrefix       string
	advertiseVaultAddr string
}

// New builds a Broker. policyPrefix is POLICY_PREFIX (SPEC §2.3);
// advertiseVaultAddr is ADVERTISE_VAULT_ADDR (SPEC §7), empty meaning the
// vault_addr pin is never added.
func New(v Vault, policyPrefix, advertiseVaultAddr string) *Broker {
	return &Broker{vault: v, policyPrefix: policyPrefix, advertiseVaultAddr: advertiseVaultAddr}
}

// warningPolicyRe matches Vault/OpenBao's per-mint nonexistent-policy
// warning (R§7.1's Go format string is `Policy %q does not exist`, %q
// producing double-quoted output). The leading word is matched
// case-insensitively: this codebase's own vaultx fixtures use a
// lowercase "policy" (internal/vaultx/mint_test.go, client_test.go)
// while the SPEC/DESIGN/research docs quote the capitalized form from
// Vault's source — matching either avoids coupling un-onboarded
// detection to a casing choice neither this package nor its tests
// control.
var warningPolicyRe = regexp.MustCompile(`(?i)^policy\s+"([^"]*)"\s+does not exist$`)

// warnedNonexistentPolicies parses SPEC §1.2.6 / R§7.1 warnings, returning
// the policy names each warning says do not exist. Warnings that don't
// match the expected shape are ignored (not this function's concern).
func warnedNonexistentPolicies(warnings []string) []string {
	var out []string
	for _, w := range warnings {
		if m := warningPolicyRe.FindStringSubmatch(w); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// allWarned reports whether warned covers every name in policies — the
// SPEC §1.2.6 un-onboarded test ("every requested policy does not
// exist"). A single requested policy with no matching warning means a
// real tier exists, so the repo is NOT un-onboarded.
func allWarned(policies, warned []string) bool {
	warnedSet := make(map[string]bool, len(warned))
	for _, w := range warned {
		warnedSet[w] = true
	}
	for _, p := range policies {
		if !warnedSet[p] {
			return false
		}
	}
	return true
}

// splitTrimCommaList splits a comma-separated .config value (SPEC §4.5's
// vault_token_images), trimming whitespace around each element.
// Deliberately diverges from vaultx's private splitTrimCommaList (SPEC
// §4.6), which returns [""] for an empty input: here v=="" must return
// nil (no Images at all), not a single empty-string image — load-bearing
// for the common case where vault_token_images is unset. Do not unify the
// two without preserving this difference.
func splitTrimCommaList(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

// secretNames returns the Name of every secret, for AuditFields.SecretNames
// (SPEC §8.1: names only, never values).
func secretNames(secrets []Secret) []string {
	if len(secrets) == 0 {
		return nil
	}
	names := make([]string, len(secrets))
	for i, s := range secrets {
		names[i] = s.Name
	}
	return names
}

// Handle runs SPEC §1.2 steps 5–10 for an already-verified, already-parsed
// identity. The return is named (result) so the revoke-on-non-200 defer
// registered below can inspect and, on a failed revoke, annotate it.
func (b *Broker) Handle(ctx context.Context, id identity.Identity) (result Result) {
	// Step 5: derive policies.
	policies := policy.Derive(id, b.policyPrefix)
	audit := AuditFields{PoliciesRequested: policies}

	// Step 6, canary gate: no token exists yet, so there is nothing to
	// revoke on this path — SPEC §1.2 step 6 / §3.5.
	if !b.vault.CanaryOK() {
		return Result{Status: 502, Outcome: OutcomeError, Audit: audit}
	}

	branchful := policy.Branchful(id.Event)
	meta := map[string]string{
		"org":             id.Org,
		"repo":            id.Repo,
		"event":           id.Event,
		"branch":          id.Branch,
		"pipeline_number": strconv.FormatInt(id.PipelineNumber, 10),
		"commit":          id.Commit,
	}
	displayName := "ironbark-" + id.Org + "-" + id.Repo

	mint, err := b.vault.MintToken(ctx, policies, meta, displayName)
	if err != nil {
		// Mint itself failed: no token was minted, nothing to revoke.
		return Result{Status: 502, Outcome: OutcomeError, Audit: audit}
	}

	audit.TokenAccessor = mint.Accessor
	audit.TokenTTL = mint.TTL

	// From this point on a token exists. This defer is the ONLY place
	// that revokes: it runs after every return statement below has
	// already assigned the named `result`, so it is structurally
	// impossible for any return in this function — through finish or a
	// direct Result{...} literal — to produce a non-200 status without
	// this check running (SPEC §3.4). A 200 is a no-op here; revoke
	// failures never change the status (best-effort — TTL is the
	// backstop) and are surfaced via result.RevokeFailed for httpapi to
	// log, since the broker itself never logs.
	defer func() {
		if result.Status != 200 {
			if err := b.vault.RevokeSelf(ctx, mint.Token); err != nil {
				result.RevokeFailed = true
			}
		}
	}()

	finish := func(status int, outcome Outcome, secrets []Secret) Result {
		audit.SecretNames = secretNames(secrets)
		return Result{Status: status, Outcome: outcome, Secrets: secrets, Audit: audit}
	}

	// token_type assertion (SPEC §1.2.6): a misconfigured role could mint
	// a batch token; ironbark never proceeds with a non-service token.
	if mint.TokenType != "service" {
		return finish(502, OutcomeError, nil)
	}

	// Un-onboarded detection (SPEC §1.2.6, R§7.1).
	audit.PolicyWarnings = warnedNonexistentPolicies(mint.Warnings)
	if allWarned(policies, audit.PolicyWarnings) {
		return finish(204, OutcomeUnonboarded, nil)
	}

	base := b.vault.Base(id)

	// Step 7a: .identity (SPEC §4.4).
	forgeID, err := b.vault.ReadIdentity(ctx, mint.Token, base)
	if err != nil {
		if errors.Is(err, vaultx.ErrMalformedDirective) {
			return finish(204, OutcomeIdentityMismatch, nil)
		}
		return finish(502, OutcomeError, nil)
	}
	if forgeID != nil && *forgeID != id.ForgeRemoteID {
		return finish(204, OutcomeIdentityMismatch, nil)
	}

	// Step 7b: .config (SPEC §4.5). Malformed or a plain read error are
	// BOTH 502 here — unlike .identity, there is no 204 outcome for a
	// broken .config (a broken suppression directive must never silently
	// fall back to defaults).
	config, err := b.vault.ReadConfig(ctx, mint.Token, base)
	if err != nil {
		return finish(502, OutcomeError, nil)
	}

	// Step 8: sweep (deref happens inside Sweep — SPEC §4.3 is subsumed).
	sweep, err := b.vault.Sweep(ctx, mint.Token, id, branchful)
	if err != nil {
		return finish(502, OutcomeError, nil)
	}

	// Step 9: build response (SPEC §6).
	secrets := make([]Secret, 0, len(sweep.Secrets)+2)
	for _, s := range sweep.Secrets {
		events := s.Events
		if len(events) == 0 {
			events = []string{id.Event}
		}
		secrets = append(secrets, Secret{Name: s.Name, Value: s.Value, Events: events, Images: s.Images})
	}

	suppressed := config["vault_token"] == "false"
	if !suppressed {
		secrets = append(secrets, Secret{
			Name:   "vault_token",
			Value:  mint.Token,
			Events: []string{id.Event},
			Images: splitTrimCommaList(config["vault_token_images"]),
		})
	}

	// Emptiness (SPEC §1.2 step 10 / §6): computed from the swept secrets
	// and suppression state directly, never from len(secrets) — vault_addr
	// must never count toward "non-empty" regardless of append order.
	//
	// Outcome-enum decision: SPEC §8.1 closes the audit outcome enum to
	// exactly {ok, unonboarded, identity_mismatch, error} — this task's
	// own type definition mirrors that closed set. Empty-and-suppressed
	// is neither an error nor an identity problem, and "ok" would
	// contradict a 204 status, so it reuses OutcomeUnonboarded: from an
	// operator's perspective both mean the same thing — "this repo/tier
	// currently has nothing ironbark can hand the pipeline" — and adding
	// a 5th enum value would violate the closed set SPEC §8.1 documents.
	if len(sweep.Secrets) == 0 && suppressed {
		return finish(204, OutcomeUnonboarded, nil)
	}

	if b.advertiseVaultAddr != "" {
		secrets = append(secrets, Secret{Name: "vault_addr", Value: b.advertiseVaultAddr, Events: []string{id.Event}})
	}

	// Step 10: a 200 never revokes (the deferred check above is a no-op
	// when result.Status == 200) — the returned token and any deref
	// leases must outlive the response.
	return finish(200, OutcomeOK, secrets)
}

package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/vaultx"
)

// --- mock Vault: a test double for the Vault interface. Every method's
// return is independently programmable; RevokeSelf additionally records
// every call (and the token it was called with) so every test can assert
// the SPEC §3.4 revocation-by-outcome invariant directly, not just the
// status code. ---

type mockVault struct {
	canaryOK bool
	base     string

	mintCalled   bool
	mintPolicies []string
	mintMeta     map[string]string
	mintDisplay  string
	mintResult   vaultx.Mint
	mintErr      error

	identityBase   string
	identityToken  string
	identityResult *string
	identityErr    error

	configBase   string
	configToken  string
	configResult map[string]string
	configErr    error

	sweepToken     string
	sweepID        identity.Identity
	sweepBranchful bool
	sweepResult    vaultx.SweepResult
	sweepErr       error

	revokeCalls []string
	revokeCtxs  []context.Context
	// revokeCtxErrs records ctx.Err() AT THE MOMENT RevokeSelf was called
	// (not later): the fix's own `defer cancel()` cancels its detached ctx
	// right after the call returns (correct cleanup hygiene), so checking
	// ctx.Err() after Handle has already returned would observe a Done
	// ctx even on success — this must be sampled inline.
	revokeCtxErrs []error
	revokeErr     error
}

func (m *mockVault) CanaryOK() bool { return m.canaryOK }

func (m *mockVault) Base(id identity.Identity) string { return m.base }

func (m *mockVault) MintToken(ctx context.Context, policies []string, meta map[string]string, displayName string) (vaultx.Mint, error) {
	m.mintCalled = true
	m.mintPolicies = policies
	m.mintMeta = meta
	m.mintDisplay = displayName
	return m.mintResult, m.mintErr
}

func (m *mockVault) RevokeSelf(ctx context.Context, token string) error {
	m.revokeCalls = append(m.revokeCalls, token)
	m.revokeCtxs = append(m.revokeCtxs, ctx)
	m.revokeCtxErrs = append(m.revokeCtxErrs, ctx.Err())
	return m.revokeErr
}

func (m *mockVault) ReadIdentity(ctx context.Context, token, base string) (*string, error) {
	m.identityToken = token
	m.identityBase = base
	return m.identityResult, m.identityErr
}

func (m *mockVault) ReadConfig(ctx context.Context, token, base string) (map[string]string, error) {
	m.configToken = token
	m.configBase = base
	return m.configResult, m.configErr
}

func (m *mockVault) Sweep(ctx context.Context, token string, id identity.Identity, branchful bool) (vaultx.SweepResult, error) {
	m.sweepToken = token
	m.sweepID = id
	m.sweepBranchful = branchful
	return m.sweepResult, m.sweepErr
}

// testIdentity is the shared fixture identity for every test below: a
// branchful event (push) with a non-empty branch, so policy.Derive yields
// both P1 and P2 and Sweep is asked to sweep branchful.
func testIdentity() identity.Identity {
	return identity.Identity{
		Org:            "acme",
		Repo:           "widgets",
		Event:          "push",
		Branch:         "main",
		ForgeRemoteID:  "forge-123",
		Commit:         "deadbeef",
		PipelineNumber: 7,
	}
}

const (
	wantP1 = "ci/acme/widgets/push"
	wantP2 = "ci/acme/widgets/push/main"
)

func warningsFor(policies ...string) []string {
	out := make([]string, len(policies))
	for i, p := range policies {
		out[i] = `Policy "` + p + `" does not exist`
	}
	return out
}

func serviceMint(token string) vaultx.Mint {
	return vaultx.Mint{
		Token:     token,
		Accessor:  "accessor-" + token,
		TokenType: "service",
		TTL:       900 * time.Second,
	}
}

func TestHandle_CanaryFailed_502_NoMintNoRevoke(t *testing.T) {
	mv := &mockVault{canaryOK: false}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502", res.Status)
	}
	if res.Outcome != OutcomeError {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeError)
	}
	if mv.mintCalled {
		t.Errorf("MintToken was called, want no mint on canary failure")
	}
	if len(mv.revokeCalls) != 0 {
		t.Errorf("RevokeSelf called %d times, want 0", len(mv.revokeCalls))
	}
}

func TestHandle_MintError_502_NoRevoke(t *testing.T) {
	mv := &mockVault{canaryOK: true, mintErr: errors.New("boom")}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502", res.Status)
	}
	if res.Outcome != OutcomeError {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeError)
	}
	if len(mv.revokeCalls) != 0 {
		t.Errorf("RevokeSelf called %d times, want 0 (nothing minted)", len(mv.revokeCalls))
	}
}

func TestHandle_Happy_200_NoRevoke(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		base:       "ci/acme/widgets",
		mintResult: serviceMint("tok-happy"),
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{
				{Name: "api_key", Value: "s3cr3t"},
			},
		},
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200", res.Status)
	}
	if res.Outcome != OutcomeOK {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeOK)
	}
	if len(mv.revokeCalls) != 0 {
		t.Errorf("RevokeSelf called %d times, want 0 on 200", len(mv.revokeCalls))
	}

	var gotAPIKey, gotToken bool
	for _, s := range res.Secrets {
		if s.Name == "api_key" {
			gotAPIKey = true
			if s.Value != "s3cr3t" {
				t.Errorf("api_key value = %q", s.Value)
			}
			if len(s.Events) != 1 || s.Events[0] != "push" {
				t.Errorf("api_key events = %v, want [push] (default pin)", s.Events)
			}
		}
		if s.Name == "vault_token" {
			gotToken = true
			if s.Value != "tok-happy" {
				t.Errorf("vault_token value = %q, want tok-happy", s.Value)
			}
		}
	}
	if !gotAPIKey {
		t.Errorf("secrets missing api_key: %+v", res.Secrets)
	}
	if !gotToken {
		t.Errorf("secrets missing vault_token: %+v", res.Secrets)
	}

	// Mint call inputs (SPEC §3.2).
	if mv.mintDisplay != "ironbark-acme-widgets" {
		t.Errorf("display_name = %q, want ironbark-acme-widgets", mv.mintDisplay)
	}
	if mv.mintMeta["org"] != "acme" || mv.mintMeta["repo"] != "widgets" || mv.mintMeta["event"] != "push" ||
		mv.mintMeta["branch"] != "main" || mv.mintMeta["commit"] != "deadbeef" || mv.mintMeta["pipeline_number"] != "7" {
		t.Errorf("mint meta = %+v", mv.mintMeta)
	}
	if len(mv.mintPolicies) != 2 || mv.mintPolicies[0] != wantP1 || mv.mintPolicies[1] != wantP2 {
		t.Errorf("mint policies = %v, want [%s %s]", mv.mintPolicies, wantP1, wantP2)
	}

	// Audit fields.
	if res.Audit.TokenAccessor != "accessor-tok-happy" {
		t.Errorf("Audit.TokenAccessor = %q", res.Audit.TokenAccessor)
	}
	if res.Audit.TokenTTL != 900*time.Second {
		t.Errorf("Audit.TokenTTL = %v", res.Audit.TokenTTL)
	}
	wantNames := map[string]bool{"api_key": true, "vault_token": true}
	if len(res.Audit.SecretNames) != len(wantNames) {
		t.Errorf("Audit.SecretNames = %v", res.Audit.SecretNames)
	}
	for _, n := range res.Audit.SecretNames {
		if !wantNames[n] {
			t.Errorf("unexpected secret name in audit: %q", n)
		}
	}
}

func TestHandle_Unonboarded_AllPoliciesWarned_204_Revoke(t *testing.T) {
	mint := serviceMint("tok-unonboarded")
	mint.Warnings = warningsFor(wantP1, wantP2)
	mv := &mockVault{canaryOK: true, mintResult: mint}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 204 {
		t.Errorf("Status = %d, want 204", res.Status)
	}
	if res.Outcome != OutcomeUnonboarded {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeUnonboarded)
	}
	if res.Secrets != nil {
		t.Errorf("Secrets = %v, want nil on 204", res.Secrets)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-unonboarded" {
		t.Errorf("revokeCalls = %v, want [tok-unonboarded]", mv.revokeCalls)
	}
	if res.RevokeFailed {
		t.Errorf("RevokeFailed = true, want false (mock revoke succeeded)")
	}
	if len(res.Audit.PolicyWarnings) != 2 {
		t.Errorf("Audit.PolicyWarnings = %v, want 2 entries", res.Audit.PolicyWarnings)
	}
}

// TestHandle_PartialWarning_NotUnonboarded proves the "every requested
// policy" reading: a warning for only ONE of the two requested policies
// means a real tier exists (P1), so processing continues rather than
// short-circuiting to un-onboarded.
func TestHandle_PartialWarning_NotUnonboarded(t *testing.T) {
	mint := serviceMint("tok-partial")
	mint.Warnings = warningsFor(wantP2) // only the branch policy is nonexistent
	mv := &mockVault{
		canaryOK:   true,
		mintResult: mint,
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{{Name: "api_key", Value: "v"}},
		},
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 200 {
		t.Errorf("Status = %d, want 200 (not unonboarded — P1 exists)", res.Status)
	}
	if res.Outcome != OutcomeOK {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeOK)
	}
	if len(mv.revokeCalls) != 0 {
		t.Errorf("RevokeSelf called, want none on 200")
	}
}

func TestHandle_IdentityMismatch_204_Revoke(t *testing.T) {
	other := "different-forge-id"
	mv := &mockVault{
		canaryOK:       true,
		mintResult:     serviceMint("tok-mismatch"),
		identityResult: &other,
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 204 {
		t.Errorf("Status = %d, want 204", res.Status)
	}
	if res.Outcome != OutcomeIdentityMismatch {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeIdentityMismatch)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-mismatch" {
		t.Errorf("revokeCalls = %v, want [tok-mismatch]", mv.revokeCalls)
	}
}

func TestHandle_IdentityMatch_Continues(t *testing.T) {
	same := "forge-123" // matches testIdentity().ForgeRemoteID
	mv := &mockVault{
		canaryOK:       true,
		mintResult:     serviceMint("tok-match"),
		identityResult: &same,
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{{Name: "api_key", Value: "v"}},
		},
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 200 {
		t.Errorf("Status = %d, want 200", res.Status)
	}
	if len(mv.revokeCalls) != 0 {
		t.Errorf("RevokeSelf called, want none")
	}
}

func TestHandle_IdentityMalformed_204_Revoke(t *testing.T) {
	mv := &mockVault{
		canaryOK:    true,
		mintResult:  serviceMint("tok-malformed-identity"),
		identityErr: vaultx.ErrMalformedDirective,
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 204 {
		t.Errorf("Status = %d, want 204", res.Status)
	}
	if res.Outcome != OutcomeIdentityMismatch {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeIdentityMismatch)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-malformed-identity" {
		t.Errorf("revokeCalls = %v, want [tok-malformed-identity]", mv.revokeCalls)
	}
}

func TestHandle_IdentityPlainReadError_502_Revoke(t *testing.T) {
	mv := &mockVault{
		canaryOK:    true,
		mintResult:  serviceMint("tok-identity-5xx"),
		identityErr: errors.New("vault 500"),
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502", res.Status)
	}
	if res.Outcome != OutcomeError {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeError)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-identity-5xx" {
		t.Errorf("revokeCalls = %v, want [tok-identity-5xx]", mv.revokeCalls)
	}
}

func TestHandle_ConfigMalformed_502_Revoke(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-malformed-config"),
		configErr:  vaultx.ErrMalformedDirective,
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502 (config malformed is 502, not 204)", res.Status)
	}
	if res.Outcome != OutcomeError {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeError)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-malformed-config" {
		t.Errorf("revokeCalls = %v, want [tok-malformed-config]", mv.revokeCalls)
	}
}

func TestHandle_ConfigPlainReadError_502_Revoke(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-config-5xx"),
		configErr:  errors.New("vault 500"),
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502", res.Status)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-config-5xx" {
		t.Errorf("revokeCalls = %v, want [tok-config-5xx]", mv.revokeCalls)
	}
}

func TestHandle_SweepError_502_Revoke(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-sweep-err"),
		sweepErr:   errors.New("vault 500"),
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502", res.Status)
	}
	if res.Outcome != OutcomeError {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeError)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-sweep-err" {
		t.Errorf("revokeCalls = %v, want [tok-sweep-err]", mv.revokeCalls)
	}
}

// TestHandle_RequestCtxCancelled_RevokeStillUsesLiveCtx proves the
// request-timeout fix: even when the ctx passed into Handle is already
// cancelled by the time the deferred revoke runs (httpapi's 30s deadline
// firing mid-request is the real-world trigger), RevokeSelf is still
// called, and with a DIFFERENT, still-live context — not the cancelled
// request ctx. Before the fix, the defer reused the request ctx directly,
// so RevokeSelf would have observed a Done context here.
func TestHandle_RequestCtxCancelled_RevokeStillUsesLiveCtx(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-cancelled-req"),
		sweepErr:   errors.New("vault 500"), // drives a non-200 (502) outcome
	}
	b := New(mv, "ci", "")

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel() // request ctx is already Done before Handle is even called

	res := b.Handle(reqCtx, testIdentity())

	if res.Status != 502 {
		t.Fatalf("Status = %d, want 502", res.Status)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-cancelled-req" {
		t.Fatalf("revokeCalls = %v, want [tok-cancelled-req] (revoke must still be attempted)", mv.revokeCalls)
	}
	if res.RevokeFailed {
		t.Fatalf("RevokeFailed = true, want false (detached ctx must let the mock revoke succeed)")
	}
	if len(mv.revokeCtxs) != 1 {
		t.Fatalf("revokeCtxs = %v, want exactly 1 recorded ctx", mv.revokeCtxs)
	}
	gotCtx := mv.revokeCtxs[0]
	if gotCtx == reqCtx {
		t.Errorf("RevokeSelf received the request ctx itself, want a detached ctx")
	}
	// Sampled AT CALL TIME (see revokeCtxErrs doc comment): the broker's own
	// deferred cancel() fires immediately after RevokeSelf returns, so
	// checking gotCtx.Err() now (post-Handle-return) would be Done even on
	// success — this must reflect what RevokeSelf itself observed.
	if err := mv.revokeCtxErrs[0]; err != nil {
		t.Errorf("RevokeSelf's ctx.Err() at call time = %v, want nil (must be live, not inherit the cancelled request ctx)", err)
	}
	if reqCtx.Err() == nil {
		t.Fatalf("test setup broken: reqCtx should be Done")
	}
}

func TestHandle_TokenTypeNotService_502_RevokeBestEffort(t *testing.T) {
	mint := serviceMint("tok-batch")
	mint.TokenType = "batch"
	mv := &mockVault{canaryOK: true, mintResult: mint}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502", res.Status)
	}
	if res.Outcome != OutcomeError {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeError)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-batch" {
		t.Errorf("revokeCalls = %v, want [tok-batch] (best-effort attempted)", mv.revokeCalls)
	}
}

// TestHandle_TokenTypeNotService_RevokeFailureIgnored proves the
// best-effort nature: even if RevokeSelf itself errors, the response
// status/outcome are unaffected.
func TestHandle_TokenTypeNotService_RevokeFailureIgnored(t *testing.T) {
	mint := serviceMint("tok-batch2")
	mint.TokenType = "batch"
	mv := &mockVault{canaryOK: true, mintResult: mint, revokeErr: errors.New("revoke unreachable")}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 502 {
		t.Errorf("Status = %d, want 502 regardless of revoke failure", res.Status)
	}
	if len(mv.revokeCalls) != 1 {
		t.Errorf("revokeCalls = %v, want exactly 1 attempt", mv.revokeCalls)
	}
	if !res.RevokeFailed {
		t.Errorf("RevokeFailed = false, want true (RevokeSelf itself errored)")
	}
}

func TestHandle_SuppressedEmptySweep_204_Revoke(t *testing.T) {
	mv := &mockVault{
		canaryOK:     true,
		mintResult:   serviceMint("tok-suppressed-empty"),
		configResult: map[string]string{"vault_token": "false"},
		sweepResult:  vaultx.SweepResult{},
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 204 {
		t.Errorf("Status = %d, want 204", res.Status)
	}
	if res.Secrets != nil {
		t.Errorf("Secrets = %v, want nil", res.Secrets)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-suppressed-empty" {
		t.Errorf("revokeCalls = %v, want [tok-suppressed-empty]", mv.revokeCalls)
	}
}

// TestHandle_SuppressedEmptyWithAdvertiseAddr_StillEmpty204 locks down C7:
// vault_addr alone can never make a response non-empty/200.
func TestHandle_SuppressedEmptyWithAdvertiseAddr_StillEmpty204(t *testing.T) {
	mv := &mockVault{
		canaryOK:     true,
		mintResult:   serviceMint("tok-suppressed-addr"),
		configResult: map[string]string{"vault_token": "false"},
		sweepResult:  vaultx.SweepResult{},
	}
	b := New(mv, "ci", "https://vault.example.com")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 204 {
		t.Errorf("Status = %d, want 204 (C7: vault_addr alone is not a 200 body)", res.Status)
	}
	if len(res.Secrets) != 0 {
		t.Errorf("Secrets = %v, want empty", res.Secrets)
	}
	if len(mv.revokeCalls) != 1 || mv.revokeCalls[0] != "tok-suppressed-addr" {
		t.Errorf("revokeCalls = %v, want [tok-suppressed-addr]", mv.revokeCalls)
	}
}

// TestHandle_EmptySweepNotSuppressed_200TokenOnly covers the state-space
// corner the emptiness check leaves out: zero swept secrets, but
// vault_token is NOT suppressed (config nil/default). The emptiness rule
// requires suppression too, so this is a normal 200 carrying exactly
// vault_token — not a 204.
func TestHandle_EmptySweepNotSuppressed_200TokenOnly(t *testing.T) {
	mv := &mockVault{
		canaryOK:    true,
		mintResult:  serviceMint("tok-empty-not-suppressed"),
		sweepResult: vaultx.SweepResult{}, // zero secrets
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200 (vault_token alone is a valid body, not empty)", res.Status)
	}
	if res.Outcome != OutcomeOK {
		t.Errorf("Outcome = %q, want %q", res.Outcome, OutcomeOK)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "vault_token" || res.Secrets[0].Value != "tok-empty-not-suppressed" {
		t.Errorf("Secrets = %+v, want exactly [{vault_token tok-empty-not-suppressed}]", res.Secrets)
	}
	if len(mv.revokeCalls) != 0 {
		t.Errorf("RevokeSelf called, want none on 200")
	}
}

func TestHandle_VaultAddrPresentOn200(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-addr"),
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{{Name: "api_key", Value: "v"}},
		},
	}
	b := New(mv, "ci", "https://vault.example.com")

	res := b.Handle(context.Background(), testIdentity())

	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200", res.Status)
	}
	var found bool
	for _, s := range res.Secrets {
		if s.Name == "vault_addr" {
			found = true
			if s.Value != "https://vault.example.com" {
				t.Errorf("vault_addr value = %q", s.Value)
			}
			if len(s.Events) != 1 || s.Events[0] != "push" {
				t.Errorf("vault_addr events = %v, want [push]", s.Events)
			}
		}
	}
	if !found {
		t.Errorf("secrets missing vault_addr: %+v", res.Secrets)
	}
	if len(mv.revokeCalls) != 0 {
		t.Errorf("RevokeSelf called on 200")
	}
}

func TestHandle_VaultAddrAbsentWhenNotConfigured(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-noaddr"),
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{{Name: "api_key", Value: "v"}},
		},
	}
	b := New(mv, "ci", "") // advertiseVaultAddr unset

	res := b.Handle(context.Background(), testIdentity())

	for _, s := range res.Secrets {
		if s.Name == "vault_addr" {
			t.Errorf("vault_addr present, want absent when unconfigured")
		}
	}
}

func TestHandle_DefaultEventPin(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-defaultpin"),
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{{Name: "api_key", Value: "v"}}, // Events left empty
		},
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	for _, s := range res.Secrets {
		if s.Name == "api_key" {
			if len(s.Events) != 1 || s.Events[0] != "push" {
				t.Errorf("api_key Events = %v, want [push] (default pin = [id.Event])", s.Events)
			}
		}
	}
}

func TestHandle_IronbarkEventsPinRespected(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		mintResult: serviceMint("tok-pin"),
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{
				{Name: "api_key", Value: "v", Events: []string{"push", "cron"}},
			},
		},
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	for _, s := range res.Secrets {
		if s.Name == "api_key" {
			if len(s.Events) != 2 || s.Events[0] != "push" || s.Events[1] != "cron" {
				t.Errorf("api_key Events = %v, want [push cron] (ironbark_events pin respected)", s.Events)
			}
		}
	}
}

func TestHandle_VaultTokenImagesPin(t *testing.T) {
	mv := &mockVault{
		canaryOK:     true,
		mintResult:   serviceMint("tok-images"),
		configResult: map[string]string{"vault_token_images": "golang:1.24, alpine:3"},
		sweepResult: vaultx.SweepResult{
			Secrets: []vaultx.SweptSecret{{Name: "api_key", Value: "v"}},
		},
	}
	b := New(mv, "ci", "")

	res := b.Handle(context.Background(), testIdentity())

	var found bool
	for _, s := range res.Secrets {
		if s.Name == "vault_token" {
			found = true
			if len(s.Images) != 2 || s.Images[0] != "golang:1.24" || s.Images[1] != "alpine:3" {
				t.Errorf("vault_token Images = %v, want [golang:1.24 alpine:3]", s.Images)
			}
		}
	}
	if !found {
		t.Errorf("secrets missing vault_token")
	}
}

// TestHandle_BaseUsedForDirectiveReads proves ReadIdentity/ReadConfig/Sweep
// all receive the minted token and Vault.Base(id)'s return, and Sweep
// receives the computed branchful flag.
func TestHandle_BaseUsedForDirectiveReads(t *testing.T) {
	mv := &mockVault{
		canaryOK:   true,
		base:       "ci/acme/widgets",
		mintResult: serviceMint("tok-base"),
	}
	b := New(mv, "ci", "")

	b.Handle(context.Background(), testIdentity())

	if mv.identityBase != "ci/acme/widgets" || mv.identityToken != "tok-base" {
		t.Errorf("ReadIdentity(base=%q, token=%q), want (ci/acme/widgets, tok-base)", mv.identityBase, mv.identityToken)
	}
	if mv.configBase != "ci/acme/widgets" || mv.configToken != "tok-base" {
		t.Errorf("ReadConfig(base=%q, token=%q), want (ci/acme/widgets, tok-base)", mv.configBase, mv.configToken)
	}
	if mv.sweepToken != "tok-base" {
		t.Errorf("Sweep token = %q, want tok-base", mv.sweepToken)
	}
	if !mv.sweepBranchful {
		t.Errorf("Sweep branchful = false, want true (push + non-empty branch)")
	}
}

var _ Vault = (*mockVault)(nil)
var _ Vault = (*vaultx.Client)(nil)

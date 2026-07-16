package vaultx

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunCanary_HappyPath(t *testing.T) {
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := c.runCanary(context.Background(), "ci"); err != nil {
		t.Fatalf("runCanary: %v", err)
	}
	if !c.CanaryOK() {
		t.Errorf("CanaryOK() = false after a passing canary, want true")
	}
	if got := fv.mintCallCount(); got != 1 {
		t.Errorf("mintCalls = %d, want 1", got)
	}
	if got := fv.revokeCallCount(); got != 1 {
		t.Errorf("revokeCalls = %d, want 1", got)
	}
	if got := fv.lastPoliciesValue(); len(got) != 1 || got[0] != "ci/ironbark-selftest" {
		t.Errorf("canary minted policy = %v, want [ci/ironbark-selftest]", got)
	}
}

func TestRunCanary_BatchTokenTypeFails(t *testing.T) {
	fv := newFakeVault()
	fv.setMintTokenType("batch")
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	err = c.runCanary(context.Background(), "ci")
	if err == nil {
		t.Fatalf("runCanary: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "token_type") {
		t.Errorf("error = %q, want it to name the violated expectation (token_type)", err)
	}
	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true, want false after a token_type violation")
	}
	if got := fv.revokeCallCount(); got != 1 {
		t.Errorf("revokeCalls = %d, want 1 (a failed-assertion token must still be revoked, SPEC §3.4)", got)
	}
	if got, want := fv.lastRevokeTokenValue(), fv.lastMintedTokenValue(); got != want {
		t.Errorf("revoked token = %q, want the minted canary token %q", got, want)
	}
}

func TestRunCanary_RenewableTrueFails(t *testing.T) {
	fv := newFakeVault()
	fv.setMintRenewable(true)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	err = c.runCanary(context.Background(), "ci")
	if err == nil {
		t.Fatalf("runCanary: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "renewable") {
		t.Errorf("error = %q, want it to name the violated expectation (renewable)", err)
	}
	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true, want false after a renewable violation")
	}
	if got := fv.revokeCallCount(); got != 1 {
		t.Errorf("revokeCalls = %d, want 1 (a failed-assertion token must still be revoked, SPEC §3.4)", got)
	}
	if got, want := fv.lastRevokeTokenValue(), fv.lastMintedTokenValue(); got != want {
		t.Errorf("revoked token = %q, want the minted canary token %q", got, want)
	}
}

func TestRunCanary_OrphanFalseFails(t *testing.T) {
	fv := newFakeVault()
	orphanFalse := false
	fv.setMintOrphan(&orphanFalse)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	err = c.runCanary(context.Background(), "ci")
	if err == nil {
		t.Fatalf("runCanary: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "orphan") {
		t.Errorf("error = %q, want it to name the violated expectation (orphan)", err)
	}
	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true, want false after an orphan violation")
	}
	if got := fv.revokeCallCount(); got != 1 {
		t.Errorf("revokeCalls = %d, want 1 (a failed-assertion token must still be revoked, SPEC §3.4)", got)
	}
	if got, want := fv.lastRevokeTokenValue(), fv.lastMintedTokenValue(); got != want {
		t.Errorf("revoked token = %q, want the minted canary token %q", got, want)
	}
}

func TestRunCanary_OrphanOmittedFromResponsePasses(t *testing.T) {
	fv := newFakeVault()
	fv.setMintOrphan(nil)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := c.runCanary(context.Background(), "ci"); err != nil {
		t.Fatalf("runCanary: %v (orphan omission must not fail the canary, SPEC §3.5)", err)
	}
	if !c.CanaryOK() {
		t.Errorf("CanaryOK() = false, want true")
	}
}

func TestRunCanary_RevokeSelfFailureFails(t *testing.T) {
	fv := newFakeVault()
	fv.setRevokeFail(true)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	err = c.runCanary(context.Background(), "ci")
	if err == nil {
		t.Fatalf("runCanary: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "revoke-self") {
		t.Errorf("error = %q, want it to name the violated expectation (revoke-self)", err)
	}
	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true, want false after a revoke-self failure")
	}
}

func TestRunCanary_MintFailureFails(t *testing.T) {
	fv := newFakeVault()
	fv.setMintFail(true)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := c.runCanary(context.Background(), "ci"); err == nil {
		t.Fatalf("runCanary: expected error, got nil")
	}
	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true, want false after a mint failure")
	}
}

// TestRun_ReloginRerunsRealCanary proves the Task 8 wiring: New sets
// canaryFn to the real runCanary (not left at Task 7's no-op default), and
// Run's re-login coordination (DEC-0007: canaryOK resets false on every
// login, canary re-runs after) drives the REAL canary — not a
// test-injected stub. Forcing a renew failure triggers a re-login; the
// fake's mint counter must increase again afterward.
func TestRun_ReloginRerunsRealCanary(t *testing.T) {
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.renewAfter = func(int) time.Duration { return 5 * time.Millisecond }
	c.retryInterval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, "ci")

	waitFor(t, 2*time.Second, func() bool { return c.CanaryOK() })
	before := fv.mintCallCount()
	if before < 1 {
		t.Fatalf("mintCalls = %d before forcing a re-login, want >= 1", before)
	}

	fv.setRenewFail(true)

	waitFor(t, 2*time.Second, func() bool { return fv.loginCallCount() >= 2 })
	waitFor(t, 2*time.Second, func() bool { return fv.mintCallCount() > before })
	waitFor(t, 2*time.Second, func() bool { return c.CanaryOK() })
}

// TestRun_CanaryKeepsFailingRetriesAndStaysUnhealthy drives the real
// wired canary (via Run, no canaryFn override) with a mint that always
// fails: the retry cadence must keep invoking it every retryInterval, and
// CanaryOK/Healthy must never flip true.
func TestRun_CanaryKeepsFailingRetriesAndStaysUnhealthy(t *testing.T) {
	fv := newFakeVault()
	fv.setMintFail(true)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.renewAfter = func(int) time.Duration { return time.Hour } // don't let renewal interfere
	c.retryInterval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, "ci")

	waitFor(t, 2*time.Second, func() bool { return fv.mintCallCount() >= 3 })

	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true, want false while the canary keeps failing")
	}
	if c.Healthy() {
		t.Errorf("Healthy() = true, want false while the canary keeps failing")
	}
}

package vaultx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeVault fakes just enough of Vault's HTTP API for the AppRole session
// lifecycle: POST auth/approle/login and POST auth/token/renew-self. Both
// endpoints' failure mode and the login lease duration are controllable
// and call-counted, mutex-guarded for concurrent access from the Run
// goroutine and the test.
type fakeVault struct {
	mu           sync.Mutex
	loginCalls   int
	renewCalls   int
	loginFail    bool
	renewFail    bool
	leaseSeconds int
}

func newFakeVault() *fakeVault {
	return &fakeVault{leaseSeconds: 60}
}

func (f *fakeVault) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			f.mu.Lock()
			f.loginCalls++
			n := f.loginCalls
			fail := f.loginFail
			lease := f.leaseSeconds
			f.mu.Unlock()

			if fail {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"errors":["permission denied"]}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"auth":{"client_token":"login-token-%d","lease_duration":%d,"renewable":true}}`, n, lease)

		case "/v1/auth/token/renew-self":
			f.mu.Lock()
			f.renewCalls++
			fail := f.renewFail
			lease := f.leaseSeconds
			f.mu.Unlock()

			if fail {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"errors":["permission denied"]}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"auth":{"client_token":"renewed-token","lease_duration":%d,"renewable":true}}`, lease)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (f *fakeVault) loginCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginCalls
}

func (f *fakeVault) renewCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.renewCalls
}

func (f *fakeVault) setLoginFail(v bool) {
	f.mu.Lock()
	f.loginFail = v
	f.mu.Unlock()
}

func (f *fakeVault) setRenewFail(v bool) {
	f.mu.Lock()
	f.renewFail = v
	f.mu.Unlock()
}

// waitFor polls cond until it returns true or timeout elapses, failing the
// test on timeout. It keeps the concurrency tests fast and deterministic
// without a fixed sleep.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

func testConfig(addr string) Config {
	return Config{
		Addr:      addr,
		RoleID:    "role-id",
		SecretID:  "secret-id",
		TokenRole: "ci",
		KVMount:   "kv",
		KVPrefix:  "ci",
	}
}

func TestLogin_SuccessStoresToken(t *testing.T) {
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

	if c.token == "" {
		t.Errorf("token not stored on Client")
	}
	if got := c.api.Token(); got != c.token {
		t.Errorf("underlying api.Client token = %q, want %q (own session token)", got, c.token)
	}
	if !c.sessionOK {
		t.Errorf("sessionOK = false after successful login, want true")
	}
}

func TestLogin_FailureError(t *testing.T) {
	fv := newFakeVault()
	fv.setLoginFail(true)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.Login(context.Background()); err == nil {
		t.Fatalf("Login: expected error, got nil")
	}
	if c.sessionOK {
		t.Errorf("sessionOK = true after failed login, want false")
	}
}

// TestLogin_ResetsCanaryOKAtomically proves the ordering fix directly,
// without relying on sampling a timing window: seed canaryOK=true (as if
// a prior session's canary had passed), call Login with the canary seam
// NOT yet invoked, and assert CanaryOK() is already false the instant
// Login returns. If the reset were not atomic with sessionOK (e.g. done
// later by a separate setCanaryOK(false) call in Run), a concurrent
// reader between Login returning and that later call could observe
// sessionOK=true && canaryOK=true — a stale-ready reading (SPEC §3.5,
// DEC-0007).
func TestLogin_ResetsCanaryOKAtomically(t *testing.T) {
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Seed a stale canary pass from a "previous session".
	c.mu.Lock()
	c.canaryOK = true
	c.mu.Unlock()

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if !c.sessionOK {
		t.Fatalf("sessionOK = false after successful login, want true")
	}
	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true immediately after Login, want false (stale pass must not survive a login)")
	}
}

func TestRun_LoginFailureIsUnhealthy(t *testing.T) {
	fv := newFakeVault()
	fv.setLoginFail(true)
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.retryInterval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, "ci")

	waitFor(t, 2*time.Second, func() bool { return fv.loginCallCount() >= 2 })

	if c.Healthy() {
		t.Errorf("Healthy() = true, want false while login keeps failing")
	}
}

func TestRun_RenewFailureTriggersRelogin(t *testing.T) {
	fv := newFakeVault()
	fv.setRenewFail(true)
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

	// Renew must actually be attempted and fail, and a fresh login must
	// follow (initial login + at least one re-login).
	waitFor(t, 2*time.Second, func() bool {
		return fv.renewCallCount() > 0 && fv.loginCallCount() >= 2
	})

	waitFor(t, 2*time.Second, func() bool { return c.Healthy() })
}

func TestRun_CanaryRunsAfterInitialLoginAndRetriesOnFailure(t *testing.T) {
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.renewAfter = func(int) time.Duration { return time.Hour } // don't let renewal interfere
	c.retryInterval = 5 * time.Millisecond

	var mu sync.Mutex
	calls := 0
	var gotPrefix string
	c.canaryFn = func(_ context.Context, policyPrefix string) error {
		mu.Lock()
		calls++
		gotPrefix = policyPrefix
		mu.Unlock()
		return errors.New("canary failing")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, "ci")

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls >= 1
	})

	mu.Lock()
	p := gotPrefix
	mu.Unlock()
	if p != "ci" {
		t.Errorf("canaryFn policyPrefix = %q, want %q", p, "ci")
	}

	if c.Healthy() {
		t.Errorf("Healthy() = true while canary is failing, want false")
	}
	if c.CanaryOK() {
		t.Errorf("CanaryOK() = true while canary is failing, want false")
	}

	// It retries every retryInterval while failing.
	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls >= 3
	})
}

func TestRun_CanaryRunsAgainAfterRelogin(t *testing.T) {
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.renewAfter = func(int) time.Duration { return 5 * time.Millisecond }
	c.retryInterval = 5 * time.Millisecond

	var mu sync.Mutex
	calls := 0
	c.canaryFn = func(context.Context, string) error {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil // always succeeds, so it never self-retries
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, "ci")

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls >= 1
	})
	if !c.CanaryOK() {
		t.Errorf("CanaryOK() = false after a successful canary, want true")
	}

	mu.Lock()
	before := calls
	mu.Unlock()

	// Force a renewal failure -> re-login -> the seam must run the canary
	// again (and must not leave minting "ready" on the stale pre-relogin
	// canary pass in the meantime).
	fv.setRenewFail(true)

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls > before+1
	})
	if fv.loginCallCount() < 2 {
		t.Errorf("loginCallCount = %d, want >= 2 (initial + re-login)", fv.loginCallCount())
	}
}

func TestRun_StopsOnContextCancel(t *testing.T) {
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

	done := make(chan struct{})
	go func() {
		c.Run(ctx, "ci")
		close(done)
	}()

	waitFor(t, 2*time.Second, func() bool { return fv.loginCallCount() >= 1 })
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return after context cancellation")
	}
}

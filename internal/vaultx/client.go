// Package vaultx wraps the Vault/OpenBao API client with ironbark's own
// AppRole session (SPEC §1.3) and, in later tasks, minting/sweep/deref.
//
// This file (Task 7) owns the session: Login (AppRole login), the
// renew-at-half-TTL / re-login lifecycle, and the canary SEAM that Task 8
// hangs the real startup canary (SPEC §3.5) off of. Run is the ONE
// lifecycle goroutine coordinating both: a re-login always invalidates
// the prior canary pass (canaryOK resets to false) before the canary
// re-runs, so a stale canary pass can never read as "ready" across a
// re-login (DEC-0007).
package vaultx

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// Config is vaultx's own small configuration surface (SPEC §1.3, §3) —
// distinct from config.Config; Task 12 wires one onto the other.
type Config struct {
	Addr      string
	RoleID    string
	SecretID  string
	TokenRole string
	KVMount   string
	KVPrefix  string
}

// Client holds ironbark's own Vault/OpenBao AppRole session: the
// underlying api.Client (its default token is always ironbark's own
// session token — Task 8's canary/mint calls authenticate as ironbark
// through it; minted pipeline-token calls in Task 9 use their own
// token), mutex-guarded session state, and mutex-guarded canary state.
type Client struct {
	api *api.Client
	cfg Config

	mu           sync.Mutex
	token        string // ironbark's own current AppRole session token
	leaseSeconds int    // that token's last-known lease duration
	sessionOK    bool   // login/renew succeeded and hasn't since failed
	canaryOK     bool   // the canary (Task 8) passed since the last (re-)login

	// canaryFn, renewAfter, and retryInterval below are unguarded
	// configuration knobs, not runtime state: callers (Task 8/12) must
	// set them after New() and before the first `go c.Run(...)`, never
	// mutate them concurrently with a running Run — Run reads them
	// without holding c.mu.

	// canaryFn is the canary seam: Run invokes it after every successful
	// (re-)login, and every retryInterval while it keeps failing. Task 8
	// overrides it (in an updated New) with the real SPEC §3.5 canary.
	// The default here is a no-op success so Run's coordination logic
	// (this task) is fully exercisable before Task 8 exists.
	canaryFn func(ctx context.Context, policyPrefix string) error

	// renewAfter and retryInterval make Run's timing injectable: prod
	// renews at half the token's lease duration and retries a failed
	// login or canary every 60s; tests override both to short fixed
	// values so they don't wait on real clock time.
	renewAfter    func(leaseSeconds int) time.Duration
	retryInterval time.Duration
}

// New builds a Client for cfg.Addr. It does not contact Vault — call Run
// (or Login) to establish the AppRole session.
func New(cfg Config) (*Client, error) {
	apiClient, err := api.NewClient(&api.Config{Address: cfg.Addr})
	if err != nil {
		return nil, fmt.Errorf("vaultx: new client: %w", err)
	}

	return &Client{
		api:           apiClient,
		cfg:           cfg,
		canaryFn:      func(context.Context, string) error { return nil },
		renewAfter:    func(leaseSeconds int) time.Duration { return time.Duration(leaseSeconds/2) * time.Second },
		retryInterval: 60 * time.Second,
	}, nil
}

// Login performs an AppRole login (POST auth/approle/login) using
// cfg.RoleID/cfg.SecretID. On success it sets the returned client token as
// the underlying api.Client's default token (so subsequent calls made
// through it — renew-self, and Task 8's canary/mint — authenticate as
// ironbark) and, in the SAME locked section, sets sessionOK=true AND
// resets canaryOK=false — atomically, so no concurrent Healthy() read can
// ever observe a live session paired with a stale pre-login canary pass
// (SPEC §3.5, DEC-0007). On failure it records the session as not-OK and
// returns the error.
func (c *Client) Login(ctx context.Context) error {
	secret, err := c.api.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]interface{}{
		"role_id":   c.cfg.RoleID,
		"secret_id": c.cfg.SecretID,
	})
	if err != nil {
		c.setSessionOK(false)
		return fmt.Errorf("vaultx: approle login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		c.setSessionOK(false)
		return fmt.Errorf("vaultx: approle login: response has no auth")
	}

	c.mu.Lock()
	// SetToken is not I/O (api.Client guards it with its own internal
	// lock) — it belongs inside this critical section too, so that a
	// concurrent Login can never interleave and leave c.api's default
	// token and c.token/sessionOK/canaryOK reflecting two different
	// login responses. The whole post-login state flip is one atomic
	// unit.
	c.api.SetToken(secret.Auth.ClientToken)
	c.token = secret.Auth.ClientToken
	c.leaseSeconds = secret.Auth.LeaseDuration
	c.sessionOK = true
	// Every successful login — initial or re-login — invalidates any
	// prior canary pass. This MUST be set atomically with sessionOK, in
	// the same critical section: otherwise a concurrent Healthy() read
	// could observe sessionOK=true paired with a stale pre-login
	// canaryOK=true before Run gets a chance to reset it (SPEC §3.5,
	// DEC-0007).
	c.canaryOK = false
	c.mu.Unlock()

	return nil
}

// renewSelf renews ironbark's own token (POST auth/token/renew-self,
// authenticated as the token itself via the api.Client's default token).
func (c *Client) renewSelf(ctx context.Context) error {
	secret, err := c.api.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		c.setSessionOK(false)
		return fmt.Errorf("vaultx: renew-self: %w", err)
	}

	leaseSeconds := 0
	if secret != nil && secret.Auth != nil {
		leaseSeconds = secret.Auth.LeaseDuration
	}

	c.mu.Lock()
	c.leaseSeconds = leaseSeconds
	c.sessionOK = true
	c.mu.Unlock()

	return nil
}

// Healthy reports readiness: the AppRole session is valid AND the canary
// has passed since the current session began (SPEC §1.1 /readyz).
func (c *Client) Healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionOK && c.canaryOK
}

// CanaryOK reports whether the SPEC §3.5 canary has passed since the
// current (re-)login — independent of overall Healthy(), for finer-grained
// inspection.
func (c *Client) CanaryOK() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.canaryOK
}

func (c *Client) setSessionOK(v bool) {
	c.mu.Lock()
	c.sessionOK = v
	c.mu.Unlock()
}

func (c *Client) setCanaryOK(v bool) {
	c.mu.Lock()
	c.canaryOK = v
	c.mu.Unlock()
}

func (c *Client) currentLeaseSeconds() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leaseSeconds
}

// Run is ironbark's one Vault-session lifecycle goroutine (SPEC §1.3,
// §3.5). It logs in; while logged in, it renews at ~renewAfter(leaseTTL)
// and, after every successful (re-)login, runs the canary seam — retrying
// the canary every retryInterval while it fails. A renewal failure
// triggers a re-login; a login failure (initial or re-login) is retried
// every retryInterval. Run returns when ctx is canceled.
func (c *Client) Run(ctx context.Context, policyPrefix string) {
	for {
		if err := c.Login(ctx); err != nil {
			if !sleepOrDone(ctx, c.retryInterval) {
				return
			}
			continue
		}

		// Login already reset canaryOK=false atomically with sessionOK=true
		// (DEC-0007) — no separate reset needed here.

		if !c.sessionLoop(ctx, policyPrefix) {
			return
		}
		// sessionLoop returned true: renewal failed, loop back to Login.
	}
}

// sessionLoop runs the canary (with retry-on-failure) and the renewal
// timer concurrently until either the token fails to renew (returns true:
// caller should re-login) or ctx is canceled (returns false).
func (c *Client) sessionLoop(ctx context.Context, policyPrefix string) bool {
	renewTimer := time.NewTimer(c.renewAfter(c.currentLeaseSeconds()))
	defer renewTimer.Stop()

	var canaryTimer *time.Timer
	var canaryCh <-chan time.Time
	disarmCanaryRetry := func() {
		if canaryTimer != nil {
			canaryTimer.Stop()
		}
		canaryTimer = nil
		canaryCh = nil
	}
	defer disarmCanaryRetry()

	runCanary := func() {
		if err := c.canaryFn(ctx, policyPrefix); err != nil {
			c.setCanaryOK(false)
			canaryTimer = time.NewTimer(c.retryInterval)
			canaryCh = canaryTimer.C
			return
		}
		c.setCanaryOK(true)
		disarmCanaryRetry()
	}
	runCanary()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-renewTimer.C:
			if err := c.renewSelf(ctx); err != nil {
				return true
			}
			renewTimer.Reset(c.renewAfter(c.currentLeaseSeconds()))
		case <-canaryCh:
			runCanary()
		}
	}
}

// sleepOrDone waits d or until ctx is canceled, returning false if ctx won
// (so callers can stop promptly instead of finishing out the sleep).
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

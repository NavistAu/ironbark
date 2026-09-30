package vaultx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// fakeLeaseRevoke fakes PUT sys/leases/revoke: every call lands on the
// same path, so unlike fakeKV (keyed by path) this records an ORDERED
// list of calls (method, token, decoded lease_id) and lets a specific
// lease_id be configured to fail with a given status.
type fakeLeaseRevoke struct {
	mu      sync.Mutex
	calls   []leaseRevokeCall
	failIDs map[string]int // lease_id -> status code to return
}

type leaseRevokeCall struct {
	method  string
	path    string
	token   string
	leaseID string
}

func (f *fakeLeaseRevoke) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			LeaseID string `json:"lease_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		f.mu.Lock()
		f.calls = append(f.calls, leaseRevokeCall{
			method:  r.Method,
			path:    r.URL.Path,
			token:   r.Header.Get("X-Vault-Token"),
			leaseID: body.LeaseID,
		})
		status, shouldFail := f.failIDs[body.LeaseID]
		f.mu.Unlock()

		if shouldFail {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errors":["denied"]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *fakeLeaseRevoke) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestRevokeLeases_AllSucceed proves RevokeLeases PUTs sys/leases/revoke
// once per ID, with the caller's token and a {"lease_id": id} body, and
// returns a nil error slice when every revoke succeeds.
func TestRevokeLeases_AllSucceed(t *testing.T) {
	fv := &fakeLeaseRevoke{failIDs: map[string]int{}}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ids := []string{"lease-1", "lease-2"}
	errs := c.RevokeLeases(context.Background(), "caller-token", ids)
	if errs != nil {
		t.Fatalf("RevokeLeases = %v, want nil", errs)
	}
	if fv.callCount() != 2 {
		t.Fatalf("calls = %d, want 2", fv.callCount())
	}
	for i, id := range ids {
		call := fv.calls[i]
		if call.method != http.MethodPut {
			t.Errorf("call %d method = %q, want PUT", i, call.method)
		}
		if call.path != "/v1/sys/leases/revoke" {
			t.Errorf("call %d path = %q, want /v1/sys/leases/revoke", i, call.path)
		}
		if call.token != "caller-token" {
			t.Errorf("call %d token = %q, want caller-token", i, call.token)
		}
		if call.leaseID != id {
			t.Errorf("call %d lease_id = %q, want %q", i, call.leaseID, id)
		}
	}
}

// TestRevokeLeases_OneFailureOthersStillSent proves a 403 on one ID
// yields exactly one error, and every other ID is still attempted.
func TestRevokeLeases_OneFailureOthersStillSent(t *testing.T) {
	fv := &fakeLeaseRevoke{failIDs: map[string]int{"lease-2": http.StatusForbidden}}
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	errs := c.RevokeLeases(context.Background(), "caller-token", []string{"lease-1", "lease-2", "lease-3"})
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly 1 error", errs)
	}
	if fv.callCount() != 3 {
		t.Fatalf("calls = %d, want 3 (all IDs attempted despite one failure)", fv.callCount())
	}
}

// TestRevokeLeases_NeverCallsRevokeSelf proves RevokeLeases never touches
// auth/token/revoke-self (CLIENT-SPEC §1.4: that would revoke the
// caller's actual Vault session, not a lease).
func TestRevokeLeases_NeverCallsRevokeSelf(t *testing.T) {
	fv := &fakeLeaseRevoke{failIDs: map[string]int{}}
	revokeSelfCalled := false
	mux := http.NewServeMux()
	mux.Handle("/v1/sys/leases/revoke", fv.handler())
	mux.HandleFunc("/v1/auth/token/revoke-self", func(w http.ResponseWriter, r *http.Request) {
		revokeSelfCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	c.RevokeLeases(context.Background(), "caller-token", []string{"lease-1"})
	if revokeSelfCalled {
		t.Errorf("RevokeLeases called auth/token/revoke-self, must never do so")
	}
}

func TestCheckToken(t *testing.T) {
	cases := []struct {
		status  int
		wantErr string // "", "rejected" or "other"
	}{
		{200, ""}, {404, ""}, {403, "rejected"}, {500, "other"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/auth/token/lookup-self" || r.Header.Get("X-Vault-Token") != "tok" {
				t.Errorf("unexpected request %s token=%q", r.URL.Path, r.Header.Get("X-Vault-Token"))
			}
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}))
		c, err := New(Config{Addr: srv.URL, KVMount: "kv", KVPrefix: "ci"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		err = c.CheckToken(context.Background(), "tok")
		srv.Close()
		switch tc.wantErr {
		case "":
			if err != nil {
				t.Errorf("status %d: err = %v, want nil", tc.status, err)
			}
		case "rejected":
			if !errors.Is(err, ErrTokenRejected) {
				t.Errorf("status %d: err = %v, want ErrTokenRejected", tc.status, err)
			}
		default:
			if err == nil || errors.Is(err, ErrTokenRejected) {
				t.Errorf("status %d: err = %v, want a plain error", tc.status, err)
			}
		}
	}
}

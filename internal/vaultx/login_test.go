package vaultx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeBao serves auth/jwt/login and the token endpoints from canned values.
type fakeBao struct {
	mu        sync.Mutex
	loginCode int
	loginBody string
	lookup    string // lookup-self data body
	revoked   []string
}

func (f *fakeBao) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/auth/jwt/login":
		w.WriteHeader(f.loginCode)
		_, _ = w.Write([]byte(f.loginBody))
	case "/v1/auth/token/lookup-self":
		_, _ = w.Write([]byte(`{"data":` + f.lookup + `}`))
	case "/v1/auth/token/revoke-self":
		f.revoked = append(f.revoked, r.Header.Get("X-Vault-Token"))
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func loginOK(orphan bool, typ string) string {
	b, _ := json.Marshal(map[string]any{"auth": map[string]any{
		"client_token": "tok1", "accessor": "acc1", "lease_duration": 900, "token_type": typ, "orphan": orphan}})
	return string(b)
}

func newFake(t *testing.T, f *fakeBao) *Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	c, err := NewConn(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginJWTOK(t *testing.T) {
	f := &fakeBao{loginCode: 200, loginBody: loginOK(true, "service"), lookup: `{"explicit_max_ttl":900}`}
	tok, err := newFake(t, f).LoginJWT(context.Background(), "jwt", "ci-prod", "j")
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "tok1" || tok.Accessor != "acc1" || tok.TTL.Seconds() != 900 {
		t.Fatalf("token = %+v", tok)
	}
	if len(f.revoked) != 0 {
		t.Fatalf("revoked = %v", f.revoked)
	}
}

func TestLoginJWTClassification(t *testing.T) {
	cases := []struct {
		name, body string
		refused    bool
	}{
		{"role missing", `{"errors":["role \"x\" could not be found"]}`, true},
		{"bound claim", `{"errors":["error validating claims: claim \"repo_key\" does not match any associated bound claim values"]}`, true},
		{"claim missing", `{"errors":["error validating claims: claim \"event\" is missing"]}`, true},
		{"bad signature", `{"errors":["error validating token: error verifying token signature: no known key successfully validated the token signature"]}`, false},
		{"expired", `{"errors":["error validating token: invalid expiration time (exp) claim: token is expired"]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBao{loginCode: 400, loginBody: tc.body}
			_, err := newFake(t, f).LoginJWT(context.Background(), "jwt", "r", "j")
			var ref *RefusedError
			if got := errors.As(err, &ref); got != tc.refused {
				t.Fatalf("refused = %v (err %v), want %v", got, err, tc.refused)
			}
			if err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestLoginJWTTransportIsNotRefusal(t *testing.T) {
	c, _ := NewConn("http://127.0.0.1:1", nil)
	_, err := c.LoginJWT(context.Background(), "jwt", "r", "j")
	var ref *RefusedError
	if err == nil || errors.As(err, &ref) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoginJWTAssertions(t *testing.T) {
	cases := []struct {
		name, login, lookup, reason string
	}{
		{"batch token", loginOK(true, "batch"), `{"explicit_max_ttl":900}`, "token_type"},
		{"not orphan", loginOK(false, "service"), `{"explicit_max_ttl":900}`, "orphan"},
		{"no explicit max", loginOK(true, "service"), `{"explicit_max_ttl":0}`, "explicit_max_ttl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBao{loginCode: 200, loginBody: tc.login, lookup: tc.lookup}
			_, err := newFake(t, f).LoginJWT(context.Background(), "jwt", "ci-prod", "j")
			var ae *AssertionError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want AssertionError", err)
			}
			if !strings.Contains(ae.Reason, tc.reason) || !strings.Contains(err.Error(), "ci-prod") {
				t.Fatalf("err = %v", err)
			}
			if len(f.revoked) != 1 || f.revoked[0] != "tok1" {
				t.Fatalf("revoked = %v, want the token revoked", f.revoked)
			}
		})
	}
}

func TestRevokeSelf(t *testing.T) {
	f := &fakeBao{}
	if err := newFake(t, f).RevokeSelf(context.Background(), "tokX"); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "tokX" {
		t.Fatalf("revoked = %v", f.revoked)
	}
}

package vaultx

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

func TestMintToken_ParsesAllFields(t *testing.T) {
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

	meta := map[string]string{"org": "acme", "repo": "widgets"}
	mint, err := c.MintToken(context.Background(), []string{"ci/acme/widgets"}, meta, "ironbark-acme-widgets")
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	if mint.Token == "" {
		t.Errorf("Token empty")
	}
	if mint.Accessor == "" {
		t.Errorf("Accessor empty")
	}
	if mint.TokenType != "service" {
		t.Errorf("TokenType = %q, want %q", mint.TokenType, "service")
	}
	if mint.Renewable {
		t.Errorf("Renewable = true, want false")
	}
	if mint.TTL != 900*time.Second {
		t.Errorf("TTL = %v, want 900s", mint.TTL)
	}
	if mint.Orphan == nil || !*mint.Orphan {
		t.Errorf("Orphan = %v, want pointer to true", mint.Orphan)
	}
	wantWarning := `policy "ci/ironbark-selftest" does not exist`
	if len(mint.Warnings) != 1 || mint.Warnings[0] != wantWarning {
		t.Errorf("Warnings = %v, want [%q]", mint.Warnings, wantWarning)
	}

	if got := fv.lastPoliciesValue(); len(got) != 1 || got[0] != "ci/acme/widgets" {
		t.Errorf("fake saw policies = %v, want [ci/acme/widgets]", got)
	}
	if got := fv.lastMetaValue(); got["org"] != "acme" || got["repo"] != "widgets" {
		t.Errorf("fake saw meta = %v", got)
	}
	if got := fv.lastDisplayNameValue(); got != "ironbark-acme-widgets" {
		t.Errorf("fake saw display_name = %q, want %q", got, "ironbark-acme-widgets")
	}
}

// TestMintToken_RequestBodyHasExactlyThreeKeys locks the SPEC §3.2
// omission down directly: ttl, num_uses, and type must NEVER be sent —
// the token role config governs them. Asserting the body's exact key set
// (not just that the three expected keys are present) guards against a
// future edit silently adding a 4th field.
func TestMintToken_RequestBodyHasExactlyThreeKeys(t *testing.T) {
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

	if _, err := c.MintToken(context.Background(), []string{"ci/x"}, map[string]string{"org": "acme"}, "d"); err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	var generic map[string]json.RawMessage
	if err := json.Unmarshal(fv.lastMintBodyRawValue(), &generic); err != nil {
		t.Fatalf("decode fake-observed body: %v", err)
	}

	keys := make([]string, 0, len(generic))
	for k := range generic {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	want := []string{"display_name", "meta", "policies"}
	if len(keys) != len(want) {
		t.Fatalf("request body keys = %v, want exactly %v (SPEC §3.2: no ttl/num_uses/type)", keys, want)
	}
	for i, k := range keys {
		if k != want[i] {
			t.Errorf("request body keys = %v, want exactly %v (SPEC §3.2: no ttl/num_uses/type)", keys, want)
			break
		}
	}
}

func TestMintToken_OrphanOmittedParsesNil(t *testing.T) {
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

	mint, err := c.MintToken(context.Background(), []string{"ci/x"}, nil, "d")
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if mint.Orphan != nil {
		t.Errorf("Orphan = %v, want nil when the response omits it", *mint.Orphan)
	}
}

func TestMintToken_MintFailureReturnsError(t *testing.T) {
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

	if _, err := c.MintToken(context.Background(), []string{"ci/x"}, nil, "d"); err == nil {
		t.Fatalf("MintToken: expected error, got nil")
	}
}

func TestRevokeSelf_UsesMintedTokenNotOwnSession(t *testing.T) {
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

	mint, err := c.MintToken(context.Background(), []string{"ci/x"}, nil, "d")
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	if err := c.RevokeSelf(context.Background(), mint.Token); err != nil {
		t.Fatalf("RevokeSelf: %v", err)
	}

	if got := fv.revokeCallCount(); got != 1 {
		t.Errorf("revokeCalls = %d, want 1", got)
	}
	got := fv.lastRevokeTokenValue()
	if got != mint.Token {
		t.Errorf("fake saw X-Vault-Token = %q, want the minted token %q", got, mint.Token)
	}
	if got == c.token {
		t.Errorf("RevokeSelf sent ironbark's own session token %q, want the minted token", c.token)
	}

	// The per-request token override in RevokeSelf must not leak into the
	// shared api.Client's own default token (ironbark's session).
	if c.api.Token() != c.token {
		t.Errorf("api.Client default token = %q after RevokeSelf, want unchanged ironbark session token %q", c.api.Token(), c.token)
	}
}

func TestRevokeSelf_FailureReturnsError(t *testing.T) {
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

	if err := c.RevokeSelf(context.Background(), "some-token"); err == nil {
		t.Fatalf("RevokeSelf: expected error, got nil")
	}
}

//go:build integration

// Task 15: the SPEC §9.4 end-to-end HTTP smoke test. Unlike Task 14's
// TestBrokerSuite (which calls broker.Handle directly, bypassing HTTP),
// this file boots the FULL stack — vaultx.Client -> broker.Broker ->
// httpapi.Server — wired exactly as cmd/ironbark/main.go does it, serves
// it on a real in-process HTTP listener, and drives it with a genuinely
// signed *http.Request built via internal/wpsign/wpsigntest. It proves
// the whole chain: sign -> httpapi.Verify -> identity.Parse ->
// broker.Handle -> mint -> sweep -> JSON response -> the returned
// vault_token actually authenticating a scoped Vault/OpenBao read.
//
// Run:
//
//	docker compose -f test/integration/docker-compose.yml up -d
//	go test -tags integration ./test/integration -run TestE2E -v
//	docker compose -f test/integration/docker-compose.yml down -v
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"ironbark/internal/broker"
	"ironbark/internal/httpapi"
	"ironbark/internal/vaultx"
	"ironbark/internal/wpsign/wpsigntest"
)

// e2eFreshnessWindow is generous relative to the real signing/round-trip
// latency below; it exists to bound staleness, not to be tight.
const e2eFreshnessWindow = 30 * time.Second

// e2eRequestTimeout mirrors cmd/ironbark/main.go's requestTimeout.
const e2eRequestTimeout = 30 * time.Second

// loadE2EKeys reads the same checked-in test-only Ed25519 keypair
// internal/wpsign's own matrix uses (internal/wpsign/testdata), resolved
// relative to this package's directory since t.Run subtests do not change
// the working directory.
func loadE2EKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	privPEM, err := os.ReadFile("../../internal/wpsign/testdata/dev-ed25519.pem")
	if err != nil {
		t.Fatalf("read test private key: %v", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatalf("decode test private key PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test private key: %v", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("test private key is not ed25519, got %T", privAny)
	}

	pubPEM, err := os.ReadFile("../../internal/wpsign/testdata/dev-ed25519.pub")
	if err != nil {
		t.Fatalf("read test public key: %v", err)
	}
	block, _ = pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("decode test public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test public key: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("test public key is not ed25519, got %T", pubAny)
	}

	return priv, pub
}

// e2eStack is the full in-process HTTP stack for one product, wired as
// cmd/ironbark/main.go wires it (minus the signal/shutdown machinery,
// which this test doesn't need).
type e2eStack struct {
	server *httptest.Server
	client *vaultx.Client
}

// newE2EStack boots vaultx.Client -> broker.Broker -> httpapi.Server for
// addr, logs the client in, runs the startup canary (required for the
// broker's mint gate — CanaryOK must be true), and serves the resulting
// http.Handler on a real listener.
func newE2EStack(t *testing.T, ctx context.Context, addr string, fx Fixture, pub ed25519.PublicKey) *e2eStack {
	t.Helper()

	vc, err := vaultx.New(vaultx.Config{
		Addr:      addr,
		RoleID:    fx.RoleID,
		SecretID:  fx.SecretID,
		TokenRole: "ci",
		KVMount:   "kv",
		KVPrefix:  "ci",
	})
	if err != nil {
		t.Fatalf("vaultx.New: %v", err)
	}
	if err := vc.Login(ctx); err != nil {
		t.Fatalf("vaultx Login: %v", err)
	}
	if err := vc.RunCanary(ctx, "ci"); err != nil {
		t.Fatalf("RunCanary: %v", err)
	}
	if !vc.CanaryOK() {
		t.Fatalf("CanaryOK() = false after a passing canary")
	}

	brk := broker.New(vc, "ci", addr)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httpapi.New(brk, vc.Healthy, pub, e2eFreshnessWindow, e2eRequestTimeout, time.Now, logger)
	vc.SetMetrics(srv.VaultMetrics())

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	return &e2eStack{server: ts, client: vc}
}

// woodpeckerPayload builds a realistic Woodpecker secret-extension POST
// body for the given repo/forgeID, event=push, branch=main — matching
// exactly what internal/identity.Parse expects (repo.full_name,
// repo.forge_remote_id, pipeline.event/branch/number/commit).
func woodpeckerPayload(t *testing.T, fullName, forgeID string) []byte {
	t.Helper()
	body := map[string]interface{}{
		"repo": map[string]interface{}{
			"full_name":       fullName,
			"forge_remote_id": forgeID,
		},
		"pipeline": map[string]interface{}{
			"event":  "push",
			"branch": Branch,
			"number": 42,
			"commit": "deadbeefcafebabe",
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// signedRequest builds a real POST http.Request against serverURL, signed
// with priv exactly as Woodpecker's server signs its extension calls
// (wpsigntest.Sign).
func signedRequest(t *testing.T, serverURL string, body []byte, priv ed25519.PrivateKey) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, serverURL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if err := wpsigntest.Sign(req, body, priv); err != nil {
		t.Fatalf("wpsigntest.Sign: %v", err)
	}
	return req
}

type e2eSecret struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Events []string `json:"events"`
	Images []string `json:"images,omitempty"`
}

type e2eResponseBody struct {
	Secrets []e2eSecret `json:"secrets"`
}

func findE2ESecret(secrets []e2eSecret, name string) (e2eSecret, bool) {
	for _, s := range secrets {
		if s.Name == name {
			return s, true
		}
	}
	return e2eSecret{}, false
}

func e2eSecretNames(secrets []e2eSecret) []string {
	names := make([]string, len(secrets))
	for i, s := range secrets {
		names[i] = s.Name
	}
	sort.Strings(names)
	return names
}

// TestE2E is SPEC §9.4: a full signed-request round trip through the real
// HTTP stack against each product, followed by using the returned
// vault_token as a raw Vault/OpenBao client to prove it is genuinely
// scoped (a granted read succeeds and matches the fixture's seeded value;
// a disjoint read 403s).
func TestE2E(t *testing.T) {
	priv, pub := loadE2EKeys(t)

	for _, p := range products {
		p := p
		t.Run(p.name, func(t *testing.T) {
			ctx := t.Context()
			fx := SetupProduct(t, p.addr, p.rootToken)
			stack := newE2EStack(t, ctx, p.addr, fx, pub)

			// ---- unsigned POST -> 401 ----
			t.Run("unsigned_post_401", func(t *testing.T) {
				body := woodpeckerPayload(t, "itest/"+RepoOnboarded, ForgeRemoteIDRepo1)
				req, err := http.NewRequest(http.MethodPost, stack.server.URL+"/", strings.NewReader(string(body)))
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("do: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("Status = %d, want 401", resp.StatusCode)
				}
			})

			// ---- signed POST for the un-onboarded repo -> 204 ----
			t.Run("signed_unonboarded_204", func(t *testing.T) {
				body := woodpeckerPayload(t, "itest/"+RepoUnonboarded, "")
				req := signedRequest(t, stack.server.URL, body, priv)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("do: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					t.Errorf("Status = %d, want 204", resp.StatusCode)
				}
			})

			// ---- signed POST for the onboarded repo -> 200, full chain ----
			var mintedToken string
			t.Run("signed_onboarded_200", func(t *testing.T) {
				body := woodpeckerPayload(t, "itest/"+RepoOnboarded, ForgeRemoteIDRepo1)
				req := signedRequest(t, stack.server.URL, body, priv)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("do: %v", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					t.Fatalf("Status = %d, want 200", resp.StatusCode)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}

				var rb e2eResponseBody
				if err := json.NewDecoder(resp.Body).Decode(&rb); err != nil {
					t.Fatalf("decode response body: %v", err)
				}

				names := e2eSecretNames(rb.Secrets)
				t.Logf("%s: round-tripped secret names: %v", p.name, names)

				// Base/event/branch-tier entries the fixture seeded for
				// repo1/push/main (see fixture.go's package doc comment),
				// plus vault_token and vault_addr (broker.New below is
				// wired with advertiseVaultAddr=p.addr, matching
				// cmd/ironbark/main.go's AdvertiseVaultAddr wiring).
				// dbref_* names vary (derived from the database engine's
				// dynamic creds response) so they're checked by prefix,
				// not exact name.
				expectedFixed := []string{"branchonly", "dup", "eventonly", "general1_pass", "general1_user", "nonstring_label", "pinned", "shorthand1", "vault_addr", "vault_token"}
				var dbrefSeen bool
				var otherNames []string
				for _, n := range names {
					if strings.HasPrefix(n, "dbref_") {
						dbrefSeen = true
						continue
					}
					otherNames = append(otherNames, n)
				}
				if !equalStrings(otherNames, expectedFixed) {
					t.Errorf("non-dbref secret names = %v, want %v", otherNames, expectedFixed)
				}
				if !dbrefSeen {
					t.Errorf("expected at least one dbref_* secret, got none (full set: %v)", names)
				}

				tok, ok := findE2ESecret(rb.Secrets, "vault_token")
				if !ok || tok.Value == "" {
					t.Fatalf("vault_token secret missing or empty in response: %+v", rb.Secrets)
				}
				mintedToken = tok.Value

				if addr, ok := findE2ESecret(rb.Secrets, "vault_addr"); !ok || addr.Value != p.addr {
					t.Errorf("vault_addr secret = %+v, want value %q", addr, p.addr)
				}
			})

			if mintedToken == "" {
				t.Fatal("no vault_token minted; cannot exercise the round-tripped token")
			}

			// ---- use the round-tripped token as a raw Vault client ----
			raw, err := api.NewClient(&api.Config{Address: p.addr})
			if err != nil {
				t.Fatalf("new raw client: %v", err)
			}
			raw.SetToken(mintedToken)

			t.Run("minted_token_reads_granted_path", func(t *testing.T) {
				secret, err := raw.Logical().ReadWithContext(ctx, "kv/data/ci/"+TestOrg+"/"+RepoOnboarded+"/general1")
				if err != nil {
					t.Fatalf("read granted path: %v", err)
				}
				if secret == nil || secret.Data == nil {
					t.Fatalf("read granted path: nil response")
				}
				data, _ := secret.Data["data"].(map[string]interface{})
				if data == nil {
					t.Fatalf("read granted path: no data field in %+v", secret.Data)
				}
				if data["user"] != "baseuser" || data["pass"] != "basepass" {
					t.Errorf("general1 data = %+v, want {user:baseuser pass:basepass} (fixture-seeded value)", data)
				}
			})

			t.Run("minted_token_denied_on_disjoint_path", func(t *testing.T) {
				_, err := raw.Logical().ReadWithContext(ctx, "kv/data/ci/"+TestOrg+"/"+RepoUnonboarded+"/anything")
				if err == nil {
					t.Fatalf("read disjoint path: want error (403), got success")
				}
				var respErr *api.ResponseError
				if !errors.As(err, &respErr) {
					t.Fatalf("read disjoint path: want *api.ResponseError, got %T: %v", err, err)
				}
				if respErr.StatusCode != http.StatusForbidden {
					t.Errorf("read disjoint path status = %d, want 403 (body: %v)", respErr.StatusCode, respErr.Errors)
				}
			})
		})
	}
}

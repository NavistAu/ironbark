package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/wpsign/wpsigntest"
)

const testWindow = 10 * time.Second

var testBody = []byte(`{"repo":{"full_name":"acme/widget","forge_remote_id":"forge-1"},"pipeline":{"event":"push","branch":"main","number":7,"commit":"deadbeef"}}`)

// --- test fixtures: the checked-in wpsign test keypair, shared with
// internal/wpsign's own signature matrix (Task 5) and cmd/ironbark's smoke
// run (Task 12). ---

func loadTestKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	privPEM, err := os.ReadFile("../wpsign/testdata/dev-ed25519.pem")
	if err != nil {
		t.Fatalf("read testdata private key: %v", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatalf("decode testdata private key PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse testdata private key: %v", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("testdata private key is not ed25519, got %T", privAny)
	}

	pubPEM, err := os.ReadFile("../wpsign/testdata/dev-ed25519.pub")
	if err != nil {
		t.Fatalf("read testdata public key: %v", err)
	}
	block, _ = pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("decode testdata public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse testdata public key: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("testdata public key is not ed25519, got %T", pubAny)
	}

	return priv, pub
}

// signedRequest builds an httptest request over body, signed exactly as
// Woodpecker signs (wpsigntest), ready to hand to httptest.NewRecorder +
// Server.ServeHTTP.
func signedRequest(t *testing.T, key ed25519.PrivateKey, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := wpsigntest.Sign(req, body, key); err != nil {
		t.Fatalf("wpsigntest.Sign: %v", err)
	}
	return req
}

// --- mock broker.Handler ---

type mockHandler struct {
	mu     sync.Mutex
	result broker.Result
	block  chan struct{} // if non-nil, Handle blocks on this channel (or ctx.Done())
	gotID  identity.Identity
	called bool
}

func (m *mockHandler) Handle(ctx context.Context, id identity.Identity) broker.Result {
	m.mu.Lock()
	m.called = true
	m.gotID = id
	block := m.block
	m.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
		}
	}
	return m.result
}

func (m *mockHandler) wasCalledWith() identity.Identity {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gotID
}

// --- captured slog logger: a JSON handler writing into a locked buffer so
// tests can assert exact audit-line shapes. ---

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// logLines parses each JSON line in the buffer into a map for field
// assertions.
func (b *syncBuffer) logLines(t *testing.T) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if raw == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("unmarshal log line %q: %v", raw, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func testLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

// --- Server construction helper ---

func newTestServer(t *testing.T, h Handler, ready Ready, pub ed25519.PublicKey, timeout time.Duration) (*Server, *syncBuffer) {
	t.Helper()
	logger, buf := testLogger()
	if ready == nil {
		ready = func() bool { return true }
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	s := New(h, ready, pub, testWindow, timeout, time.Now, logger)
	return s, buf
}

func okResult() broker.Result {
	return broker.Result{
		Status:  200,
		Outcome: broker.OutcomeOK,
		Secrets: []broker.Secret{
			{Name: "api_key", Value: "s3cr3t", Events: []string{"push"}},
			{Name: "vault_token", Value: "tok-abc", Events: []string{"push"}, Images: []string{"golang:1.24"}},
		},
		Audit: broker.AuditFields{
			PoliciesRequested: []string{"ci/acme/widget/push"},
			SecretNames:       []string{"api_key", "vault_token"},
			TokenAccessor:     "accessor-abc",
			TokenTTL:          900 * time.Second,
		},
	}
}

// --- tests ---

func TestUnsignedPOST_401AndRefusedSignatureAudit(t *testing.T) {
	_, pub := loadTestKeys(t)
	mh := &mockHandler{result: okResult()}
	s, buf := newTestServer(t, mh, nil, pub, 0)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testBody))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if mh.called {
		t.Errorf("broker Handler was called, want no call on refused signature")
	}

	lines := buf.logLines(t)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(lines), lines)
	}
	line := lines[0]
	if line["outcome"] != "refused_signature" {
		t.Errorf("outcome = %v, want refused_signature", line["outcome"])
	}
	if _, ok := line["remote_addr"]; !ok {
		t.Errorf("log line missing remote_addr: %v", line)
	}
	if _, ok := line["reason"]; !ok {
		t.Errorf("log line missing reason: %v", line)
	}
	// SPEC §8.1: the refused-signature line carries NOTHING derived from
	// the payload.
	forbidden := []string{"org", "repo", "event", "branch", "pipeline_number", "policies_requested", "secrets_returned", "token_accessor", "token_ttl"}
	for _, k := range forbidden {
		if _, ok := line[k]; ok {
			t.Errorf("refused-signature log line leaked payload-derived field %q: %v", k, line)
		}
	}
}

func TestSignedValidPOST_200RendersBrokerResultAndAudit(t *testing.T) {
	priv, pub := loadTestKeys(t)
	res := okResult()
	mh := &mockHandler{result: res}
	s, buf := newTestServer(t, mh, nil, pub, 0)

	req := signedRequest(t, priv, testBody)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Secrets []struct {
			Name   string   `json:"name"`
			Value  string   `json:"value"`
			Events []string `json:"events"`
			Images []string `json:"images"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v (body=%s)", err, rec.Body.String())
	}
	if len(body.Secrets) != 2 {
		t.Fatalf("secrets = %+v, want 2 entries", body.Secrets)
	}

	var gotAPIKey, gotToken bool
	rawBody := rec.Body.String()
	for _, sec := range body.Secrets {
		switch sec.Name {
		case "api_key":
			gotAPIKey = true
			if sec.Value != "s3cr3t" {
				t.Errorf("api_key value = %q", sec.Value)
			}
			if len(sec.Images) != 0 {
				t.Errorf("api_key images = %v, want none", sec.Images)
			}
			// images must be OMITTED (not present as null/[]) when empty.
			if strings.Contains(rawBody, `"name":"api_key","value":"s3cr3t","events":["push"],"images"`) {
				t.Errorf("api_key entry includes an images key, want omitted: %s", rawBody)
			}
		case "vault_token":
			gotToken = true
			if sec.Value != "tok-abc" {
				t.Errorf("vault_token value = %q", sec.Value)
			}
			if len(sec.Images) != 1 || sec.Images[0] != "golang:1.24" {
				t.Errorf("vault_token images = %v, want [golang:1.24]", sec.Images)
			}
		}
	}
	if !gotAPIKey || !gotToken {
		t.Fatalf("secrets = %+v, missing expected entries", body.Secrets)
	}

	gotID := mh.wasCalledWith()
	if gotID.Org != "acme" || gotID.Repo != "widget" || gotID.Event != "push" || gotID.Branch != "main" {
		t.Errorf("Handle called with identity %+v, want org=acme repo=widget event=push branch=main", gotID)
	}

	lines := buf.logLines(t)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(lines), lines)
	}
	line := lines[0]
	if line["outcome"] != "ok" {
		t.Errorf("outcome = %v, want ok", line["outcome"])
	}
	if line["org"] != "acme" || line["repo"] != "widget" {
		t.Errorf("org/repo = %v/%v, want acme/widget", line["org"], line["repo"])
	}
	if line["token_accessor"] != "accessor-abc" {
		t.Errorf("token_accessor = %v, want accessor-abc", line["token_accessor"])
	}
}

func TestResult204_EmptyBody(t *testing.T) {
	priv, pub := loadTestKeys(t)
	mh := &mockHandler{result: broker.Result{Status: 204, Outcome: broker.OutcomeUnonboarded}}
	s, _ := newTestServer(t, mh, nil, pub, 0)

	req := signedRequest(t, priv, testBody)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
}

func TestResult502_EmptyBody(t *testing.T) {
	priv, pub := loadTestKeys(t)
	mh := &mockHandler{result: broker.Result{Status: 502, Outcome: broker.OutcomeError}}
	s, _ := newTestServer(t, mh, nil, pub, 0)

	req := signedRequest(t, priv, testBody)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
}

func TestRoutes_MethodAndNotFound(t *testing.T) {
	_, pub := loadTestKeys(t)
	mh := &mockHandler{result: okResult()}
	s, _ := newTestServer(t, mh, nil, pub, 0)

	t.Run("GET / -> 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("GET /unknown -> 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("GET /healthz -> 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("GET /metrics -> 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

func TestReadyz_TracksReadySource(t *testing.T) {
	_, pub := loadTestKeys(t)
	mh := &mockHandler{result: okResult()}
	ready := true
	s, _ := newTestServer(t, mh, func() bool { return ready }, pub, 0)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when ready", rec.Code)
	}

	ready = false
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when not ready", rec.Code)
	}
}

func TestBodyOverLimit_413(t *testing.T) {
	priv, pub := loadTestKeys(t)
	mh := &mockHandler{result: okResult()}
	s, _ := newTestServer(t, mh, nil, pub, 0)

	oversized := bytes.Repeat([]byte("a"), (1<<20)+1)
	oversizedJSON := append([]byte(`{"repo":{"full_name":"acme/widget"},"pipeline":{"event":"push"},"pad":"`), oversized...)
	oversizedJSON = append(oversizedJSON, []byte(`"}`)...)

	req := signedRequest(t, priv, oversizedJSON)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if mh.called {
		t.Errorf("broker Handler was called, want no call over the body limit")
	}
}

func TestTimeout_502WithErrorAudit(t *testing.T) {
	priv, pub := loadTestKeys(t)
	mh := &mockHandler{
		result: okResult(),
		block:  make(chan struct{}), // never closed: Handle blocks until ctx expires
	}
	s, buf := newTestServer(t, mh, nil, pub, 50*time.Millisecond)

	req := signedRequest(t, priv, testBody)
	rec := httptest.NewRecorder()

	start := time.Now()
	s.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ServeHTTP took %v, want to return promptly after the injected 50ms timeout", elapsed)
	}

	lines := buf.logLines(t)
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(lines), lines)
	}
	if lines[0]["outcome"] != "error" {
		t.Errorf("outcome = %v, want error", lines[0]["outcome"])
	}
}

func TestRevokeFailed_LogsErrorLine(t *testing.T) {
	priv, pub := loadTestKeys(t)
	res := broker.Result{
		Status:       502,
		Outcome:      broker.OutcomeError,
		RevokeFailed: true,
		Audit:        broker.AuditFields{TokenAccessor: "accessor-doomed"},
	}
	mh := &mockHandler{result: res}
	s, buf := newTestServer(t, mh, nil, pub, 0)

	req := signedRequest(t, priv, testBody)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}

	lines := buf.logLines(t)
	var sawError bool
	for _, l := range lines {
		if l["level"] == "ERROR" {
			sawError = true
		}
	}
	if !sawError {
		t.Fatalf("no ERROR-level log line found for RevokeFailed=true: %v", lines)
	}
	if len(lines) < 2 {
		t.Fatalf("got %d log lines, want the verified audit line plus a revoke-failure error line: %v", len(lines), lines)
	}
}

func TestMalformedPayload_400(t *testing.T) {
	priv, pub := loadTestKeys(t)
	mh := &mockHandler{result: okResult()}
	s, _ := newTestServer(t, mh, nil, pub, 0)

	malformed := []byte(`not json`)
	req := signedRequest(t, priv, malformed)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if mh.called {
		t.Errorf("broker Handler was called, want no call on malformed payload")
	}
}

func TestMetrics_SignatureFailureIncrement(t *testing.T) {
	_, pub := loadTestKeys(t)
	mh := &mockHandler{result: okResult()}
	s, _ := newTestServer(t, mh, nil, pub, 0)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testBody))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	mrec := httptest.NewRecorder()
	s.ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	exposition := mrec.Body.String()
	if !strings.Contains(exposition, "ironbark_signature_failures_total") {
		t.Errorf("metrics exposition missing ironbark_signature_failures_total:\n%s", exposition)
	}
	if !strings.Contains(exposition, `reason="missing_signature"`) {
		t.Errorf("metrics exposition missing reason=missing_signature label:\n%s", exposition)
	}
}

func TestServeHTTP_IsHTTPHandler(t *testing.T) {
	var _ http.Handler = (*Server)(nil)
}

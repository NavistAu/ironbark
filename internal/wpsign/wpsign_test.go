package wpsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/wpsign/wpsigntest"

	"github.com/yaronf/httpsign"
)

const testWindow = 10 * time.Second

var testBody = []byte(`{"repo":{"full_name":"acme/widget"},"pipeline":{"event":"push"}}`)

// loadTestKeys reads the checked-in test-only Ed25519 keypair
// (internal/wpsign/testdata) used by this matrix and by cmd/ironbark's
// smoke run (Task 12).
func loadTestKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	privPEM, err := os.ReadFile("testdata/dev-ed25519.pem")
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

	pubPEM, err := os.ReadFile("testdata/dev-ed25519.pub")
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

// newSignedRequest builds an httptest request over testBody and signs it
// with wpsigntest per o.
func newSignedRequest(t *testing.T, key ed25519.PrivateKey, body []byte, o wpsigntest.Opts) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := wpsigntest.SignOpts(req, body, key, o); err != nil {
		t.Fatalf("wpsigntest.SignOpts: %v", err)
	}
	return req
}

// createdOf reads back the actual "created" signature parameter embedded
// by wpsigntest (which always signs at real wall-clock time — Task 4's
// harness has no CreatedAt override). The stale/future-created matrix
// cases derive their injected `now` from this value rather than from
// wall-clock offsets, so the test is deterministic under a slow CI.
func createdOf(t *testing.T, req *http.Request) time.Time {
	t.Helper()
	details, err := httpsign.RequestDetails(signatureName, req)
	if err != nil {
		t.Fatalf("httpsign.RequestDetails: %v", err)
	}
	if details.Created == nil {
		t.Fatalf("signed request has no created parameter")
	}
	return *details.Created
}

func nowFrom(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestVerifyMatrix(t *testing.T) {
	priv, pub := loadTestKeys(t)

	t.Run("valid, fresh", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{})
		created := createdOf(t, req)
		err := Verify(req, testBody, pub, testWindow, nowFrom(created))
		if err != nil {
			t.Fatalf("Verify() = %v, want nil", err)
		}
	})

	t.Run("no Signature/Signature-Input headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(testBody))
		err := Verify(req, testBody, pub, testWindow, time.Now)
		assertReason(t, err, ReasonMissingSignature)
	})

	t.Run("signed with a different key", func(t *testing.T) {
		_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate other key: %v", err)
		}
		req := newSignedRequest(t, otherPriv, testBody, wpsigntest.Opts{})
		err = Verify(req, testBody, pub, testWindow, time.Now)
		assertReason(t, err, ReasonWrongKey)
	})

	t.Run("body swapped after signing", func(t *testing.T) {
		tampered := []byte(`{"repo":{"full_name":"attacker/evil"}}`)
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{TamperBodyAfterSign: tampered})
		err := Verify(req, tampered, pub, testWindow, time.Now)
		assertReason(t, err, ReasonDigestMismatch)
	})

	// The next two rows lock in that the `body` argument, not r.Body, is
	// authoritative for the digest check — every other row in this matrix
	// passes byte-identical bytes as both, so that fact is otherwise only
	// established by code inspection, not by a test.
	t.Run("body argument authoritative: r.Body altered post-sign, body arg still matches signature", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{})
		created := createdOf(t, req)
		// Mutate r.Body directly (not via TamperBodyAfterSign, which the
		// harness itself uses to test digest mismatch) — Verify must
		// never consult it.
		req.Body = io.NopCloser(bytes.NewReader([]byte(`{"r.Body":"must never be read by Verify"}`)))
		err := Verify(req, testBody, pub, testWindow, nowFrom(created))
		if err != nil {
			t.Fatalf("Verify() = %v, want nil (the body argument matches the signed Content-Digest; r.Body must be ignored)", err)
		}
	})

	t.Run("body argument authoritative: r.Body matches signature, body arg does not", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{}) // r.Body left as the correctly-signed bytes
		wrongBody := []byte(`{"body arg":"deliberately wrong, must be rejected"}`)
		err := Verify(req, wrongBody, pub, testWindow, time.Now)
		assertReason(t, err, ReasonDigestMismatch)
	})

	t.Run("Content-Digest header stripped after signing", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{OmitDigestHeader: true})
		err := Verify(req, testBody, pub, testWindow, time.Now)
		assertReason(t, err, ReasonDigestMismatch)
	})

	t.Run("components cover only @request-target", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{Components: []string{"@request-target"}})
		err := Verify(req, testBody, pub, testWindow, time.Now)
		assertReason(t, err, ReasonUncoveredComponent)
	})

	// Mirror of the row above: this SPEC §9.1 row is an "or" over both
	// required components, so both directions of uncovered-component must
	// be exercised. Here @request-target is the one left uncovered.
	t.Run("components cover only content-digest", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{Components: []string{"content-digest"}})
		err := Verify(req, testBody, pub, testWindow, time.Now)
		assertReason(t, err, ReasonUncoveredComponent)
	})

	t.Run("created omitted", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{OmitCreated: true})
		err := Verify(req, testBody, pub, testWindow, time.Now)
		assertReason(t, err, ReasonMissingCreated)
	})

	t.Run("created stale (older than window)", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{})
		created := createdOf(t, req)
		err := Verify(req, testBody, pub, testWindow, nowFrom(created.Add(11*time.Second)))
		assertReason(t, err, ReasonStaleCreated)
	})

	t.Run("created in the future beyond window", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{})
		created := createdOf(t, req)
		err := Verify(req, testBody, pub, testWindow, nowFrom(created.Add(-11*time.Second)))
		assertReason(t, err, ReasonStaleCreated)
	})

	t.Run("byte-identical replay within window is accepted", func(t *testing.T) {
		req := newSignedRequest(t, priv, testBody, wpsigntest.Opts{})
		created := createdOf(t, req)
		now := nowFrom(created)
		if err := Verify(req, testBody, pub, testWindow, now); err != nil {
			t.Fatalf("first Verify() = %v, want nil", err)
		}
		if err := Verify(req, testBody, pub, testWindow, now); err != nil {
			t.Fatalf("replay Verify() = %v, want nil (replays inside the window are accepted, SPEC §5)", err)
		}
	})
}

func assertReason(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("Verify() = nil, want Reason %q", want)
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("Verify() = %v (%T), want *VerifyError", err, err)
	}
	if ve.Reason != want {
		t.Fatalf("Verify() reason = %q, want %q (err: %v)", ve.Reason, want, err)
	}
}

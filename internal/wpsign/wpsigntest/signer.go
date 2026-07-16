// Package wpsigntest is a test-only signer that mirrors Woodpecker's
// RFC-9421 extension-request signature [WP§8] so internal/wpsign.Verify can
// be exercised against a faithful, byte-compatible signature without a real
// Woodpecker server. It is imported by tests only; it is not part of
// ironbark's runtime.
package wpsigntest

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yaronf/httpsign"
)

// signatureName is Woodpecker's literal signature label
// (server/services/utils/http.go: pubKeyID := "woodpecker-ci-extensions").
const signatureName = "woodpecker-ci-extensions"

// defaultComponents are the covered components Woodpecker signs [WP§8].
var defaultComponents = []string{"@request-target", "content-digest"}

// Opts controls deliberate deviations from a faithful Woodpecker signature,
// for exercising wpsign.Verify's failure taxonomy. The zero value produces
// no deviation; use Sign for the faithful case.
//
// There is deliberately no way to forge the "created" timestamp: this
// harness only ever emits real, validly-signed requests (created = actual
// signing time). Task 5's stale/future-created matrix cases are exercised
// by advancing the *verifier's* injected `now` (wpsign.Verify's `now
// func() time.Time` parameter), not by forging the signer's clock.
type Opts struct {
	// OmitCreated disables the signed "created" parameter entirely.
	OmitCreated bool
	// Components, if non-nil, overrides the set of covered components
	// (default: @request-target, content-digest).
	Components []string
	// TamperBodyAfterSign, if non-nil, replaces the request body (and
	// ContentLength) with this content AFTER signing, so any Content-Digest
	// that was signed no longer matches.
	TamperBodyAfterSign []byte
	// OmitDigestHeader removes the Content-Digest header AFTER signing,
	// even though it was covered by the signature.
	OmitDigestHeader bool
}

// Sign signs req exactly as Woodpecker's server does: an Ed25519 signer
// built from httpsign.NewSignConfig() (default-signed "created", no
// nonce/expires) over "@request-target" and "content-digest", with
// Content-Digest auto-generated from body [WP§8].
func Sign(req *http.Request, body []byte, key ed25519.PrivateKey) error {
	return SignOpts(req, body, key, Opts{})
}

// SignOpts is Sign with optional deviations; see Opts.
func SignOpts(req *http.Request, body []byte, key ed25519.PrivateKey, o Opts) error {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	cfg := httpsign.NewSignConfig()
	if o.OmitCreated {
		cfg.SignCreated(false)
	}

	components := defaultComponents
	if o.Components != nil {
		components = o.Components
	}

	signer, err := httpsign.NewEd25519Signer(key, cfg, httpsign.Headers(components...))
	if err != nil {
		return fmt.Errorf("wpsigntest: build signer: %w", err)
	}

	if containsFold(components, "content-digest") && req.Body != nil {
		digest, err := httpsign.GenerateContentDigestHeader(&req.Body, []string{httpsign.DigestSha256})
		if err != nil {
			return fmt.Errorf("wpsigntest: generate content-digest: %w", err)
		}
		req.Header.Set("Content-Digest", digest)
	}

	sigInput, sig, err := httpsign.SignRequest(signatureName, *signer, req)
	if err != nil {
		return fmt.Errorf("wpsigntest: sign request: %w", err)
	}
	req.Header.Set("Signature", sig)
	req.Header.Set("Signature-Input", sigInput)

	if o.TamperBodyAfterSign != nil {
		req.Body = io.NopCloser(bytes.NewReader(o.TamperBodyAfterSign))
		req.ContentLength = int64(len(o.TamperBodyAfterSign))
	}
	if o.OmitDigestHeader {
		req.Header.Del("Content-Digest")
	}

	return nil
}

func containsFold(components []string, name string) bool {
	for _, c := range components {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
}

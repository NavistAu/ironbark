// Package wpsign verifies Woodpecker's RFC-9421 HTTP Message Signature on
// incoming secret-extension requests (SPEC §5, WP§8). This is the single
// most security-load-bearing unit in ironbark: nothing in a request is
// trusted — including the payload used to derive Vault policy — unless
// Verify returns nil.
package wpsign

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yaronf/httpsign"
)

// signatureName is Woodpecker's literal signature label
// (server/services/utils/http.go: pubKeyID := "woodpecker-ci-extensions") [WP§8].
const signatureName = "woodpecker-ci-extensions"

// requiredComponents are the components Woodpecker's signature MUST cover
// (SPEC §5); a signature omitting either is rejected.
var requiredComponents = []string{"@request-target", "content-digest"}

// Reason is the signature-verification failure taxonomy (SPEC §5): each
// value is its own metrics label and audit-log reason. Never derived from
// or carrying payload data.
type Reason string

const (
	ReasonMissingSignature   Reason = "missing_signature"
	ReasonUnparseable        Reason = "unparseable"
	ReasonWrongKey           Reason = "wrong_key"
	ReasonDigestMismatch     Reason = "digest_mismatch"
	ReasonUncoveredComponent Reason = "uncovered_component"
	ReasonMissingCreated     Reason = "missing_created"
	ReasonStaleCreated       Reason = "stale_created"
)

// VerifyError is returned by Verify on any rejection. Err, when non-nil,
// wraps the underlying library error for diagnostics; neither it nor
// Reason ever carries request/payload data (SPEC §5, §8.1).
type VerifyError struct {
	Reason Reason
	Err    error
}

func (e *VerifyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("wpsign: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("wpsign: %s", e.Reason)
}

func (e *VerifyError) Unwrap() error { return e.Err }

// Verify checks r's RFC-9421 signature (named "woodpecker-ci-extensions",
// matching Woodpecker's own signer [WP§8]) against pub. It requires:
//
//   - a Signature and Signature-Input header;
//   - covered components including @request-target and content-digest;
//   - a Content-Digest header whose RFC-9530 sha-256 digest matches body
//     (the actual bytes the caller received — checked independently of
//     the signing library, which does not itself validate the header
//     against a body);
//   - a valid Ed25519 signature under pub;
//   - a "created" signature parameter within window of now().
//
// Contract: body MUST be the exact bytes the caller treats as r's
// payload. The Content-Digest check is recomputed over body, not read
// from r.Body — r.Body is never touched by Verify — so the caller is
// responsible for passing the same bytes it will later hand to
// identity.Parse.
//
// Returns nil on success, else a *VerifyError. now is injected so callers
// can test freshness deterministically; production passes time.Now.
func Verify(r *http.Request, body []byte, pub ed25519.PublicKey, window time.Duration, now func() time.Time) error {
	if r.Header.Get("Signature") == "" || r.Header.Get("Signature-Input") == "" {
		return &VerifyError{Reason: ReasonMissingSignature}
	}

	verifyConfig := httpsign.NewVerifyConfig().SetVerifyCreated(false) // we enforce freshness ourselves, below, against the injected now
	verifier, err := httpsign.NewEd25519Verifier(pub, verifyConfig, httpsign.Headers(requiredComponents...))
	if err != nil {
		return &VerifyError{Reason: ReasonUnparseable, Err: err}
	}

	if err := httpsign.VerifyRequest(signatureName, *verifier, r); err != nil {
		return &VerifyError{Reason: classifyVerifyError(err), Err: err}
	}

	// The library verifies the Content-Digest *header string* was covered
	// by the signature; it does not itself recompute the digest against
	// the actual body. Do that explicitly, against the caller-supplied
	// body (the bytes actually received), so a body swapped after signing
	// is caught even though the (unchanged) header string still verifies.
	digestBody := io.NopCloser(bytes.NewReader(body))
	if err := httpsign.ValidateContentDigestHeader(r.Header.Values("Content-Digest"), &digestBody, []string{httpsign.DigestSha256}); err != nil {
		return &VerifyError{Reason: ReasonDigestMismatch, Err: err}
	}

	details, err := httpsign.RequestDetails(signatureName, r)
	if err != nil {
		return &VerifyError{Reason: ReasonUnparseable, Err: err}
	}
	if details.Created == nil {
		return &VerifyError{Reason: ReasonMissingCreated}
	}
	if drift := now().Sub(*details.Created); drift > window || drift < -window {
		return &VerifyError{Reason: ReasonStaleCreated}
	}

	return nil
}

// classifyVerifyError maps a github.com/yaronf/httpsign verification
// error to our failure taxonomy. The library exposes no sentinel error
// values for these cases, so this matches on its (stable, payload-free)
// message text. TestVerifyMatrix exercises every branch below with an
// exact-Reason assertion, so a future httpsign version that reworded
// these messages would fail CI loudly (wrong Reason) rather than
// silently drifting everything to ReasonUnparseable — that test coverage
// is this function's upgrade guard.
func classifyVerifyError(err error) Reason {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "does not cover all required fields"):
		return ReasonUncoveredComponent
	case strings.Contains(msg, "signature verification failed"):
		return ReasonWrongKey
	case strings.Contains(msg, "content-digest"):
		// Covered per Signature-Input, but the header itself is missing
		// from the message (e.g. stripped after signing) — verification
		// cannot confirm body integrity, so this is digest-mismatch class.
		// This matches signatures.go's lowercase "header content-digest
		// not found" (the covered-but-absent-header path reached via
		// VerifyRequest's own signature-base construction), not
		// digest.go's Title-Case "Content-Digest" messages — those never
		// reach this function, since our own explicit
		// ValidateContentDigestHeader call (below, in Verify) handles
		// that path directly and returns ReasonDigestMismatch itself.
		return ReasonDigestMismatch
	default:
		return ReasonUnparseable
	}
}

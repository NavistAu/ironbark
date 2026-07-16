// This file (Task 8) owns the SPEC §3.5 startup canary: the real
// implementation the Task 7 canaryFn seam invokes after every (re-)login.
package vaultx

import (
	"context"
	"fmt"
)

// runCanary is the SPEC §3.5 startup canary. It mints against
// c.cfg.TokenRole with the single conventional-but-nonexistent policy
// "<policyPrefix>/ironbark-selftest" — a nonexistent policy mints fine
// with a warning and grants nothing (R§7.1), so the mint is expected to
// SUCCEED; the canary asserts on the minted token's PROPERTIES, not on
// the absence of warnings:
//
//   - mint succeeds (proves AppRole capability and that the role glob
//     covers the convention prefix, R§7.6)
//   - token_type == "service" (catches G1 without granting ironbark any
//     read on the role)
//   - renewable == false (cycle-2 C2-1)
//   - orphan == true, asserted only if the response exposes it (cycle-2
//     G2-3; the integration test is the definitive orphan check)
//   - revoke-self on the minted token succeeds (proves the default
//     policy survived role config, C5)
//
// Any violation returns an error naming the specific expectation that
// failed; Run (Task 7) logs it and retries every retryInterval. A token
// that fails one of the three property assertions is revoked best-effort
// before runCanary returns (SPEC §3.4: "a token that fails our own trust
// assertions has no reason to stay alive" — without this, a sustained
// role misconfiguration mints and abandons a live service token every
// retryInterval until its own TTL). Revoke failures on that path are
// swallowed, per §3.4 "revoke failures are logged and do not change the
// outcome" — this package has no logging infrastructure yet (a later
// task wires §8 observability), so the discard IS the "logged and
// ignored" outcome for now; the original assertion error is always what
// gets returned, never the revoke error.
//
// On success it flips canaryOK true itself: Run's seam only strictly
// needs this on success, since Login already resets canaryOK false
// atomically with every (re-)login (DEC-0007) — but setting it here too
// makes runCanary correctly testable standalone, not only through Run.
//
// New wires this as the default canaryFn, so Run's lifecycle actually
// exercises the real canary, not Task 7's no-op stub.
func (c *Client) runCanary(ctx context.Context, policyPrefix string) error {
	policy := policyPrefix + "/ironbark-selftest"

	mint, err := c.MintToken(ctx, []string{policy}, nil, "ironbark-canary")
	if err != nil {
		return fmt.Errorf("vaultx: canary: mint: %w", err)
	}

	if assertErr := canaryAssertMintProperties(mint); assertErr != nil {
		_ = c.RevokeSelf(ctx, mint.Token) // best-effort cleanup; see doc comment above
		return assertErr
	}

	if err := c.RevokeSelf(ctx, mint.Token); err != nil {
		return fmt.Errorf("vaultx: canary: revoke-self: %w", err)
	}

	c.setCanaryOK(true)
	return nil
}

// canaryAssertMintProperties checks the three SPEC §3.5 property
// assertions (token_type, renewable, orphan) against a successful mint.
// Split out from runCanary so the mint-vs-assert-vs-revoke sequencing
// above stays linear: on any non-nil result, the caller revokes the
// failed-assertion token before returning it.
func canaryAssertMintProperties(mint Mint) error {
	if mint.TokenType != "service" {
		return fmt.Errorf("vaultx: canary: token_type = %q, want %q", mint.TokenType, "service")
	}
	if mint.Renewable {
		return fmt.Errorf("vaultx: canary: renewable = true, want false")
	}
	if mint.Orphan != nil && !*mint.Orphan {
		return fmt.Errorf("vaultx: canary: orphan = false, want true")
	}
	return nil
}

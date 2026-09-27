package main

// Exit-code mapping (CLIENT-SPEC §7), in one place: every command
// (get/env/run/auth) that returns an error to main funnels it through
// exitCode rather than deciding its own status.

import (
	"errors"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/identity"
)

// exitCode maps any error resolve/get/env/run returns to the CLIENT-SPEC
// §7 exit code. nil maps to 0. auth (Task 10) decides its own exit code
// directly (it has no resolve pipeline to fail) and does not call this.
func exitCode(err error) int {
	if err == nil {
		return 0
	}

	var checkoutErr *gitenv.CheckoutError
	if errors.As(err, &checkoutErr) {
		return 2
	}
	if errors.Is(err, identity.ErrInvalidRemote) {
		return 2
	}
	if errors.Is(err, errConfig) {
		return 2
	}
	if errors.Is(err, errUnknownSecret) {
		return 3
	}
	var selErr *gitenv.SelectError
	if errors.As(err, &selErr) {
		return 4
	}
	if errors.Is(err, errVault) {
		return 5
	}
	if errors.Is(err, errUsage) {
		return 1
	}
	// Every error resolve/get/env/run can produce is one of the above;
	// this is not expected to be reached, but a Vault-shaped failure is
	// the safest fallback for an error this function doesn't recognize.
	return 5
}

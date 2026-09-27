package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/identity"
)

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"usage", errUsage, 1},
		{"checkout error", &gitenv.CheckoutError{Msg: "not a git checkout"}, 2},
		{"invalid remote", fmt.Errorf("wrap: %w", identity.ErrInvalidRemote), 2},
		{"config error", fmt.Errorf("%w: no address", errConfig), 2},
		{"unknown secret", fmt.Errorf("%w: %q", errUnknownSecret, "foo"), 3},
		{"select error", &gitenv.SelectError{Kind: "ambiguous"}, 4},
		{"vault error", fmt.Errorf("%w: sweep: boom", errVault), 5},
		{"unrecognized error", errors.New("something else"), 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCode(tc.err); got != tc.want {
				t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

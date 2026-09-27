// This file implements `ib get <name>` (CLIENT-SPEC §1.2, plan Task 8).
package main

import (
	"context"
	"fmt"
	"io"
)

// leaseNote is the CLIENT-SPEC §1.4 stderr note get/env print when the
// sweep created any lease: get and env leave leases to expire on their
// TTL (only ib run revokes them), and say so.
const leaseNote = "ib: leases created; they expire on TTL"

// cmdGet resolves the checkout's environment, sweeps it, and writes the
// named secret's value to stdout: no trailing newline unless isTerminal
// (CLIENT-SPEC §1.2 — production determines this via os.Stdout.Stat()'s
// ModeCharDevice bit). An unknown name wraps errUnknownSecret, which
// exitCode maps to exit 3.
func cmdGet(ctx context.Context, name string, opts resolveOpts, stdout io.Writer, isTerminal bool) error {
	secrets, leaseIDs, _, err := resolve(ctx, opts)
	if err != nil {
		return err
	}

	s, ok := secrets[name]
	if !ok {
		return fmt.Errorf("%w: %q", errUnknownSecret, name)
	}

	if len(leaseIDs) > 0 {
		fmt.Fprintln(opts.Stderr, leaseNote)
	}

	fmt.Fprint(stdout, s.Value)
	if isTerminal {
		fmt.Fprintln(stdout)
	}
	return nil
}

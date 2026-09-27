// This file implements `ib get <name>` (CLIENT-SPEC §1.2, plan Task 8).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// leaseNote is the CLIENT-SPEC §1.4 stderr note get/env print when the
// sweep created any lease: get and env leave leases to expire on their
// TTL (only ib run revokes them), and say so.
const leaseNote = "ib: leases created; they expire on TTL"

// getJSON is `ib get --output json`'s stdout shape (CLIENT-SPEC §1.2).
type getJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cmdGet resolves the checkout's environment, sweeps it, and writes the
// named secret. output == "json" writes one getJSON object (CLIENT-SPEC
// §1.2); any other value (the default, "raw") writes the value alone, with
// no trailing newline unless isTerminal (production determines this via
// os.Stdout.Stat()'s ModeCharDevice bit). An unknown name wraps
// errUnknownSecret, which exitCode maps to exit 3.
func cmdGet(ctx context.Context, name string, opts resolveOpts, stdout io.Writer, isTerminal bool, output string) error {
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

	if output == outputJSON {
		return json.NewEncoder(stdout).Encode(getJSON{Name: name, Value: s.Value})
	}

	fmt.Fprint(stdout, s.Value)
	if isTerminal {
		fmt.Fprintln(stdout)
	}
	return nil
}

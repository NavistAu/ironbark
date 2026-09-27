// This file implements `ib env` (CLIENT-SPEC §1.3, plan Task 8).
package main

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/navistau/ironbark/internal/envfile"
)

// cmdEnv resolves and sweeps as cmdGet, then writes every secret to stdout
// as one envfile.Format line per secret, sorted by name (CLIENT-SPEC
// §1.3).
func cmdEnv(ctx context.Context, opts resolveOpts, stdout io.Writer) error {
	secrets, leaseIDs, err := resolve(ctx, opts)
	if err != nil {
		return err
	}

	if len(leaseIDs) > 0 {
		fmt.Fprintln(opts.Stderr, leaseNote)
	}

	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		fmt.Fprint(stdout, envfile.Format(n, secrets[n].Value))
	}
	return nil
}

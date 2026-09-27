// This file implements `ib env` (CLIENT-SPEC §1.3, plan Task 8).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/navistau/ironbark/internal/envfile"
)

// envJSON is `ib env --output json`'s stdout shape (CLIENT-SPEC §1.3):
// Secrets is keyed by the sweep's own lowercase names (not the
// SECRET_<NAME> form the default envfile.Format lines use).
// encoding/json sorts string-keyed map keys when marshaling, satisfying
// the "sorted keys" requirement without any extra work here.
type envJSON struct {
	Branch  string            `json:"branch"`
	Rule    string            `json:"rule"`
	Secrets map[string]string `json:"secrets"`
}

// cmdEnv resolves and sweeps as cmdGet, then writes every secret to
// stdout. output == "json" writes one envJSON object (CLIENT-SPEC §1.3);
// any other value (the default, "env") writes one envfile.Format line per
// secret, sorted by name.
func cmdEnv(ctx context.Context, opts resolveOpts, stdout io.Writer, output string) error {
	secrets, leaseIDs, sel, err := resolve(ctx, opts)
	if err != nil {
		return err
	}

	if len(leaseIDs) > 0 {
		fmt.Fprintln(opts.Stderr, leaseNote)
	}

	if output == outputJSON {
		out := envJSON{Branch: sel.Branch, Rule: sel.Rule, Secrets: make(map[string]string, len(secrets))}
		for n, s := range secrets {
			out.Secrets[n] = s.Value
		}
		return json.NewEncoder(stdout).Encode(out)
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

// Command ib is ironbark's local client (docs/CLIENT-SPEC.md). This file
// implements the resolve pipeline (design §12.2): checkout, environment
// selection, and the §8.2 walk with the caller's own token — the pipeline
// get/env/run all share. The walk itself lives in internal/walk, the same
// code the broker uses.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/vaultx"
	"github.com/navistau/ironbark/internal/walk"
)

// Sentinel errors resolve (and get/env/run) wrap failures with; exitCode
// (exitcode.go) pattern-matches on these — and on gitenv's own
// *CheckoutError/*SelectError types, and identity.ErrInvalidRemote, which
// are already distinguishable on their own — to map every command's
// failure to its CLIENT-SPEC §7 exit code, in one place. These carry no
// "ib: " prefix of their own: every call site that prints one of these
// errors to stderr already adds that prefix (`fmt.Fprintln(stderr, "ib:",
// err)`), so baking it in here as well doubled it ("ib: ib: ...").
var (
	// errConfig covers CLIENT-SPEC §7 exit 2 causes that don't already
	// have their own typed error: a bad ibcfg.Load or vaultx.New.
	errConfig = errors.New("configuration error")
	// errUnknownSecret is wrapped with the requested name by get/run.
	errUnknownSecret = errors.New("unknown secret name")
	// errVault covers exit 5: any Vault error other than 403/404
	// encountered while discovering branch tiers or sweeping.
	errVault = errors.New("vault error")
	// errUsage covers exit 1: a CLI invocation error (bad flags/args).
	errUsage = errors.New("usage error")
)

// resolveOpts is everything resolve needs beyond what it derives from the
// checkout itself.
type resolveOpts struct {
	Runner gitenv.Runner
	// Client reads OpenBao as the caller's own token (CLIENT-SPEC §5.1), the
	// walk's resolve mappings included, so a dynamic lease is the caller's.
	Client walk.Client
	Leases *leaseAPI
	Tmpl   grantcfg.Template
	// Env and Target are --env/IB_ENV and --target/IB_TARGET, already merged
	// (flag wins); "" means unset.
	Env, Target string
	Stderr      io.Writer
}

// resolve runs checkout -> environment selection -> the §8.2 walk and returns
// the secrets by name, the lease ids the walk took, and the selection (`ib env
// --output json` reports it). ib never returns ironbark_status or vault_token:
// the caller's own token is never handed to the wrapped command. Every line
// the operator needs (the selection, skipped entries, warnings) goes to
// opts.Stderr. On a walk failure the leases already taken are revoked before
// the error returns.
func resolve(ctx context.Context, opts resolveOpts) (map[string]walk.Secret, []string, gitenv.Selection, error) {
	info, err := gitenv.Checkout(opts.Runner)
	if err != nil {
		return nil, nil, gitenv.Selection{}, err // *gitenv.CheckoutError -> exit 2
	}
	org, repo, err := identity.ParseRemote(info.OriginURL)
	if err != nil {
		return nil, nil, gitenv.Selection{}, err // wraps identity.ErrInvalidRemote -> exit 2
	}
	org, repo = identity.Esc(org), identity.Esc(repo)

	sel, err := gitenv.Select(ctx, opts.Client, opts.Tmpl, gitenv.SelectInput{
		Org: org, Repo: repo, Branch: info.Branch, Env: opts.Env, Target: opts.Target,
	})
	if err != nil {
		var se *gitenv.SelectError
		if errors.As(err, &se) {
			return nil, nil, gitenv.Selection{}, err // -> exit 4
		}
		return nil, nil, gitenv.Selection{}, opts.vaultError(ctx, "select environment", err)
	}
	printSelection(opts.Stderr, sel)

	var leaseIDs []string
	res, err := walk.Walk(ctx, opts.Client, levels.Levels(opts.Tmpl, org, repo, sel.Env, sel.Target.Escaped), walk.Options{
		Resolve: func(ctx context.Context, path string) (*vaultx.Secret, error) {
			s, err := opts.Client.Read(ctx, path)
			if s != nil && s.LeaseID != "" {
				leaseIDs = append(leaseIDs, s.LeaseID)
			}
			return s, err
		},
	})
	if err != nil {
		if len(leaseIDs) > 0 {
			reportRevokeErrors(opts.Stderr, opts.Leases.Revoke(ctx, leaseIDs))
		}
		return nil, nil, sel, opts.vaultError(ctx, "walk", err)
	}

	// A 403 on every level reads as "nothing visible", which a stale token
	// also produces: ask OpenBao about the token itself.
	read := false
	for _, o := range res.Levels {
		read = read || o == walk.LevelRead
	}
	if !read {
		if err := opts.Leases.CheckToken(ctx); err != nil {
			return nil, nil, sel, opts.vaultError(ctx, "check token", err)
		}
	}

	for _, w := range res.Warnings {
		fmt.Fprintf(opts.Stderr, "ib: warning: %s\n", w)
	}
	for _, e := range res.IgnoredEvents {
		fmt.Fprintf(opts.Stderr, "ib: %s: ironbark_events is ignored; event pins are role bound_claims\n", e)
	}
	if len(res.SkippedEntries) > 0 {
		fmt.Fprintf(opts.Stderr, "ib: skipped %d entries: no read on them or their targets (%s)\n", len(res.SkippedEntries), strings.Join(res.SkippedEntries, ", "))
	}

	secrets := make(map[string]walk.Secret, len(res.Secrets))
	for _, s := range res.Secrets {
		if s.Name == "vault_token" {
			continue
		}
		secrets[s.Name] = s
	}
	return secrets, leaseIDs, sel, nil
}

// vaultError classifies an OpenBao failure: a rejected token is a
// configuration problem (exit 2), anything else exit 5.
func (o resolveOpts) vaultError(ctx context.Context, what string, err error) error {
	if errors.Is(err, errTokenRejected) || (errors.Is(err, vaultx.ErrForbidden) && o.Leases.CheckToken(ctx) == errTokenRejected) {
		return fmt.Errorf("%w: OpenBao rejected the token (expired or invalid); run `ib auth`", errConfig)
	}
	return fmt.Errorf("%w: %s: %v", errVault, what, err)
}

// reportRevokeErrors writes one line per failed lease revoke, except that
// 403s (the caller's token may not revoke leases at all — the leases just
// expire on their TTL) collapse into a single line rather than one per
// lease on every run.
func reportRevokeErrors(w io.Writer, errs []error) {
	denied := 0
	for _, err := range errs {
		var respErr *api.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
			denied++
			continue
		}
		fmt.Fprintf(w, "ib: revoke lease failed: %v\n", err)
	}
	if denied > 0 {
		fmt.Fprintf(w, "ib: %d lease(s) not revocable with this token (403); they expire on TTL\n", denied)
	}
}

// printSelection writes the visibility line: the chosen environment and why.
func printSelection(w io.Writer, sel gitenv.Selection) {
	if sel.Env == "" {
		fmt.Fprintln(w, "ib: no environment; repo level only")
		return
	}
	line := fmt.Sprintf("ib: env %s (%s)", sel.Env, sel.Rule)
	if len(sel.Target.Segments) > 0 {
		line += ", target " + strings.Join(sel.Target.Segments, "/")
	}
	fmt.Fprintln(w, line)
}

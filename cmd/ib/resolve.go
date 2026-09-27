// Command ib is ironbark's local client (docs/CLIENT-SPEC.md). This file
// implements the resolve pipeline (CLIENT-SPEC §2–4, plan Task 8): checkout
// discovery, identity, branch-tier discovery, environment (branch)
// selection, and the sweep — the common pipeline get/env/run all share. No
// sweep, naming, deref or pin logic is reimplemented here: it all lives in
// internal/vaultx, the same code the broker uses.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/vaultx"
)

// Sentinel errors resolve (and get/env/run) wrap failures with; exitCode
// (exitcode.go) pattern-matches on these — and on gitenv's own
// *CheckoutError/*SelectError types, and identity.ErrInvalidRemote, which
// are already distinguishable on their own — to map every command's
// failure to its CLIENT-SPEC §7 exit code, in one place.
var (
	// errConfig covers CLIENT-SPEC §7 exit 2 causes that don't already
	// have their own typed error: a bad ibcfg.Load or vaultx.New.
	errConfig = errors.New("ib: configuration error")
	// errUnknownSecret is wrapped with the requested name by get/run.
	errUnknownSecret = errors.New("ib: unknown secret name")
	// errVault covers exit 5: any Vault error other than 403/404
	// encountered while discovering branch tiers or sweeping.
	errVault = errors.New("ib: vault error")
	// errUsage covers exit 1: a CLI invocation error (bad flags/args).
	errUsage = errors.New("ib: usage error")
)

// resolveOpts is everything resolve needs beyond the identity it derives
// from the checkout itself.
type resolveOpts struct {
	Runner gitenv.Runner
	Vault  *vaultx.Client
	// Token is the caller's own Vault/OpenBao token (CLIENT-SPEC §5.1):
	// every Vault call resolve makes authenticates as this, never as any
	// session vaultx.Client itself might otherwise hold.
	Token string
	// Branch is --branch/IB_BRANCH, already resolved to a single value by
	// the caller (flag wins over env, CLIENT-SPEC §1); "" means no
	// override.
	Branch string
	Stderr io.Writer
}

// resolve runs the CLIENT-SPEC §2–4 pipeline: checkout -> identity ->
// branch-tier discovery -> environment selection -> sweep. It writes every
// CLIENT-SPEC §3 visibility/staleness line to opts.Stderr as it goes. On a
// sweep failure it revokes any leases the partial sweep created
// (CLIENT-SPEC §4) before returning the error. Images (CLIENT-SPEC §4,
// ironbark_images) are never applied — ib has no step image locally.
func resolve(ctx context.Context, opts resolveOpts) (map[string]vaultx.SweptSecret, []string, error) {
	info, err := gitenv.Checkout(opts.Runner)
	if err != nil {
		return nil, nil, err // *gitenv.CheckoutError -> exit 2
	}

	org, repo, err := identity.ParseRemote(info.OriginURL)
	if err != nil {
		return nil, nil, err // wraps identity.ErrInvalidRemote -> exit 2
	}
	id := identity.Identity{Org: org, Repo: repo, Event: "push"}

	tiers, err := opts.Vault.ListBranchTiers(ctx, opts.Token, id)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: list branch tiers: %v", errVault, err)
	}

	tracked, dist, reflogFrom, stale, lsErr := gitenv.Facts(opts.Runner, info.Branch, tiers)
	for _, b := range stale {
		fmt.Fprintf(opts.Stderr, "ib: origin/%s differs from the forge; git fetch\n", b)
	}
	if lsErr != nil {
		fmt.Fprintln(opts.Stderr, "ib: freshness unknown (git ls-remote failed)")
	}

	sel, err := gitenv.Select(gitenv.SelectInput{
		Override:   opts.Branch,
		Current:    info.Branch,
		Detached:   info.Detached,
		Tracked:    tracked,
		Distance:   dist,
		ReflogFrom: reflogFrom,
	})
	if err != nil {
		return nil, nil, err // *gitenv.SelectError -> exit 4
	}
	printSelection(opts.Stderr, sel)

	id.Branch = sel.Branch
	branchful := id.Branch != ""

	sweep, err := opts.Vault.Sweep(ctx, opts.Token, id, branchful)
	if err != nil {
		if len(sweep.LeaseIDs) > 0 {
			for _, revokeErr := range opts.Vault.RevokeLeases(ctx, opts.Token, sweep.LeaseIDs) {
				fmt.Fprintf(opts.Stderr, "ib: revoke lease failed: %v\n", revokeErr)
			}
		}
		return nil, nil, fmt.Errorf("%w: sweep: %v", errVault, err)
	}

	secrets := make(map[string]vaultx.SweptSecret, len(sweep.Secrets))
	for _, s := range sweep.Secrets {
		// CLIENT-SPEC §4: ironbark_events is applied with event "push"; a
		// secret pinned away from push is not returned. An unpinned
		// secret (Events empty) is always kept — SPEC §4.6's default pin
		// is the request's own event, which is always "push" here.
		if len(s.Events) > 0 && !containsString(s.Events, "push") {
			continue
		}
		secrets[s.Name] = s
	}

	return secrets, sweep.LeaseIDs, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ruleDisplay maps a gitenv Selection.Rule code to CLIENT-SPEC §3's
// human-readable phrase for the visibility line (e.g. "ib: env develop
// (nearest ancestor, 3 commits)").
func ruleDisplay(rule string) string {
	switch rule {
	case "override":
		return "override"
	case "direct":
		return "direct match"
	case "nearest":
		return "nearest ancestor"
	case "reflog":
		return "reflog"
	case "cascade":
		return "cascade"
	default:
		return rule
	}
}

// printSelection writes the CLIENT-SPEC §3 "Visibility" line: the chosen
// branch and the rule that chose it, always — including the dedicated
// "no branch tiers at all" line.
func printSelection(w io.Writer, sel gitenv.Selection) {
	if sel.Rule == "no-branch-tiers" {
		fmt.Fprintln(w, "ib: no branch tiers; event and base tiers only")
		return
	}
	if sel.Detail == "" {
		fmt.Fprintf(w, "ib: env %s (%s)\n", sel.Branch, ruleDisplay(sel.Rule))
		return
	}
	fmt.Fprintf(w, "ib: env %s (%s, %s)\n", sel.Branch, ruleDisplay(sel.Rule), sel.Detail)
}

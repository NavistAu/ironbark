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
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/vaultx"
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
// CLIENT-SPEC §3 visibility/staleness line to opts.Stderr as it goes, plus
// (CLIENT-SPEC §4) one line naming any pointer entries the sweep skipped
// because their $ref target 403/404'd. On a sweep failure it revokes any
// leases the partial sweep created (CLIENT-SPEC §4) before returning the
// error. Images (CLIENT-SPEC §4, ironbark_images) are never applied — ib
// has no step image locally. The returned gitenv.Selection is the §3
// branch choice (Branch/Rule) — cmdEnv's `--output json` (CLIENT-SPEC
// §1.3) reports it alongside the secrets; callers that don't need it
// (get, run) discard it.
func resolve(ctx context.Context, opts resolveOpts) (map[string]vaultx.SweptSecret, []string, gitenv.Selection, error) {
	info, err := gitenv.Checkout(opts.Runner)
	if err != nil {
		return nil, nil, gitenv.Selection{}, err // *gitenv.CheckoutError -> exit 2
	}

	org, repo, err := identity.ParseRemote(info.OriginURL)
	if err != nil {
		return nil, nil, gitenv.Selection{}, err // wraps identity.ErrInvalidRemote -> exit 2
	}
	id := identity.Identity{Org: org, Repo: repo, Event: "push"}

	tiers, err := opts.Vault.ListBranchTiers(ctx, opts.Token, id)
	if err != nil {
		return nil, nil, gitenv.Selection{}, fmt.Errorf("%w: list branch tiers: %v", errVault, err)
	}

	// A 403 on the tier LIST reads as "nothing visible" — which a stale
	// token also produces. With nothing listed, ask Vault about the token
	// itself so an expired one is an error, not an empty success.
	if len(tiers) == 0 {
		if err := opts.Vault.CheckToken(ctx, opts.Token); err != nil {
			if errors.Is(err, vaultx.ErrTokenRejected) {
				return nil, nil, gitenv.Selection{}, fmt.Errorf("%w: Vault rejected the token (expired or invalid); run `ib auth`", errConfig)
			}
			return nil, nil, gitenv.Selection{}, fmt.Errorf("%w: check token: %v", errVault, err)
		}
	}

	tracked := gitenv.TrackedBranches(opts.Runner, info.Branch, tiers)

	// M1 / CLIENT-SPEC §3: the staleness check (ls-remote) runs "before
	// rule 3" — only when rules 1-2 (override, direct match) don't already
	// decide the branch, sparing the network round trip when they do.
	var dist map[string]int
	var reflogFrom string
	if gitenv.NeedsAncestry(opts.Branch, info.Branch, tracked) {
		var stale []string
		var lsErr error
		dist, reflogFrom, stale, lsErr = gitenv.Ancestry(opts.Runner, info.Branch, tracked)
		for _, b := range stale {
			fmt.Fprintf(opts.Stderr, "ib: origin/%s differs from the forge; git fetch\n", b)
		}
		if lsErr != nil {
			fmt.Fprintln(opts.Stderr, "ib: freshness unknown (git ls-remote failed)")
		}
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
		return nil, nil, gitenv.Selection{}, err // *gitenv.SelectError -> exit 4
	}
	printSelection(opts.Stderr, sel)

	id.Branch = sel.Branch
	branchful := id.Branch != ""

	sweep, err := opts.Vault.Sweep(ctx, opts.Token, id, branchful)
	if err != nil {
		if len(sweep.LeaseIDs) > 0 {
			reportRevokeErrors(opts.Stderr, opts.Vault.RevokeLeases(ctx, opts.Token, sweep.LeaseIDs))
		}
		return nil, nil, sel, fmt.Errorf("%w: sweep: %v", errVault, err)
	}

	if len(sweep.SkippedDerefs) > 0 {
		fmt.Fprintf(opts.Stderr, "ib: skipped %d entries: no read on their targets (%s)\n", len(sweep.SkippedDerefs), strings.Join(sweep.SkippedDerefs, ", "))
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

	return secrets, sweep.LeaseIDs, sel, nil
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

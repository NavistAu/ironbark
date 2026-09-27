// Package gitenv implements CLIENT-SPEC §3 environment (branch) selection
// for the ib client: a pure decision function (Select) plus a git adapter
// (Checkout, Facts) that gathers its input from a checkout.
package gitenv

import (
	"fmt"
	"sort"
	"strings"
)

// Cascade is the built-in tie-break order for CLIENT-SPEC §3 rule 5: least
// to most production-like, so an unresolved guess lands on a lower
// environment. Exact names only; not configurable in M3.
var Cascade = []string{
	"dev", "develop", "development", "test", "testing", "qa", "uat",
	"stage", "staging", "preprod", "trunk", "main", "master", "prod",
	"production", "live",
}

// SelectInput is everything Select needs to choose an environment branch,
// already gathered from a checkout and its remote (by the git adapter's
// Checkout/Facts, or a test fixture). Select makes no git calls itself.
type SelectInput struct {
	// Override is --branch/IB_BRANCH, or "" if neither was given.
	Override string
	// Current is the checked-out branch's short name, or "" when Detached.
	Current string
	// Detached is true for a detached HEAD: there is no checked-out
	// branch, so rule 4 (tie via reflog) is skipped.
	Detached bool
	// Tracked lists git branch short names whose escaped form
	// (identity.Esc) names a branch directory the caller's token can see
	// under <B>/push/.
	Tracked []string
	// Distance holds, for each Tracked branch with a remote-tracking ref
	// origin/T that shares history with HEAD, the ancestor distance
	// d(T) = commits in HEAD not in origin/T. A Tracked branch with no
	// origin/T, or no common history with HEAD, is absent here.
	Distance map[string]int
	// ReflogFrom is the short branch name HEAD's branch was created from
	// (per its reflog creation entry), or "" if none/unknown/detached.
	ReflogFrom string
}

// Selection is the environment Select chose, and why.
type Selection struct {
	// Branch is the chosen branch's short name, or "" when
	// Rule == "no-branch-tiers".
	Branch string
	// Rule is which CLIENT-SPEC §3 rule decided it: "override", "direct",
	// "nearest", "reflog", "cascade", or "no-branch-tiers".
	Rule string
	// Detail is a human-readable elaboration for display (e.g. an
	// ancestor distance); empty when the rule needs none.
	Detail string
}

// SelectError is returned when Select cannot settle on a single branch.
type SelectError struct {
	// Kind is one of:
	//   "not-tracked"            — an override named a branch that isn't tracked.
	//   "ambiguous"               — a tie survived both the reflog and cascade tie-breaks.
	//   "no-ancestor"             — no tracked branch shares history with HEAD.
	//   "override-without-tiers" — an override was given but there are no branch tiers at all.
	Kind string
	// Candidates holds the tied branches and their distances; populated
	// only for Kind == "ambiguous".
	Candidates map[string]int
}

func (e *SelectError) Error() string {
	switch e.Kind {
	case "ambiguous":
		names := make([]string, 0, len(e.Candidates))
		for n := range e.Candidates {
			names = append(names, n)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, fmt.Sprintf("%s (%d)", n, e.Candidates[n]))
		}
		return fmt.Sprintf("ambiguous branch selection: %s; pass --branch", strings.Join(parts, ", "))
	case "no-ancestor":
		return "no tracked branch shares history with HEAD; pass --branch"
	case "not-tracked":
		return "branch is not tracked (no visible branch tier); pass a tracked --branch"
	case "override-without-tiers":
		return "repository has no branch tiers; --branch is not applicable"
	default:
		return "branch selection failed: " + e.Kind
	}
}

// NeedsAncestry reports whether Select would need rule 3+ facts (ancestor
// distance, reflog, cascade) to decide: false when rule 1 (override) or
// rule 2 (direct match) already settles it, or when there are no branch
// tiers at all (Select's own "no branch tiers" short-circuit, which also
// needs no ancestry). CLIENT-SPEC §3's staleness check ("before rule 3")
// only runs when this is true — an override or direct match makes the
// network round trip moot (M1).
func NeedsAncestry(override, current string, tracked []string) bool {
	if len(tracked) == 0 {
		return false
	}
	if override != "" {
		return false
	}
	if current != "" && contains(tracked, current) {
		return false
	}
	return true
}

// Select chooses an environment branch per CLIENT-SPEC §3, given facts
// already gathered from the checkout and its remote. Select makes no git
// calls itself and is deterministic in its input.
func Select(in SelectInput) (Selection, error) {
	// "No branch tiers at all" (CLIENT-SPEC §3): skips every other rule.
	if len(in.Tracked) == 0 {
		if in.Override != "" {
			return Selection{}, &SelectError{Kind: "override-without-tiers"}
		}
		return Selection{Rule: "no-branch-tiers"}, nil
	}

	// Rule 1: override.
	if in.Override != "" {
		if !contains(in.Tracked, in.Override) {
			return Selection{}, &SelectError{Kind: "not-tracked"}
		}
		return Selection{Branch: in.Override, Rule: "override"}, nil
	}

	// Rule 2: direct match.
	if in.Current != "" && contains(in.Tracked, in.Current) {
		return Selection{Branch: in.Current, Rule: "direct"}, nil
	}

	// Rule 3: nearest ancestor. Find the tracked branches with the lowest
	// distance; branches absent from Distance (no origin/T, or no common
	// history with HEAD) are dropped.
	var candidates []string
	minDist := 0
	for _, t := range in.Tracked {
		d, ok := in.Distance[t]
		if !ok {
			continue
		}
		switch {
		case len(candidates) == 0 || d < minDist:
			minDist = d
			candidates = []string{t}
		case d == minDist:
			candidates = append(candidates, t)
		}
	}

	if len(candidates) == 0 {
		return Selection{}, &SelectError{Kind: "no-ancestor"}
	}
	if len(candidates) == 1 {
		return Selection{Branch: candidates[0], Rule: "nearest", Detail: distDetail(minDist)}, nil
	}

	// Rule 4: tie -> reflog (skipped in a detached HEAD, which has no
	// checked-out branch and therefore no branch reflog entry).
	if !in.Detached && in.ReflogFrom != "" {
		for _, c := range candidates {
			if c == in.ReflogFrom {
				return Selection{Branch: c, Rule: "reflog", Detail: distDetail(minDist)}, nil
			}
		}
	}

	// Rule 5: tie -> cascade. Cascade is least-to-most production-like, so
	// the lowest cascade index wins.
	bestIdx := -1
	winner := ""
	for _, c := range candidates {
		idx := cascadeIndex(c)
		if idx >= 0 && (bestIdx == -1 || idx < bestIdx) {
			bestIdx = idx
			winner = c
		}
	}
	if bestIdx >= 0 {
		return Selection{Branch: winner, Rule: "cascade", Detail: distDetail(minDist)}, nil
	}

	// Rule 6: fail.
	cands := make(map[string]int, len(candidates))
	for _, c := range candidates {
		cands[c] = in.Distance[c]
	}
	return Selection{}, &SelectError{Kind: "ambiguous", Candidates: cands}
}

func distDetail(d int) string {
	if d == 1 {
		return "1 commit"
	}
	return fmt.Sprintf("%d commits", d)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func cascadeIndex(name string) int {
	for i, c := range Cascade {
		if c == name {
			return i
		}
	}
	return -1
}

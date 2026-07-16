// Package policy derives Vault policy names from a request identity,
// per SPEC §2.3.
package policy

import "ironbark/internal/identity"

// branchfulEvents is the single source of the branchful event set,
// consumed by Derive and by the broker's Sweep call (SPEC §2.3, §4.1).
var branchfulEvents = map[string]bool{
	"push":                true,
	"pull_request":        true,
	"pull_request_closed": true,
	"release":             true,
	"cron":                true,
}

// Branchful reports whether event is a branchful event: push,
// pull_request, pull_request_closed, release, or cron. manual and
// deployment are never branchful — their branch fields are
// caller-supplied or inherited, not forge-verified. tag has no branch.
// Unknown events are not branchful.
func Branchful(event string) bool {
	return branchfulEvents[event]
}

// Derive returns the Vault policy names for id under prefix, per SPEC
// §2.3: always P1 = <prefix>/<org>/<repo>/<event>; additionally
// P2 = P1 + "/" + identity.Esc(branch) iff Branchful(id.Event) and
// id.Branch is non-empty.
func Derive(id identity.Identity, prefix string) []string {
	p1 := prefix + "/" + id.Org + "/" + id.Repo + "/" + id.Event

	if !Branchful(id.Event) || id.Branch == "" {
		return []string{p1}
	}

	p2 := p1 + "/" + identity.Esc(id.Branch)
	return []string{p1, p2}
}

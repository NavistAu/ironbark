// Package forge resolves an actor's teams on the forge (design §2). Team
// membership is forge-owned; what a team grants stays in Vault.
package forge

import "context"

// TeamResolver returns the teams of repo org/repo that login belongs to.
// Any error means the lookup failed as a whole; the caller fails closed
// (no team policies) and never fails the pipeline.
type TeamResolver interface {
	Teams(ctx context.Context, org, repo, login string) ([]string, error)
}

// Lookups are the two forge lookups the grant model needs (design §4.2,
// §4.4). Each is bounded by IRONBARK_FORGE_TIMEOUT; any error means the
// lookup failed and the caller fails closed.
type Lookups interface {
	// BranchProtected reports the forge's `protected` flag for the branch.
	BranchProtected(ctx context.Context, org, repo, branch string) (bool, error)
	// QualifiedTeams returns login's teams of org/repo as esc(org)/esc(team).
	QualifiedTeams(ctx context.Context, org, repo, login string) ([]string, error)
}

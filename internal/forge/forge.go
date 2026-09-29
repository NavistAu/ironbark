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

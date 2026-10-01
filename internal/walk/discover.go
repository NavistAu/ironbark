// Package walk implements the read side of the grant model: environment
// discovery from level entries (design §4.5) and the §8.2 walk. It reads
// through a small Client so ironbark and ib share it.
package walk

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/selector"
	"github.com/navistau/ironbark/internal/vaultx"
)

// Client is what the walk needs from OpenBao, already bound to one token.
// Errors wrapping vaultx.ErrForbidden or vaultx.ErrNotFound are the 403 and
// 404 the walk skips; anything else is a failure.
type Client interface {
	Token() string
	List(ctx context.Context, path string) ([]string, error)
	Read(ctx context.Context, path string) (*vaultx.Secret, error)
	LevelMetadata(ctx context.Context, path string) (md map[string]string, found bool, err error)
}

// BranchesKey is the custom_metadata key that makes an entry an environment
// level. The walk never delivers such an entry as a secret.
const BranchesKey = "branches"

// Discovery is the outcome of matching a branch against the level entries
// under a repo level.
type Discovery struct {
	Claimants []string // environment levels whose `branches` claim the branch, sorted
	Malformed []string // levels with a malformed branch pattern
}

// Discover lists the repo level and, for each entry without a trailing slash
// whose name is in the environment grammar, reads its custom_metadata. An
// entry carrying `branches` is an environment level; the branch is matched
// against it (§4.5, §8.1). org and repo are the escaped path values. Any
// failure other than a 404 is an error: a claimant the token cannot see must
// not let another level win (§9.3). The token needs only the metadata grant
// of the `ci` role.
func Discover(ctx context.Context, c Client, tmpl grantcfg.Template, org, repo, branch string) (Discovery, error) {
	repoLevel := levels.Levels(tmpl, org, repo, "", nil)[0]
	keys, err := c.List(ctx, repoLevel.Metadata)
	if err != nil {
		if errors.Is(err, vaultx.ErrNotFound) {
			return Discovery{}, nil
		}
		return Discovery{}, fmt.Errorf("walk: discover: list %s: %w", repoLevel.Metadata, err)
	}
	branches := map[string]string{}
	for _, k := range keys {
		if strings.HasSuffix(k, "/") || !selector.ValidEnv(k) {
			continue // a folder, or a name that cannot be an environment
		}
		md, _, err := c.LevelMetadata(ctx, repoLevel.Metadata+k)
		if err != nil {
			return Discovery{}, fmt.Errorf("walk: discover: level %q: %w", k, err)
		}
		if b, ok := md[BranchesKey]; ok {
			branches[k] = b
		}
	}
	var d Discovery
	d.Claimants, _, d.Malformed = selector.Claimants(branch, branches)
	return d, nil
}

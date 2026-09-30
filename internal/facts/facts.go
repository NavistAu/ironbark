// Package facts turns a verified Woodpecker payload plus two forge lookups
// into the facts the grant model gates on (design §4.1-§4.4). Selectors
// (environment, target) live in internal/selector; nothing here entitles.
package facts

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/navistau/ironbark/internal/forge"
	"github.com/navistau/ironbark/internal/identity"
)

// Config is what fact building needs from ironbark's configuration.
type Config struct {
	ActorForge string // "none" | "gitea" | "github" | "bitbucket"; "" == "none"
}

// Facts are the verified facts of one pipeline. Absent facts are empty
// strings; JWT issuance omits them rather than sending them empty. Teams are
// not here: they need the environment (see ResolveTeams).
type Facts struct {
	Org, Repo string // lowercased, unescaped
	RepoKey   string // esc(org)/esc(repo)#esc(forge_remote_id)
	Event     string // lowercased
	Branch    string // absent for pull_request*, tag, release, unknown events
	Ref       string // present only with Branch
	// BranchProtected is "true" only when the forge says protected AND
	// ref == refs/heads/<branch>; "false" otherwise (incl. lookup failure or
	// no forge); "" when Branch is absent.
	BranchProtected string
	Actor           string
	Pipeline        string            // pipeline number; audit only
	Variables       map[string]string // manual, cron and deployment only
}

type payload struct {
	Repo *struct {
		FullName      string `json:"full_name"`
		ForgeRemoteID string `json:"forge_remote_id"`
	} `json:"repo"`
	Pipeline *struct {
		Event     string            `json:"event"`
		Branch    string            `json:"branch"`
		Ref       string            `json:"ref"`
		Number    int64             `json:"number"`
		Sender    string            `json:"sender"`
		Author    string            `json:"author"`
		Variables map[string]string `json:"variables"`
	} `json:"pipeline"`
}

// Build implements design §4.1-§4.3. lk nil means no forge configured
// (IRONBARK_FORGE_PROVIDER=none): branch_protected is then "false". A payload
// that cannot yield org/repo/repo_key/event wraps identity.ErrMalformed.
func Build(ctx context.Context, body []byte, lk forge.Lookups, cfg Config) (Facts, error) {
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Facts{}, fmt.Errorf("%w: invalid JSON: %v", identity.ErrMalformed, err)
	}
	if p.Repo == nil {
		return Facts{}, fmt.Errorf("%w: missing repo", identity.ErrMalformed)
	}
	if p.Pipeline == nil {
		return Facts{}, fmt.Errorf("%w: missing pipeline", identity.ErrMalformed)
	}
	parts := strings.Split(p.Repo.FullName, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Facts{}, fmt.Errorf("%w: invalid repo.full_name %q", identity.ErrMalformed, p.Repo.FullName)
	}
	if p.Repo.ForgeRemoteID == "" {
		return Facts{}, fmt.Errorf("%w: missing repo.forge_remote_id", identity.ErrMalformed)
	}
	if p.Pipeline.Event == "" {
		return Facts{}, fmt.Errorf("%w: missing pipeline.event", identity.ErrMalformed)
	}

	f := Facts{
		Org:      strings.ToLower(parts[0]),
		Repo:     strings.ToLower(parts[1]),
		Event:    strings.ToLower(p.Pipeline.Event),
		Pipeline: strconv.FormatInt(p.Pipeline.Number, 10),
	}
	f.RepoKey = identity.Esc(f.Org) + "/" + identity.Esc(f.Repo) + "#" + identity.Esc(p.Repo.ForgeRemoteID)

	pl := p.Pipeline
	actorForge := cfg.ActorForge != "" && cfg.ActorForge != "none"
	switch f.Event {
	case "push":
		f.Branch, f.Ref = pl.Branch, pl.Ref
		if actorForge {
			f.Actor = pl.Sender
		}
	case "manual":
		f.Branch, f.Ref = pl.Branch, pl.Ref
		f.Actor = pl.Author
		f.Variables = pl.Variables
	case "deployment", "cron":
		f.Branch, f.Ref = pl.Branch, pl.Ref
		f.Variables = pl.Variables
	case "pull_request", "tag", "release":
		if actorForge {
			f.Actor = pl.Sender
		}
	}
	if len(f.Variables) == 0 {
		f.Variables = nil
	}
	if f.Branch == "" {
		f.Branch, f.Ref = "", ""
		return f, nil
	}

	f.BranchProtected = "false"
	if lk != nil && f.Ref == "refs/heads/"+f.Branch {
		if ok, err := lk.BranchProtected(ctx, f.Org, f.Repo, f.Branch); err == nil && ok {
			f.BranchProtected = "true"
		}
	}
	return f, nil
}

// ResolveTeams looks up the actor's teams (design §4.4): only when an actor
// exists and an environment is selected, and never without a forge. On error
// it returns nil teams and the error; the caller emits no teams claim.
func ResolveTeams(ctx context.Context, lk forge.Lookups, f Facts, env string) ([]string, error) {
	if lk == nil || f.Actor == "" || env == "" {
		return nil, nil
	}
	teams, err := lk.QualifiedTeams(ctx, f.Org, f.Repo, f.Actor)
	if err != nil {
		return nil, err
	}
	return teams, nil
}

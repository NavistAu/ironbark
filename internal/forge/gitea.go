package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxBody bounds every forge response body read.
const maxBody = 1 << 20

// Gitea resolves teams on a Gitea-family forge (Gitea, Forgejo): the repo's
// teams, then login's membership of each. No caching.
type Gitea struct {
	base    string
	token   string
	timeout time.Duration
	hc      *http.Client
}

var _ TeamResolver = (*Gitea)(nil)

// NewGitea returns a resolver for the forge at baseURL. timeout bounds a
// whole Teams lookup, not each call. hc nil uses a default client.
func NewGitea(baseURL, token string, timeout time.Duration, hc *http.Client) *Gitea {
	if hc == nil {
		hc = &http.Client{}
	}
	return &Gitea{base: strings.TrimRight(baseURL, "/"), token: token, timeout: timeout, hc: hc}
}

// Teams implements TeamResolver. A 405 on repo-teams (a user-owned repo has
// no org teams) yields no teams; any other repo-teams non-200 and any membership status other than 200/404 fail
// the whole lookup; it never returns a partial list. The repo-teams
// endpoint is unpaginated in Gitea and Forgejo.
func (g *Gitea) Teams(ctx context.Context, org, repo, login string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	status, body, err := g.get(ctx, "/api/v1/repos/"+url.PathEscape(org)+"/"+url.PathEscape(repo)+"/teams")
	if err != nil {
		return nil, fmt.Errorf("forge: GET repos/{org}/{repo}/teams: %w", err)
	}
	// 405: Gitea/Forgejo answer a user-owned repo's teams endpoint with
	// "method not allowed" — a user has no org teams, so there are none.
	if status == http.StatusMethodNotAllowed {
		return []string{}, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("forge: GET repos/{org}/{repo}/teams: status %d", status)
	}
	var teams []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &teams); err != nil {
		return nil, fmt.Errorf("forge: GET repos/{org}/{repo}/teams: decode: %w", err)
	}

	out := []string{}
	for _, t := range teams {
		status, _, err := g.get(ctx, fmt.Sprintf("/api/v1/teams/%d/members/%s", t.ID, url.PathEscape(login)))
		if err != nil {
			return nil, fmt.Errorf("forge: GET teams/{id}/members/{login}: %w", err)
		}
		switch status {
		case http.StatusOK:
			out = append(out, t.Name)
		case http.StatusNotFound:
		default:
			return nil, fmt.Errorf("forge: GET teams/{id}/members/{login}: status %d", status)
		}
	}
	return out, nil
}

func (g *Gitea) get(ctx context.Context, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "token "+g.token)
	req.Header.Set("Accept", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

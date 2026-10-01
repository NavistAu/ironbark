package gitenv

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/vaultx"
)

const rp = "vs/metadata/pipelines/acme/mono/"

// fake is a walk.Client over maps; a path absent from md has no level
// metadata (404) and one listed in deny answers 403.
type fake struct {
	lists map[string][]string
	md    map[string]map[string]string
	deny  map[string]bool
}

func (f *fake) Token() string { return "T" }
func (f *fake) List(_ context.Context, p string) ([]string, error) {
	if f.deny[p] {
		return nil, vaultx.ErrForbidden
	}
	k, ok := f.lists[p]
	if !ok {
		return nil, vaultx.ErrNotFound
	}
	return k, nil
}
func (f *fake) Read(context.Context, string) (*vaultx.Secret, error) { return nil, vaultx.ErrNotFound }
func (f *fake) LevelMetadata(_ context.Context, p string) (map[string]string, bool, error) {
	if f.deny[p] {
		return nil, false, vaultx.ErrForbidden
	}
	m, ok := f.md[p]
	return m, ok, nil
}

func tmpl(t *testing.T) grantcfg.Template {
	t.Helper()
	tm, err := grantcfg.ParseTemplate("vs/data/pipelines/{repo}/{env}/{target...}")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func envs() *fake {
	return &fake{
		lists: map[string][]string{rp: {"db", "prod", "staging", "dev"}},
		md: map[string]map[string]string{
			rp + "prod":    {"branches": "main"},
			rp + "staging": {"branches": "release/*"},
			rp + "dev":     {"branches": "main,feat/*"},
		},
	}
}

func sel(t *testing.T, c *fake, in SelectInput) (Selection, error) {
	t.Helper()
	in.Org, in.Repo = "acme", "mono"
	return Select(context.Background(), c, tmpl(t), in)
}

func TestSelectExplicitEnvNeedsNoDiscovery(t *testing.T) {
	// the fake would 403 any listing: an explicit env must not touch it
	c := &fake{deny: map[string]bool{rp: true}}
	got, err := sel(t, c, SelectInput{Env: "staging", Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Env != "staging" || got.Rule != RuleExplicit {
		t.Errorf("got %+v", got)
	}
}

func TestSelectDiscovery(t *testing.T) {
	cases := []struct {
		name, branch, wantEnv, wantRule string
	}{
		{"one claimant", "release/1", "staging", RuleBranch},
		{"none: repo level only", "hotfix/none-here", "", RuleNone},
		{"detached: no branch", "", "", RuleNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sel(t, envs(), SelectInput{Branch: tc.branch})
			if err != nil {
				t.Fatal(err)
			}
			if got.Env != tc.wantEnv || got.Rule != tc.wantRule {
				t.Errorf("got %+v, want env %q rule %q", got, tc.wantEnv, tc.wantRule)
			}
		})
	}
}

func TestSelectSeveralClaimantsNamedInError(t *testing.T) {
	_, err := sel(t, envs(), SelectInput{Branch: "main"})
	var se *SelectError
	if !errors.As(err, &se) || se.Kind != "ambiguous" {
		t.Fatalf("err = %v, want ambiguous SelectError", err)
	}
	if !reflect.DeepEqual(se.Claimants, []string{"dev", "prod"}) {
		t.Errorf("Claimants = %v", se.Claimants)
	}
	if !strings.Contains(err.Error(), "dev") || !strings.Contains(err.Error(), "prod") || !strings.Contains(err.Error(), "--env") {
		t.Errorf("message %q must name the levels and point at --env", err)
	}
}

func TestSelectUnreadableLevelIsAnError(t *testing.T) {
	c := envs()
	c.deny = map[string]bool{rp + "prod": true}
	_, err := sel(t, c, SelectInput{Branch: "release/1"})
	if !errors.Is(err, vaultx.ErrForbidden) {
		t.Fatalf("err = %v, want the 403 (a hidden claimant must not let another level win)", err)
	}
}

func TestSelectTarget(t *testing.T) {
	got, err := sel(t, envs(), SelectInput{Env: "prod", Target: "web/api"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Target.Escaped, []string{"web", "api"}) {
		t.Errorf("Target = %+v", got.Target)
	}
}

func TestSelectInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   SelectInput
		kind string
	}{
		{"env grammar", SelectInput{Env: "Prod!"}, "invalid-env"},
		{"target grammar", SelectInput{Env: "prod", Target: "a//b"}, "invalid-target"},
		{"target without an environment", SelectInput{Branch: "hotfix/none-here", Target: "web"}, "target-without-env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sel(t, envs(), tc.in)
			var se *SelectError
			if !errors.As(err, &se) || se.Kind != tc.kind {
				t.Fatalf("err = %v, want SelectError kind %s", err, tc.kind)
			}
		})
	}
}

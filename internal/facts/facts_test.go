package facts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/identity"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "payloads", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mutate returns fixture name with edit applied to its decoded JSON.
func mutate(t *testing.T, name string, edit func(repo, pipeline map[string]any)) []byte {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(load(t, name), &d); err != nil {
		t.Fatal(err)
	}
	edit(d["repo"].(map[string]any), d["pipeline"].(map[string]any))
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fakeForge struct {
	protected  bool
	err        error
	teams      []string
	teamsErr   error
	protCalls  []string
	teamsCalls int
	teamsLogin string
}

func (f *fakeForge) BranchProtected(_ context.Context, org, repo, branch string) (bool, error) {
	f.protCalls = append(f.protCalls, org+"/"+repo+"@"+branch)
	return f.protected, f.err
}

func (f *fakeForge) QualifiedTeams(_ context.Context, _, _, login string) ([]string, error) {
	f.teamsCalls++
	f.teamsLogin = login
	return f.teams, f.teamsErr
}

type want struct {
	event, branch, ref, protected, actor string
	vars                                 map[string]string
}

func TestBuildFixtures(t *testing.T) {
	prot := "true"
	cases := []struct {
		fixture string
		want    want
	}{
		{"gitea-push", want{"push", "main", "refs/heads/main", prot, "alice", nil}},
		{"gitea-approved", want{"push", "main", "refs/heads/main", prot, "alice", nil}},
		{"gitlab-push", want{"push", "main", "refs/heads/main", prot, "", nil}},
		{"gitea-pull-request", want{"pull_request", "", "", "", "bob", nil}},
		{"gitea-tag", want{"tag", "", "", "", "alice", nil}},
		{"gitlab-release", want{"release", "", "", "", "Jane Doe", nil}},
		{"gitea-manual", want{"manual", "main", "refs/heads/main", prot, "carol", map[string]string{"DEPLOY_TO": "api/eu", "OTHER": "x"}}},
		{"gitea-manual-no-target", want{"manual", "main", "refs/heads/main", prot, "carol", nil}},
		{"gitea-promotion", want{"deployment", "main", "refs/heads/main", prot, "", map[string]string{"DEPLOY_TO": "api/eu", "OTHER": "x"}}},
		{"github-deployment", want{"deployment", "main", "refs/heads/main", prot, "", nil}},
		{"cron", want{"cron", "main", "refs/heads/main", prot, "", nil}},
		{"unknown-event", want{"someday_event", "", "", "", "", nil}},
		// The promoted-PR trap: parent ref is a PR head, branch is protected.
		{"gitea-promotion-of-pr", want{"deployment", "main", "refs/pull/4/head", "false", "", map[string]string{"DEPLOY_TO": "api/eu", "OTHER": "x"}}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			ff := &fakeForge{protected: true}
			f, err := Build(context.Background(), load(t, c.fixture), ff, Config{ActorForge: "gitea"})
			if err != nil {
				t.Fatal(err)
			}
			w := c.want
			if f.Org != "acme" || f.Repo != "widgets" || f.RepoKey != "acme/widgets#42" {
				t.Errorf("identity: %+v", f)
			}
			if f.Event != w.event || f.Branch != w.branch || f.Ref != w.ref || f.BranchProtected != w.protected || f.Actor != w.actor {
				t.Errorf("got %+v, want %+v", f, w)
			}
			if !reflect.DeepEqual(f.Variables, w.vars) {
				t.Errorf("variables = %v, want %v", f.Variables, w.vars)
			}
			if f.Pipeline == "" {
				t.Error("pipeline number missing")
			}
		})
	}
}

func TestPromotedPRTrapSkipsOrIgnoresLookup(t *testing.T) {
	// Even if the forge says "protected", a ref that is not the branch head
	// ref never yields branch_protected=true.
	ff := &fakeForge{protected: true}
	f, err := Build(context.Background(), load(t, "gitea-promotion-of-pr"), ff, Config{})
	if err != nil || f.BranchProtected != "false" || f.Branch != "main" {
		t.Fatalf("%+v %v", f, err)
	}
}

func TestPullRequestClosedHasNoBranch(t *testing.T) {
	ff := &fakeForge{protected: true}
	b := mutate(t, "gitea-pull-request", func(_, p map[string]any) { p["event"] = "pull_request_closed" })
	f, err := Build(context.Background(), b, ff, Config{ActorForge: "gitea"})
	if err != nil {
		t.Fatal(err)
	}
	if f.Event != "pull_request_closed" || f.Branch != "" || f.Ref != "" || f.BranchProtected != "" {
		t.Errorf("%+v", f)
	}
	if len(ff.protCalls) != 0 {
		t.Errorf("forge called for a branchless event: %v", ff.protCalls)
	}
}

func TestPullRequestNeverLooksUpBranch(t *testing.T) {
	ff := &fakeForge{protected: true}
	if _, err := Build(context.Background(), load(t, "gitea-pull-request"), ff, Config{}); err != nil {
		t.Fatal(err)
	}
	if len(ff.protCalls) != 0 {
		t.Errorf("forge called: %v", ff.protCalls)
	}
}

func TestEventLowercased(t *testing.T) {
	b := mutate(t, "gitea-push", func(_, p map[string]any) { p["event"] = "PUSH" })
	f, err := Build(context.Background(), b, &fakeForge{protected: true}, Config{})
	if err != nil || f.Event != "push" || f.Branch != "main" {
		t.Errorf("%+v %v", f, err)
	}
}

func TestActorForgeValues(t *testing.T) {
	cases := []struct {
		forge     string
		push, man string
	}{
		{"none", "", "carol"},
		{"", "", "carol"},
		{"gitea", "alice", "carol"},
		{"github", "alice", "carol"},
		{"bitbucket", "alice", "carol"},
	}
	for _, c := range cases {
		t.Run(c.forge, func(t *testing.T) {
			ff := &fakeForge{}
			f, _ := Build(context.Background(), load(t, "gitea-push"), ff, Config{ActorForge: c.forge})
			if f.Actor != c.push {
				t.Errorf("push actor = %q, want %q", f.Actor, c.push)
			}
			f, _ = Build(context.Background(), load(t, "gitea-manual"), ff, Config{ActorForge: c.forge})
			if f.Actor != c.man {
				t.Errorf("manual actor = %q, want %q", f.Actor, c.man)
			}
			// A promote and cron never have an actor, whatever the forge.
			f, _ = Build(context.Background(), load(t, "gitea-promotion"), ff, Config{ActorForge: c.forge})
			if f.Actor != "" {
				t.Errorf("deployment actor = %q", f.Actor)
			}
			f, _ = Build(context.Background(), load(t, "cron"), ff, Config{ActorForge: c.forge})
			if f.Actor != "" {
				t.Errorf("cron actor = %q", f.Actor)
			}
		})
	}
}

func TestForgeErrorMeansFalse(t *testing.T) {
	ff := &fakeForge{protected: true, err: errors.New("boom")}
	f, err := Build(context.Background(), load(t, "gitea-push"), ff, Config{})
	if err != nil || f.BranchProtected != "false" {
		t.Errorf("%+v %v", f, err)
	}
	if len(ff.protCalls) != 1 || ff.protCalls[0] != "acme/widgets@main" {
		t.Errorf("calls = %v", ff.protCalls)
	}
}

func TestForgeUnprotected(t *testing.T) {
	f, _ := Build(context.Background(), load(t, "gitea-push"), &fakeForge{protected: false}, Config{})
	if f.BranchProtected != "false" {
		t.Errorf("%+v", f)
	}
}

func TestNoForgeMeansFalse(t *testing.T) {
	f, err := Build(context.Background(), load(t, "gitea-push"), nil, Config{})
	if err != nil || f.BranchProtected != "false" || f.Branch != "main" {
		t.Errorf("%+v %v", f, err)
	}
}

func TestOrgRepoLowercasedRepoKeyEscaped(t *testing.T) {
	b := mutate(t, "gitea-push", func(r, _ map[string]any) {
		r["full_name"] = "Acme/My Repo"
		r["forge_remote_id"] = "A/7"
	})
	f, err := Build(context.Background(), b, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if f.Org != "acme" || f.Repo != "my repo" || f.RepoKey != "acme/my%20repo#%41%2f7" {
		t.Errorf("%+v", f)
	}
}

func TestMalformed(t *testing.T) {
	bad := map[string][]byte{
		"not json":     []byte("{"),
		"no repo":      []byte(`{"pipeline":{"event":"push"}}`),
		"no pipeline":  []byte(`{"repo":{"full_name":"a/b","forge_remote_id":"1"}}`),
		"no event":     []byte(`{"repo":{"full_name":"a/b","forge_remote_id":"1"},"pipeline":{}}`),
		"no slash":     []byte(`{"repo":{"full_name":"ab","forge_remote_id":"1"},"pipeline":{"event":"push"}}`),
		"two slashes":  []byte(`{"repo":{"full_name":"a/b/c","forge_remote_id":"1"},"pipeline":{"event":"push"}}`),
		"empty half":   []byte(`{"repo":{"full_name":"a/","forge_remote_id":"1"},"pipeline":{"event":"push"}}`),
		"no remote id": []byte(`{"repo":{"full_name":"a/b"},"pipeline":{"event":"push"}}`),
	}
	for name, b := range bad {
		if _, err := Build(context.Background(), b, nil, Config{}); !errors.Is(err, identity.ErrMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestResolveTeams(t *testing.T) {
	ff := &fakeForge{teams: []string{"acme/deployers"}}
	f := Facts{Org: "acme", Repo: "widgets", Actor: "alice"}

	got, err := ResolveTeams(context.Background(), ff, f, "prod")
	if err != nil || !reflect.DeepEqual(got, []string{"acme/deployers"}) || ff.teamsLogin != "alice" {
		t.Errorf("%v %v", got, err)
	}

	// no environment, no actor, no forge: no lookup
	ff.teamsCalls = 0
	if got, _ := ResolveTeams(context.Background(), ff, f, ""); got != nil || ff.teamsCalls != 0 {
		t.Errorf("env-less lookup: %v calls=%d", got, ff.teamsCalls)
	}
	f2 := f
	f2.Actor = ""
	if got, _ := ResolveTeams(context.Background(), ff, f2, "prod"); got != nil || ff.teamsCalls != 0 {
		t.Errorf("actor-less lookup: %v calls=%d", got, ff.teamsCalls)
	}
	if got, err := ResolveTeams(context.Background(), nil, f, "prod"); got != nil || err != nil {
		t.Errorf("nil forge: %v %v", got, err)
	}

	// failure: no teams, error reported
	ff.teamsErr = errors.New("down")
	got, err = ResolveTeams(context.Background(), ff, f, "prod")
	if got != nil || err == nil || strings.Contains(err.Error(), "token") {
		t.Errorf("%v %v", got, err)
	}
}

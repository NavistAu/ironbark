//go:build integration

package integration

import "testing"

// TestGrantHarness proves the fixture: the plugin is mounted, a view is
// readable, and a role logs in with a signed JWT and reads only its level.
func TestGrantHarness(t *testing.T) {
	g := GetGrant(t)
	org, repo := "acme", uniq("mono")
	g.KV(t, "src/harness", map[string]any{"v": "FAKE"})
	g.View(t, "pipelines/"+org+"/"+repo+"/db", map[string]any{"target": "kv/data/src/harness"})
	if c := g.Code("root", "vs/data/pipelines/"+org+"/"+repo+"/db"); c != 200 {
		t.Fatalf("root view read = %d", c)
	}
	g.Role(t, "ci", map[string]any{"repo_key": []string{org + "/" + repo + "#7"}, "event": []string{"push"}},
		[]string{"ci-project"}, nil)
	tok, err := g.LoginRaw("ci", g.JWT(t, Req{Org: org, Repo: repo, ID: "7"}))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if c := g.Code(tok, "vs/data/pipelines/"+org+"/"+repo+"/db"); c != 200 {
		t.Fatalf("own repo level = %d, want 200", c)
	}
	if c := g.Code(tok, "vs/data/pipelines/"+org+"/other/db"); c != 403 {
		t.Fatalf("other repo = %d, want 403", c)
	}
}

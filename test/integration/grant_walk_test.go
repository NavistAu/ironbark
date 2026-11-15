//go:build integration

package integration

import (
	"context"
	"reflect"
	"testing"

	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/walk"
)

func names(r walk.Result) map[string]string {
	m := map[string]string{}
	for _, s := range r.Secrets {
		m[s.Name] = s.Value
	}
	return m
}

func TestGrantWalk(t *testing.T) {
	g := GetGrant(t)
	c := grantConn(t)
	ctx := context.Background()
	org, repo := "acme", uniq("wk")
	base := "pipelines/" + org + "/" + repo + "/"
	g.Role(t, "ci-staging", map[string]any{"repo_key": []string{org + "/" + repo + "#1"}, "env": "staging",
		"event": []string{"push"}}, []string{"ci-project", "ci-env", "ci-target"}, nil)

	put := func(view, val string) {
		g.KV(t, "src/"+repo+"/"+view, map[string]any{"value": val})
		g.View(t, base+view, map[string]any{"target": "kv/data/src/" + repo + "/" + view})
	}
	put("repo_secret", "R")
	put("staging/env_secret", "E")
	put("staging/web/parent_secret", "P")
	put("staging/web/api/api_secret", "A")
	put("staging/web/cli/cli_secret", "C")
	put("prod/prod_secret", "PROD")

	login := func(r Req) string {
		r.Org, r.Repo, r.ID = org, repo, "1"
		tok, err := c.LoginJWT(ctx, "jwt", "ci-staging", g.JWT(t, r))
		if err != nil {
			t.Fatal(err)
		}
		return tok.Value
	}
	tok := login(Req{Env: "staging", Source: "variable", Target: "web/api"})
	sess := c.As(tok)

	t.Run("nested target reads parents and not a sibling", func(t *testing.T) {
		r, err := walk.Walk(ctx, sess, levels.Levels(g.Tmpl, org, repo, "staging", []string{"web", "api"}), walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"repo_secret": "R", "env_secret": "E", "parent_secret": "P", "api_secret": "A"}
		if !reflect.DeepEqual(names(r), want) {
			t.Fatalf("names = %v", names(r))
		}
		if g.Code(tok, "vs/data/"+base+"staging/web/cli/cli_secret") != 403 {
			t.Error("sibling data read should 403")
		}
	})
	t.Run("another env and another repo 403 and are skipped", func(t *testing.T) {
		r, err := walk.Walk(ctx, sess, levels.Levels(g.Tmpl, org, repo, "prod", nil), walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Levels["prod"] != walk.LevelSkipped403 || names(r)["prod_secret"] != "" {
			t.Fatalf("levels = %v names = %v", r.Levels, names(r))
		}
		r, err = walk.Walk(ctx, sess, levels.Levels(g.Tmpl, org, uniq("other"), "", nil), walk.Options{})
		if err != nil || r.Levels["."] != walk.LevelSkipped403 || len(r.Secrets) != 0 {
			t.Fatalf("other repo: %v %v %v", err, r.Levels, r.Secrets)
		}
	})
	t.Run("a target below an unreadable env level is still read", func(t *testing.T) {
		// login with env staging but a role/policy set lacking ci-env
		g.Role(t, "ci-staging-noenv", map[string]any{"repo_key": []string{org + "/" + repo + "#1"}, "env": "staging"},
			[]string{"ci-project", "ci-target"}, nil)
		jwt := g.JWT(t, Req{Org: org, Repo: repo, ID: "1", Env: "staging", Source: "variable", Target: "web/api"})
		tk, err := c.LoginJWT(ctx, "jwt", "ci-staging-noenv", jwt)
		if err != nil {
			t.Fatal(err)
		}
		r, err := walk.Walk(ctx, c.As(tk.Value), levels.Levels(g.Tmpl, org, repo, "staging", []string{"web", "api"}), walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Levels["staging"] != walk.LevelSkipped403 || names(r)["api_secret"] != "A" || names(r)["env_secret"] != "" {
			t.Fatalf("levels = %v names = %v", r.Levels, names(r))
		}
	})
	t.Run("pins come from the mapping, not the upstream's metadata (G13)", func(t *testing.T) {
		g.KV(t, "src/"+repo+"/pinned", map[string]any{"value": "X"})
		g.Write(t, "kv/metadata/src/"+repo+"/pinned", map[string]any{"custom_metadata": map[string]string{"ironbark_images": "evil/img"}})
		g.View(t, base+"pinned", map[string]any{"target": "kv/data/src/" + repo + "/pinned",
			"custom_metadata": map[string]string{"ironbark_images": "good/a,good/b", "ironbark_events": "push"}})
		r, err := walk.Walk(ctx, sess, levels.Levels(g.Tmpl, org, repo, "", nil), walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, s := range r.Secrets {
			if s.Name == "pinned" {
				got = s.Images
			}
		}
		if !reflect.DeepEqual(got, []string{"good/a", "good/b"}) {
			t.Fatalf("pins = %v", got)
		}
		if !reflect.DeepEqual(r.IgnoredEvents, []string{"./pinned"}) {
			t.Fatalf("ignored events = %v", r.IgnoredEvents)
		}
	})
}

// A plain KV v2 tree (no voidstar): entry-level pins, and the empty
// vault_token marker.
func TestGrantWalkPlainKV(t *testing.T) {
	g := GetGrant(t)
	c := grantConn(t)
	ctx := context.Background()
	org, repo := "acme", uniq("pk")
	tm, err := grantcfg.ParseTemplate("kv/data/plain/{repo}/{env}/{target...}")
	if err != nil {
		t.Fatal(err)
	}
	project, env, target := levels.RenderPolicies(tm, g.Accessor)
	for n, p := range map[string]string{"kv-project": project, "kv-env": env, "kv-target": target} {
		if err := g.Root.Sys().PutPolicy(n, p); err != nil {
			t.Fatal(err)
		}
	}
	g.Role(t, "kv-ci", map[string]any{"repo_key": []string{org + "/" + repo + "#1"}}, []string{"kv-project", "kv-env", "kv-target"}, nil)
	base := "plain/" + org + "/" + repo + "/"
	g.KV(t, base+"plain_secret", map[string]any{"value": "P"})
	g.Write(t, "kv/metadata/"+base+"plain_secret", map[string]any{"custom_metadata": map[string]string{"ironbark_images": "img/one"}})
	g.KV(t, base+"vault_token", map[string]any{})
	g.KV(t, base+"staging/multi", map[string]any{"user": "u", "pass": "p"})

	tok, err := c.LoginJWT(ctx, "jwt", "kv-ci", g.JWT(t, Req{Org: org, Repo: repo, ID: "1", Env: "staging", Source: "variable"}))
	if err != nil {
		t.Fatal(err)
	}
	r, err := walk.Walk(ctx, c.As(tok.Value), levels.Levels(tm, org, repo, "staging", nil), walk.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := names(r)
	if got["plain_secret"] != "P" || got["multi_user"] != "u" || got["multi_pass"] != "p" || got["vault_token"] != tok.Value {
		t.Fatalf("names = %v", got)
	}
	for _, s := range r.Secrets {
		if s.Name == "plain_secret" && !reflect.DeepEqual(s.Images, []string{"img/one"}) {
			t.Fatalf("entry pins = %v", s.Images)
		}
	}
}

//go:build integration

package integration

import (
	"context"
	"reflect"
	"testing"

	"github.com/navistau/ironbark/internal/walk"
)

func TestGrantDiscovery(t *testing.T) {
	g := GetGrant(t)
	c := grantConn(t)
	org, repo := "acme", uniq("dc")
	base := "pipelines/" + org + "/" + repo + "/"
	g.KV(t, "src/dc", map[string]any{"v": "FAKE"})
	for env, branches := range map[string]string{"prod": "main", "staging": "release/*,staging", "qa": "main"} {
		g.View(t, base+env+"/db", map[string]any{"target": "kv/data/src/dc"})
		g.Level(t, base+env, map[string]string{"branches": branches})
	}
	g.View(t, base+"shared", map[string]any{"target": "kv/data/src/dc"})
	g.Role(t, "ci", map[string]any{"repo_key": []string{"acme/*#*"}, "event": []string{"push"}}, []string{"ci-project"}, nil)

	ctx := context.Background()
	tok, err := c.LoginJWT(ctx, "jwt", "ci", g.JWT(t, Req{Org: org, Repo: repo, ID: "1", Branch: "main"}))
	if err != nil {
		t.Fatal(err)
	}
	sess := c.As(tok.Value)
	tm := g.Tmpl

	t.Run("reads branches of every env level", func(t *testing.T) {
		for env, want := range map[string]string{"prod": "main", "staging": "release/*,staging", "qa": "main"} {
			md, ok, err := sess.LevelMetadata(ctx, "vs/metadata/"+base+env+"/")
			if err != nil || !ok || md["branches"] != want {
				t.Fatalf("%s: %v %v %v", env, md, ok, err)
			}
		}
	})
	t.Run("cannot read any env data", func(t *testing.T) {
		for _, env := range []string{"prod", "staging", "qa"} {
			if c := g.Code(tok.Value, "vs/data/"+base+env+"/db"); c != 403 {
				t.Errorf("%s data = %d, want 403", env, c)
			}
		}
		if c := g.Code(tok.Value, "vs/data/"+base+"shared"); c != 200 {
			t.Errorf("repo level = %d, want 200", c)
		}
	})
	t.Run("two claimants are reported", func(t *testing.T) {
		d, err := walk.Discover(ctx, sess, tm, org, repo, "main")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(d.Claimants, []string{"prod", "qa"}) {
			t.Fatalf("claimants = %v", d.Claimants)
		}
	})
	t.Run("one claimant", func(t *testing.T) {
		d, err := walk.Discover(ctx, sess, tm, org, repo, "release/1")
		if err != nil || !reflect.DeepEqual(d.Claimants, []string{"staging"}) {
			t.Fatalf("d = %+v, err %v", d, err)
		}
	})
	t.Run("no claimant", func(t *testing.T) {
		d, err := walk.Discover(ctx, sess, tm, org, repo, "feature/x")
		if err != nil || len(d.Claimants) != 0 {
			t.Fatalf("d = %+v, err %v", d, err)
		}
	})
	t.Run("another repo's levels are unreadable, so discovery errors", func(t *testing.T) {
		if _, err := walk.Discover(ctx, sess, tm, org, uniq("other"), "main"); err == nil {
			t.Fatal("want an error listing a repo the token is not scoped to")
		}
	})
}

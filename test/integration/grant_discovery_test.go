//go:build integration

package integration

import (
	"context"
	"reflect"
	"testing"

	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/vaultx"
	"github.com/navistau/ironbark/internal/walk"
)

// TestGrantDiscovery runs the same discovery on voidstar and on plain KV v2.
func TestGrantDiscovery(t *testing.T) {
	for _, p := range []struct {
		name string
		get  func(*testing.T) *Grant
	}{{"openbao", GetGrant}, {"vault", GetVault}} {
		t.Run(p.name, func(t *testing.T) { discovery(t, p.get(t)) })
	}
}

func discovery(t *testing.T, g *Grant) {
	c, err := vaultx.NewConn(g.Addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	org, repo := "acme", uniq("dc")
	base := "pipelines/" + org + "/" + repo + "/"
	for env, branches := range map[string]string{"prod": "main", "staging": "release/*,staging", "qa": "main"} {
		g.Secret(t, org+"/"+repo+"/"+env+"/db", "FAKE")
		g.Level(t, base+env, map[string]string{"branches": branches})
	}
	// A level with no secrets yet is still discoverable.
	g.Level(t, base+"fresh", map[string]string{"branches": "fresh/*"})
	g.Secret(t, org+"/"+repo+"/shared", "FAKE")
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
			md, ok, err := sess.LevelMetadata(ctx, g.Mount+"/metadata/"+base+env)
			if err != nil || !ok || md["branches"] != want {
				t.Fatalf("%s: %v %v %v", env, md, ok, err)
			}
		}
	})
	t.Run("cannot read any env data", func(t *testing.T) {
		for _, env := range []string{"prod", "staging", "qa"} {
			if c := g.Code(tok.Value, g.Data(org+"/"+repo+"/"+env+"/db")); c != 403 {
				t.Errorf("%s data = %d, want 403", env, c)
			}
		}
		if c := g.Code(tok.Value, g.Data(org+"/"+repo+"/shared")); c != 200 {
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
	t.Run("a level with no secrets is discovered", func(t *testing.T) {
		d, err := walk.Discover(ctx, sess, tm, org, repo, "fresh/1")
		if err != nil || !reflect.DeepEqual(d.Claimants, []string{"fresh"}) {
			t.Fatalf("d = %+v, err %v", d, err)
		}
	})
	t.Run("the walk does not deliver level entries as secrets", func(t *testing.T) {
		res, err := walk.Walk(ctx, sess, levels.Levels(tm, org, repo, "", nil)[:1], walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Secrets) != 1 || res.Secrets[0].Name != "shared" {
			t.Fatalf("secrets = %+v", res.Secrets)
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

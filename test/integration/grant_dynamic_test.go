//go:build integration

package integration

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/vaultx"
	"github.com/navistau/ironbark/internal/walk"
)

func compose(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"compose", "-f", "docker-compose.yml"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %v: %v\n%s", args, err, out)
	}
}

// leaseCount is the number of live leases under a database role, as root.
func leaseCount(g *Grant, role string) int {
	s, err := g.Root.Logical().List("sys/leases/lookup/database/creds/" + role + "/")
	if err != nil || s == nil {
		return 0
	}
	return len(s.Data["keys"].([]any))
}

func waitLeases(t *testing.T, g *Grant, role string, want int) {
	t.Helper()
	for i := 0; i < 30; i++ {
		if leaseCount(g, role) == want {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("leases under %s = %d, want %d", role, leaseCount(g, role), want)
}

func TestGrantDynamic(t *testing.T) {
	g := GetGrant(t)
	c := grantConn(t)
	ctx := context.Background()
	org, repo, env := "acme", uniq("dy"), uniq("e")
	base := "pipelines/" + org + "/" + repo + "/" + env + "/web/"
	dbRole := env + "-web" // the <env>-<t1> convention ci-dynamic grants
	g.DBRole(t, dbRole)
	g.DBRole(t, "other-"+env+"-web")
	g.View(t, base+"db", map[string]any{"mode": "resolve", "target": "database/creds/" + dbRole,
		"custom_metadata": map[string]string{"ironbark_images": "x/deploy"}})
	g.View(t, base+"ungranted", map[string]any{"mode": "resolve", "target": "database/creds/other-" + env + "-web"})
	g.Role(t, "ci-dyn", map[string]any{"repo_key": []string{org + "/" + repo + "#1"}, "env": env},
		[]string{"ci-project", "ci-env", "ci-target", "ci-dynamic"}, nil)
	lv := levels.Levels(g.Tmpl, org, repo, env, []string{"web"})
	login := func(t *testing.T) vaultx.Token {
		t.Helper()
		tok, err := c.LoginJWT(ctx, "jwt", "ci-dyn", g.JWT(t, Req{Org: org, Repo: repo, ID: "1", Env: env, Source: "variable", Target: "web"}))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	t.Run("resolve yields a lease owned by the pipeline token", func(t *testing.T) {
		tok := login(t)
		r, err := walk.Walk(ctx, c.As(tok.Value), lv, walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		got := names(r)
		if got["db_username"] == "" || got["db_password"] == "" {
			t.Fatalf("names = %v", got)
		}
		for _, s := range r.Secrets {
			if s.Name == "db_username" && (len(s.Images) != 1 || s.Images[0] != "x/deploy") {
				t.Fatalf("pins = %v", s.Images)
			}
		}
		if got := leaseCount(g, dbRole); got != 1 {
			t.Fatalf("leases = %d, want 1", got)
		}
		// The cascade below is what proves the parenting: the lease is revoked
		// with the token, not by expiry. (The lease-lookup API does not expose
		// the parent token accessor.)
		if err := c.RevokeSelf(ctx, tok.Value); err != nil {
			t.Fatal(err)
		}
		waitLeases(t, g, dbRole, 0)
	})
	t.Run("a resolve to an ungranted path is skipped", func(t *testing.T) {
		tok := login(t)
		defer c.RevokeSelf(ctx, tok.Value)
		r, err := walk.Walk(ctx, c.As(tok.Value), lv, walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if names(r)["ungranted_username"] != "" {
			t.Fatalf("names = %v", names(r))
		}
		found := false
		for _, e := range r.SkippedEntries {
			found = found || e == env+"/web/ungranted"
		}
		if !found {
			t.Fatalf("skipped = %v", r.SkippedEntries)
		}
		if leaseCount(g, "other-"+env+"-web") != 0 {
			t.Fatal("a lease was minted for the ungranted role")
		}
	})
	t.Run("an engine error fails the walk and the leases taken go with the token", func(t *testing.T) {
		g.View(t, base+"a_first", map[string]any{"mode": "resolve", "target": "database/creds/" + dbRole})
		g.View(t, base+"z_last", map[string]any{"mode": "resolve", "target": "database/creds/" + dbRole})
		defer g.Root.Logical().Delete("vs/admin/map/" + base + "a_first")
		defer g.Root.Logical().Delete("vs/admin/map/" + base + "z_last")
		tok := login(t)
		sess := c.As(tok.Value)
		calls := 0
		stopped := false
		defer func() {
			if stopped {
				compose(t, "up", "-d", "--wait", "postgres")
			}
		}()
		_, err := walk.Walk(ctx, sess, lv, walk.Options{Resolve: func(ctx context.Context, p string) (*vaultx.Secret, error) {
			s, err := sess.Read(ctx, p)
			if calls++; calls == 1 { // first resolve done: take the engine down
				compose(t, "stop", "postgres")
				stopped = true
			}
			return s, err
		}})
		if err == nil {
			t.Fatal("want the walk to fail when the engine errors")
		}
		compose(t, "up", "-d", "--wait", "postgres")
		stopped = false
		if leaseCount(g, dbRole) < 1 {
			t.Fatalf("expected the first lease to exist before the token is revoked")
		}
		if err := c.RevokeSelf(ctx, tok.Value); err != nil {
			t.Fatal(err)
		}
		waitLeases(t, g, dbRole, 0)
	})
}

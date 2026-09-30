//go:build integration

package integration

// Plan task 4.5: the real httpapi server, in process, over the real broker,
// vaultx.Conn and walk against the compose OpenBao 2.7.0 + voidstar, with
// requests signed by wpsigntest. Only the forge is a fake (branch protection
// by branch name). Every JWT role name here is e2e-prefixed so the roles do
// not collide with the other grant tests' shared roles.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/httpapi"
	"github.com/navistau/ironbark/internal/vaultx"
	"github.com/navistau/ironbark/internal/wpsign/wpsigntest"
)

// e2eForge answers BranchProtected true only for main; no teams.
type e2eForge struct{}

func (e2eForge) BranchProtected(_ context.Context, _, _, branch string) (bool, error) {
	return branch == "main", nil
}
func (e2eForge) QualifiedTeams(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// recVault records every login's accessor and every revoke, around the real
// connection.
type recVault struct {
	broker.Vault
	mu        sync.Mutex
	accessors []string
	revoked   []string
}

func (r *recVault) LoginJWT(ctx context.Context, mount, role, jwt string) (vaultx.Token, error) {
	tok, err := r.Vault.LoginJWT(ctx, mount, role, jwt)
	if err == nil {
		r.mu.Lock()
		r.accessors = append(r.accessors, tok.Accessor)
		r.mu.Unlock()
	}
	return tok, err
}

func (r *recVault) RevokeSelf(ctx context.Context, token string) error {
	err := r.Vault.RevokeSelf(ctx, token)
	r.mu.Lock()
	r.revoked = append(r.revoked, token)
	r.mu.Unlock()
	return err
}

func (r *recVault) reset() {
	r.mu.Lock()
	r.accessors, r.revoked = nil, nil
	r.mu.Unlock()
}

type e2eBody struct {
	Secrets []struct {
		Name   string   `json:"name"`
		Value  string   `json:"value"`
		Images []string `json:"images"`
	} `json:"secrets"`
}

func (b e2eBody) get(name string) (string, bool) {
	for _, s := range b.Secrets {
		if s.Name == name {
			return s.Value, true
		}
	}
	return "", false
}

func (b e2eBody) names() []string {
	var out []string
	for _, s := range b.Secrets {
		out = append(out, s.Name)
	}
	return out
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) requestLines(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(l.b.String()), "\n") {
		var m map[string]any
		if raw == "" || json.Unmarshal([]byte(raw), &m) != nil {
			continue
		}
		if m["msg"] == "request" {
			out = append(out, m)
		}
	}
	return out
}

func (l *logBuf) reset() { l.mu.Lock(); l.b.Reset(); l.mu.Unlock() }

func TestGrantE2E(t *testing.T) {
	g := GetGrant(t)
	priv, pub := loadE2EKeys(t)
	conn := grantConn(t)
	rec := &recVault{Vault: broker.FromConn(conn)}
	logs := &logBuf{}
	brk := broker.New(rec, g.Signer, broker.Config{
		Data: g.Tmpl, EnvVar: "DEPLOY_ENV", TargetVar: "DEPLOY_TO", JWTRole: "e2e-{env}", JWTMount: "jwt",
		ActorForge: "none",
	}, broker.WithLookups(e2eForge{}))
	srv := httpapi.New(brk, func() bool { return true }, pub, 30*time.Second, 30*time.Second, time.Now,
		slog.New(slog.NewJSONHandler(logs, nil)))
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// One repo with a prod environment (claims main), a nested web/api
	// target, a dynamic-credentials mapping, and a metadata-only vault_token
	// marker; a second repo where two environments claim main.
	org, repoA, repoB := "acme", uniq("e2ea"), uniq("e2eb")
	baseA, baseB := "pipelines/"+org+"/"+repoA+"/", "pipelines/"+org+"/"+repoB+"/"
	g.KV(t, "src/e2e", map[string]any{"value": "FAKE-E2E"})
	view := func(rel string) { g.View(t, rel, map[string]any{"target": "kv/data/src/e2e"}) }
	view(baseA + "shared")
	view(baseA + "prod/db")
	view(baseA + "prod/web/api/token")
	g.Level(t, baseA+"prod", map[string]string{"branches": "main"})
	g.DBRole(t, "prod-web")
	g.View(t, baseA+"prod/web/dyn", map[string]any{"mode": "resolve", "target": "database/creds/prod-web"})
	g.View(t, baseA+"prod/vault_token", map[string]any{"mode": "metadata",
		"custom_metadata": map[string]string{"ironbark_images": "deploy"}})
	for _, env := range []string{"prod", "beta"} {
		view(baseB + env + "/db")
		g.Level(t, baseB+env, map[string]string{"branches": "main"})
	}
	claim := map[string]any{"repo_key": []string{org + "/e2e*#*"}}
	g.Role(t, "e2e", claim, []string{"ci-project"}, nil)
	all := []string{"ci-project", "ci-env", "ci-target", "ci-dynamic"}
	g.Role(t, "e2e-prod", map[string]any{"repo_key": []string{org + "/e2e*#*"}, "branch_protected": []string{"true"}}, all, nil)
	g.Role(t, "e2e-beta", map[string]any{"repo_key": []string{org + "/e2e*#*"}, "branch_protected": []string{"true"}}, all, nil)

	type opts struct {
		repo, event, branch, deployTo, message string
		vars                                   map[string]string
	}
	send := func(t *testing.T, o opts) (int, e2eBody) {
		t.Helper()
		rec.reset()
		logs.reset()
		if o.event == "" {
			o.event = "push"
		}
		ref := ""
		if o.branch != "" {
			ref = "refs/heads/" + o.branch
		}
		payload, _ := json.Marshal(map[string]any{
			"repo": map[string]any{"full_name": org + "/" + o.repo, "forge_remote_id": "1"},
			"pipeline": map[string]any{"event": o.event, "branch": o.branch, "ref": ref, "number": 9,
				"deploy_to": o.deployTo, "message": o.message, "variables": o.vars},
		})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", bytes.NewReader(payload))
		if err := wpsigntest.Sign(req, payload, priv); err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b e2eBody
		if resp.StatusCode == 200 {
			if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode, b
	}
	statusOf := func(t *testing.T, b e2eBody) string {
		t.Helper()
		v, ok := b.get("ironbark_status")
		if !ok {
			t.Fatalf("no ironbark_status in %v", b.names())
		}
		return v
	}
	onlyStatus := func(b e2eBody) bool { return len(b.Secrets) == 1 && b.Secrets[0].Name == "ironbark_status" }
	tokenDead := func(t *testing.T, accessor string) bool {
		t.Helper()
		_, err := g.Root.Auth().Token().LookupAccessor(accessor)
		return err != nil
	}
	oneAudit := func(t *testing.T) map[string]any {
		t.Helper()
		lines := logs.requestLines(t)
		if len(lines) != 1 {
			t.Fatalf("got %d request audit lines, want 1: %v", len(lines), lines)
		}
		return lines[0]
	}
	explicitProd := map[string]string{"DEPLOY_ENV": "prod"}

	t.Run("push to protected main: discovery, then prod", func(t *testing.T) {
		code, b := send(t, opts{repo: repoA, branch: "main"})
		if code != 200 {
			t.Fatalf("code = %d", code)
		}
		if v, _ := b.get("db"); v != "FAKE-E2E" {
			t.Errorf("prod db = %q; names %v", v, b.names())
		}
		if _, ok := b.get("shared"); !ok {
			t.Error("repo-level secret missing")
		}
		st := statusOf(t, b)
		for _, w := range []string{"outcome=ok", "env=prod", "env_source=branch", "role=e2e-prod"} {
			if !strings.Contains(st, w) {
				t.Errorf("status %q lacks %s", st, w)
			}
		}
		if len(rec.accessors) != 2 || !tokenDead(t, rec.accessors[0]) || tokenDead(t, rec.accessors[1]) {
			t.Errorf("want discovery token revoked, prod token live: %v", rec.accessors)
		}
		a := oneAudit(t)
		if a["discovery_login"] != true || a["env_source"] != "branch" || a["role"] != "e2e-prod" || a["outcome"] != "ok" {
			t.Errorf("audit = %v", a)
		}
	})

	t.Run("audit line carries the section 10 fields and no values", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "manual", branch: "main", vars: explicitProd})
		a := oneAudit(t)
		for _, k := range []string{"org", "repo", "repo_key", "event", "branch", "ref", "branch_protected", "env", "env_source",
			"role", "sub", "jti", "levels", "secrets_returned", "token_accessor", "token_ttl", "outcome"} {
			if _, ok := a[k]; !ok {
				t.Errorf("audit lacks %s: %v", k, a)
			}
		}
		if a["env_source"] != "variable" {
			t.Errorf("env_source = %v", a["env_source"])
		}
		raw, _ := json.Marshal(a)
		for _, s := range b.Secrets {
			if s.Name != "ironbark_status" && strings.Contains(string(raw), s.Value) {
				t.Errorf("secret value of %s in the audit line", s.Name)
			}
		}
	})

	t.Run("manual DEPLOY_ENV and DEPLOY_TO walk the target levels", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "manual", branch: "main",
			vars: map[string]string{"DEPLOY_ENV": "prod", "DEPLOY_TO": "web/api"}})
		for _, n := range []string{"shared", "db", "token"} {
			if _, ok := b.get(n); !ok {
				t.Errorf("missing %s: %v", n, b.names())
			}
		}
		if !strings.Contains(statusOf(t, b), "target=web/api") {
			t.Errorf("status = %s", statusOf(t, b))
		}
	})

	t.Run("promote with deploy_to", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "deployment", branch: "main", deployTo: "web/api", vars: explicitProd})
		if _, ok := b.get("token"); !ok {
			t.Errorf("target level not walked: %v", b.names())
		}
		if a := oneAudit(t); a["target_source"] != "deploy_to" {
			t.Errorf("audit = %v", a)
		}
	})

	t.Run("resolve mapping yields dynamic credentials", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "manual", branch: "main",
			vars: map[string]string{"DEPLOY_ENV": "prod", "DEPLOY_TO": "web"}})
		if u, ok := b.get("dyn_username"); !ok || u == "" {
			t.Fatalf("dynamic credential missing: %v", b.names())
		}
		if _, ok := b.get("dyn_password"); !ok {
			t.Error("dyn_password missing")
		}
	})

	t.Run("pull request: repo level only", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "pull_request"})
		if _, ok := b.get("shared"); !ok {
			t.Errorf("names = %v", b.names())
		}
		if _, ok := b.get("db"); ok {
			t.Error("env secret on a PR")
		}
		if a := oneAudit(t); a["discovery_login"] == true || a["role"] != "e2e" {
			t.Errorf("audit = %v", a)
		}
	})

	t.Run("tag: repo level only", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "tag"})
		if _, ok := b.get("shared"); !ok || len(b.Secrets) != 2 {
			t.Errorf("names = %v", b.names())
		}
	})

	t.Run("explicit env refused from an unprotected branch", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "manual", branch: "feature", vars: explicitProd})
		if !onlyStatus(b) || !strings.Contains(statusOf(t, b), "outcome=refused") {
			t.Errorf("body = %v status %s", b.names(), statusOf(t, b))
		}
		if a := oneAudit(t); a["env_refused"] != true {
			t.Errorf("audit = %v", a)
		}
	})

	t.Run("invalid selectors: status only, no login", func(t *testing.T) {
		for name, o := range map[string]opts{
			"env grammar": {repo: repoA, event: "manual", branch: "main", vars: map[string]string{"DEPLOY_ENV": "Prod!"}},
			"dotdot":      {repo: repoA, event: "manual", branch: "main", vars: map[string]string{"DEPLOY_ENV": "prod", "DEPLOY_TO": "web/../x"}},
			"dot":         {repo: repoA, event: "deployment", branch: "main", deployTo: "./x", vars: explicitProd},
		} {
			_, b := send(t, o)
			if !onlyStatus(b) || !strings.Contains(statusOf(t, b), "outcome=invalid") || len(rec.accessors) != 0 {
				t.Errorf("%s: names %v status %s logins %d", name, b.names(), statusOf(t, b), len(rec.accessors))
			}
		}
	})

	t.Run("two claimants: config_error, discovery token revoked", func(t *testing.T) {
		_, b := send(t, opts{repo: repoB, branch: "main"})
		st := statusOf(t, b)
		if !onlyStatus(b) || !strings.Contains(st, "outcome=config_error") || !strings.Contains(st, "levels=beta,prod") {
			t.Errorf("body %v status %s", b.names(), st)
		}
		if len(rec.accessors) != 1 || !tokenDead(t, rec.accessors[0]) {
			t.Errorf("discovery token not revoked: %v", rec.accessors)
		}
	})

	t.Run("status-only ok response revokes the token", func(t *testing.T) {
		// A repo with nothing under it: the walk skips its levels, the
		// response carries only ironbark_status, and the token must die.
		_, b := send(t, opts{repo: uniq("e2ec"), event: "tag"})
		if !onlyStatus(b) || !strings.Contains(statusOf(t, b), "outcome=ok") || len(rec.accessors) != 1 || !tokenDead(t, rec.accessors[0]) {
			t.Errorf("names %v accessors %v", b.names(), rec.accessors)
		}
	})

	t.Run("vault_token present only with the marker mapping", func(t *testing.T) {
		_, b := send(t, opts{repo: repoA, event: "manual", branch: "main", vars: explicitProd})
		tok, ok := b.get("vault_token")
		if !ok || tok == "" {
			t.Fatalf("vault_token missing: %v", b.names())
		}
		for _, s := range b.Secrets {
			if s.Name == "vault_token" && (len(s.Images) != 1 || s.Images[0] != "deploy") {
				t.Errorf("images = %v", s.Images)
			}
		}
		if g.Code(tok, "vs/data/"+baseA+"prod/db") != 200 {
			t.Error("the returned vault_token must authenticate")
		}
		if a := oneAudit(t); a["vault_token_issued"] != true {
			t.Errorf("audit = %v", a)
		}
		_, b = send(t, opts{repo: repoA, event: "pull_request"})
		if _, ok := b.get("vault_token"); ok {
			t.Error("vault_token without a marker at a walked level")
		}
	})
}

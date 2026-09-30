//go:build integration

package integration

// Plan task 5.5: the real `ib` binary against the grant-model fixture, as a
// person: a static policy (design §12.2) instead of the templated CI ones,
// the caller's own token, no ironbark in the loop. All data is fake.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	ibBinOnce sync.Once
	ibBinPath string
	ibBinErr  error
)

// buildIBBinary builds cmd/ib once per test binary run.
func buildIBBinary(t *testing.T) string {
	t.Helper()
	ibBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ib-integration-bin")
		if err != nil {
			ibBinErr = err
			return
		}
		ibBinPath = filepath.Join(dir, "ib")
		if out, err := exec.Command("go", "build", "-o", ibBinPath, "github.com/navistau/ironbark/cmd/ib").CombinedOutput(); err != nil {
			ibBinErr = fmt.Errorf("go build ./cmd/ib: %w\n%s", err, out)
		}
	})
	if ibBinErr != nil {
		t.Fatalf("buildIBBinary: %v", ibBinErr)
	}
	return ibBinPath
}

// ibRepo makes a git checkout on branch whose origin is acme/<repo>. ib makes
// no network call, so the origin never has to exist.
func ibRepo(t *testing.T, org, repo, branch string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "empty.gitconfig")
	if err := os.WriteFile(cfg, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL": cfg, "GIT_CONFIG_SYSTEM": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
		"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
	} {
		t.Setenv(k, v)
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", branch},
		{"commit", "-q", "--allow-empty", "-m", "c0"},
		{"remote", "add", "origin", "https://forge.example/" + org + "/" + repo + ".git"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// humanToken is a token under a static personal policy for one repo: read on
// the repo level and on env's whole subtree, level metadata under the repo
// (env's own rule must carry "read" too: the most specific path wins, and the
// subtree glob would otherwise shadow the `+/` read),
// the env's dynamic role, and lease revocation. Nothing else.
func humanToken(t *testing.T, g *Grant, org, repo, env, dbRole string, levelMetadata bool) string {
	t.Helper()
	base := org + "/" + repo
	pol := fmt.Sprintf(`
path "vs/data/pipelines/%[1]s/+"            { capabilities = ["read"] }
path "vs/metadata/pipelines/%[1]s/"         { capabilities = ["list"] }
path "vs/data/pipelines/%[1]s/%[2]s/*"      { capabilities = ["read"] }
path "vs/metadata/pipelines/%[1]s/%[2]s/*"  { capabilities = ["list", "read"] }
path "database/creds/%[3]s"                 { capabilities = ["read"] }
path "sys/leases/revoke"                    { capabilities = ["update"] }
`, base, env, dbRole)
	if levelMetadata {
		pol += fmt.Sprintf("path \"vs/metadata/pipelines/%s/+/\" { capabilities = [\"read\"] }\n", base)
	}
	name := "ib-human-" + repo
	if err := g.Root.Sys().PutPolicy(name, pol); err != nil {
		t.Fatal(err)
	}
	s, err := g.Root.Logical().Write("auth/token/create", map[string]any{"policies": []string{name}, "ttl": "15m", "no_parent": true})
	if err != nil {
		t.Fatal(err)
	}
	return s.Auth.ClientToken
}

// runIB runs the built ib in dir against the fixture as token. HOME is empty,
// so no real ~/.config/ib/config is read.
func runIB(t *testing.T, g *Grant, token, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(buildIBBinary(t), args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(),
		"BAO_ADDR=" + g.Addr, "BAO_TOKEN=" + token,
		"IRONBARK_DATA_PATH=" + g.Mount + "/data/pipelines/{repo}/{env}/{target...}",
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run ib %v: %v", args, err)
		}
		return so.String(), se.String(), ee.ExitCode()
	}
	return so.String(), se.String(), 0
}

type ibEnvOut struct {
	Env     string            `json:"env"`
	Rule    string            `json:"rule"`
	Secrets map[string]string `json:"secrets"`
}

func ibEnvJSON(t *testing.T, g *Grant, token, dir string, args ...string) ibEnvOut {
	t.Helper()
	so, se, code := runIB(t, g, token, dir, append([]string{"env", "--output", "json"}, args...)...)
	if code != 0 {
		t.Fatalf("ib env %v exited %d: %s", args, code, se)
	}
	var out ibEnvOut
	if err := json.Unmarshal([]byte(so), &out); err != nil {
		t.Fatalf("ib env output: %v", err)
	}
	return out
}

func TestIBGrant(t *testing.T) {
	g := GetGrant(t)
	org, repo, env := "acme", uniq("ib"), uniq("e")
	base := "pipelines/" + org + "/" + repo + "/"
	dbRole := env + "-web"
	g.DBRole(t, dbRole)

	g.Secret(t, org+"/"+repo+"/repo_secret", "R")
	g.Secret(t, org+"/"+repo+"/"+env+"/env_secret", "E")
	g.Secret(t, org+"/"+repo+"/"+env+"/web/parent_secret", "P")
	g.Secret(t, org+"/"+repo+"/"+env+"/web/api/api_secret", "A")
	g.Secret(t, org+"/"+repo+"/"+env+"/web/cli/cli_secret", "C")
	g.Secret(t, org+"/"+repo+"/other/other_secret", "O")
	g.View(t, base+env+"/web/db", map[string]any{"mode": "resolve", "target": "database/creds/" + dbRole})
	g.Secret(t, org+"/"+repo+"/"+env+"/short", "ab1")
	g.Level(t, base+env, map[string]string{"branches": "release/*"})
	g.Level(t, base+"other", map[string]string{"branches": "main"})
	tok := humanToken(t, g, org, repo, env, dbRole, true)

	t.Run("static policy walks project, env and a nested target, and nothing beside", func(t *testing.T) {
		out := ibEnvJSON(t, g, tok, ibRepo(t, org, repo, "wip/x"), "--env", env, "--target", "web/api")
		want := map[string]string{"repo_secret": "R", "env_secret": "E", "short": "ab1", "parent_secret": "P", "api_secret": "A"}
		for n, v := range want {
			if out.Secrets[n] != v {
				t.Errorf("%s = %q, want %q", n, out.Secrets[n], v)
			}
		}
		for _, n := range []string{"cli_secret", "other_secret"} {
			if _, ok := out.Secrets[n]; ok {
				t.Errorf("%s must not be readable", n)
			}
		}
		if out.Env != env || out.Rule != "explicit" {
			t.Errorf("env, rule = %q, %q", out.Env, out.Rule)
		}
	})

	t.Run("discovery from the local branch", func(t *testing.T) {
		out := ibEnvJSON(t, g, tok, ibRepo(t, org, repo, "release/1"))
		if out.Env != env || out.Rule != "branch" || out.Secrets["env_secret"] != "E" {
			t.Errorf("release/1: env %q rule %q secrets %v", out.Env, out.Rule, out.Secrets)
		}
		out = ibEnvJSON(t, g, tok, ibRepo(t, org, repo, "wip/x"))
		if out.Env != "" || out.Rule != "none" || len(out.Secrets) != 1 || out.Secrets["repo_secret"] != "R" {
			t.Errorf("wip/x: env %q rule %q secrets %v", out.Env, out.Rule, out.Secrets)
		}
	})

	t.Run("several claimants exit 4 naming them", func(t *testing.T) {
		g.Level(t, base+"other", map[string]string{"branches": "release/*"})
		defer g.Level(t, base+"other", map[string]string{"branches": "main"})
		so, se, code := runIB(t, g, tok, ibRepo(t, org, repo, "release/1"), "env")
		if code != 4 || so != "" || !strings.Contains(se, env) || !strings.Contains(se, "other") {
			t.Errorf("code %d stdout %q stderr %q", code, so, se)
		}
	})

	t.Run("an env level whose metadata the caller cannot read fails closed", func(t *testing.T) {
		blind := humanToken(t, g, org, repo, env, dbRole, false)
		so, _, code := runIB(t, g, blind, ibRepo(t, org, repo, "release/1"), "env")
		if code == 0 || so != "" {
			t.Errorf("code %d stdout %q, want a failure and no secrets", code, so)
		}
	})

	t.Run("run: the resolve lease is the caller's and is revoked after the child", func(t *testing.T) {
		// Earlier subtests' `ib env` left leases to expire on TTL, as documented.
		g.Write(t, "sys/leases/revoke-prefix/database/creds/"+dbRole, nil)
		waitLeases(t, g, dbRole, 0)
		envFile := filepath.Join(t.TempDir(), "a.env")
		if err := os.WriteFile(envFile, []byte("DBU=ironbark://db_username\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		so, se, code := runIB(t, g, tok, ibRepo(t, org, repo, "wip/x"), "run", "--env", env, "--target", "web", "--env-file", envFile, "--no-masking", "--", "sh", "-c", "echo $DBU")
		if code != 0 || strings.TrimSpace(so) == "" {
			t.Fatalf("code %d stdout %q stderr %q", code, so, se)
		}
		waitLeases(t, g, dbRole, 0)
	})

	t.Run("run: every value is masked, however short; --no-masking shows it", func(t *testing.T) {
		envFile := filepath.Join(t.TempDir(), "a.env")
		if err := os.WriteFile(envFile, []byte("V=ironbark://short\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir := ibRepo(t, org, repo, "wip/x")
		so, _, code := runIB(t, g, tok, dir, "run", "--env", env, "--env-file", envFile, "--", "sh", "-c", `echo "x${V}x"`)
		if code != 0 || strings.Contains(so, "ab1") || !strings.Contains(so, "concealed") {
			t.Errorf("masked: code %d stdout %q", code, so)
		}
		so, _, _ = runIB(t, g, tok, dir, "run", "--env", env, "--env-file", envFile, "--no-masking", "--", "sh", "-c", "echo $V")
		if strings.TrimSpace(so) != "ab1" {
			t.Errorf("unmasked stdout = %q", so)
		}
	})

	t.Run("a reference the walk did not produce leaves the variable unset", func(t *testing.T) {
		envFile := filepath.Join(t.TempDir(), "a.env")
		if err := os.WriteFile(envFile, []byte("NOPE=ironbark://nothing_here\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		so, se, code := runIB(t, g, tok, ibRepo(t, org, repo, "wip/x"), "run", "--env", env, "--env-file", envFile, "--", "sh", "-c", "echo [$NOPE]")
		if code != 0 || strings.TrimSpace(so) != "[]" || !strings.Contains(se, "NOPE left unset") {
			t.Errorf("code %d stdout %q stderr %q", code, so, se)
		}
	})
}

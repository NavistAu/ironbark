package main

// Git fixture helpers for cmd/ib's own tests: a bare "forge" repo plus a
// clone, with the clone's origin URL rewritten (after cloning) to a
// CLIENT-SPEC-parseable form so identity.ParseRemote succeeds. This
// mirrors internal/gitenv/git_test.go's fixture (unexported there, so not
// importable across the package boundary) but adds the URL rewrite step
// gitenv's own tests don't need. Rewriting the URL only after the clone's
// initial fetch means refs/remotes/origin/* are already populated from the
// real (local, bare) remote; a later `git ls-remote origin` (gitenv.Facts'
// staleness check) then fails against the fake host — expected and
// non-fatal, matching gitenv's own TestFacts_LsRemoteFailure.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ibFixtureOriginURL is the fake-but-parseable origin every ibFixture ends
// up with: org=acme, repo=widgets (CLIENT-SPEC §2).
const ibFixtureOriginURL = "https://forge.example/acme/widgets.git"

func setGitTestEnv(t *testing.T) {
	t.Helper()

	cfg := filepath.Join(t.TempDir(), "empty.gitconfig")
	if err := os.WriteFile(cfg, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "ib-test")
	t.Setenv("GIT_AUTHOR_EMAIL", "ib-test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "ib-test")
	t.Setenv("GIT_COMMITTER_EMAIL", "ib-test@example.com")
}

func gitRaw(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v (dir=%s): %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commitFixture(t *testing.T, dir, content, msg string) {
	t.Helper()
	writeFixtureFile(t, filepath.Join(dir, "f.txt"), content)
	gitRaw(t, dir, "commit", "-q", "-am", msg)
}

// ibFixture is a bare "forge" repo, the seed repo used to populate it, and
// a clone of it — the clone is what tests point an ExecRunner at.
type ibFixture struct {
	forge string
	seed  string
	clone string
}

// newIBFixture builds forge (bare, branch main) <- seed (one commit on
// main, pushed) <- clone, then rewrites the clone's origin URL to
// ibFixtureOriginURL. extra, if non-nil, runs against the seed repo after
// main is pushed but before the clone is made — e.g. to push additional
// branches so the clone's fetch picks them up too.
func newIBFixture(t *testing.T, extra func(seedDir string)) ibFixture {
	t.Helper()
	setGitTestEnv(t)

	root := t.TempDir()
	fx := ibFixture{
		forge: filepath.Join(root, "forge.git"),
		seed:  filepath.Join(root, "seed"),
		clone: filepath.Join(root, "clone"),
	}

	gitRaw(t, root, "init", "-q", "--bare", "-b", "main", fx.forge)
	gitRaw(t, root, "init", "-q", "-b", "main", fx.seed)
	gitRaw(t, fx.seed, "config", "user.name", "ib-test")
	gitRaw(t, fx.seed, "config", "user.email", "ib-test@example.com")
	writeFixtureFile(t, filepath.Join(fx.seed, "f.txt"), "0")
	gitRaw(t, fx.seed, "add", "f.txt")
	gitRaw(t, fx.seed, "commit", "-q", "-m", "c0")
	gitRaw(t, fx.seed, "remote", "add", "origin", fx.forge)
	gitRaw(t, fx.seed, "push", "-q", "origin", "main")

	if extra != nil {
		extra(fx.seed)
	}

	gitRaw(t, root, "clone", "-q", fx.forge, fx.clone)
	gitRaw(t, fx.clone, "config", "user.name", "ib-test")
	gitRaw(t, fx.clone, "config", "user.email", "ib-test@example.com")
	gitRaw(t, fx.clone, "remote", "set-url", "origin", ibFixtureOriginURL)

	return fx
}

// pushBranch checks out a new branch named name from "from" in the seed
// repo, adds n commits, and pushes it — for use as newIBFixture's extra
// callback.
func pushBranch(t *testing.T, seedDir, name, from string, n int) {
	t.Helper()
	gitRaw(t, seedDir, "checkout", "-q", "-b", name, from)
	for i := 0; i < n; i++ {
		commitFixture(t, seedDir, name+"-"+strconv.Itoa(i), name+"-commit-"+strconv.Itoa(i))
	}
	gitRaw(t, seedDir, "push", "-q", "origin", name)
}

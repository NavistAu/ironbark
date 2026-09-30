package gitenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setGitTestEnv isolates git's config resolution for the fixture repos
// built in this file: no global/system gitconfig, no network, a fixed
// committer identity so commits succeed without a real user profile.
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

// gitRaw runs git directly (not through the Runner under test) to build
// fixture repos.
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

func commit(t *testing.T, dir, content, msg string) {
	t.Helper()
	writeFixtureFile(t, filepath.Join(dir, "f.txt"), content)
	gitRaw(t, dir, "commit", "-q", "-am", msg)
}

// fixture is a bare "forge" repo plus a clone of it, with local
// user.name/email set on every working repo, no network involved (the
// remote is a local filesystem path).
type fixture struct {
	forge string
	seed  string
	clone string
}

// newFixture builds: forge (bare) <- seed (pushes main, then develop with
// one extra commit) <- clone. main has 1 commit, develop has 2.
func newFixture(t *testing.T) fixture {
	t.Helper()
	setGitTestEnv(t)

	root := t.TempDir()
	fx := fixture{
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

	gitRaw(t, fx.seed, "checkout", "-q", "-b", "develop")
	commit(t, fx.seed, "1", "c1")
	gitRaw(t, fx.seed, "push", "-q", "origin", "develop")

	gitRaw(t, root, "clone", "-q", fx.forge, fx.clone)
	gitRaw(t, fx.clone, "config", "user.name", "ib-test")
	gitRaw(t, fx.clone, "config", "user.email", "ib-test@example.com")

	return fx
}

func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	sa, err := os.Stat(a)
	if err != nil {
		t.Fatalf("stat %s: %v", a, err)
	}
	sb, err := os.Stat(b)
	if err != nil {
		t.Fatalf("stat %s: %v", b, err)
	}
	return os.SameFile(sa, sb)
}

func TestCheckout_Basics(t *testing.T) {
	fx := newFixture(t)
	r := ExecRunner{Dir: fx.clone}

	info, err := Checkout(r)
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}
	if !sameDir(t, info.TopLevel, fx.clone) {
		t.Errorf("TopLevel = %q, want same dir as %q", info.TopLevel, fx.clone)
	}
	if info.Branch != "main" {
		t.Errorf("Branch = %q, want main", info.Branch)
	}
	if info.Detached {
		t.Errorf("Detached = true, want false")
	}
	if info.OriginURL != fx.forge {
		t.Errorf("OriginURL = %q, want %q", info.OriginURL, fx.forge)
	}
}

func TestCheckout_Detached(t *testing.T) {
	fx := newFixture(t)
	gitRaw(t, fx.clone, "checkout", "-q", "--detach", "HEAD")
	r := ExecRunner{Dir: fx.clone}

	info, err := Checkout(r)
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}
	if !info.Detached {
		t.Errorf("Detached = false, want true")
	}
	if info.Branch != "" {
		t.Errorf("Branch = %q, want empty", info.Branch)
	}
}

func TestCheckout_NotAGitRepo(t *testing.T) {
	setGitTestEnv(t)
	dir := t.TempDir()
	r := ExecRunner{Dir: dir}

	_, err := Checkout(r)
	if err == nil {
		t.Fatal("Checkout: expected error, got nil")
	}
	if _, ok := err.(*CheckoutError); !ok {
		t.Errorf("Checkout error type = %T, want *CheckoutError", err)
	}
}

func TestCheckout_NoOrigin(t *testing.T) {
	setGitTestEnv(t)
	dir := t.TempDir()
	gitRaw(t, dir, "init", "-q", "-b", "main", dir)
	gitRaw(t, dir, "config", "user.name", "ib-test")
	gitRaw(t, dir, "config", "user.email", "ib-test@example.com")
	writeFixtureFile(t, filepath.Join(dir, "f.txt"), "0")
	gitRaw(t, dir, "add", "f.txt")
	gitRaw(t, dir, "commit", "-q", "-m", "c0")

	r := ExecRunner{Dir: dir}
	_, err := Checkout(r)
	if err == nil {
		t.Fatal("Checkout: expected error, got nil")
	}
	if _, ok := err.(*CheckoutError); !ok {
		t.Errorf("Checkout error type = %T, want *CheckoutError", err)
	}
}

// writeFakeGit writes an executable named "git" at dir/git running script
// (a #!/bin/sh body), and prepends dir to PATH for the duration of the
// test — so ExecRunner's hardcoded exec.Command("git", ...) resolves to
// this fake instead of the real git.
func writeFakeGit(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "git")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestExecRunner_GitEnvNonInteractive proves every git invocation from ib
// runs with GIT_TERMINAL_PROMPT=0 and GIT_SSH_COMMAND set to a
// non-interactive (BatchMode) form (I4), regardless of whatever the
// caller's own environment already has set for either variable.
func TestExecRunner_GitEnvNonInteractive(t *testing.T) {
	writeFakeGit(t, `echo "TERM_PROMPT=$GIT_TERMINAL_PROMPT"
echo "SSH_COMMAND=$GIT_SSH_COMMAND"
`)
	t.Setenv("GIT_TERMINAL_PROMPT", "1")
	t.Setenv("GIT_SSH_COMMAND", "ssh -oSomethingInteractive=yes")

	r := ExecRunner{Dir: t.TempDir()}
	out, err := r.Git("status")
	if err != nil {
		t.Fatalf("Git: %v", err)
	}
	if !strings.Contains(out, "TERM_PROMPT=0") {
		t.Errorf("output = %q, want GIT_TERMINAL_PROMPT=0 regardless of the caller's own env", out)
	}
	if !strings.Contains(out, "SSH_COMMAND=ssh -o BatchMode=yes") {
		t.Errorf("output = %q, want a forced non-interactive GIT_SSH_COMMAND", out)
	}
}

// TestExecRunner_LsRemoteTimeout proves a hanging `git ls-remote` is
// bounded by lsRemoteTimeout (I4) rather than blocking forever — shrunk
// here so the test itself stays fast.
func TestExecRunner_LsRemoteTimeout(t *testing.T) {
	writeFakeGit(t, "sleep 5\n")

	orig := lsRemoteTimeout
	lsRemoteTimeout = 100 * time.Millisecond
	t.Cleanup(func() { lsRemoteTimeout = orig })

	r := ExecRunner{Dir: t.TempDir()}
	start := time.Now()
	_, err := r.Git("ls-remote", "--heads", "origin")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Git(ls-remote): expected an error (timeout), got nil")
	}
	if elapsed > 3*time.Second {
		t.Errorf("Git(ls-remote) took %v, want it bounded by the shrunk lsRemoteTimeout", elapsed)
	}
}

// TestExecRunner_NonLsRemoteCommandsNotTimeBounded proves the 10s bound is
// specific to ls-remote (the one git command ib runs that touches the
// network) — an ordinary local git command is not subject to it.
func TestExecRunner_NonLsRemoteCommandsNotTimeBounded(t *testing.T) {
	orig := lsRemoteTimeout
	lsRemoteTimeout = 50 * time.Millisecond
	t.Cleanup(func() { lsRemoteTimeout = orig })

	writeFakeGit(t, "sleep 0.2\necho ok\n")

	r := ExecRunner{Dir: t.TempDir()}
	out, err := r.Git("status")
	if err != nil {
		t.Fatalf("Git(status): %v, want it to finish (not ls-remote-bounded)", err)
	}
	if strings.TrimSpace(out) != "ok" {
		t.Errorf("Git(status) = %q, want %q", out, "ok")
	}
}

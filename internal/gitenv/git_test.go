package gitenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
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

// TestFacts_NearestAncestorDistances reproduces the Task 5 example
// distances (develop 3, main 13): develop accumulates 10 commits ahead of
// main, then "feature" branches from origin/develop and adds 3 more.
func TestFacts_NearestAncestorDistances(t *testing.T) {
	fx := newFixture(t)

	// Push develop out to 10 commits ahead of main (it already has c1).
	for i := 2; i <= 10; i++ {
		commit(t, fx.seed, "d"+string(rune('0'+i)), "develop-commit")
	}
	gitRaw(t, fx.seed, "push", "-q", "origin", "develop")

	gitRaw(t, fx.clone, "fetch", "-q", "origin")
	gitRaw(t, fx.clone, "checkout", "-q", "-b", "feature", "origin/develop")
	for i := 1; i <= 3; i++ {
		commit(t, fx.clone, "f"+string(rune('0'+i)), "feature-commit")
	}

	r := ExecRunner{Dir: fx.clone}
	tracked, dist, reflogFrom, stale, lsErr := Facts(r, "feature", []string{"main", "develop"})

	wantTracked := []string{"develop", "main"}
	sort.Strings(tracked)
	if !reflect.DeepEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v", tracked, wantTracked)
	}
	wantDist := map[string]int{"develop": 3, "main": 13}
	if !reflect.DeepEqual(dist, wantDist) {
		t.Errorf("dist = %v, want %v", dist, wantDist)
	}
	if reflogFrom != "develop" {
		t.Errorf("reflogFrom = %q, want develop", reflogFrom)
	}
	if stale != nil {
		t.Errorf("stale = %v, want nil", stale)
	}
	if lsErr != nil {
		t.Errorf("lsRemoteErr = %v, want nil", lsErr)
	}
}

// TestFacts_Worktree asserts a linked worktree (whose .git is a file)
// yields the same facts as a normal checkout, including the reflog
// pointing at the branch it was cut from.
func TestFacts_Worktree(t *testing.T) {
	fx := newFixture(t)
	wt := filepath.Join(filepath.Dir(fx.clone), "wt")

	// Use the explicit origin/develop ref as the start point: this git
	// version's "worktree add" DWIMs a bare branch name that only exists
	// as a remote-tracking ref into checking out THAT name instead of
	// honoring -b (reproduced independently of this package; verified
	// against git 2.55.0). The explicit ref sidesteps it and is exactly
	// equivalent to CLIENT-SPEC's "branch cut from develop" scenario.
	gitRaw(t, fx.clone, "worktree", "add", "-q", "-b", "feat", wt, "origin/develop")

	r := ExecRunner{Dir: wt}

	top, err := ExecRunner{Dir: wt}.Git("rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("rev-parse --show-toplevel in worktree: %v", err)
	}
	if !sameDir(t, top, wt) {
		t.Errorf("worktree TopLevel = %q, want same dir as %q", top, wt)
	}

	tracked, dist, reflogFrom, stale, lsErr := Facts(r, "feat", []string{"main", "develop"})

	wantTracked := []string{"develop", "main"}
	sort.Strings(tracked)
	if !reflect.DeepEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v", tracked, wantTracked)
	}
	wantDist := map[string]int{"develop": 0, "main": 1}
	if !reflect.DeepEqual(dist, wantDist) {
		t.Errorf("dist = %v, want %v", dist, wantDist)
	}
	if reflogFrom != "develop" {
		t.Errorf("reflogFrom = %q, want develop", reflogFrom)
	}
	if stale != nil {
		t.Errorf("stale = %v, want nil", stale)
	}
	if lsErr != nil {
		t.Errorf("lsRemoteErr = %v, want nil", lsErr)
	}
}

func TestFacts_Detached(t *testing.T) {
	fx := newFixture(t)
	gitRaw(t, fx.clone, "checkout", "-q", "--detach", "HEAD")
	r := ExecRunner{Dir: fx.clone}

	tracked, dist, reflogFrom, _, lsErr := Facts(r, "", []string{"main", "develop"})

	wantTracked := []string{"develop", "main"}
	sort.Strings(tracked)
	if !reflect.DeepEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v", tracked, wantTracked)
	}
	// Detached at main's tip (c0), which is also an ancestor of
	// origin/develop (c0, c1): 0 commits unique to HEAD on either side.
	wantDist := map[string]int{"develop": 0, "main": 0}
	if !reflect.DeepEqual(dist, wantDist) {
		t.Errorf("dist = %v, want %v", dist, wantDist)
	}
	if reflogFrom != "" {
		t.Errorf("reflogFrom = %q, want empty (detached: no checked-out branch)", reflogFrom)
	}
	if lsErr != nil {
		t.Errorf("lsRemoteErr = %v, want nil", lsErr)
	}
}

func TestFacts_OrphanNoAncestor(t *testing.T) {
	fx := newFixture(t)
	gitRaw(t, fx.clone, "checkout", "-q", "--orphan", "orphan1")
	gitRaw(t, fx.clone, "rm", "-q", "-r", "--cached", ".")
	writeFixtureFile(t, filepath.Join(fx.clone, "o.txt"), "orphan")
	gitRaw(t, fx.clone, "add", "o.txt")
	gitRaw(t, fx.clone, "commit", "-q", "-m", "orphan-commit")

	r := ExecRunner{Dir: fx.clone}
	tracked, dist, _, _, lsErr := Facts(r, "orphan1", []string{"main", "develop"})

	wantTracked := []string{"develop", "main"}
	sort.Strings(tracked)
	if !reflect.DeepEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v", tracked, wantTracked)
	}
	if len(dist) != 0 {
		t.Errorf("dist = %v, want empty (no common history)", dist)
	}
	if lsErr != nil {
		t.Errorf("lsRemoteErr = %v, want nil", lsErr)
	}
}

func TestFacts_StaleRef(t *testing.T) {
	fx := newFixture(t)

	// The forge advances develop after the clone already fetched it.
	commit(t, fx.seed, "2", "c2-on-forge")
	gitRaw(t, fx.seed, "push", "-q", "origin", "develop")

	r := ExecRunner{Dir: fx.clone}
	_, _, _, stale, lsErr := Facts(r, "main", []string{"main", "develop"})

	if lsErr != nil {
		t.Fatalf("lsRemoteErr = %v, want nil", lsErr)
	}
	if !reflect.DeepEqual(stale, []string{"develop"}) {
		t.Errorf("stale = %v, want [develop]", stale)
	}
}

// TestFacts_LocalBranchNameCollisionWithRemoteShortName reproduces a git
// `%(refname:short)` gotcha (M5): when a LOCAL branch happens to be named
// "origin/<name>" — colliding with what a remote-tracking branch's short
// form would otherwise be — git's shortening degrades
// refs/remotes/origin/<name> to the unhelpful "remotes/origin/<name>"
// instead of "origin/<name>" (verified against git 2.x: shortening avoids
// an ambiguous result). A plain TrimPrefix("origin/") then leaves the
// name unrecognizable and the branch silently looks untracked.
// `%(refname:lstrip=3)` sidesteps the ambiguity entirely: it always
// strips exactly the three refs/remotes/origin/ components, regardless of
// any colliding local branch.
func TestFacts_LocalBranchNameCollisionWithRemoteShortName(t *testing.T) {
	fx := newFixture(t)

	gitRaw(t, fx.seed, "checkout", "-q", "-b", "conflict", "main")
	commit(t, fx.seed, "c-conflict", "conflict-commit")
	gitRaw(t, fx.seed, "push", "-q", "origin", "conflict")

	gitRaw(t, fx.clone, "fetch", "-q", "origin")
	// A LOCAL branch literally named "origin/conflict" collides with the
	// short form git would otherwise give refs/remotes/origin/conflict.
	gitRaw(t, fx.clone, "branch", "origin/conflict", "main")

	r := ExecRunner{Dir: fx.clone}
	tracked, _, _, _, lsErr := Facts(r, "main", []string{"conflict"})
	if lsErr != nil {
		t.Fatalf("lsRemoteErr = %v, want nil", lsErr)
	}
	if !contains(tracked, "conflict") {
		t.Errorf("tracked = %v, want it to include %q despite the colliding local branch name", tracked, "conflict")
	}
}

// TestFacts_ReflogHexLetteredBranchName reproduces M6: a branch named
// entirely with hex-alphabet letters (e.g. "cafe") looks, byte for byte,
// exactly like an abbreviated SHA. isSHA's old byte-pattern heuristic
// misclassified it as a SHA and cleared reflogFrom to "", losing the
// CLIENT-SPEC §3 rule 4 tie-break entirely for such a branch. Checking
// whether refs/heads/<X> or refs/remotes/origin/<X> actually exists
// (rather than guessing from X's byte pattern) gets this right.
func TestFacts_ReflogHexLetteredBranchName(t *testing.T) {
	fx := newFixture(t)

	gitRaw(t, fx.seed, "checkout", "-q", "-b", "cafe", "main")
	commit(t, fx.seed, "c-cafe", "cafe-commit")
	gitRaw(t, fx.seed, "push", "-q", "origin", "cafe")

	gitRaw(t, fx.clone, "fetch", "-q", "origin")
	gitRaw(t, fx.clone, "checkout", "-q", "-b", "work", "origin/cafe")

	r := ExecRunner{Dir: fx.clone}
	_, _, reflogFrom, _, lsErr := Facts(r, "work", []string{"cafe"})
	if lsErr != nil {
		t.Fatalf("lsRemoteErr = %v, want nil", lsErr)
	}
	if reflogFrom != "cafe" {
		t.Errorf("reflogFrom = %q, want %q (a hex-lettered branch name is not a SHA)", reflogFrom, "cafe")
	}
}

// TestFacts_ReflogNonexistentNameIgnored reproduces T2's "leading '.'"
// case: a git reflog's "branch: Created from <X>" message is free text,
// not itself validated against real refs — X could name something that
// isn't (and, since git rejects any dot-led ref component, could never
// be) an actual branch. Facts must treat that as unknown (reflogFrom ==
// "") rather than propagating an impossible name forward, which the old
// isSHA-only check did not do (a non-hex string was always accepted as a
// branch name, with no existence check at all).
func TestFacts_ReflogNonexistentNameIgnored(t *testing.T) {
	fx := newFixture(t)
	gitRaw(t, fx.clone, "checkout", "-q", "-b", "work", "main")

	// Fabricate a reflog entry no real git operation could produce: a
	// "Created from" target that is not, and could never be, a real ref
	// (git rejects any dot-led ref component).
	sha := gitRaw(t, fx.clone, "rev-parse", "HEAD")
	logPath := filepath.Join(fx.clone, ".git", "logs", "refs", "heads", "work")
	line := sha + " " + sha + " ib-test <ib-test@example.com> 1700000000 +0000\tbranch: Created from .hidden\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	r := ExecRunner{Dir: fx.clone}
	_, _, reflogFrom, _, lsErr := Facts(r, "work", []string{"main", "develop"})
	if lsErr != nil {
		t.Fatalf("lsRemoteErr = %v, want nil", lsErr)
	}
	if reflogFrom != "" {
		t.Errorf("reflogFrom = %q, want empty (no such branch exists)", reflogFrom)
	}
}

func TestFacts_LsRemoteFailure(t *testing.T) {
	fx := newFixture(t)
	gitRaw(t, fx.clone, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "does-not-exist.git"))

	r := ExecRunner{Dir: fx.clone}
	tracked, dist, _, stale, lsErr := Facts(r, "main", []string{"main", "develop"})

	if lsErr == nil {
		t.Fatal("lsRemoteErr = nil, want non-nil")
	}
	if stale != nil {
		t.Errorf("stale = %v, want nil", stale)
	}
	// tracked/dist do not depend on ls-remote and should still be populated:
	// HEAD is main's tip (c0), which is also an ancestor of origin/develop
	// (c0, c1), so both distances are 0.
	wantTracked := []string{"develop", "main"}
	sort.Strings(tracked)
	if !reflect.DeepEqual(tracked, wantTracked) {
		t.Errorf("tracked = %v, want %v", tracked, wantTracked)
	}
	wantDist := map[string]int{"develop": 0, "main": 0}
	if !reflect.DeepEqual(dist, wantDist) {
		t.Errorf("dist = %v, want %v", dist, wantDist)
	}
}

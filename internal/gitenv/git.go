package gitenv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/navistau/ironbark/internal/identity"
)

// lsRemoteTimeout bounds how long a `git ls-remote` invocation — the only
// git command ib runs that touches the network (CLIENT-SPEC §3's
// staleness check) — may block before ib gives up, per I4. A package
// variable rather than a constant so tests can shrink it. On expiry or
// any other failure, the caller (gitenv.Facts/Ancestry) already reports
// CLIENT-SPEC §3's "freshness unknown" warning.
var lsRemoteTimeout = 10 * time.Second

// Runner runs git with the given arguments and returns trimmed stdout on
// success. On failure, the returned error's message includes stderr.
type Runner interface {
	Git(args ...string) (string, error)
}

// ExecRunner runs git as a subprocess rooted at Dir, inheriting the
// current process's environment. Tests control git's behavior (isolation
// from global config, committer identity, ...) via os.Setenv/t.Setenv,
// since a child process with a nil Env inherits the parent's.
type ExecRunner struct {
	Dir string
}

// Git implements Runner.
func (r ExecRunner) Git(args ...string) (string, error) {
	ctx := context.Background()
	if len(args) > 0 && args[0] == "ls-remote" {
		// I4: the only git command ib runs that touches the network is
		// bounded, so an unreachable/hanging forge can't hang ib.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lsRemoteTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.Dir
	cmd.Env = nonInteractiveGitEnv()
	// If ls-remote's context deadline fires, killing git itself is not
	// enough to bound the wait: a child it spawned (e.g. ssh) can inherit
	// the stdout/stderr pipes and keep them open after git exits. WaitDelay
	// forces the pipes closed (and Wait to return) shortly after
	// cancellation regardless. Harmless for every other call here, which
	// never cancels.
	cmd.WaitDelay = time.Second

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// nonInteractiveGitEnv returns the current process's environment with
// GIT_TERMINAL_PROMPT and GIT_SSH_COMMAND forced to non-interactive
// values (I4), so a git invocation from ib can never block on a
// credential prompt — regardless of what the caller's own environment, or
// a bao/vault-adjacent tool config, might otherwise set for either.
func nonInteractiveGitEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_TERMINAL_PROMPT=") || strings.HasPrefix(kv, "GIT_SSH_COMMAND=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -o BatchMode=yes")
	return out
}

// CheckoutError indicates the target directory is not usable as an ib
// checkout: not inside a git working tree, or lacking an "origin" remote.
// cmd/ib maps it to exit 2 (CLIENT-SPEC §7).
type CheckoutError struct {
	Msg string
	Err error
}

func (e *CheckoutError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *CheckoutError) Unwrap() error { return e.Err }

// CheckoutInfo is what Checkout learns about a working tree.
type CheckoutInfo struct {
	// TopLevel is the working tree root (git rev-parse --show-toplevel);
	// this resolves correctly for a linked worktree too, whose .git is a
	// file rather than a directory.
	TopLevel string
	// Branch is the checked-out branch's short name, or "" when Detached.
	Branch string
	// Detached is true for a detached HEAD.
	Detached bool
	// OriginURL is the "origin" remote's URL, verbatim.
	OriginURL string
}

// Checkout locates the working tree rooted wherever r runs git, and reads
// its checked-out branch (or detached state) and origin remote. Not a git
// checkout, or no "origin" remote, returns a *CheckoutError.
func Checkout(r Runner) (CheckoutInfo, error) {
	top, err := r.Git("rev-parse", "--show-toplevel")
	if err != nil {
		return CheckoutInfo{}, &CheckoutError{Msg: "not a git checkout", Err: err}
	}

	info := CheckoutInfo{TopLevel: top}

	if branch, err := r.Git("symbolic-ref", "-q", "--short", "HEAD"); err != nil {
		info.Detached = true
	} else {
		info.Branch = branch
	}

	origin, err := r.Git("remote", "get-url", "origin")
	if err != nil {
		return CheckoutInfo{}, &CheckoutError{Msg: "no origin remote", Err: err}
	}
	info.OriginURL = origin

	return info, nil
}

// TrackedBranches returns which of tiers (the branch directory names
// visible under <B>/push/, already escaped in identity.Esc form) are
// tracked branches: a remote-tracking ref origin/T whose escaped name
// matches a tier, or the checked-out branch itself (current) if its
// escaped name matches a tier even with no remote-tracking ref. Only
// local git calls (for-each-ref) — no network.
//
// current is the checked-out branch's short name ("" when detached).
func TrackedBranches(r Runner, current string, tiers []string) []string {
	tierSet := make(map[string]bool, len(tiers))
	for _, t := range tiers {
		tierSet[t] = true
	}

	trackedSet := make(map[string]bool)
	// M5: %(refname:lstrip=3) always strips exactly the three
	// refs/remotes/origin/ path components, unlike %(refname:short) —
	// whose shortening degrades to a longer, unstripped form (e.g.
	// "remotes/origin/<name>") when a LOCAL branch happens to collide
	// with the short name it would otherwise produce.
	if out, err := r.Git("for-each-ref", "--format=%(refname:lstrip=3)", "refs/remotes/origin"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			name := strings.TrimSpace(line)
			if name == "" || name == "HEAD" {
				// refs/remotes/origin/HEAD lstrips to "HEAD".
				continue
			}
			if tierSet[identity.Esc(name)] {
				trackedSet[name] = true
			}
		}
	}
	// Direct match works without a remote-tracking ref.
	if current != "" && tierSet[identity.Esc(current)] {
		trackedSet[current] = true
	}

	tracked := make([]string, 0, len(trackedSet))
	for name := range trackedSet {
		tracked = append(tracked, name)
	}
	sort.Strings(tracked)
	return tracked
}

// Ancestry gathers CLIENT-SPEC §3 rule 3+ facts for the tracked branches:
// each one's ancestor distance from HEAD, the checked-out branch's reflog
// creation entry, and (the "Stale refs" check) which tracked branches'
// origin/T disagrees with the forge — the one network call this package
// makes (`git ls-remote`). Callers only need this when rules 1-2
// (override, direct match) did not already decide (NeedsAncestry):
// CLIENT-SPEC §3 explicitly runs the staleness check "before rule 3", not
// before rules 1-2.
func Ancestry(r Runner, current string, tracked []string) (dist map[string]int, reflogFrom string, stale []string, lsRemoteErr error) {
	dist = make(map[string]int)
	for _, t := range tracked {
		ref := "origin/" + t
		if _, err := r.Git("rev-parse", "--verify", "-q", ref); err != nil {
			continue // no origin/T
		}
		if _, err := r.Git("merge-base", "HEAD", ref); err != nil {
			continue // no common history
		}
		out, err := r.Git("rev-list", "--count", ref+"..HEAD")
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(out)
		if err != nil {
			continue
		}
		dist[t] = n
	}

	reflogFrom = ""
	if current != "" {
		if out, err := r.Git("reflog", "show", "--format=%gs", "refs/heads/"+current); err == nil {
			const prefix = "branch: Created from "
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, prefix) {
					continue
				}
				// "Last line matching": the reflog is newest-first, so the
				// branch-creation entry is normally the last line and the
				// bottommost match; keep overwriting so the final match
				// wins if more than one line happens to match.
				ref := strings.TrimPrefix(line, prefix)
				ref = strings.TrimPrefix(ref, "refs/heads/")
				ref = strings.TrimPrefix(ref, "refs/remotes/origin/")
				ref = strings.TrimPrefix(ref, "origin/")
				if ref == "HEAD" || !branchRefExists(r, ref) {
					reflogFrom = ""
				} else {
					reflogFrom = ref
				}
			}
		}
	}

	out, err := r.Git("ls-remote", "--heads", "origin")
	if err != nil {
		return dist, reflogFrom, nil, err
	}

	forgeSHA := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "refs/heads/")
		forgeSHA[name] = fields[0]
	}

	var staleList []string
	for _, t := range tracked {
		localSHA, err := r.Git("rev-parse", "origin/"+t)
		if err != nil {
			continue
		}
		if fsha, ok := forgeSHA[t]; ok && fsha != localSHA {
			staleList = append(staleList, t)
		}
	}
	sort.Strings(staleList)

	return dist, reflogFrom, staleList, nil
}

// Facts is TrackedBranches followed unconditionally by Ancestry — kept for
// callers (and tests) that want every fact in one call. cmd/ib's resolve
// pipeline calls the two separately instead, per M1: Ancestry's ls-remote
// network call must not run before rules 1-2 have had a chance to decide
// (NeedsAncestry).
func Facts(r Runner, current string, tiers []string) (tracked []string, dist map[string]int, reflogFrom string, stale []string, lsRemoteErr error) {
	tracked = TrackedBranches(r, current, tiers)
	dist, reflogFrom, stale, lsRemoteErr = Ancestry(r, current, tracked)
	return tracked, dist, reflogFrom, stale, lsRemoteErr
}

// branchRefExists reports whether name is a real branch — a local
// refs/heads/<name> or remote-tracking refs/remotes/origin/<name> ref
// actually exists. Used to classify a git reflog's free-text "Created
// from <X>" entry (CLIENT-SPEC §3 rule 4): X is a branch only if one of
// these refs exists; anything else — a SHA, or free text that merely
// looks like one (M6: a byte-pattern heuristic alone misclassifies a
// valid hex-lettered branch name like "cafe" as a SHA), or a name that
// could never be a real ref at all — is not.
func branchRefExists(r Runner, name string) bool {
	if _, err := r.Git("rev-parse", "--verify", "-q", "refs/heads/"+name); err == nil {
		return true
	}
	if _, err := r.Git("rev-parse", "--verify", "-q", "refs/remotes/origin/"+name); err == nil {
		return true
	}
	return false
}

package gitenv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
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

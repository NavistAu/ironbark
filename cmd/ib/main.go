// Command ib is ironbark's local client: it gives a local run the same
// secrets a CI run on the same repository and environment would get
// (docs/CLIENT-SPEC.md). This file is wiring only: argument dispatch,
// flag parsing, and building each command's dependencies (internal/ibcfg,
// internal/vaultx, internal/gitenv) from the real environment. The actual
// behaviour lives in resolve.go/get.go/env.go/run.go/auth.go.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/ibcfg"
	"github.com/navistau/ironbark/internal/vaultx"
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// dispatch is main's testable core: it never calls os.Exit itself.
func dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: ib <get|env|run|auth> ...")
		return 1
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "get":
		return dispatchGet(rest, stdout, stderr)
	case "env":
		return dispatchEnv(rest, stdout, stderr)
	case "run":
		return dispatchRun(rest, stdin, stdout, stderr)
	case "auth":
		return cmdAuth(rest, stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "ib: unknown command %q\n", cmd)
		return 1
	}
}

// buildResolveOpts loads CLIENT-SPEC §5 configuration from the real
// environment and builds the resolveOpts every get/env/run invocation
// shares. branchFlag is the command's own --branch value ("" if unset);
// it wins over IB_BRANCH (ibcfg.Config.Branch) per CLIENT-SPEC §1.
func buildResolveOpts(branchFlag string, stderr io.Writer) (resolveOpts, error) {
	home, _ := os.UserHomeDir()
	cfg, err := ibcfg.Load(os.Getenv, home)
	if err != nil {
		return resolveOpts{}, fmt.Errorf("%w: %v", errConfig, err)
	}

	vc, err := vaultx.New(vaultx.Config{
		Addr:     cfg.Addr,
		KVMount:  cfg.KVMount,
		KVPrefix: cfg.KVPrefix,
		TLS:      cfg.TLS,
	})
	if err != nil {
		return resolveOpts{}, fmt.Errorf("%w: %v", errConfig, err)
	}

	branch := branchFlag
	if branch == "" {
		branch = cfg.Branch
	}

	return resolveOpts{
		Runner: gitenv.ExecRunner{},
		Vault:  vc,
		Token:  cfg.Token,
		Branch: branch,
		Stderr: stderr,
	}, nil
}

// stdoutIsTerminal reports whether w is a character-device *os.File
// (CLIENT-SPEC §1.2's trailing-newline rule for `ib get`). A non-*os.File
// writer (e.g. a test's bytes.Buffer) is never a terminal.
func stdoutIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// splitBranchFlag pulls a --branch <name> (or --branch=<name>, or the
// single-dash form) pair out of args wherever it appears, returning the
// branch value ("" if not given) and the remaining args in their original
// relative order (M8). Go's flag package alone stops parsing at the first
// non-flag argument, so `ib get NAME --branch x` would otherwise leave
// both NAME and --branch/x as unrecognized positional args — get/env's
// --branch (CLIENT-SPEC §1) needs to work regardless of where it appears.
// ib run does NOT use this: its own "--" already marks where ib's flags
// end and the child command begins, so flags-after-positionals has no
// meaning there.
func splitBranchFlag(args []string) (branch string, rest []string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--branch" || a == "-branch":
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("%w: %s needs a value", errUsage, a)
			}
			i++
			branch = args[i]
		case strings.HasPrefix(a, "--branch="):
			branch = strings.TrimPrefix(a, "--branch=")
		case strings.HasPrefix(a, "-branch="):
			branch = strings.TrimPrefix(a, "-branch=")
		default:
			rest = append(rest, a)
		}
	}
	return branch, rest, nil
}

func dispatchGet(args []string, stdout, stderr io.Writer) int {
	branch, rest, err := splitBranchFlag(args)
	if err != nil || len(rest) != 1 {
		fmt.Fprintln(stderr, "ib: usage: ib get [--branch <name>] <name>")
		return 1
	}

	opts, err := buildResolveOpts(branch, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}

	if err := cmdGet(context.Background(), rest[0], opts, stdout, stdoutIsTerminal(stdout)); err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}
	return 0
}

func dispatchEnv(args []string, stdout, stderr io.Writer) int {
	branch, rest, err := splitBranchFlag(args)
	if err != nil || len(rest) != 0 {
		fmt.Fprintln(stderr, "ib: usage: ib env [--branch <name>]")
		return 1
	}

	opts, err := buildResolveOpts(branch, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}

	if err := cmdEnv(context.Background(), opts, stdout); err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}
	return 0
}

func dispatchRun(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	runOpts, branch, cmdArgs, err := parseRunArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}

	// M2: building resolveOpts loads CLIENT-SPEC §5 Vault configuration,
	// which a run with no ironbark:// reference at all doesn't need — so
	// it's deferred to cmdRun, which only calls this when a reference is
	// actually present.
	buildOpts := func() (resolveOpts, error) { return buildResolveOpts(branch, stderr) }

	return cmdRun(context.Background(), runOpts, cmdArgs, buildOpts, os.Environ(), stdin, stdout, stderr)
}

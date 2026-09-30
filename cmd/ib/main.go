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

// buildResolveOpts loads configuration (CLIENT-SPEC §5) and builds the
// resolveOpts every get/env/run invocation shares. envFlag and targetFlag
// are the command's own --env/--target ("" if unset); each wins over
// IB_ENV/IB_TARGET.
func buildResolveOpts(envFlag, targetFlag string, stderr io.Writer) (resolveOpts, error) {
	home, _ := os.UserHomeDir()
	cfg, err := ibcfg.Load(os.Getenv, home)
	if err != nil {
		return resolveOpts{}, fmt.Errorf("%w: %v", errConfig, err)
	}

	client, leases, err := newVault(cfg.Addr, cfg.TLS, cfg.Token)
	if err != nil {
		return resolveOpts{}, fmt.Errorf("%w: %v", errConfig, err)
	}

	env, target := cfg.Env, cfg.Target
	if envFlag != "" {
		env = envFlag
	}
	if targetFlag != "" {
		target = targetFlag
	}

	return resolveOpts{
		Runner: gitenv.ExecRunner{},
		Client: client,
		Leases: leases,
		Tmpl:   cfg.DataPath,
		Env:    env,
		Target: target,
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

// splitFlag pulls a --<name> <value> (or --<name>=<value>, or the
// single-dash form) pair out of args wherever it appears, returning the
// value ("" if not given) and the remaining args in their original
// relative order (M8). Go's flag package alone stops parsing at the first
// non-flag argument, so `ib get NAME --env x` would otherwise leave
// both NAME and --branch/x as unrecognized positional args — get/env's
// --env and --target (design §12.2) and --output (CLIENT-SPEC §1.2/§1.3) need to
// work regardless of where they appear. ib run does NOT use this: its own
// "--" already marks where ib's flags end and the child command begins,
// so flags-after-positionals has no meaning there.
func splitFlag(args []string, name string) (value string, rest []string, err error) {
	long, short := "--"+name, "-"+name
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == long || a == short:
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("%w: %s needs a value", errUsage, a)
			}
			i++
			value = args[i]
		case strings.HasPrefix(a, long+"="):
			value = strings.TrimPrefix(a, long+"=")
		case strings.HasPrefix(a, short+"="):
			value = strings.TrimPrefix(a, short+"=")
		default:
			rest = append(rest, a)
		}
	}
	return value, rest, nil
}

// splitOutputFlag pulls --output (CLIENT-SPEC §1.2/§1.3) out of args; see
// splitFlag.
func splitOutputFlag(args []string) (output string, rest []string, err error) {
	return splitFlag(args, "output")
}

// outputJSON is the --output value shared by `ib get` and `ib env` that
// switches both from their default (human/shell-oriented) format to a
// single JSON object on stdout (CLIENT-SPEC §1.2/§1.3). get's default is
// "raw", env's is "env" — both accept "" (flag omitted) to mean their own
// default, so only the json case needs a named constant here.
const outputJSON = "json"

// splitSelectionFlags pulls --env and --target out of args; see splitFlag.
func splitSelectionFlags(args []string) (env, target string, rest []string, err error) {
	if env, rest, err = splitFlag(args, "env"); err != nil {
		return "", "", nil, err
	}
	if target, rest, err = splitFlag(rest, "target"); err != nil {
		return "", "", nil, err
	}
	return env, target, rest, nil
}

func dispatchGet(args []string, stdout, stderr io.Writer) int {
	const usage = "ib: usage: ib get [--env <name>] [--target <path>] [--output raw|json] <name>"

	env, target, rest, err := splitSelectionFlags(args)
	if err != nil {
		fmt.Fprintln(stderr, usage)
		return 1
	}
	output, rest, err := splitOutputFlag(rest)
	if err != nil || len(rest) != 1 || (output != "" && output != "raw" && output != outputJSON) {
		fmt.Fprintln(stderr, usage)
		return 1
	}

	opts, err := buildResolveOpts(env, target, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}

	if err := cmdGet(context.Background(), rest[0], opts, stdout, stdoutIsTerminal(stdout), output); err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}
	return 0
}

func dispatchEnv(args []string, stdout, stderr io.Writer) int {
	const usage = "ib: usage: ib env [--env <name>] [--target <path>] [--output env|json]"

	env, target, rest, err := splitSelectionFlags(args)
	if err != nil {
		fmt.Fprintln(stderr, usage)
		return 1
	}
	output, rest, err := splitOutputFlag(rest)
	if err != nil || len(rest) != 0 || (output != "" && output != "env" && output != outputJSON) {
		fmt.Fprintln(stderr, usage)
		return 1
	}

	opts, err := buildResolveOpts(env, target, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}

	if err := cmdEnv(context.Background(), opts, stdout, output); err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}
	return 0
}

func dispatchRun(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	runOpts, cmdArgs, err := parseRunArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return exitCode(err)
	}

	// M2: building resolveOpts loads CLIENT-SPEC §5 configuration, which a
	// run with no ironbark:// reference at all doesn't need — so it's
	// deferred to cmdRun, which only calls this when a reference is
	// actually present.
	buildOpts := func() (resolveOpts, error) { return buildResolveOpts(runOpts.Env, runOpts.Target, stderr) }

	return cmdRun(context.Background(), runOpts, cmdArgs, buildOpts, os.Environ(), stdin, stdout, stderr)
}

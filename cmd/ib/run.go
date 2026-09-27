// This file implements `ib run` (CLIENT-SPEC §1.4, plan Task 9).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/navistau/ironbark/internal/envfile"
	"github.com/navistau/ironbark/internal/mask"
	"github.com/navistau/ironbark/internal/vaultx"
)

// runOpts is cmdRun's own configuration, parsed from ib run's flags by
// parseRunArgs.
type runOpts struct {
	EnvFiles  []string
	NoMasking bool
}

// stringSliceFlag implements flag.Value for a repeatable string flag
// (--env-file).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseRunArgs splits args (everything ib run received) at the first
// literal "--": what precedes it are ib run's own flags, what follows is
// the child command. A missing "--", or nothing after it, is a usage
// error (CLIENT-SPEC §7 exit 1).
func parseRunArgs(args []string) (opts runOpts, branch string, cmdArgs []string, err error) {
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 {
		return runOpts{}, "", nil, fmt.Errorf("%w: ib run needs a '--' before the command", errUsage)
	}
	cmdArgs = args[sepIdx+1:]
	if len(cmdArgs) == 0 {
		return runOpts{}, "", nil, fmt.Errorf("%w: no command given after '--'", errUsage)
	}

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var envFiles stringSliceFlag
	fs.Var(&envFiles, "env-file", "env file to layer onto the child's environment (repeatable)")
	noMasking := fs.Bool("no-masking", false, "pass the child's stdio through untouched")
	branchFlag := fs.String("branch", "", "override the selected branch (CLIENT-SPEC §3 rule 1)")
	if err := fs.Parse(args[:sepIdx]); err != nil {
		return runOpts{}, "", nil, fmt.Errorf("%w: %v", errUsage, err)
	}

	return runOpts{EnvFiles: envFiles, NoMasking: *noMasking}, *branchFlag, cmdArgs, nil
}

// envOverride is one parsed --env-file entry, in file/entry order.
type envOverride struct{ key, value string }

// loadEnvFiles parses every path in order, flattening their entries
// (later files, and later entries within a file, override earlier ones —
// applied by cmdRun via map assignment, which is naturally last-wins).
func loadEnvFiles(paths []string) ([]envOverride, error) {
	var out []envOverride
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		entries, err := envfile.Parse(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, e := range entries {
			out = append(out, envOverride{key: e.Key, value: e.Value})
		}
	}
	return out, nil
}

func environMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func mapToEnviron(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

// childExitCode reports the exit code cmdRun should report for the child
// process: its own exit status, or 128+signal if it was killed by a
// signal (CLIENT-SPEC §1.4).
func childExitCode(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
		return exitErr.ExitCode()
	}
	// The child never ran at all (e.g. executable not found) — not a
	// CLIENT-SPEC §7 code (there is no child status to report), treated as
	// a usage-shaped failure.
	return 1
}

// cmdRun implements `ib run` (CLIENT-SPEC §1.4): builds the child's
// environment from environ plus each env file in opts.EnvFiles (in
// order, later wins), resolving any exact `ironbark://<name>` value via a
// single resolve() call — performed, and buildOpts (which loads Vault
// configuration — CLIENT-SPEC §5, M2) called, only if at least one such
// reference exists. An unresolved reference exits 3 before the child
// starts. Masking (default on) pipes the child's stdout/stderr through a
// mask.Writer for every resolved reference's value; --no-masking passes
// stdio straight through. Signals in the forwarded set are relayed to the
// child. Every lease the sweep created — referenced by this run or not
// (I1) — is revoked as soon as the sweep succeeds (deferred immediately,
// so an unresolved reference or a cmd.Start failure below still revokes —
// I2), best-effort: failures go to stderr without changing the exit code.
// The return value is the process exit code: the child's own (or
// 128+signal), or a CLIENT-SPEC §7 code for a resolve failure encountered
// before the child ever started.
func cmdRun(ctx context.Context, opts runOpts, cmdArgs []string, buildOpts func() (resolveOpts, error), environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	overrides, err := loadEnvFiles(opts.EnvFiles)
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return 1
	}

	hasRef := false
	for _, o := range overrides {
		if _, ok := envfile.Ref(o.value); ok {
			hasRef = true
			break
		}
	}

	var secrets map[string]vaultx.SweptSecret
	if hasRef {
		ropts, berr := buildOpts()
		if berr != nil {
			fmt.Fprintln(stderr, "ib:", berr)
			return exitCode(berr)
		}

		var leaseIDs []string
		var rerr error
		secrets, leaseIDs, _, rerr = resolve(ctx, ropts)
		if rerr != nil {
			fmt.Fprintln(stderr, "ib:", rerr)
			return exitCode(rerr)
		}
		if len(leaseIDs) > 0 {
			// I2: armed immediately on a successful sweep, so it still
			// runs on every exit path below — an unresolved reference, a
			// cmd.Start failure, or the child actually running.
			defer func() {
				for _, revokeErr := range ropts.Vault.RevokeLeases(ctx, ropts.Token, leaseIDs) {
					fmt.Fprintf(stderr, "ib: revoke lease failed: %v\n", revokeErr)
				}
			}()
		}
	}

	envMap := environMap(environ)
	var usedValues []string
	for _, o := range overrides {
		val := o.value
		if name, ok := envfile.Ref(o.value); ok {
			s, found := secrets[name]
			if !found {
				fmt.Fprintf(stderr, "ib: unresolved secret reference %q\n", name)
				return 3
			}
			val = s.Value
			usedValues = append(usedValues, val)
		}
		envMap[o.key] = val
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = mapToEnviron(envMap)
	cmd.Stdin = stdin

	var flushers []func() error
	if opts.NoMasking {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	} else {
		mwOut := mask.NewWriter(stdout, usedValues)
		mwErr := mask.NewWriter(stderr, usedValues)
		cmd.Stdout = mwOut
		cmd.Stderr = mwErr
		flushers = []func() error{mwOut.Flush, mwErr.Flush}
	}

	// I3: armed before Start, not after — a signal arriving in the window
	// right around the child spawning must still reach it.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return 1
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
waitLoop:
	for {
		select {
		case sig := <-sigCh:
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		case waitErr = <-done:
			break waitLoop
		}
	}

	for _, flush := range flushers {
		_ = flush()
	}

	return childExitCode(waitErr)
}

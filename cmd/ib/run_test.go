package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseRunArgs(t *testing.T) {
	t.Run("missing --", func(t *testing.T) {
		_, _, err := parseRunArgs([]string{"echo", "hi"})
		if err == nil {
			t.Fatal("parseRunArgs: expected an error for a missing '--', got nil")
		}
		if exitCode(err) != 1 {
			t.Errorf("exitCode(err) = %d, want 1", exitCode(err))
		}
	})

	t.Run("no command after --", func(t *testing.T) {
		_, _, err := parseRunArgs([]string{"--no-masking", "--"})
		if err == nil {
			t.Fatal("parseRunArgs: expected an error for no command, got nil")
		}
		if exitCode(err) != 1 {
			t.Errorf("exitCode(err) = %d, want 1", exitCode(err))
		}
	})

	t.Run("flags and command parsed", func(t *testing.T) {
		opts, cmdArgs, err := parseRunArgs([]string{
			"--env-file", "a.env", "--env-file", "b.env", "--no-masking", "--env", "develop", "--target", "web/api",
			"--", "echo", "--flag", "hi",
		})
		if err != nil {
			t.Fatalf("parseRunArgs: %v", err)
		}
		if len(opts.EnvFiles) != 2 || opts.EnvFiles[0] != "a.env" || opts.EnvFiles[1] != "b.env" {
			t.Errorf("EnvFiles = %v, want [a.env b.env]", opts.EnvFiles)
		}
		if !opts.NoMasking {
			t.Error("NoMasking = false, want true")
		}
		if opts.Env != "develop" || opts.Target != "web/api" {
			t.Errorf("Env, Target = %q, %q, want develop, web/api", opts.Env, opts.Target)
		}
		want := []string{"echo", "--flag", "hi"}
		if len(cmdArgs) != len(want) {
			t.Fatalf("cmdArgs = %v, want %v", cmdArgs, want)
		}
		for i := range want {
			if cmdArgs[i] != want[i] {
				t.Errorf("cmdArgs[%d] = %q, want %q", i, cmdArgs[i], want[i])
			}
		}
	})
}

// buildOptsFunc wraps an already-built resolveOpts as the lazy builder
// cmdRun now takes (M2): tests that don't care about deferred config
// loading just want their fixed opts back every time.
func buildOptsFunc(o resolveOpts) func() (resolveOpts, error) {
	return func() (resolveOpts, error) { return o, nil }
}

func writeEnvFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCmdRun_RefResolvedAndLiteralPassedThrough proves an ironbark://
// reference is replaced by the secret's value, an ordinary literal value
// passes through unchanged, and the sweep (and the fake Vault it talks
// to) is only touched because a reference is present. Masking is
// disabled here since it's the substitution, not the masking, under
// test — TestCmdRun_Masking covers masking on its own.
func TestCmdRun_RefResolvedAndLiteralPassedThrough(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://shared\nLITERAL_VAL=plain-value\n")
	opts := runOpts{EnvFiles: []string{envFile}, NoMasking: true}

	cmdArgs := helperArgs("printenv", "SECRET_VAL")
	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), opts, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stdout.String() != "shared-value" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "shared-value")
	}

	stdout.Reset()
	cmdArgs = helperArgs("printenv", "LITERAL_VAL")
	code = cmdRun(context.Background(), opts, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0", code)
	}
	if stdout.String() != "plain-value" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "plain-value")
	}
}

// TestCmdRun_UnresolvedRef proves a reference the walk didn't produce leaves
// its variable unset (even one the caller's environment already had), with
// one stderr line naming it, and the child still runs (design §12.4).
func TestCmdRun_UnresolvedRef(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://does_not_exist\n")

	cmdArgs := helperArgs("printenv", "SECRET_VAL")
	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, cmdArgs, buildOptsFunc(ropts), append(os.Environ(), "SECRET_VAL=stale"), nil, &stdout, &stderr)
	if code != 0 {
		t.Errorf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("child saw SECRET_VAL = %q, want it unset", stdout.String())
	}
	if n := strings.Count(stderr.String(), "SECRET_VAL left unset"); n != 1 || !strings.Contains(stderr.String(), "does_not_exist") {
		t.Errorf("stderr = %q, want one line naming SECRET_VAL and does_not_exist", stderr.String())
	}
}

// TestCmdRun_Masking proves a resolved value split by the child across
// two writes is fully masked by default, and shown verbatim with
// --no-masking.
func TestCmdRun_Masking(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://shared\n")
	cmdArgs := helperArgs("splitwrite", "shared-value")

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "shared-value") {
		t.Errorf("stdout = %q, leaked the secret value", stdout.String())
	}
	if !strings.Contains(stdout.String(), "<concealed by ib>") {
		t.Errorf("stdout = %q, want the masked placeholder", stdout.String())
	}

	stdout.Reset()
	code = cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}, NoMasking: true}, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0", code)
	}
	if stdout.String() != "shared-value" {
		t.Errorf("stdout = %q, want the unmasked value %q", stdout.String(), "shared-value")
	}
}

// TestCmdRun_RevokesAllSweptLeases proves ib run revokes every lease the
// sweep created, not only the ones behind values actually substituted
// into the child's environment (I1): setupGetEnvFixture's "dbref" secret
// is lease-bearing but never referenced by this test's env file.
func TestCmdRun_RevokesAllSweptLeases(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://shared\n")
	cmdArgs := helperArgs("printenv", "SECRET_VAL")

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	revoked := fv.revokedIDs()
	if len(revoked) != 1 || revoked[0] != "database/creds/readonly/abc" {
		t.Errorf("revoked leases = %v, want [database/creds/readonly/abc] (the sweep's dbref lease, though never referenced)", revoked)
	}
}

// TestCmdRun_UnresolvedRefStillRevokesLeases proves a run with an unresolved
// reference still revokes every lease the walk took (I2).
func TestCmdRun_UnresolvedRefStillRevokesLeases(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "A=ironbark://shared\nB=ironbark://does_not_exist\n")

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, helperArgs("exit", "0"), buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Errorf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	revoked := fv.revokedIDs()
	if len(revoked) != 1 || revoked[0] != "database/creds/readonly/abc" {
		t.Errorf("revoked leases = %v, want [database/creds/readonly/abc]", revoked)
	}
}

// TestCmdRun_StartFailureStillRevokesLeases proves a cmd.Start failure
// (exit 1, before the child ever runs) still revokes every lease the
// sweep created (I2).
func TestCmdRun_StartFailureStillRevokesLeases(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://shared\n")
	cmdArgs := []string{filepath.Join(t.TempDir(), "does-not-exist-binary")}

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 1 {
		t.Errorf("cmdRun exit = %d, want 1 (cmd.Start failure)", code)
	}

	revoked := fv.revokedIDs()
	if len(revoked) != 1 || revoked[0] != "database/creds/readonly/abc" {
		t.Errorf("revoked leases = %v, want [database/creds/readonly/abc] even though the child never started", revoked)
	}
}

// TestCmdRun_EnvFileWithNoRefSkipsConfigBuild proves ib run never builds
// Vault config (which would need BAO_ADDR/BAO_TOKEN) when the only
// --env-file given holds no ironbark:// reference (M2): buildOpts here
// fails the test if called at all. Unchanged from before CLIENT-SPEC
// §1.4's no-file mode existed — omitting --env-file entirely is a
// different case now (TestCmdRun_NoFileMode_* below), which always
// sweeps.
func TestCmdRun_EnvFileWithNoRefSkipsConfigBuild(t *testing.T) {
	buildOpts := func() (resolveOpts, error) {
		t.Fatal("buildOpts should not be called when no env file references a secret")
		return resolveOpts{}, nil
	}

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "LITERAL=plain-value\n")

	cmdArgs := helperArgs("exit", "0")
	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, cmdArgs, buildOpts, os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Errorf("cmdRun exit = %d, want 0", code)
	}
}

// TestDispatchRun_EnvFileNoRefDoesNotNeedVaultConfig proves the real
// dispatchRun entry point (main.go) defers building Vault config until
// it's known to be needed (M2): with no Vault env vars set at all, an
// --env-file with no ironbark:// reference still runs successfully
// instead of failing with a configuration error. Omitting --env-file
// entirely now always sweeps — see TestCmdRun_NoFileMode_* below.
func TestDispatchRun_EnvFileNoRefDoesNotNeedVaultConfig(t *testing.T) {
	t.Setenv("BAO_ADDR", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("VAULT_TOKEN", "")

	envFile := writeEnvFile(t, t.TempDir(), "a.env", "LITERAL=plain-value\n")

	var stdout, stderr bytes.Buffer
	code := dispatchRun([]string{"--env-file", envFile, "--", "true"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Errorf("dispatchRun(--env-file, --, true) = %d, want 0 (no ironbark:// ref, so no Vault config should be required): stderr=%s", code, stderr.String())
	}
}

// TestCmdRun_NoFileMode_InjectsAllSweptSecrets proves that omitting
// --env-file entirely (CLIENT-SPEC §1.4) does not skip the sweep — every
// swept secret lands in the child's environment as SECRET_<NAME>
// (envfile.Key: the same upper-cased naming `ib env` uses), alongside the
// caller's own environment.
func TestCmdRun_NoFileMode_InjectsAllSweptSecrets(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{NoMasking: true}, helperArgs("printenv", "SECRET_SHARED"), buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stdout.String() != "shared-value" {
		t.Errorf("SECRET_SHARED = %q, want %q", stdout.String(), "shared-value")
	}

	stdout.Reset()
	code = cmdRun(context.Background(), runOpts{NoMasking: true}, helperArgs("printenv", "SECRET_DBREF_USERNAME"), buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stdout.String() != "u" {
		t.Errorf("SECRET_DBREF_USERNAME = %q, want %q", stdout.String(), "u")
	}
}

// TestCmdRun_NoFileMode_OverwritesExistingSecretEnvVar proves a caller env
// var that already has the same SECRET_<NAME> name is overwritten by the
// swept value (CLIENT-SPEC §1.4).
func TestCmdRun_NoFileMode_OverwritesExistingSecretEnvVar(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	environ := append(os.Environ(), "SECRET_SHARED=stale-value")

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{NoMasking: true}, helperArgs("printenv", "SECRET_SHARED"), buildOptsFunc(ropts), environ, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stdout.String() != "shared-value" {
		t.Errorf("SECRET_SHARED = %q, want the swept value %q to win over the caller's own", stdout.String(), "shared-value")
	}
}

// TestCmdRun_NoFileMode_Masking proves masking covers every secret
// injected in no-file mode, not only values resolved from an --env-file
// reference.
func TestCmdRun_NoFileMode_Masking(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	cmdArgs := helperArgs("splitwrite", "shared-value")
	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{}, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "shared-value") {
		t.Errorf("stdout = %q, leaked the secret value", stdout.String())
	}
	if !strings.Contains(stdout.String(), "<concealed by ib>") {
		t.Errorf("stdout = %q, want the masked placeholder", stdout.String())
	}
}

// TestCmdRun_NoFileMode_RevokesAllSweptLeases proves ib run revokes every
// lease the sweep created in no-file mode too (CLIENT-SPEC §1.4) — not
// only when --env-file references trigger the sweep.
func TestCmdRun_NoFileMode_RevokesAllSweptLeases(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{}, helperArgs("exit", "0"), buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	revoked := fv.revokedIDs()
	if len(revoked) != 1 || revoked[0] != "database/creds/readonly/abc" {
		t.Errorf("revoked leases = %v, want [database/creds/readonly/abc]", revoked)
	}
}

// TestCmdRun_ChildExitCode proves ib exits with the child's own exit
// status. No --env-file is given, so (CLIENT-SPEC §1.4) this still
// sweeps — setupGetEnvFixture supplies the working fixture it now needs.
func TestCmdRun_ChildExitCode(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := vc.opts(t, fx, new(bytes.Buffer))
	cmdArgs := helperArgs("exit", "7")

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{}, cmdArgs, buildOptsFunc(ropts), os.Environ(), nil, &stdout, &stderr)
	if code != 7 {
		t.Errorf("cmdRun exit = %d, want 7 (stderr: %s)", code, stderr.String())
	}
}

// TestCmdRun_ForwardsSIGTERM proves a signal ib receives is forwarded to
// its child. This needs a real, separate `ib` process (built by TestMain)
// to send an actual SIGTERM to — sending it to the test binary itself
// would kill the whole test run.
func TestCmdRun_ForwardsSIGTERM(t *testing.T) {
	if ibBinaryPath == "" {
		t.Skip("ib binary not built (helper invocation)")
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "sigterm.out")
	// An --env-file with no ironbark:// reference (CLIENT-SPEC §1.4) never
	// sweeps, so this needs no working Vault — only signal forwarding to
	// the running child is under test here. Omitting --env-file entirely
	// would now always sweep (see TestCmdRun_NoFileMode_* above).
	envFile := writeEnvFile(t, dir, "a.env", "X=1\n")
	args := append([]string{"run", "--env-file", envFile, "--"}, helperArgs("waitsigterm", outFile)...)

	cmd := exec.Command(ibBinaryPath, args...)
	cmd.Env = os.Environ()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ib run: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(outFile + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the helper child to become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal ib: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("ib run: %v (stderr: %s)", err, stderr.String())
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read %s: %v", outFile, err)
	}
	if string(got) != "got-sigterm" {
		t.Errorf("helper output = %q, want got-sigterm", got)
	}
}

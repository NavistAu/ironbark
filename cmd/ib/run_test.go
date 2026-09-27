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

	"github.com/navistau/ironbark/internal/gitenv"
)

func TestParseRunArgs(t *testing.T) {
	t.Run("missing --", func(t *testing.T) {
		_, _, _, err := parseRunArgs([]string{"echo", "hi"})
		if err == nil {
			t.Fatal("parseRunArgs: expected an error for a missing '--', got nil")
		}
		if exitCode(err) != 1 {
			t.Errorf("exitCode(err) = %d, want 1", exitCode(err))
		}
	})

	t.Run("no command after --", func(t *testing.T) {
		_, _, _, err := parseRunArgs([]string{"--no-masking", "--"})
		if err == nil {
			t.Fatal("parseRunArgs: expected an error for no command, got nil")
		}
		if exitCode(err) != 1 {
			t.Errorf("exitCode(err) = %d, want 1", exitCode(err))
		}
	})

	t.Run("flags and command parsed", func(t *testing.T) {
		opts, branch, cmdArgs, err := parseRunArgs([]string{
			"--env-file", "a.env", "--env-file", "b.env", "--no-masking", "--branch", "develop",
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
		if branch != "develop" {
			t.Errorf("branch = %q, want develop", branch)
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
	ropts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: new(bytes.Buffer)}

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://shared\nLITERAL_VAL=plain-value\n")
	opts := runOpts{EnvFiles: []string{envFile}, NoMasking: true}

	cmdArgs := helperArgs("printenv", "SECRET_VAL")
	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), opts, cmdArgs, ropts, os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stdout.String() != "shared-value" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "shared-value")
	}

	stdout.Reset()
	cmdArgs = helperArgs("printenv", "LITERAL_VAL")
	code = cmdRun(context.Background(), opts, cmdArgs, ropts, os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0", code)
	}
	if stdout.String() != "plain-value" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "plain-value")
	}
}

// TestCmdRun_UnresolvedRef proves a reference the sweep didn't produce
// exits 3 before the child ever starts.
func TestCmdRun_UnresolvedRef(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: new(bytes.Buffer)}

	dir := t.TempDir()
	marker := filepath.Join(dir, "ran.marker")
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://does_not_exist\n")

	cmdArgs := helperArgs("marker", marker)
	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, cmdArgs, ropts, os.Environ(), nil, &stdout, &stderr)
	if code != 3 {
		t.Errorf("cmdRun exit = %d, want 3 (stderr: %s)", code, stderr.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("child ran (marker file exists), want it never started")
	}
}

// TestCmdRun_Masking proves a resolved value split by the child across
// two writes is fully masked by default, and shown verbatim with
// --no-masking.
func TestCmdRun_Masking(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	ropts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: new(bytes.Buffer)}

	dir := t.TempDir()
	envFile := writeEnvFile(t, dir, "a.env", "SECRET_VAL=ironbark://shared\n")
	cmdArgs := helperArgs("splitwrite", "shared-value")

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}}, cmdArgs, ropts, os.Environ(), nil, &stdout, &stderr)
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
	code = cmdRun(context.Background(), runOpts{EnvFiles: []string{envFile}, NoMasking: true}, cmdArgs, ropts, os.Environ(), nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdRun exit = %d, want 0", code)
	}
	if stdout.String() != "shared-value" {
		t.Errorf("stdout = %q, want the unmasked value %q", stdout.String(), "shared-value")
	}
}

// TestCmdRun_ChildExitCode proves ib exits with the child's own exit
// status.
func TestCmdRun_ChildExitCode(t *testing.T) {
	ropts := resolveOpts{Stderr: new(bytes.Buffer)}
	cmdArgs := helperArgs("exit", "7")

	var stdout, stderr bytes.Buffer
	code := cmdRun(context.Background(), runOpts{}, cmdArgs, ropts, os.Environ(), nil, &stdout, &stderr)
	if code != 7 {
		t.Errorf("cmdRun exit = %d, want 7", code)
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

	outFile := filepath.Join(t.TempDir(), "sigterm.out")
	args := append([]string{"run", "--"}, helperArgs("waitsigterm", outFile)...)

	cmd := exec.Command(ibBinaryPath, args...)
	cmd.Env = append(os.Environ(), "BAO_ADDR=http://127.0.0.1:1", "BAO_TOKEN=test-token")
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

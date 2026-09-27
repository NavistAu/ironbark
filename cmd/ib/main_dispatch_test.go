package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestDispatch_UnknownCommand and TestDispatch_NoArgs cover main's own
// usage-error paths (CLIENT-SPEC §7 exit 1); the get/env/run/auth
// commands themselves are covered in their own _test.go files.

func TestDispatch_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch(nil, nil, &stdout, &stderr)
	if code != 1 {
		t.Errorf("dispatch(nil) = %d, want 1", code)
	}
}

func TestDispatch_UnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"bogus"}, nil, &stdout, &stderr)
	if code != 1 {
		t.Errorf("dispatch(bogus) = %d, want 1", code)
	}
}

// TestDispatchGet_UsageErrors covers ib get's own flag/arg validation
// (missing name, too many names) without needing real Vault/git config.
func TestDispatchGet_UsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"a", "b"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := dispatchGet(args, &stdout, &stderr)
		if code != 1 {
			t.Errorf("dispatchGet(%v) = %d, want 1", args, code)
		}
	}
}

// TestDispatchGet_BranchFlagAfterPositionalArg reproduces M8: `ib get NAME
// --branch x` must work the same as `ib get --branch x NAME` — Go's flag
// package alone stops parsing at the first non-flag argument, so putting
// --branch after NAME used to leave both as unrecognized positional args
// and fail with a usage error. Chdir'd into an empty (non-git) temp dir so
// the deterministic failure mode is exit 2 ("not a git checkout"), proving
// the flag WAS recognized and argument parsing proceeded — a usage error
// (exit 1) is exactly the old, wrong outcome.
func TestDispatchGet_BranchFlagAfterPositionalArg(t *testing.T) {
	t.Setenv("BAO_ADDR", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "test-token")
	chdirTemp(t)

	var stdout, stderr bytes.Buffer
	code := dispatchGet([]string{"myname", "--branch", "develop"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("dispatchGet(myname, --branch, develop) = %d, want 2 (not a git checkout) — the flag after the positional name must still be recognized, not treated as a usage error", code)
	}
}

// TestDispatchEnv_BranchFlagAfterOtherArgs mirrors
// TestDispatchGet_BranchFlagAfterPositionalArg for `ib env`, which takes
// no positional args of its own but must still accept --branch wherever
// it appears among its (otherwise empty) argument list.
func TestDispatchEnv_BranchFlagAfterOtherArgs(t *testing.T) {
	t.Setenv("BAO_ADDR", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "test-token")
	chdirTemp(t)

	var stdout, stderr bytes.Buffer
	code := dispatchEnv([]string{"--branch", "develop"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("dispatchEnv(--branch, develop) = %d, want 2 (not a git checkout)", code)
	}
}

// TestDispatchGet_UnknownOutputValue proves an unrecognized --output value
// is a usage error (exit 1), not silently accepted or forwarded.
func TestDispatchGet_UnknownOutputValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatchGet([]string{"myname", "--output", "bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("dispatchGet(myname, --output, bogus) = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on a usage error", stdout.String())
	}
}

// TestDispatchEnv_UnknownOutputValue mirrors
// TestDispatchGet_UnknownOutputValue for `ib env`.
func TestDispatchEnv_UnknownOutputValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatchEnv([]string{"--output", "bogus"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("dispatchEnv(--output, bogus) = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on a usage error", stdout.String())
	}
}

// TestDispatchGet_OutputFlagAfterPositionalArg proves --output, like
// --branch (M8), is recognized regardless of where it appears relative to
// the positional name — it reuses splitFlag/splitBranchFlag's own
// splitting.
func TestDispatchGet_OutputFlagAfterPositionalArg(t *testing.T) {
	t.Setenv("BAO_ADDR", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "test-token")
	chdirTemp(t)

	var stdout, stderr bytes.Buffer
	code := dispatchGet([]string{"myname", "--output", "json"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("dispatchGet(myname, --output, json) = %d, want 2 (not a git checkout) — --output after the positional name must still be recognized", code)
	}
}

// TestDispatchGet_BranchAndOutputFlagsCombined proves --branch and
// --output can both appear, in either order, alongside the positional
// name.
func TestDispatchGet_BranchAndOutputFlagsCombined(t *testing.T) {
	t.Setenv("BAO_ADDR", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "test-token")
	chdirTemp(t)

	var stdout, stderr bytes.Buffer
	code := dispatchGet([]string{"myname", "--output", "json", "--branch", "develop"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("dispatchGet(myname, --output, json, --branch, develop) = %d, want 2 (not a git checkout)", code)
	}
}

// TestDispatchEnv_OutputFlagAfterOtherArgs mirrors
// TestDispatchGet_OutputFlagAfterPositionalArg for `ib env`.
func TestDispatchEnv_OutputFlagAfterOtherArgs(t *testing.T) {
	t.Setenv("BAO_ADDR", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "test-token")
	chdirTemp(t)

	var stdout, stderr bytes.Buffer
	code := dispatchEnv([]string{"--branch", "develop", "--output", "json"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("dispatchEnv(--branch, develop, --output, json) = %d, want 2 (not a git checkout)", code)
	}
}

// chdirTemp changes the process's working directory to a fresh empty temp
// dir (never a git checkout) for the duration of the calling test,
// restoring it on cleanup. get/env build their Runner from the process's
// cwd (gitenv.ExecRunner{}, no Dir override), so this gives a
// deterministic, fast Checkout failure (exit 2) without needing a real
// git fixture.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// TestBuildResolveOpts_BranchPrecedence proves --branch (passed as
// branchFlag) wins over IB_BRANCH, and that IB_BRANCH is used as the
// fallback when no flag is given (CLIENT-SPEC §1).
func TestBuildResolveOpts_BranchPrecedence(t *testing.T) {
	t.Setenv("BAO_ADDR", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "test-token")
	t.Setenv("IB_BRANCH", "from-env")

	var stderr bytes.Buffer
	opts, err := buildResolveOpts("from-flag", &stderr)
	if err != nil {
		t.Fatalf("buildResolveOpts: %v", err)
	}
	if opts.Branch != "from-flag" {
		t.Errorf("Branch = %q, want from-flag (flag wins)", opts.Branch)
	}

	opts, err = buildResolveOpts("", &stderr)
	if err != nil {
		t.Fatalf("buildResolveOpts: %v", err)
	}
	if opts.Branch != "from-env" {
		t.Errorf("Branch = %q, want from-env (IB_BRANCH fallback)", opts.Branch)
	}
}

// TestBuildResolveOpts_MissingConfig proves a missing Vault address maps
// to exit 2 via exitCode.
func TestBuildResolveOpts_MissingConfig(t *testing.T) {
	t.Setenv("BAO_ADDR", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("VAULT_TOKEN", "")

	var stderr bytes.Buffer
	_, err := buildResolveOpts("", &stderr)
	if err == nil {
		t.Fatal("buildResolveOpts: expected an error, got nil")
	}
	if exitCode(err) != 2 {
		t.Errorf("exitCode(err) = %d, want 2", exitCode(err))
	}
}

// TestDispatchGet_MissingVaultAddress_StderrText proves the printed stderr
// line for a missing Vault address carries exactly one "ib: " prefix.
// buildResolveOpts wraps ibcfg's own error with errConfig, and dispatchGet
// prints that error prefixed with "ib: " — before the dogfood fix,
// errConfig's own message already started with "ib: ", doubling it to
// "ib: ib: configuration error: ...".
func TestDispatchGet_MissingVaultAddress_StderrText(t *testing.T) {
	t.Setenv("BAO_ADDR", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("VAULT_TOKEN", "")

	var stdout, stderr bytes.Buffer
	code := dispatchGet([]string{"name"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("dispatchGet = %d, want 2 (stderr: %s)", code, stderr.String())
	}

	want := "ib: configuration error: ibcfg: no Vault address set (BAO_ADDR or VAULT_ADDR)\n"
	if stderr.String() != want {
		t.Errorf("stderr = %q, want %q (exactly one \"ib: \" prefix)", stderr.String(), want)
	}
}

// TestDispatchGet_UnknownName_StderrText proves the printed stderr line for
// an unknown secret name carries exactly one "ib: " prefix. get.go wraps
// the miss with errUnknownSecret, and dispatchGet prints that error
// prefixed with "ib: " — before the dogfood fix, errUnknownSecret's own
// message already started with "ib: ", doubling it to
// "ib: ib: unknown secret name: ...".
func TestDispatchGet_UnknownName_StderrText(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("BAO_TOKEN", rtToken)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("IB_KV_MOUNT", "")
	t.Setenv("IB_KV_PREFIX", "")
	t.Setenv("IB_BRANCH", "")

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(fx.clone); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	var stdout, stderr bytes.Buffer
	code := dispatchGet([]string{"nope"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("dispatchGet = %d, want 3 (stderr: %s)", code, stderr.String())
	}

	lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
	last := lines[len(lines)-1]
	want := `ib: unknown secret name: "nope"`
	if last != want {
		t.Errorf("last stderr line = %q, want %q (exactly one \"ib: \" prefix)", last, want)
	}
}

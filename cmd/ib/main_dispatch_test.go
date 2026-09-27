package main

import (
	"bytes"
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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/envfile"
	"github.com/navistau/ironbark/internal/gitenv"
)

func TestCmdEnv_SortedFormatAndLeaseNote(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	if err := cmdEnv(context.Background(), opts, &stdout, ""); err != nil {
		t.Fatalf("cmdEnv: %v (stderr: %s)", err, stderr.String())
	}

	want := envfile.Format("dbref_password", "p") +
		envfile.Format("dbref_username", "u") +
		envfile.Format("shared", "shared-value")
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
	if !strings.Contains(stderr.String(), "expire") {
		t.Errorf("stderr = %q, want a lease-expiry note", stderr.String())
	}
}

// TestCmdEnv_JSONOutput_ShapeAndSorting exercises CLIENT-SPEC §1.3's
// --output json shape: {"branch", "rule", "secrets"}, secrets keyed by the
// sweep's own lowercase names (not SECRET_<NAME>), sorted.
func TestCmdEnv_JSONOutput_ShapeAndSorting(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	if err := cmdEnv(context.Background(), opts, &stdout, "json"); err != nil {
		t.Fatalf("cmdEnv: %v (stderr: %s)", err, stderr.String())
	}

	var got envJSON
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %q)", err, stdout.String())
	}
	if got.Branch != "main" {
		t.Errorf("Branch = %q, want %q", got.Branch, "main")
	}
	if got.Rule != "direct" {
		t.Errorf("Rule = %q, want %q", got.Rule, "direct")
	}
	want := map[string]string{
		"dbref_password": "p",
		"dbref_username": "u",
		"shared":         "shared-value",
	}
	if len(got.Secrets) != len(want) {
		t.Fatalf("Secrets = %v, want keys %v", got.Secrets, want)
	}
	for k, v := range want {
		if got.Secrets[k] != v {
			t.Errorf("Secrets[%q] = %q, want %q", k, got.Secrets[k], v)
		}
	}

	// Sorted keys is a wire-format guarantee, not just a decoding
	// convenience — pin it down on the raw JSON text.
	text := stdout.String()
	iPass := strings.Index(text, `"dbref_password"`)
	iUser := strings.Index(text, `"dbref_username"`)
	iShared := strings.Index(text, `"shared"`)
	if iPass < 0 || iUser < 0 || iShared < 0 || !(iPass < iUser && iUser < iShared) {
		t.Errorf("secrets keys not sorted in raw JSON: %s", text)
	}
}

// TestCmdEnv_JSONOutput_PureStdout proves stdout carries nothing but the
// one JSON object — no leading/trailing junk, no extra lines.
func TestCmdEnv_JSONOutput_PureStdout(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	if err := cmdEnv(context.Background(), opts, &stdout, "json"); err != nil {
		t.Fatalf("cmdEnv: %v (stderr: %s)", err, stderr.String())
	}

	if !json.Valid(stdout.Bytes()) {
		t.Fatalf("stdout is not valid JSON: %q", stdout.String())
	}
	if n := strings.Count(stdout.String(), "\n"); n != 1 {
		t.Errorf("stdout has %d newlines, want exactly 1 (json.Encoder's trailing newline, nothing else)", n)
	}
}

// TestCmdEnv_JSONOutput_StderrUnchanged proves --output json doesn't touch
// what goes to stderr: the same lease note printed in the default (env)
// mode is printed, verbatim, in json mode too.
func TestCmdEnv_JSONOutput_StderrUnchanged(t *testing.T) {
	fxEnv, fvEnv := setupGetEnvFixture(t)
	vcEnv := newTestVault(t, fvEnv)
	var stderrEnv, stdoutEnv bytes.Buffer
	optsEnv := resolveOpts{Runner: gitenv.ExecRunner{Dir: fxEnv.clone}, Vault: vcEnv, Token: rtToken, Stderr: &stderrEnv}
	if err := cmdEnv(context.Background(), optsEnv, &stdoutEnv, ""); err != nil {
		t.Fatalf("cmdEnv (env): %v", err)
	}

	fxJSON, fvJSON := setupGetEnvFixture(t)
	vcJSON := newTestVault(t, fvJSON)
	var stderrJSON, stdoutJSON bytes.Buffer
	optsJSON := resolveOpts{Runner: gitenv.ExecRunner{Dir: fxJSON.clone}, Vault: vcJSON, Token: rtToken, Stderr: &stderrJSON}
	if err := cmdEnv(context.Background(), optsJSON, &stdoutJSON, "json"); err != nil {
		t.Fatalf("cmdEnv (json): %v", err)
	}

	if stderrEnv.String() != stderrJSON.String() {
		t.Errorf("stderr differs between output modes:\nenv:  %q\njson: %q", stderrEnv.String(), stderrJSON.String())
	}
}

// TestCmdEnv_JSONOutput_NoBranchTiers_EmptyBranch exercises the "chosen or
// empty" branch case: CLIENT-SPEC §3's no-branch-tiers path selects no
// branch at all, so the JSON object's "branch" is "" and "rule" names the
// no-branch-tiers path, not an omitted or null field.
func TestCmdEnv_JSONOutput_NoBranchTiers_EmptyBranch(t *testing.T) {
	fx := newIBFixture(t, nil)

	fv := newFakeVault()
	fv.set("/v1/kv/metadata/"+rtBase, 200, listBody([]string{"shared"}))
	fv.set("/v1/kv/data/"+rtBase+"/shared", 200, entryBody(map[string]interface{}{"value": "shared-value"}, nil))

	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	if err := cmdEnv(context.Background(), opts, &stdout, "json"); err != nil {
		t.Fatalf("cmdEnv: %v (stderr: %s)", err, stderr.String())
	}

	var got envJSON
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %q)", err, stdout.String())
	}
	if got.Branch != "" {
		t.Errorf("Branch = %q, want empty (no branch tiers)", got.Branch)
	}
	if got.Rule != "no-branch-tiers" {
		t.Errorf("Rule = %q, want %q", got.Rule, "no-branch-tiers")
	}
	if len(got.Secrets) != 1 || got.Secrets["shared"] != "shared-value" {
		t.Errorf("Secrets = %v, want just shared=shared-value", got.Secrets)
	}
}

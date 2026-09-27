package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/gitenv"
)

func setupGetEnvFixture(t *testing.T) (ibFixture, *fakeVault) {
	t.Helper()
	fx := newIBFixture(t, nil) // clone stays on "main" after clone

	fv := newFakeVault()
	fv.set("/v1/kv/metadata/"+rtEvent, 200, listBody([]string{"main/"}))
	fv.set("/v1/kv/metadata/"+rtBase, 200, listBody([]string{"shared"}))
	fv.set("/v1/kv/data/"+rtBase+"/shared", 200, entryBody(map[string]interface{}{"value": "shared-value"}, nil))
	fv.set("/v1/kv/metadata/"+rtMain, 200, listBody([]string{"dbref"}))
	fv.set("/v1/kv/data/"+rtMain+"/dbref", 200, entryBody(map[string]interface{}{"$ref": "database/creds/readonly"}, nil))
	fv.set("/v1/database/creds/readonly", 200, derefBody(map[string]interface{}{"username": "u", "password": "p"}, "database/creds/readonly/abc"))

	return fx, fv
}

func TestCmdGet_ValueAndTerminalNewline(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	var stdout bytes.Buffer
	if err := cmdGet(context.Background(), "shared", opts, &stdout, false, ""); err != nil {
		t.Fatalf("cmdGet: %v (stderr: %s)", err, stderr.String())
	}
	if stdout.String() != "shared-value" {
		t.Errorf("stdout = %q, want %q (no trailing newline, not a terminal)", stdout.String(), "shared-value")
	}

	stdout.Reset()
	if err := cmdGet(context.Background(), "shared", opts, &stdout, true, ""); err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if stdout.String() != "shared-value\n" {
		t.Errorf("stdout = %q, want %q (trailing newline, a terminal)", stdout.String(), "shared-value\n")
	}
}

func TestCmdGet_LeaseNote(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	if err := cmdGet(context.Background(), "dbref_username", opts, &stdout, false, ""); err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if stdout.String() != "u" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "u")
	}
	if !strings.Contains(stderr.String(), "expire") {
		t.Errorf("stderr = %q, want a lease-expiry note", stderr.String())
	}
}

func TestCmdGet_UnknownName(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	err := cmdGet(context.Background(), "nope", opts, &stdout, false, "")
	if err == nil {
		t.Fatal("cmdGet: expected an error for an unknown name, got nil")
	}
	if exitCode(err) != 3 {
		t.Errorf("exitCode(err) = %d, want 3", exitCode(err))
	}
}

// TestCmdGet_JSONOutput exercises CLIENT-SPEC §1.2's --output json shape: a
// single {"name": ..., "value": ...} object, and nothing else, on stdout.
func TestCmdGet_JSONOutput(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	if err := cmdGet(context.Background(), "shared", opts, &stdout, false, "json"); err != nil {
		t.Fatalf("cmdGet: %v (stderr: %s)", err, stderr.String())
	}

	var got map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout: %q)", err, stdout.String())
	}
	if len(got) != 2 {
		t.Errorf("json object has %d keys, want 2 (name, value): %v", len(got), got)
	}
	if got["name"] != "shared" {
		t.Errorf(`json["name"] = %v, want "shared"`, got["name"])
	}
	if got["value"] != "shared-value" {
		t.Errorf(`json["value"] = %v, want "shared-value"`, got["value"])
	}

	want := `{"name":"shared","value":"shared-value"}` + "\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want %q (pure JSON, nothing else)", stdout.String(), want)
	}
}

// TestCmdGet_JSONOutput_StderrUnchanged proves --output json doesn't touch
// what goes to stderr: the same lease note printed in raw mode is printed,
// verbatim, in json mode too.
func TestCmdGet_JSONOutput_StderrUnchanged(t *testing.T) {
	fxRaw, fvRaw := setupGetEnvFixture(t)
	vcRaw := newTestVault(t, fvRaw)
	var stderrRaw, stdoutRaw bytes.Buffer
	optsRaw := resolveOpts{Runner: gitenv.ExecRunner{Dir: fxRaw.clone}, Vault: vcRaw, Token: rtToken, Stderr: &stderrRaw}
	if err := cmdGet(context.Background(), "dbref_username", optsRaw, &stdoutRaw, false, ""); err != nil {
		t.Fatalf("cmdGet (raw): %v", err)
	}

	fxJSON, fvJSON := setupGetEnvFixture(t)
	vcJSON := newTestVault(t, fvJSON)
	var stderrJSON, stdoutJSON bytes.Buffer
	optsJSON := resolveOpts{Runner: gitenv.ExecRunner{Dir: fxJSON.clone}, Vault: vcJSON, Token: rtToken, Stderr: &stderrJSON}
	if err := cmdGet(context.Background(), "dbref_username", optsJSON, &stdoutJSON, false, "json"); err != nil {
		t.Fatalf("cmdGet (json): %v", err)
	}

	if stderrRaw.String() != stderrJSON.String() {
		t.Errorf("stderr differs between output modes:\nraw:  %q\njson: %q", stderrRaw.String(), stderrJSON.String())
	}
	if !strings.Contains(stderrJSON.String(), "expire") {
		t.Errorf("stderr = %q, want a lease-expiry note in json mode too", stderrJSON.String())
	}
}

// TestCmdGet_JSONOutput_UnknownName_PrintsNothingOnStdout proves the error
// path never writes to stdout, json mode included.
func TestCmdGet_JSONOutput_UnknownName_PrintsNothingOnStdout(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	vc := newTestVault(t, fv)
	var stdout, stderr bytes.Buffer
	opts := resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Vault: vc, Token: rtToken, Stderr: &stderr}

	err := cmdGet(context.Background(), "nope", opts, &stdout, false, "json")
	if err == nil {
		t.Fatal("cmdGet: expected an error for an unknown name, got nil")
	}
	if exitCode(err) != 3 {
		t.Errorf("exitCode(err) = %d, want 3", exitCode(err))
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty (error path must print nothing to stdout)", stdout.String())
	}
}

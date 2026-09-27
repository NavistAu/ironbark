package main

import (
	"bytes"
	"context"
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
	if err := cmdGet(context.Background(), "shared", opts, &stdout, false); err != nil {
		t.Fatalf("cmdGet: %v (stderr: %s)", err, stderr.String())
	}
	if stdout.String() != "shared-value" {
		t.Errorf("stdout = %q, want %q (no trailing newline, not a terminal)", stdout.String(), "shared-value")
	}

	stdout.Reset()
	if err := cmdGet(context.Background(), "shared", opts, &stdout, true); err != nil {
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

	if err := cmdGet(context.Background(), "dbref_username", opts, &stdout, false); err != nil {
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

	err := cmdGet(context.Background(), "nope", opts, &stdout, false)
	if err == nil {
		t.Fatal("cmdGet: expected an error for an unknown name, got nil")
	}
	if exitCode(err) != 3 {
		t.Errorf("exitCode(err) = %d, want 3", exitCode(err))
	}
}

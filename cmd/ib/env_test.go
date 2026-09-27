package main

import (
	"bytes"
	"context"
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

	if err := cmdEnv(context.Background(), opts, &stdout); err != nil {
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

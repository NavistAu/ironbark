package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// writeStubCLI writes an executable shell script named name into dir that
// appends its own name and args to a shared log file, then exits with
// exitCode.
func writeStubCLI(t *testing.T, dir, name string, exitCode int, logFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub CLI script is POSIX shell only")
	}
	script := "#!/bin/sh\necho \"" + name + " $*\" >> " + logFile + "\nexit " + strconv.Itoa(exitCode) + "\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestCmdAuth_PrefersBao(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	writeStubCLI(t, dir, "bao", 0, logFile)
	writeStubCLI(t, dir, "vault", 0, logFile)
	t.Setenv("PATH", dir)

	var stdout, stderr bytes.Buffer
	code := cmdAuth([]string{"-method=userpass"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdAuth exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	log, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(log) != "bao login -method=userpass\n" {
		t.Errorf("log = %q, want bao invoked with login -method=userpass", log)
	}
}

func TestCmdAuth_FallsBackToVault(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	writeStubCLI(t, dir, "vault", 0, logFile)
	t.Setenv("PATH", dir)

	var stdout, stderr bytes.Buffer
	code := cmdAuth(nil, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("cmdAuth exit = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	log, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(log) != "vault login\n" {
		t.Errorf("log = %q, want vault invoked with login", log)
	}
}

func TestCmdAuth_NeitherFound(t *testing.T) {
	dir := t.TempDir() // empty: neither bao nor vault on PATH
	t.Setenv("PATH", dir)

	var stdout, stderr bytes.Buffer
	code := cmdAuth(nil, nil, &stdout, &stderr)
	if code != 2 {
		t.Errorf("cmdAuth exit = %d, want 2", code)
	}
	if !containsBoth(stderr.String(), "bao", "vault") {
		t.Errorf("stderr = %q, want it to name both bao and vault", stderr.String())
	}
}

func TestCmdAuth_PassesThroughExitCode(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	writeStubCLI(t, dir, "vault", 5, logFile)
	t.Setenv("PATH", dir)

	var stdout, stderr bytes.Buffer
	code := cmdAuth([]string{"-method=ldap", "-path=foo"}, nil, &stdout, &stderr)
	if code != 5 {
		t.Errorf("cmdAuth exit = %d, want 5 (the stub's own exit code)", code)
	}

	log, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(log) != "vault login -method=ldap -path=foo\n" {
		t.Errorf("log = %q, want args passed through verbatim", log)
	}
}

func containsBoth(s, a, b string) bool {
	return strings.Contains(s, a) && strings.Contains(s, b)
}

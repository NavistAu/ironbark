package main

// TestHelperProcess is not a real test of cmd/ib: it is re-executed (via
// os.Args[0], the compiled test binary) as the "child command" ib run
// tests hand to cmdRun, selected by scanning os.Args for a literal "--"
// exactly as os/exec's own TestHelperProcess pattern does (stdlib
// precedent: os/exec_test.go). Run normally by `go test`, os.Args carries
// no such "--" and this is a silent no-op.

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// helperArgs builds the args cmdRun's child command should be: this test
// binary, re-invoked to run only TestHelperProcess, with mode/rest after
// the "--" marker TestHelperProcess scans for.
func helperArgs(mode string, rest ...string) []string {
	args := []string{os.Args[0], "-test.run=TestHelperProcess", "--", mode}
	return append(args, rest...)
}

func TestHelperProcess(t *testing.T) {
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		return // not invoked as a helper process; a no-op under `go test`
	}

	mode, rest := args[0], args[1:]
	switch mode {
	case "printenv":
		fmt.Print(os.Getenv(rest[0]))
	case "exit":
		code, _ := strconv.Atoi(rest[0])
		os.Exit(code)
	case "splitwrite":
		// Writes value in two separate Write calls with a short pause in
		// between, so a masking Writer only catching whole single Writes
		// (rather than streaming across them) would leak half of it.
		value := rest[0]
		mid := len(value) / 2
		fmt.Fprint(os.Stdout, value[:mid])
		os.Stdout.Sync()
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(os.Stdout, value[mid:])
	case "marker":
		// Proves the child ran at all (used by the unresolved-ref test to
		// assert the opposite: this file must NOT exist).
		_ = os.WriteFile(rest[0], []byte("ran"), 0o644)
	case "waitsigterm":
		outFile := rest[0]
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM)
		_ = os.WriteFile(outFile+".ready", []byte("1"), 0o644)
		select {
		case <-ch:
			_ = os.WriteFile(outFile, []byte("got-sigterm"), 0o644)
		case <-time.After(5 * time.Second):
			_ = os.WriteFile(outFile, []byte("timeout"), 0o644)
		}
	}
	os.Exit(0)
}

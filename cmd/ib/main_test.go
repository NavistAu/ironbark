package main

// TestMain builds the actual `ib` binary once, up front, for the one test
// (signal forwarding, run_test.go) that needs a real separate `ib`
// process to send a real OS signal to — sending SIGTERM to the test
// binary itself would kill the whole test run, so that case can't be
// exercised by calling cmdRun in-process like the rest of run_test.go
// does. Every other cmd/ib test calls the package's own functions
// directly and needs no compiled binary at all.
//
// isHelperInvocation guards against building on every re-exec: when this
// same compiled test binary is re-invoked as a run_helper_test.go
// "child" command (TestHelperProcess), building ib again would be pure
// waste (and would race concurrent children over the same output path).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var ibBinaryPath string

func TestMain(m *testing.M) {
	os.Exit(testMainRun(m))
}

func testMainRun(m *testing.M) int {
	if isHelperInvocation() {
		return m.Run()
	}

	dir, err := os.MkdirTemp("", "ib-test-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ib test: mkdtemp:", err)
		return 1
	}
	defer os.RemoveAll(dir)

	ibBinaryPath = filepath.Join(dir, "ib")
	build := exec.Command("go", "build", "-o", ibBinaryPath, ".")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "ib test: go build ib:", err)
		return 1
	}

	// ib reads ~/.config/ib/config: never the developer's real one.
	os.Setenv("HOME", dir)

	return m.Run()
}

func isHelperInvocation() bool {
	for _, a := range os.Args {
		if a == "-test.run=TestHelperProcess" {
			return true
		}
	}
	return false
}

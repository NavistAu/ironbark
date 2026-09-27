// This file implements `ib auth` (CLIENT-SPEC §1.1, plan Task 10): a thin
// wrapper over the Vault/OpenBao CLI's own `login`. ib itself stores no
// token; it only ever reads one back later from ~/.vault-token
// (internal/ibcfg), the default token-helper location that CLI's login
// leaves it in.
package main

import (
	"fmt"
	"io"
	"os/exec"
)

// cmdAuth runs `bao login <args…>` if bao is on PATH, else `vault login
// <args…>`, else exits 2 naming both (CLIENT-SPEC §1.1). Arguments pass
// through unchanged; stdio is inherited (login may prompt interactively).
// The exit code is the underlying CLI's own.
func cmdAuth(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cliPath, err := findVaultCLI()
	if err != nil {
		fmt.Fprintln(stderr, "ib:", err)
		return 2
	}

	cmd := exec.Command(cliPath, append([]string{"login"}, args...)...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return childExitCode(err)
	}
	return 0
}

// findVaultCLI returns the path to bao if it's on PATH, else vault, else
// an error naming both.
func findVaultCLI() (string, error) {
	if p, err := exec.LookPath("bao"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("vault"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("neither bao nor vault found on PATH")
}

//go:build integration

// Task 11 (plan docs/plans/2026-09-28-m3-ib-client.md): ib client
// integration tests against the existing dual-product harness
// (docker-compose.yml, SetupProduct's kv mount + database engine, both
// Vault and OpenBao — see the products loop), exercising the REAL `ib`
// binary (go build ./cmd/ib) exactly as CLIENT-SPEC describes it:
// environment selection from a real git checkout, the sweep made with a
// caller-held Vault token (never AppRole/mint machinery — CLIENT-SPEC
// §6), and `ib run`'s lease revocation.
//
// The most important case here is "agreement_with_broker": for the
// identical KV layout and branch, ib env's (name, value) set must equal
// the broker's own signed-request response (reusing e2e_test.go's
// signing helpers), minus vault_addr/vault_token — CLIENT-SPEC §0's whole
// premise ("the same secrets... one resolution algorithm, two callers").
package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/navistau/ironbark/internal/envfile"
)

var (
	ibBinOnce sync.Once
	ibBinPath string
	ibBinErr  error
)

// buildIBBinary builds cmd/ib once per test binary run (shared across
// every product/scenario subtest below) and returns its path.
func buildIBBinary(t *testing.T) string {
	t.Helper()
	ibBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ib-integration-bin")
		if err != nil {
			ibBinErr = err
			return
		}
		ibBinPath = filepath.Join(dir, "ib")
		cmd := exec.Command("go", "build", "-o", ibBinPath, "github.com/navistau/ironbark/cmd/ib")
		if out, err := cmd.CombinedOutput(); err != nil {
			ibBinErr = fmt.Errorf("go build ./cmd/ib: %w\n%s", err, out)
		}
	})
	if ibBinErr != nil {
		t.Fatalf("buildIBBinary: %v", ibBinErr)
	}
	return ibBinPath
}

// ibEnviron builds a clean environment for an `ib` subprocess: the test
// process's own PATH/HOME (so git, and any bao/vault CLI, resolve), plus
// exactly the CLIENT-SPEC §5 variables the scenario needs, plus any
// extra "KEY=value" pairs — no leakage of any other BAO_*/VAULT_*/IB_*
// variable the test process itself might happen to have set.
func ibEnviron(addr, token string, extra ...string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"BAO_ADDR=" + addr,
		"BAO_TOKEN=" + token,
	}
	return append(env, extra...)
}

// runIB runs the built ib binary with args in dir under env, returning
// stdout, stderr, and its exit code (0 on a clean exit).
func runIB(t *testing.T, dir string, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(buildIBBinary(t), args...)
	cmd.Dir = dir
	cmd.Env = env
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return so.String(), se.String(), ee.ExitCode()
		}
		t.Fatalf("run ib %v: %v (stderr: %s)", args, err, se.String())
	}
	return so.String(), se.String(), 0
}

// parseIBEnv parses `ib env`'s stdout (envfile.Format lines,
// SECRET_<UPPER(name)>='<value>') back into a name->value map. Sweep
// names are already lower_snake_case, so upper-casing and re-lowering
// round-trips exactly.
func parseIBEnv(t *testing.T, stdout string) map[string]string {
	t.Helper()
	entries, err := envfile.Parse(strings.NewReader(stdout))
	if err != nil {
		t.Fatalf("parse ib env output: %v\n%s", err, stdout)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if !strings.HasPrefix(e.Key, "SECRET_") {
			t.Fatalf("ib env entry key %q missing SECRET_ prefix", e.Key)
		}
		out[strings.ToLower(strings.TrimPrefix(e.Key, "SECRET_"))] = e.Value
	}
	return out
}

func ibEnvNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// splitDbref separates the "dbref_*" names (the lease-bearing $ref's
// flattened fields, whose VALUES are fresh dynamic credentials on every
// independent sweep) from everything else, for assertions that need to
// ignore dbref's inherent per-call non-determinism while still checking
// its names are present.
func splitDbref(names []string) (dbref, other []string) {
	for _, n := range names {
		if strings.HasPrefix(n, "dbref_") {
			dbref = append(dbref, n)
		} else {
			other = append(other, n)
		}
	}
	return dbref, other
}

func TestIBClient(t *testing.T) {
	for _, p := range products {
		p := p
		t.Run(p.name, func(t *testing.T) {
			ctx := t.Context()
			fx := SetupProduct(t, p.addr, p.rootToken)
			root := NewRootClient(t, p.addr, p.rootToken)
			setupIBFixture(t, ctx, root)
			git := newIBGitFixture(t)

			fullToken := mintIBToken(t, ctx, root, []string{ibPolicyBase, ibPolicyMain, ibPolicyDevelop})
			noBranchToken := mintIBToken(t, ctx, root, []string{ibPolicyBase})

			var mainSecrets map[string]string

			// ---- on main: base + event + main-branch tiers, both $refs ----
			t.Run("main_branch", func(t *testing.T) {
				env := ibEnviron(p.addr, fullToken)
				stdout, stderr, code := runIB(t, git.mainClone, env, "env")
				if code != 0 {
					t.Fatalf("ib env exit %d, stderr: %s", code, stderr)
				}
				mainSecrets = parseIBEnv(t, stdout)

				dbrefNames, otherNames := splitDbref(ibEnvNames(mainSecrets))
				wantFixed := []string{"kvref", "prod_only", "shared", "shared_push"}
				if !equalStrings(otherNames, wantFixed) {
					t.Errorf("ib env (main) non-dbref names = %v, want %v", otherNames, wantFixed)
				}
				if len(dbrefNames) == 0 {
					t.Errorf("ib env (main) has no dbref_* secret from the $ref deref into the database engine")
				}
				if mainSecrets["shared"] != "shared-value" {
					t.Errorf("shared = %q, want %q", mainSecrets["shared"], "shared-value")
				}
				if mainSecrets["shared_push"] != "shared-push-value" {
					t.Errorf("shared_push = %q, want %q", mainSecrets["shared_push"], "shared-push-value")
				}
				if mainSecrets["prod_only"] != "prod-only-value" {
					t.Errorf("prod_only = %q, want %q", mainSecrets["prod_only"], "prod-only-value")
				}
				if mainSecrets["kvref"] != "kv-target-value" {
					t.Errorf("kvref = %q, want %q (KV v2-shaped $ref deref)", mainSecrets["kvref"], "kv-target-value")
				}
				if !strings.Contains(stderr, "ib: env main (direct match)") {
					t.Errorf("stderr = %q, want the direct-match visibility line", stderr)
				}
			})

			// ---- on a branch cut from develop: dev_only instead of prod_only ----
			t.Run("branch_cut_from_develop", func(t *testing.T) {
				env := ibEnviron(p.addr, fullToken)
				stdout, stderr, code := runIB(t, git.featureClone, env, "env")
				if code != 0 {
					t.Fatalf("ib env exit %d, stderr: %s", code, stderr)
				}
				secrets := parseIBEnv(t, stdout)

				dbrefNames, otherNames := splitDbref(ibEnvNames(secrets))
				wantFixed := []string{"dev_only", "kvref", "shared", "shared_push"}
				if !equalStrings(otherNames, wantFixed) {
					t.Errorf("ib env (feature/develop) non-dbref names = %v, want %v", otherNames, wantFixed)
				}
				if len(dbrefNames) == 0 {
					t.Errorf("ib env (feature/develop) has no dbref_* secret")
				}
				if secrets["dev_only"] != "dev-only-value" {
					t.Errorf("dev_only = %q, want %q", secrets["dev_only"], "dev-only-value")
				}
				if _, ok := secrets["prod_only"]; ok {
					t.Errorf("prod_only leaked on a branch cut from develop: %v", ibEnvNames(secrets))
				}
				if !strings.Contains(stderr, "ib: env develop (nearest ancestor") {
					t.Errorf("stderr = %q, want a nearest-ancestor visibility line naming develop", stderr)
				}
			})

			// ---- a caller token without read on push/main/* gets no
			// prod_only, even overriding --branch main explicitly: branch
			// selection is an environment choice, not access control
			// (CLIENT-SPEC §3/§6) ----
			t.Run("branch_tier_requires_its_own_policy", func(t *testing.T) {
				env := ibEnviron(p.addr, noBranchToken)
				stdout, stderr, code := runIB(t, git.mainClone, env, "env", "--branch", "main")
				if code != 0 {
					t.Fatalf("ib env --branch main (no branch policy) exit %d, stderr: %s", code, stderr)
				}
				secrets := parseIBEnv(t, stdout)
				if _, ok := secrets["prod_only"]; ok {
					t.Errorf("prod_only present despite no read on push/main/*: %v", ibEnvNames(secrets))
				}
				if secrets["shared"] != "shared-value" {
					t.Errorf("base-tier secret missing/wrong even though the base policy alone should still grant it: %v", secrets)
				}
			})

			// ---- agreement: ib env and the broker's own signed-request
			// response must produce the same secrets for the same layout
			// and branch (CLIENT-SPEC §0) ----
			t.Run("agreement_with_broker", func(t *testing.T) {
				if mainSecrets == nil {
					t.Fatal("main_branch subtest must run first and populate its secrets")
				}

				priv, pub := loadE2EKeys(t)
				stack := newE2EStack(t, ctx, p.addr, fx, pub)

				// No .identity entry exists for acme/widgets: absent, so
				// the broker does not enforce it (SPEC §4.4) — any
				// forge_remote_id, including empty, is accepted.
				body := woodpeckerPayload(t, ibOrg+"/"+ibRepo, "")
				req := signedRequest(t, stack.server.URL, body, priv)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("signed request: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("broker response status = %d, want 200", resp.StatusCode)
				}

				var rb e2eResponseBody
				if err := json.NewDecoder(resp.Body).Decode(&rb); err != nil {
					t.Fatalf("decode broker response: %v", err)
				}

				brokerSecrets := make(map[string]string, len(rb.Secrets))
				for _, s := range rb.Secrets {
					if s.Name == "vault_addr" || s.Name == "vault_token" {
						continue
					}
					brokerSecrets[s.Name] = s.Value
				}
				brokerNames := make([]string, 0, len(brokerSecrets))
				for n := range brokerSecrets {
					brokerNames = append(brokerNames, n)
				}
				sort.Strings(brokerNames)

				if !equalStrings(ibEnvNames(mainSecrets), brokerNames) {
					t.Fatalf("secret name sets diverge:\n  ib:     %v\n  broker: %v", ibEnvNames(mainSecrets), brokerNames)
				}

				// Every deterministic (non-dbref_*) secret must match
				// byte-for-byte — CLIENT-SPEC §0's "one resolution
				// algorithm, two callers" premise. dbref_* values are
				// excluded: the database engine mints a fresh dynamic
				// credential on every independent read, so ib's own sweep
				// and the broker's own sweep legitimately get DIFFERENT
				// values for the SAME $ref entry on each call — the one
				// place value equality does not apply, by the nature of a
				// lease-bearing deref, not a weakening of this test.
				for name, want := range mainSecrets {
					if strings.HasPrefix(name, "dbref_") {
						continue
					}
					if got := brokerSecrets[name]; got != want {
						t.Errorf("secret %q: ib=%q broker=%q, want equal", name, want, got)
					}
				}
			})

			// ---- ib run revokes a lease-bearing secret's lease after the
			// child exits ----
			t.Run("run_revokes_lease", func(t *testing.T) {
				dir := t.TempDir()
				envFile := filepath.Join(dir, "secrets.env")
				outFile := filepath.Join(dir, "out.txt")
				if err := os.WriteFile(envFile, []byte("DBCRED=ironbark://dbref_username\n"), 0o600); err != nil {
					t.Fatalf("write env file: %v", err)
				}

				before := ibLeaseIDs(t, ctx, root, DerefRefPath)

				env := ibEnviron(p.addr, fullToken, "OUT_FILE="+outFile)
				stdout, stderr, code := runIB(t, git.mainClone, env, "run", "--env-file", envFile, "--", "sh", "-c", `printf '%s' "$DBCRED" > "$OUT_FILE"`)
				if code != 0 {
					t.Fatalf("ib run exit %d, stdout=%q stderr=%q", code, stdout, stderr)
				}

				got, err := os.ReadFile(outFile)
				if err != nil || len(got) == 0 {
					t.Fatalf("child did not receive a resolved DBCRED value: %v (content=%q)", err, got)
				}

				after := ibLeaseIDs(t, ctx, root, DerefRefPath)
				if !equalStrings(before, after) {
					t.Errorf("lease set changed across ib run: before=%v after=%v (want the deref's lease revoked by exit, i.e. a lookup on it now 404s)\nstdout=%q\nstderr=%q", before, after, stdout, stderr)
				}
			})
		})
	}
}

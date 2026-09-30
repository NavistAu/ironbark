//go:build integration && ib_legacy

// Task 11 (plan docs/plans/2026-09-28-m3-ib-client.md): KV layout,
// policies, and a git checkout fixture for the ib client integration
// suite (ib_test.go). Deliberately a separate org/repo ("acme/widgets")
// from fixture.go's itest/repoN fixtures so the two suites never
// interact — same "kv" mount and "database" engine (SetupProduct),
// disjoint KV subtree.
//
// Layout (CLIENT-SPEC §3/§4 worked example, matching the plan's Task 11
// bullet):
//
//	base   ci/acme/widgets
//	event  ci/acme/widgets/push
//	branch ci/acme/widgets/push/main, ci/acme/widgets/push/develop
//
//	  shared                 (base)   {"value":...}
//	  push/shared_push       (event)  {"value":...}
//	  push/main/prod_only    (branch) {"value":...}
//	  push/develop/dev_only  (branch) {"value":...}
//	  kvref                  (base)   {"$ref":"kv/data/ci/_ibrefstore/kvtarget"}
//	                                   — a $ref into a KV v2 path (SPEC §4.3
//	                                   "KV v2-shaped targets"). The target
//	                                   itself lives OUTSIDE the acme/widgets
//	                                   tree (ci/_ibrefstore/kvtarget) so it is
//	                                   never itself enumerated by a tier LIST
//	                                   — only reached via kvref's $ref, same
//	                                   as dbref's database-engine target.
//	  dbref                  (base)   {"$ref":"database/creds/readonly"}
//	                                   — a $ref into the lease-bearing
//	                                   `database` engine SetupProduct already
//	                                   mounts (fixture.go's setupDatabase);
//	                                   shared globally, not itself scoped to
//	                                   this org/repo
//
// Policies match exactly what the broker's policy.Derive computes for
// org=acme, repo=widgets, event=push (SPEC §2.3): P1 = ci/acme/widgets/push
// (base+event tier), P2main = ci/acme/widgets/push/main, P2develop =
// ci/acme/widgets/push/develop (branch tiers, tier-isolated from each
// other). This is what makes the agreement test (ib_test.go) meaningful: a
// caller token minted with exactly these policies has the same effective
// access a CI push to the matching branch would get from the broker.
package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

const (
	ibOrg  = "acme"
	ibRepo = "widgets"

	ibPolicyBase    = "ci/acme/widgets/push"
	ibPolicyMain    = "ci/acme/widgets/push/main"
	ibPolicyDevelop = "ci/acme/widgets/push/develop"

	// ibOriginURL is the fixture git checkouts' origin remote (CLIENT-SPEC
	// §2's https form): the last two path segments are exactly
	// ibOrg/ibRepo.
	ibOriginURL = "https://forge.example/acme/widgets.git"
)

func ibBase() string { return "ci/" + ibOrg + "/" + ibRepo }

// ibKVRefTarget is kvref's $ref deref target: a KV v2 secret deliberately
// stored OUTSIDE the ci/acme/widgets tree, so it is never itself
// enumerated by any of that tree's tier LISTs — reached only via kvref's
// $ref, the same shape dbref's database-engine target already has.
const ibKVRefTargetPath = "ci/_ibrefstore/kvtarget"

// setupIBFixture writes the KV layout and policies described in this
// file's package doc comment. Assumes SetupProduct has already run
// against root's instance (kv mount + database engine).
func setupIBFixture(t *testing.T, ctx context.Context, root *api.Client) {
	t.Helper()

	base := ibBase()
	event := base + "/push"
	main := event + "/main"
	develop := event + "/develop"

	mustPutPolicy(t, ctx, root, ibPolicyBase, policyHCL([]pathCap{
		{"kv/metadata/" + base, []string{"list"}},
		{"kv/metadata/" + event, []string{"list"}},
		{"kv/data/" + base + "/shared", []string{"read"}},
		{"kv/data/" + event + "/shared_push", []string{"read"}},
		{"kv/data/" + base + "/kvref", []string{"read"}},
		{"kv/data/" + ibKVRefTargetPath, []string{"read"}},
		{"kv/data/" + base + "/dbref", []string{"read"}},
		{"kv/data/" + base + "/cron_only", []string{"read"}},
		{"kv/data/" + base + "/push_and_cron", []string{"read"}},
		{DerefRefPath, []string{"read"}},
		// CLIENT-SPEC §1.4: ib run revokes a lease it used via the
		// caller's own token, which needs update on sys/leases/revoke.
		{"sys/leases/revoke", []string{"update"}},
	}))
	mustPutPolicy(t, ctx, root, ibPolicyMain, policyHCL([]pathCap{
		{"kv/metadata/" + main, []string{"list"}},
		{"kv/data/" + main + "/prod_only", []string{"read"}},
	}))
	mustPutPolicy(t, ctx, root, ibPolicyDevelop, policyHCL([]pathCap{
		{"kv/metadata/" + develop, []string{"list"}},
		{"kv/data/" + develop + "/dev_only", []string{"read"}},
	}))

	kv := root.KVv2("kv")
	put := func(path string, data map[string]interface{}) {
		t.Helper()
		if _, err := kv.Put(ctx, path, data); err != nil {
			t.Fatalf("integration: ib fixture kv put %s: %v", path, err)
		}
	}
	put(base+"/shared", map[string]interface{}{"value": "shared-value"})
	put(event+"/shared_push", map[string]interface{}{"value": "shared-push-value"})
	put(main+"/prod_only", map[string]interface{}{"value": "prod-only-value"})
	put(develop+"/dev_only", map[string]interface{}{"value": "dev-only-value"})
	put(ibKVRefTargetPath, map[string]interface{}{"value": "kv-target-value"})
	put(base+"/kvref", map[string]interface{}{"$ref": "kv/data/" + ibKVRefTargetPath})
	put(base+"/dbref", map[string]interface{}{"$ref": DerefRefPath})

	// T1: a secret pinned away from push (cron only) must never be
	// returned by ib (CLIENT-SPEC §4: ironbark_events applied with event
	// "push"), and one pinned to include push (alongside another event)
	// must still be returned — exercised by the agreement_with_broker
	// subtest (ib_test.go), which also proves the broker's own response
	// agrees once the same push filter is applied there.
	put(base+"/cron_only", map[string]interface{}{"value": "cron-only-value"})
	if err := kv.PutMetadata(ctx, base+"/cron_only", api.KVMetadataPutInput{
		CustomMetadata: map[string]interface{}{"ironbark_events": "cron"},
	}); err != nil {
		t.Fatalf("integration: kv metadata cron_only: %v", err)
	}
	put(base+"/push_and_cron", map[string]interface{}{"value": "push-and-cron-value"})
	if err := kv.PutMetadata(ctx, base+"/push_and_cron", api.KVMetadataPutInput{
		CustomMetadata: map[string]interface{}{"ironbark_events": "push,cron"},
	}); err != nil {
		t.Fatalf("integration: kv metadata push_and_cron: %v", err)
	}
}

// mintIBToken creates a plain Vault token directly as root with exactly
// policies attached — standing in for the operator's own scoped Vault
// token (CLIENT-SPEC §5.1/§6: ib mints nothing itself; every read is made
// with whatever token the caller already holds).
func mintIBToken(t *testing.T, ctx context.Context, root *api.Client, policies []string) string {
	t.Helper()
	secret, err := root.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{
		Policies: policies,
		TTL:      "10m",
	})
	if err != nil {
		t.Fatalf("integration: mint ib caller token (policies %v): %v", policies, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatalf("integration: mint ib caller token: no auth in response: %+v", secret)
	}
	return secret.Auth.ClientToken
}

// ibLeaseIDs lists the currently-active lease IDs under prefix (e.g.
// DerefRefPath), for the ib_test.go run_revokes_lease before/after
// snapshot. A prefix with no leases at all yields an empty slice, not an
// error (LIST 404s cleanly).
func ibLeaseIDs(t *testing.T, ctx context.Context, root *api.Client, prefix string) []string {
	t.Helper()
	secret, err := root.Logical().ListWithContext(ctx, "sys/leases/lookup/"+prefix)
	if err != nil {
		t.Fatalf("integration: list leases under %s: %v", prefix, err)
	}
	if secret == nil || secret.Data == nil {
		return nil
	}
	keys, _ := secret.Data["keys"].([]interface{})
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			ids = append(ids, s)
		}
	}
	sort.Strings(ids)
	return ids
}

// --- git checkout fixture: a bare "forge" repo (branches main, develop)
// plus two clones, mirroring cmd/ib's own unit-test fixture
// (cmd/ib/gitfixture_test.go) but built here since that file lives in
// `package main` and isn't importable from this package.

func ibSetGitEnv(t *testing.T) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "empty.gitconfig")
	if err := os.WriteFile(cfg, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "ib-integration-test")
	t.Setenv("GIT_AUTHOR_EMAIL", "ib-integration-test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "ib-integration-test")
	t.Setenv("GIT_COMMITTER_EMAIL", "ib-integration-test@example.com")
}

func ibGitRaw(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v (dir=%s): %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func ibCommit(t *testing.T, dir, content, msg string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ibGitRaw(t, dir, "commit", "-q", "-am", msg)
}

// ibGitFixture is a bare "forge" repo (branches main, develop, develop 2
// commits ahead of main) and two clones of it, both with their origin
// rewritten to ibOriginURL (org=acme, repo=widgets): mainClone stays
// checked out on "main" (direct match, CLIENT-SPEC §3 rule 2);
// featureClone checks out a local branch cut from origin/develop with one
// more commit (nearest-ancestor selection, rule 3).
type ibGitFixture struct {
	mainClone    string
	featureClone string
}

func newIBGitFixture(t *testing.T) ibGitFixture {
	t.Helper()
	ibSetGitEnv(t)

	root := t.TempDir()
	forge := filepath.Join(root, "forge.git")
	seed := filepath.Join(root, "seed")

	ibGitRaw(t, root, "init", "-q", "--bare", "-b", "main", forge)
	ibGitRaw(t, root, "init", "-q", "-b", "main", seed)
	ibGitRaw(t, seed, "config", "user.name", "ib-integration-test")
	ibGitRaw(t, seed, "config", "user.email", "ib-integration-test@example.com")
	if err := os.WriteFile(filepath.Join(seed, "f.txt"), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	ibGitRaw(t, seed, "add", "f.txt")
	ibGitRaw(t, seed, "commit", "-q", "-m", "c0")
	ibGitRaw(t, seed, "remote", "add", "origin", forge)
	ibGitRaw(t, seed, "push", "-q", "origin", "main")

	ibGitRaw(t, seed, "checkout", "-q", "-b", "develop", "main")
	ibCommit(t, seed, "1", "develop commit 1")
	ibCommit(t, seed, "2", "develop commit 2")
	ibGitRaw(t, seed, "push", "-q", "origin", "develop")

	mainClone := filepath.Join(root, "clone-main")
	ibGitRaw(t, root, "clone", "-q", forge, mainClone)
	ibGitRaw(t, mainClone, "config", "user.name", "ib-integration-test")
	ibGitRaw(t, mainClone, "config", "user.email", "ib-integration-test@example.com")
	ibGitRaw(t, mainClone, "remote", "set-url", "origin", ibOriginURL)

	featureClone := filepath.Join(root, "clone-feature")
	ibGitRaw(t, root, "clone", "-q", forge, featureClone)
	ibGitRaw(t, featureClone, "config", "user.name", "ib-integration-test")
	ibGitRaw(t, featureClone, "config", "user.email", "ib-integration-test@example.com")
	ibGitRaw(t, featureClone, "checkout", "-q", "-b", "feature", "origin/develop")
	ibCommit(t, featureClone, "3", "feature commit")
	ibGitRaw(t, featureClone, "remote", "set-url", "origin", ibOriginURL)

	return ibGitFixture{mainClone: mainClone, featureClone: featureClone}
}

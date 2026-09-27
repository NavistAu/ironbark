package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/vaultx"
)

const (
	rtBase  = "ci/acme/widgets"
	rtEvent = "ci/acme/widgets/push"
	rtMain  = "ci/acme/widgets/push/main"
	rtToken = "caller-token"
)

func newTestVault(t *testing.T, fv *fakeVault) *vaultx.Client {
	t.Helper()
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)

	c, err := vaultx.New(vaultx.Config{Addr: srv.URL, KVMount: "kv", KVPrefix: "ci"})
	if err != nil {
		t.Fatalf("vaultx.New: %v", err)
	}
	return c
}

// TestResolve_ChosenTierAndPinFiltering exercises the happy path: a
// checkout on a tracked branch ("main"), secrets swept from all three
// tiers, and a per-secret ironbark_events pin (SPEC §4.6) applied with
// event "push" (CLIENT-SPEC §4) — a secret pinned away from push is
// dropped, one pinned to include push survives alongside its unpinned
// siblings.
func TestResolve_ChosenTierAndPinFiltering(t *testing.T) {
	fx := newIBFixture(t, nil) // clone stays on "main" after clone

	fv := newFakeVault()
	fv.set("/v1/kv/metadata/"+rtEvent, 200, listBody([]string{"shared_push", "main/"}))
	fv.set("/v1/kv/data/"+rtEvent+"/shared_push", 200, entryBody(map[string]interface{}{"value": "shared-push-value"}, nil))
	fv.set("/v1/kv/metadata/"+rtBase, 200, listBody([]string{"shared"}))
	fv.set("/v1/kv/data/"+rtBase+"/shared", 200, entryBody(map[string]interface{}{"value": "shared-value"}, nil))
	fv.set("/v1/kv/metadata/"+rtMain, 200, listBody([]string{"prod_only", "pinned_cron", "pinned_push"}))
	fv.set("/v1/kv/data/"+rtMain+"/prod_only", 200, entryBody(map[string]interface{}{"value": "prod-only-value"}, nil))
	fv.set("/v1/kv/data/"+rtMain+"/pinned_cron", 200, entryBody(map[string]interface{}{"value": "pinned-cron-value"}, map[string]string{"ironbark_events": "cron"}))
	fv.set("/v1/kv/data/"+rtMain+"/pinned_push", 200, entryBody(map[string]interface{}{"value": "pinned-push-value"}, map[string]string{"ironbark_events": "push,cron"}))

	vc := newTestVault(t, fv)
	var stderr bytes.Buffer
	secrets, leaseIDs, err := resolve(context.Background(), resolveOpts{
		Runner: gitenv.ExecRunner{Dir: fx.clone},
		Vault:  vc,
		Token:  rtToken,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("resolve: %v (stderr: %s)", err, stderr.String())
	}
	if len(leaseIDs) != 0 {
		t.Errorf("leaseIDs = %v, want none", leaseIDs)
	}

	want := map[string]string{
		"shared":      "shared-value",
		"shared_push": "shared-push-value",
		"prod_only":   "prod-only-value",
		"pinned_push": "pinned-push-value",
	}
	if len(secrets) != len(want) {
		t.Fatalf("secrets = %v, want keys %v", secretNames(secrets), want)
	}
	for name, value := range want {
		s, ok := secrets[name]
		if !ok {
			t.Errorf("missing secret %q", name)
			continue
		}
		if s.Value != value {
			t.Errorf("secret %q value = %q, want %q", name, s.Value, value)
		}
	}
	if _, ok := secrets["pinned_cron"]; ok {
		t.Errorf("pinned_cron should have been dropped (pinned away from push)")
	}

	if !strings.Contains(stderr.String(), "ib: env main (direct match)") {
		t.Errorf("stderr = %q, want it to contain the direct-match visibility line", stderr.String())
	}
}

func secretNames(m map[string]vaultx.SweptSecret) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	return names
}

// TestResolve_NoBranchTiers exercises CLIENT-SPEC §3's "no branch tiers at
// all" path: ListBranchTiers sees nothing (404), so resolve sweeps only
// the event and base tiers and says so on stderr.
func TestResolve_NoBranchTiers(t *testing.T) {
	fx := newIBFixture(t, nil)

	fv := newFakeVault()
	// No entry set for rtEvent's metadata path -> 404 -> ListBranchTiers
	// returns (nil, nil) and sweepTier's own LIST of the same path also
	// sees the 404 (no event-tier secrets in this test).
	fv.set("/v1/kv/metadata/"+rtBase, 200, listBody([]string{"shared"}))
	fv.set("/v1/kv/data/"+rtBase+"/shared", 200, entryBody(map[string]interface{}{"value": "shared-value"}, nil))

	vc := newTestVault(t, fv)
	var stderr bytes.Buffer
	secrets, _, err := resolve(context.Background(), resolveOpts{
		Runner: gitenv.ExecRunner{Dir: fx.clone},
		Vault:  vc,
		Token:  rtToken,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("resolve: %v (stderr: %s)", err, stderr.String())
	}
	if len(secrets) != 1 || secrets["shared"].Value != "shared-value" {
		t.Errorf("secrets = %v, want just shared=shared-value", secrets)
	}
	if !strings.Contains(stderr.String(), "ib: no branch tiers; event and base tiers only") {
		t.Errorf("stderr = %q, want the no-branch-tiers line", stderr.String())
	}
}

// TestResolve_Ambiguous exercises CLIENT-SPEC §3 rule 6: a tie that
// survives both the reflog and cascade tie-breaks fails with the
// candidates (and their distances) named on stderr, asking for --branch.
func TestResolve_Ambiguous(t *testing.T) {
	fx := newIBFixture(t, func(seedDir string) {
		pushBranch(t, seedDir, "alpha", "main", 1)
		gitRaw(t, seedDir, "checkout", "-q", "main")
		pushBranch(t, seedDir, "beta", "main", 1)
		gitRaw(t, seedDir, "checkout", "-q", "main")
	})
	// "work" is cut from main (not alpha/beta), so its reflog names
	// "main" — neither tied candidate — and alpha/beta (lowercase,
	// unadorned names) aren't in the built-in Cascade list either: both
	// tie-breaks fall through to rule 6, ambiguous.
	gitRaw(t, fx.clone, "checkout", "-q", "-b", "work", "main")
	commitFixture(t, fx.clone, "work-1", "work-commit")

	fv := newFakeVault()
	fv.set("/v1/kv/metadata/"+rtEvent, 200, listBody([]string{"alpha/", "beta/"}))

	vc := newTestVault(t, fv)
	var stderr bytes.Buffer
	_, _, err := resolve(context.Background(), resolveOpts{
		Runner: gitenv.ExecRunner{Dir: fx.clone},
		Vault:  vc,
		Token:  rtToken,
		Stderr: &stderr,
	})
	if err == nil {
		t.Fatal("resolve: expected an error, got nil")
	}
	selErr, ok := err.(*gitenv.SelectError)
	if !ok {
		t.Fatalf("resolve error type = %T, want *gitenv.SelectError", err)
	}
	if selErr.Kind != "ambiguous" {
		t.Errorf("SelectError.Kind = %q, want ambiguous", selErr.Kind)
	}
	if _, ok := selErr.Candidates["alpha"]; !ok {
		t.Errorf("candidates = %v, want alpha present", selErr.Candidates)
	}
	if _, ok := selErr.Candidates["beta"]; !ok {
		t.Errorf("candidates = %v, want beta present", selErr.Candidates)
	}
	if exitCode(err) != 4 {
		t.Errorf("exitCode(err) = %d, want 4", exitCode(err))
	}
}

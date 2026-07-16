//go:build integration

// Task 14: per-group scenario implementations for TestBrokerSuite
// (broker_test.go). Split out purely for file-size sanity; every function
// here is called exactly once per product from TestBrokerSuite.
package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"ironbark/internal/broker"
	"ironbark/internal/identity"
	"ironbark/internal/vaultx"
)

// canaryMisconfigCase is one SPEC §9.3 canary-misconfiguration case: a
// token role identical to the documented `ci` role (SPEC §3.1) except for
// one flipped field, expected to make the canary fail with an error
// naming the violated expectation.
type canaryMisconfigCase struct {
	name          string
	roleName      string
	fields        map[string]interface{}
	wantErrSubstr string
}

// testCanaryMisconfig covers SPEC §9.3's five canary-misconfiguration
// cases. Each alternate role is named "ci-*" so the widened
// ironbark-agent policy (widenAppRolePolicyForCanaryTests) covers minting
// against it via the fixture's own AppRole.
//
// token_type=batch cannot carry token_explicit_max_ttl (integration-
// verified: both products reject the role write with "'token_type'
// cannot be 'batch' when role is set to generate tokens with an explicit
// max TTL") — that case uses token_ttl instead; every other case keeps
// token_explicit_max_ttl=90s like the real role.
func testCanaryMisconfig(t *testing.T, ctx context.Context, addr string, fx Fixture, root *api.Client) {
	t.Helper()

	batchFields := map[string]interface{}{
		"allowed_policies_glob":   []string{"ci/*"},
		"token_type":              "batch",
		"orphan":                  true,
		"renewable":               false,
		"token_no_default_policy": false,
		"token_ttl":               "90s",
	}
	renewableFields := baseCiRoleFields()
	renewableFields["renewable"] = true
	orphanFields := baseCiRoleFields()
	orphanFields["orphan"] = false
	nodefaultFields := baseCiRoleFields()
	nodefaultFields["token_no_default_policy"] = true
	narrowGlobFields := baseCiRoleFields()
	narrowGlobFields["allowed_policies_glob"] = []string{"nonmatch/*"}

	cases := []canaryMisconfigCase{
		{"token_type_batch", "ci-batch", batchFields, "token_type"},
		{"renewable_true", "ci-renewable", renewableFields, "renewable"},
		{"orphan_false", "ci-orphan", orphanFields, "orphan"},
		{"token_no_default_policy", "ci-nodefault", nodefaultFields, "revoke-self"},
		{"narrow_glob", "ci-narrowglob", narrowGlobFields, "mint"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			putRole(t, ctx, root, tc.roleName, tc.fields)

			c2 := newVaultxClient(t, ctx, addr, fx, tc.roleName)
			err := c2.RunCanary(ctx, canaryPrefix)
			if err == nil {
				t.Fatalf("RunCanary: expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErrSubstr)
			}
			if c2.CanaryOK() {
				t.Errorf("CanaryOK() = true, want false after a %s misconfiguration", tc.name)
			}

			// A subsequent broker.Handle must gate on the canary and mint
			// nothing (SPEC cycle-2 C2-2): assert via a root-client
			// accessor-count diff across the call, and bound the call
			// with a timeout so a hang (not just a wrong status) would
			// also fail the test (SPEC §9.3 group 5).
			b2 := broker.New(c2, "ci", "")
			handleCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			before := countTokenAccessors(t, ctx, root)
			res := b2.Handle(handleCtx, repo1Identity("main", ForgeRemoteIDRepo1))
			after := countTokenAccessors(t, ctx, root)

			if res.Status != 502 {
				t.Errorf("Status = %d, want 502", res.Status)
			}
			if res.Outcome != broker.OutcomeError {
				t.Errorf("Outcome = %q, want %q", res.Outcome, broker.OutcomeError)
			}
			if after != before {
				t.Errorf("token accessor count changed %d -> %d: a token was created despite the failed canary", before, after)
			}
		})
	}
}

// testTierIsolationFull covers SPEC §9.3 tier isolation (group 4) and
// precedence (branch beats base, G2): repo1/push/main, which has both P1
// and P2, must return exactly the base+event+branch-tier secrets those
// policies grant, with the branch tier's "dup" value winning. Returns the
// sorted secret-name set for the cross-product LIST-parity comparison
// (group 14).
func testTierIsolationFull(t *testing.T, ctx context.Context, root *api.Client, brk *broker.Broker) []string {
	t.Helper()
	res := brk.Handle(ctx, repo1Identity("main", ForgeRemoteIDRepo1))
	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200 (secrets: %v)", res.Status, secretNames(res.Secrets))
	}
	if res.Outcome != broker.OutcomeOK {
		t.Errorf("Outcome = %q, want %q", res.Outcome, broker.OutcomeOK)
	}

	names := secretNames(res.Secrets)
	expectedFixed := []string{"branchonly", "dup", "eventonly", "general1_pass", "general1_user", "nonstring_label", "pinned", "shorthand1", "vault_token"}
	var dbrefNames, otherNames []string
	for _, n := range names {
		if strings.HasPrefix(n, "dbref_") {
			dbrefNames = append(dbrefNames, n)
		} else {
			otherNames = append(otherNames, n)
		}
	}
	if !equalStrings(otherNames, expectedFixed) {
		t.Errorf("non-dbref secret names = %v, want %v", otherNames, expectedFixed)
	}
	if len(dbrefNames) == 0 {
		t.Errorf("expected at least one dbref_* secret from the $ref deref (database/creds/readonly), got none (full set: %v)", names)
	}

	if dup, ok := findSecret(res.Secrets, "dup"); !ok || dup.Value != "branch-dup-value" {
		t.Errorf("dup secret = %+v, want value %q (branch tier wins)", dup, "branch-dup-value")
	}
	if branchonly, ok := findSecret(res.Secrets, "branchonly"); !ok || branchonly.Value != "branch-tier-value" {
		t.Errorf("branchonly secret = %+v, want value %q", branchonly, "branch-tier-value")
	}
	if accessor := res.Audit.TokenAccessor; accessor == "" || !accessorAlive(t, ctx, root, accessor) {
		t.Errorf("token accessor not alive after a 200 response (SPEC §3.4: a 200 never revokes)")
	}

	return names
}

// testTierIsolationNoBranchPolicy covers SPEC §9.3 group 4's "push-only
// identity gets 403s on the branch tier, skipped not error" case AND
// group 6's "nonexistent branch-tier policy warns, P1 still effective":
// repo1/push/<a branch with no P2 policy>. The branch tier's own LIST
// 403s (no policy grants it) and is silently skipped; base tier's "dup"
// (inaccessible-branch fallback) surfaces instead of the branch value.
func testTierIsolationNoBranchPolicy(t *testing.T, ctx context.Context, brk *broker.Broker) []string {
	t.Helper()
	const branch = "otherbranch"
	res := brk.Handle(ctx, repo1Identity(branch, ForgeRemoteIDRepo1))
	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200", res.Status)
	}
	if res.Outcome != broker.OutcomeOK {
		t.Errorf("Outcome = %q, want %q (P1 still effective despite P2 nonexistent)", res.Outcome, broker.OutcomeOK)
	}

	names := secretNames(res.Secrets)
	for _, n := range names {
		if n == "branchonly" {
			t.Errorf("branchonly present in secrets %v; branch tier should have 403'd and been skipped", names)
		}
	}
	if dup, ok := findSecret(res.Secrets, "dup"); !ok || dup.Value != "base-dup-value" {
		t.Errorf("dup secret = %+v, want base tier's value %q (branch tier inaccessible)", dup, "base-dup-value")
	}

	wantWarned := "ci/itest/repo1/push/" + branch
	found := false
	for _, w := range res.Audit.PolicyWarnings {
		if w == wantWarned {
			found = true
		}
	}
	if !found {
		t.Errorf("PolicyWarnings = %v, want it to contain %q", res.Audit.PolicyWarnings, wantWarned)
	}

	return names
}

// testIdentityBinding covers SPEC §9.3 / §4.4's .identity match, mismatch,
// and malformed cases (group 7). The "absent" case is exercised by
// testConfigSuppression's repo3 call (see its doc comment) since the
// fixture deliberately doubles repo3 for both — see fixture.go's package
// doc.
func testIdentityBinding(t *testing.T, ctx context.Context, root *api.Client, brk *broker.Broker) {
	t.Helper()

	t.Run("match", func(t *testing.T) {
		res := brk.Handle(ctx, repo1Identity("main", ForgeRemoteIDRepo1))
		if res.Status != 200 {
			t.Errorf("Status = %d, want 200 (matching forge_remote_id)", res.Status)
		}
		if res.Outcome != broker.OutcomeOK {
			t.Errorf("Outcome = %q, want %q", res.Outcome, broker.OutcomeOK)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		res := brk.Handle(ctx, repo1Identity("main", "wrong-forge-remote-id"))
		if res.Status != 204 {
			t.Errorf("Status = %d, want 204", res.Status)
		}
		if res.Outcome != broker.OutcomeIdentityMismatch {
			t.Errorf("Outcome = %q, want %q", res.Outcome, broker.OutcomeIdentityMismatch)
		}
		if accessor := res.Audit.TokenAccessor; accessor == "" || accessorAlive(t, ctx, root, accessor) {
			t.Errorf("token accessor still alive after an identity mismatch, want revoked")
		}
	})

	t.Run("malformed", func(t *testing.T) {
		id := identity.Identity{Org: TestOrg, Repo: RepoMalformedIdentity, Event: "push", Commit: "c", PipelineNumber: 1}
		res := brk.Handle(ctx, id)
		if res.Status != 204 {
			t.Errorf("Status = %d, want 204", res.Status)
		}
		if res.Outcome != broker.OutcomeIdentityMismatch {
			t.Errorf("Outcome = %q, want %q (malformed .identity fails closed, SPEC §4.4 C1)", res.Outcome, broker.OutcomeIdentityMismatch)
		}
		if accessor := res.Audit.TokenAccessor; accessor == "" || accessorAlive(t, ctx, root, accessor) {
			t.Errorf("token accessor still alive after a malformed .identity, want revoked")
		}
	})
}

// testConfigSuppression covers SPEC §9.3 / §4.5's vault_token suppression
// (group 8): repo3 (vault_token=false, no other secrets — see fixture.go)
// for the empty-sweep 204 case, which simultaneously proves the ".identity
// absent" case (group 7's fourth sub-case): if the absent .identity were
// wrongly enforced as a mismatch, this would come back OutcomeIdentityMismatch
// instead of OutcomeUnonboarded. A second, test-local repo ("repo5") covers
// the non-empty-sweep case: 200 with the swept secret but WITHOUT vault_token.
func testConfigSuppression(t *testing.T, ctx context.Context, root *api.Client, brk *broker.Broker) {
	t.Helper()

	t.Run("empty_sweep_suppressed", func(t *testing.T) {
		id := identity.Identity{Org: TestOrg, Repo: RepoSuppression, Event: "push", Commit: "c", PipelineNumber: 1}
		res := brk.Handle(ctx, id)
		if res.Status != 204 {
			t.Errorf("Status = %d, want 204", res.Status)
		}
		// Reused OutcomeUnonboarded (not IdentityMismatch): also proves
		// repo3's absent .identity was NOT enforced as a mismatch.
		if res.Outcome != broker.OutcomeUnonboarded {
			t.Errorf("Outcome = %q, want %q", res.Outcome, broker.OutcomeUnonboarded)
		}
		if accessor := res.Audit.TokenAccessor; accessor == "" || accessorAlive(t, ctx, root, accessor) {
			t.Errorf("token accessor still alive after empty+suppressed 204, want revoked")
		}
	})

	t.Run("non_empty_sweep_suppressed", func(t *testing.T) {
		const repo = "repo5"
		repoBase := kvBase(repo)
		mustPutPolicy(t, ctx, root, "ci/itest/"+repo+"/push", policyHCL([]pathCap{
			{"kv/metadata/" + repoBase, []string{"list"}},
			{"kv/data/" + repoBase + "/.config", []string{"read"}},
			{"kv/data/" + repoBase + "/extra", []string{"read"}},
		}))
		kv := root.KVv2("kv")
		if _, err := kv.Put(ctx, repoBase+"/.config", map[string]interface{}{"vault_token": "false"}); err != nil {
			t.Fatalf("kv put .config: %v", err)
		}
		if _, err := kv.Put(ctx, repoBase+"/extra", map[string]interface{}{"value": "extra-value"}); err != nil {
			t.Fatalf("kv put extra: %v", err)
		}

		id := identity.Identity{Org: TestOrg, Repo: repo, Event: "push", Commit: "c", PipelineNumber: 1}
		res := brk.Handle(ctx, id)
		if res.Status != 200 {
			t.Fatalf("Status = %d, want 200 (secrets: %v)", res.Status, secretNames(res.Secrets))
		}
		if res.Outcome != broker.OutcomeOK {
			t.Errorf("Outcome = %q, want %q", res.Outcome, broker.OutcomeOK)
		}
		if _, ok := findSecret(res.Secrets, "extra"); !ok {
			t.Errorf("secrets = %v, want it to contain %q", secretNames(res.Secrets), "extra")
		}
		if _, ok := findSecret(res.Secrets, "vault_token"); ok {
			t.Errorf("secrets = %v, vault_token must be suppressed", secretNames(res.Secrets))
		}
	})
}

// testDerefAndLease covers SPEC §9.3 / §4.3's pointer-dereference-with-
// lease case (group 9): via the broker, repo1's "dbref" $ref entry yields
// dbref_* secrets on a 200 that does NOT revoke the token. Independently
// (driving vaultx directly, so the raw lease_id — which Handle's Result
// never exposes — is observable), it confirms a lease is created and dies
// when its owning token is revoked. A real-TTL-expiry variant is gated
// behind IRONBARK_INTEGRATION_REAL_EXPIRY (slow: sleeps past the fixture's
// 90s token_explicit_max_ttl).
func testDerefAndLease(t *testing.T, ctx context.Context, addr string, root *api.Client, client *vaultx.Client, brk *broker.Broker) {
	t.Helper()

	t.Run("via_broker_not_revoked", func(t *testing.T) {
		res := brk.Handle(ctx, repo1Identity("main", ForgeRemoteIDRepo1))
		if res.Status != 200 {
			t.Fatalf("Status = %d, want 200", res.Status)
		}
		hasDbref := false
		for _, n := range secretNames(res.Secrets) {
			if strings.HasPrefix(n, "dbref_") {
				hasDbref = true
			}
		}
		if !hasDbref {
			t.Errorf("secrets = %v, want at least one dbref_* entry from the $ref deref", secretNames(res.Secrets))
		}
		if accessor := res.Audit.TokenAccessor; accessor == "" || !accessorAlive(t, ctx, root, accessor) {
			t.Errorf("token accessor not alive after a 200 with a deref lease (SPEC §3.4: a 200 never revokes)")
		}
		if tok, ok := findSecret(res.Secrets, "vault_token"); ok {
			// Best-effort cleanup; TTL (90s, token_explicit_max_ttl) is
			// the backstop either way.
			_ = client.RevokeSelf(ctx, tok.Value)
		}
	})

	t.Run("lease_dies_on_revoke", func(t *testing.T) {
		mint, err := client.MintToken(ctx, []string{"ci/itest/repo1/push"}, nil, "lease-direct-test")
		if err != nil {
			t.Fatalf("MintToken: %v", err)
		}

		tokClient, err := api.NewClient(&api.Config{Address: addr})
		if err != nil {
			t.Fatalf("new token client: %v", err)
		}
		tokClient.SetToken(mint.Token)

		secret, err := tokClient.Logical().ReadWithContext(ctx, "database/creds/readonly")
		if err != nil {
			t.Fatalf("GET database/creds/readonly: %v", err)
		}
		if secret == nil || secret.LeaseID == "" {
			t.Fatalf("no lease_id on database/creds/readonly response: %+v", secret)
		}
		leaseID := secret.LeaseID

		if _, err := root.Sys().RenewWithContext(ctx, leaseID, 0); err != nil {
			t.Fatalf("lease %s not alive immediately after creation: %v", leaseID, err)
		}

		if err := client.RevokeSelf(ctx, mint.Token); err != nil {
			t.Fatalf("RevokeSelf: %v", err)
		}

		// Lease revocation cascades from the token revoke asynchronously
		// on both products (confirmed empirically) — poll briefly rather
		// than asserting immediately.
		deadline := time.Now().Add(5 * time.Second)
		var renewErr error
		for time.Now().Before(deadline) {
			_, renewErr = root.Sys().RenewWithContext(ctx, leaseID, 0)
			if renewErr != nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if renewErr == nil {
			t.Errorf("lease %s still renewable after its token was revoked, want it gone", leaseID)
		}
	})

	t.Run("real_ttl_expiry", func(t *testing.T) {
		if os.Getenv("IRONBARK_INTEGRATION_REAL_EXPIRY") == "" {
			t.Skip("set IRONBARK_INTEGRATION_REAL_EXPIRY=1 to run the real (>90s) TTL-expiry variant")
		}

		mint, err := client.MintToken(ctx, []string{"ci/itest/repo1/push"}, nil, "lease-real-expiry-test")
		if err != nil {
			t.Fatalf("MintToken: %v", err)
		}
		tokClient, err := api.NewClient(&api.Config{Address: addr})
		if err != nil {
			t.Fatalf("new token client: %v", err)
		}
		tokClient.SetToken(mint.Token)

		secret, err := tokClient.Logical().ReadWithContext(ctx, "database/creds/readonly")
		if err != nil {
			t.Fatalf("GET database/creds/readonly: %v", err)
		}
		leaseID := secret.LeaseID

		// token_explicit_max_ttl is 90s (fixture.go) — wait past it,
		// without touching the token (no renew), so it dies of real
		// expiry rather than an explicit revoke.
		time.Sleep(100 * time.Second)

		if _, err := root.Sys().RenewWithContext(ctx, leaseID, 0); err == nil {
			t.Errorf("lease %s still renewable 100s after mint, want it dead (token_explicit_max_ttl=90s expired)", leaseID)
		}
	})
}

// testCustomMetadataPins covers SPEC §9.3 / §4.6 (group 10): the pinned
// entry's custom_metadata surfaces as Images/Events on the returned
// secret, AND — the named §4.6/G3 assertion — custom_metadata itself
// arrives in the KV v2 data-GET response, checked directly against Vault
// (not through the sweep), on both products.
func testCustomMetadataPins(t *testing.T, ctx context.Context, root *api.Client, brk *broker.Broker) {
	t.Helper()

	res := brk.Handle(ctx, repo1Identity("main", ForgeRemoteIDRepo1))
	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200", res.Status)
	}
	pinned, ok := findSecret(res.Secrets, "pinned")
	if !ok {
		t.Fatalf("secrets = %v, want a %q entry", secretNames(res.Secrets), "pinned")
	}
	if !equalStrings(pinned.Images, []string{"alpine", "golang"}) {
		t.Errorf("pinned.Images = %v, want [alpine golang]", pinned.Images)
	}
	if !equalStrings(pinned.Events, []string{"push", "cron"}) {
		t.Errorf("pinned.Events = %v, want [push cron]", pinned.Events)
	}

	kv := root.KVv2("kv")
	s, err := kv.Get(ctx, kvBase(RepoOnboarded)+"/pinned")
	if err != nil {
		t.Fatalf("KV data-GET pinned: %v", err)
	}
	if s.CustomMetadata == nil {
		t.Fatalf("custom_metadata absent from the KV v2 data-GET response (SPEC §4.6/G3 depends on it being present)")
	}
	if got, _ := s.CustomMetadata["ironbark_images"].(string); got != "alpine,golang" {
		t.Errorf("custom_metadata[ironbark_images] = %v, want %q", s.CustomMetadata["ironbark_images"], "alpine,golang")
	}
	if got, _ := s.CustomMetadata["ironbark_events"].(string); got != "push,cron" {
		t.Errorf("custom_metadata[ironbark_events] = %v, want %q", s.CustomMetadata["ironbark_events"], "push,cron")
	}
}

// testNonStringSkipped covers SPEC §9.3 / §4.2 C4 (group 11): repo1's
// "nonstring" entry has a non-string "count" field (skipped, with a
// warning) and a string "label" sibling (must survive).
func testNonStringSkipped(t *testing.T, ctx context.Context, brk *broker.Broker) {
	t.Helper()

	res := brk.Handle(ctx, repo1Identity("main", ForgeRemoteIDRepo1))
	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200", res.Status)
	}
	label, ok := findSecret(res.Secrets, "nonstring_label")
	if !ok || label.Value != "valid-sibling" {
		t.Errorf("nonstring_label = %+v (ok=%v), want value %q", label, ok, "valid-sibling")
	}
	if _, ok := findSecret(res.Secrets, "nonstring_count"); ok {
		t.Errorf("nonstring_count present in secrets %v, want it skipped (non-string value)", secretNames(res.Secrets))
	}
}

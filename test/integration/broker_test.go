//go:build integration

// Task 14: the SPEC §9.3 integration suite. Runs the REAL *broker.Broker
// backed by a REAL *vaultx.Client (AppRole-logged-in as the fixture's
// ironbark role) against each product in turn, calling broker.Handle
// directly with constructed identity.Identity values — the HTTP layer
// (Task 11/15) is not exercised here.
//
// Every SPEC §9.3 bullet maps to one or more t.Run groups below, run once
// per product inside TestBrokerSuite. Where the fixture's own repo design
// already doubles a repo for two bullets (repo3: .identity absent AND
// .config suppression-with-empty-sweep — see fixture.go's package doc),
// this file reuses a single Handle call and asserts both facts, rather
// than re-minting a second token for a distinction the fixture doesn't
// draw.
package integration

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/vaultx"
)

// canaryPrefix is POLICY_PREFIX as used throughout the fixture (KVPrefix
// and PolicyPrefix both default to "ci" — see fixture.go's package doc).
const canaryPrefix = "ci"

// newVaultxClient builds a vaultx.Client for addr, logged in as the
// fixture's ironbark AppRole, minting against tokenRole.
func newVaultxClient(t *testing.T, ctx context.Context, addr string, fx Fixture, tokenRole string) *vaultx.Client {
	t.Helper()
	c, err := vaultx.New(vaultx.Config{
		Addr:      addr,
		RoleID:    fx.RoleID,
		SecretID:  fx.SecretID,
		TokenRole: tokenRole,
		KVMount:   "kv",
		KVPrefix:  "ci",
	})
	if err != nil {
		t.Fatalf("vaultx.New: %v", err)
	}
	if err := c.Login(ctx); err != nil {
		t.Fatalf("vaultx Login: %v", err)
	}
	return c
}

// repo1Identity builds an identity.Identity for the fixture's onboarded
// repo1, push event, with the given branch and forge_remote_id.
func repo1Identity(branch, forgeID string) identity.Identity {
	return identity.Identity{
		Org:            TestOrg,
		Repo:           RepoOnboarded,
		Event:          "push",
		Branch:         branch,
		ForgeRemoteID:  forgeID,
		Commit:         "deadbeefcafebabe",
		PipelineNumber: 42,
	}
}

// accessorAlive reports whether accessor still resolves to a live token,
// via a root-authenticated lookup-accessor call — the SPEC §9.3
// "verify via accessor lookup by a root test client" check, used both to
// confirm a token was revoked (false) and to confirm a 200's token was
// NOT revoked (true).
func accessorAlive(t *testing.T, ctx context.Context, root *api.Client, accessor string) bool {
	t.Helper()
	if accessor == "" {
		t.Fatalf("accessorAlive: empty accessor")
	}
	_, err := root.Auth().Token().LookupAccessorWithContext(ctx, accessor)
	return err == nil
}

// countTokenAccessors returns the number of live token accessors, for the
// canary-misconfig "no token created" assertion (a before/after diff
// across one broker.Handle call).
func countTokenAccessors(t *testing.T, ctx context.Context, root *api.Client) int {
	t.Helper()
	secret, err := root.Logical().ListWithContext(ctx, "auth/token/accessors")
	if err != nil {
		t.Fatalf("list auth/token/accessors: %v", err)
	}
	if secret == nil || secret.Data == nil {
		return 0
	}
	keys, _ := secret.Data["keys"].([]interface{})
	return len(keys)
}

// putRole writes auth/token/roles/<name> with fields, as root.
func putRole(t *testing.T, ctx context.Context, root *api.Client, name string, fields map[string]interface{}) {
	t.Helper()
	if _, err := root.Logical().WriteWithContext(ctx, "auth/token/roles/"+name, fields); err != nil {
		t.Fatalf("put token role %s: %v", name, err)
	}
}

// baseCiRoleFields returns the SPEC §3.1 `ci` role fields (matching
// fixture.go's setupTokenRole exactly), as a fresh map every call so
// callers can flip individual fields without aliasing.
func baseCiRoleFields() map[string]interface{} {
	return map[string]interface{}{
		"allowed_policies_glob":   []string{"ci/*"},
		"token_type":              "service",
		"orphan":                  true,
		"renewable":               false,
		"token_no_default_policy": false,
		"token_explicit_max_ttl":  "90s",
	}
}

// widenAppRolePolicyForCanaryTests extends the fixture's minimal
// "ironbark-agent" policy (create+update on auth/token/create/ci ONLY, by
// design — see fixture.go) to also cover auth/token/create/ci-* , so the
// canary-misconfiguration sub-tests below can mint against sibling roles
// (ci-batch, ci-renewable, ...) using the SAME AppRole session, without
// weakening the "ci" grant itself or touching the fixture's exact policy
// shape for the paths it documents. Test-only augmentation.
func widenAppRolePolicyForCanaryTests(t *testing.T, ctx context.Context, root *api.Client) {
	t.Helper()
	hcl := `path "auth/token/create/ci" {
  capabilities = ["create", "update"]
}

path "auth/token/create/ci-*" {
  capabilities = ["create", "update"]
}
`
	if err := root.Sys().PutPolicyWithContext(ctx, "ironbark-agent", hcl); err != nil {
		t.Fatalf("widen ironbark-agent policy: %v", err)
	}
}

func TestBrokerSuite(t *testing.T) {
	// secretSetsByProduct captures the group4 (tier isolation, full
	// branch-ful sweep) secret-name set per product, compared for
	// equality after both products' subtests complete — the SPEC §9.3
	// "LIST behavior parity on both products" assertion (group 14).
	secretSetsByProduct := map[string][]string{}

	for _, p := range products {
		p := p
		t.Run(p.name, func(t *testing.T) {
			ctx := t.Context()
			fx := SetupProduct(t, p.addr, p.rootToken)
			root := NewRootClient(t, p.addr, p.rootToken)

			client := newVaultxClient(t, ctx, p.addr, fx, "ci")
			if err := client.RunCanary(ctx, canaryPrefix); err != nil {
				t.Fatalf("canary against the documented ci role failed: %v", err)
			}
			if !client.CanaryOK() {
				t.Fatalf("CanaryOK() = false after a passing canary")
			}

			brk := broker.New(client, "ci", "")

			// ---- Group 1: canary passes on the correct role ----
			t.Run("canary_passes_on_ci_role", func(t *testing.T) {
				// Already proven above (suite setup requires it to
				// proceed); re-run once more here so this fact has its
				// own named, independently-failing assertion.
				if err := client.RunCanary(ctx, canaryPrefix); err != nil {
					t.Errorf("RunCanary against ci: %v", err)
				}
				if !client.CanaryOK() {
					t.Errorf("CanaryOK() = false")
				}
			})

			// ---- Group 2: five canary-misconfig cases ----
			t.Run("canary_misconfig", func(t *testing.T) {
				widenAppRolePolicyForCanaryTests(t, ctx, root)
				testCanaryMisconfig(t, ctx, p.addr, fx, root)
			})

			// ---- Group 3: un-onboarded repo ----
			t.Run("unonboarded_repo", func(t *testing.T) {
				id := identity.Identity{Org: TestOrg, Repo: RepoUnonboarded, Event: "push", Commit: "c", PipelineNumber: 1}
				res := brk.Handle(ctx, id)
				if res.Status != 204 {
					t.Errorf("Status = %d, want 204", res.Status)
				}
				if res.Outcome != broker.OutcomeUnonboarded {
					t.Errorf("Outcome = %q, want %q", res.Outcome, broker.OutcomeUnonboarded)
				}
				if res.Audit.TokenAccessor == "" {
					t.Fatalf("no token accessor recorded")
				}
				if accessorAlive(t, ctx, root, res.Audit.TokenAccessor) {
					t.Errorf("token accessor %s still alive, want revoked", res.Audit.TokenAccessor)
				}
			})

			// ---- Groups 4/6: tier isolation + nonexistent branch policy ----
			var fullNames, partialNames []string
			t.Run("tier_isolation_full_branch", func(t *testing.T) {
				fullNames = testTierIsolationFull(t, ctx, root, brk)
			})
			t.Run("tier_isolation_no_branch_policy", func(t *testing.T) {
				partialNames = testTierIsolationNoBranchPolicy(t, ctx, brk)
			})
			secretSetsByProduct[p.name] = fullNames
			_ = partialNames

			// ---- Group 7: .identity match/mismatch/absent/malformed ----
			t.Run("identity_binding", func(t *testing.T) {
				testIdentityBinding(t, ctx, root, brk)
			})

			// ---- Group 8: .config suppression (empty + non-empty sweep) ----
			t.Run("config_suppression", func(t *testing.T) {
				testConfigSuppression(t, ctx, root, brk)
			})

			// ---- Group 9: deref + lease ----
			t.Run("deref_and_lease", func(t *testing.T) {
				testDerefAndLease(t, ctx, p.addr, root, client, brk)
			})

			// ---- Group 10: custom_metadata pins ----
			t.Run("custom_metadata_pins", func(t *testing.T) {
				testCustomMetadataPins(t, ctx, root, brk)
			})

			// ---- Group 11: non-string value skipped ----
			t.Run("non_string_value_skipped", func(t *testing.T) {
				testNonStringSkipped(t, ctx, brk)
			})

			// ---- Group 12: TTL bound ----
			t.Run("ttl_bound", func(t *testing.T) {
				mint, err := client.MintToken(ctx, []string{"ci/itest/repo1/push"}, nil, "ttl-bound-test")
				if err != nil {
					t.Fatalf("MintToken: %v", err)
				}
				defer client.RevokeSelf(ctx, mint.Token)
				if mint.TTL <= 0 || mint.TTL > 90*time.Second {
					t.Errorf("mint.TTL = %v, want (0, 90s] (token_explicit_max_ttl bound)", mint.TTL)
				}
			})

			// ---- Group 13: privileged-client assertions ----
			t.Run("privileged_client_assertions", func(t *testing.T) {
				mint, err := client.MintToken(ctx, []string{"ci/itest/repo1/push"}, nil, "privileged-check-test")
				if err != nil {
					t.Fatalf("MintToken: %v", err)
				}
				defer client.RevokeSelf(ctx, mint.Token)

				secret, err := root.Auth().Token().LookupAccessorWithContext(ctx, mint.Accessor)
				if err != nil {
					t.Fatalf("LookupAccessor: %v", err)
				}
				if got, _ := secret.Data["type"].(string); got != "service" {
					t.Errorf("type = %v, want service", secret.Data["type"])
				}
				if got, _ := secret.Data["renewable"].(bool); got != false {
					t.Errorf("renewable = %v, want false", secret.Data["renewable"])
				}
				if got, _ := secret.Data["orphan"].(bool); got != true {
					t.Errorf("orphan = %v, want true (definitive root-client check)", secret.Data["orphan"])
				}
			})
		})
	}

	// ---- Group 14: LIST parity across products ----
	t.Run("list_parity_across_products", func(t *testing.T) {
		if len(secretSetsByProduct) != 2 {
			t.Fatalf("expected 2 products captured, got %d: %v", len(secretSetsByProduct), secretSetsByProduct)
		}
		vaultNames := append([]string(nil), secretSetsByProduct["vault"]...)
		openbaoNames := append([]string(nil), secretSetsByProduct["openbao"]...)
		sort.Strings(vaultNames)
		sort.Strings(openbaoNames)
		if len(vaultNames) == 0 {
			t.Fatalf("vault produced no secret names to compare")
		}
		if !equalStrings(vaultNames, openbaoNames) {
			t.Errorf("secret-name sets diverge between products:\n  vault:   %v\n  openbao: %v", vaultNames, openbaoNames)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// secretNames extracts the Name of every broker.Secret, sorted, for
// exact-set assertions.
func secretNames(secrets []broker.Secret) []string {
	names := make([]string, len(secrets))
	for i, s := range secrets {
		names[i] = s.Name
	}
	sort.Strings(names)
	return names
}

func findSecret(secrets []broker.Secret, name string) (broker.Secret, bool) {
	for _, s := range secrets {
		if s.Name == name {
			return s, true
		}
	}
	return broker.Secret{}, false
}

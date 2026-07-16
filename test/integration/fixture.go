//go:build integration

// Package integration provides Task 13's dual-product fixture: SetupProduct
// provisions a Vault or OpenBao dev-mode instance identically (KV v2 mount,
// tier policies, the SPEC §3.1 `ci` token role, an AppRole for ironbark
// itself, a PKI mount, and a Postgres-backed `database` secrets engine) so
// Task 14's SPEC §9.3 suite can run unmodified against both products.
//
// KV/policy layout reference (SPEC §2.3 policy names, §2.4 KV layout;
// KVMount="kv", KVPrefix="ci", PolicyPrefix="ci" — ironbark's own defaults,
// config.Load). Both prefixes default to "ci", so a policy name like
// "ci/itest/repo1/push" and the KV event-tier path segment
// "ci/itest/repo1/push" are textually identical below — that's a
// consequence of the shared default prefix, not a collision: they live in
// separate ACL/KV namespaces (the policy is a bare name; the KV path is
// additionally under the "kv/" mount).
//
//	org=itest, onboarded repo=repo1 (RepoOnboarded)
//	  base   B = kv/{data,metadata}/ci/itest/repo1
//	  event  B/push
//	  branch B/push/main                    (esc("main") == "main")
//
//	  policy ci/itest/repo1/push       (P1) — base + event tier grants,
//	                                    PLUS read on database/creds/readonly
//	                                    (the $ref deref target — see
//	                                    docker-compose.yml)
//	  policy ci/itest/repo1/push/main  (P2) — branch tier grants ONLY. A
//	                                    token minted with P1 alone gets 403
//	                                    on this tier: tier isolation (SPEC
//	                                    §4.1, "partial visibility IS the
//	                                    tiering mechanism").
//
//	  KV entries (base tier unless noted):
//	    general1     {"user":..., "pass":...}          general form
//	    shorthand1   {"value":...}                      shorthand form
//	    dup          {"value":"base-dup-value"}          ALSO at push/main
//	                 tier with a DIFFERENT value — precedence test (branch
//	                 wins, SPEC §4.2 "most specific secret wins")
//	    nonstring    {"count":3,"label":"valid-sibling"} count is skipped
//	                 (C4, non-string), label survives
//	    pinned       {"value":...} + custom_metadata{ironbark_images,
//	                 ironbark_events}                    §4.6 pin test
//	    dbref        {"$ref":"database/creds/readonly"}  deref+lease test
//	    .identity    {"forge_remote_id": ForgeRemoteIDRepo1}
//	    push/eventonly       {"value":...}               event-tier entry
//	    push/main/dup        {"value":"branch-dup-value"}(see dup above)
//	    push/main/branchonly {"value":...}               branch-tier entry
//
//	org=itest, repo=repo2 (RepoUnonboarded): NO policies created at all —
//	  P1/P2 mint with warnings and grant nothing; every sweep LIST 403s;
//	  the un-onboarded-repo case (SPEC §9.3).
//
//	org=itest, repo=repo3 (RepoSuppression): policy ci/itest/repo3/push
//	  grants ONLY .config read + base list; .config =
//	  {"vault_token":"false"}; no .identity, no other data secrets — this
//	  repo doubles as BOTH the ".identity absent" case (SPEC §4.4 "not
//	  enforced") and the vault_token-suppression-with-empty-sweep → 204
//	  case (SPEC §4.5), since it has nothing else to return either way.
//
//	org=itest, repo=repo4 (RepoMalformedIdentity): policy
//	  ci/itest/repo4/push grants base list + .identity read only;
//	  .identity = {"forge_remote_id": 12345} (a JSON number, not a string)
//	  — malformed binding, SPEC §4.4 C1 fail-closed (204 + revoke).
//
// Token role `ci` (auth/token/roles/ci) is written EXACTLY per SPEC §3.1.
// Task 14's canary-misconfiguration tests (token_type=batch, renewable=
// true, non-orphan, token_no_default_policy=true, a glob not covering the
// prefix) are NOT created here — create sibling roles (e.g.
// auth/token/roles/ci-batch) with the same base params and one field
// flipped, reusing NewRootClient's client.
//
// AppRole `ironbark` (auth/approle/role/ironbark) carries a minimal policy
// (ironbark-agent) granting ONLY create+update on auth/token/create/ci —
// no KV read, no policy read, nothing else. SetupProduct returns its
// role_id/secret_id for Task 14 / e2e to log in as.
//
// Teardown is a documented no-op: these are disposable dev-mode
// containers, torn down wholesale by `docker compose down -v` — there is
// no per-product state that needs cleaning up between tests.
package integration

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

// Test identity constants shared with Task 14 — see the package doc
// comment above for the full KV/policy layout these name.
const (
	TestOrg = "itest"

	RepoOnboarded         = "repo1"
	RepoUnonboarded       = "repo2" // no policies created — un-onboarded case
	RepoSuppression       = "repo3" // .config vault_token=false; .identity absent
	RepoMalformedIdentity = "repo4" // .identity present but malformed

	ForgeRemoteIDRepo1 = "itest-repo1-forge-id" // repo1's valid .identity value

	Branch = "main"

	// DerefRefPath is the $ref pointer target used by repo1's "dbref"
	// entry: a GET-based, lease-producing read. See docker-compose.yml for
	// why this is Postgres/database and not PKI (PKI's issue endpoint is
	// POST-only — confirmed empirically, not assumed — and ironbark's
	// sweepDeref always issues a plain GET, SPEC §4.3).
	DerefRefPath = "database/creds/readonly"
)

// Fixture is what SetupProduct hands back for Task 14 / e2e to
// authenticate as ironbark itself (AppRole login).
type Fixture struct {
	RoleID   string
	SecretID string
}

// NewRootClient builds an *api.Client authenticated as rootToken against
// addr. Exported so Task 14 can get its own privileged client for
// assertions SetupProduct doesn't need (accessor lookups, creating
// canary-misconfiguration role variants, direct PKI issuance, etc.).
func NewRootClient(t *testing.T, addr, rootToken string) *api.Client {
	t.Helper()
	c, err := api.NewClient(&api.Config{Address: addr})
	if err != nil {
		t.Fatalf("integration: new root client: %v", err)
	}
	c.SetToken(rootToken)
	return c
}

// SetupProduct provisions one Vault or OpenBao dev-mode instance (addr,
// authenticated as rootToken) with the full fixture described in the
// package doc comment. It is not safe to call twice against the same
// instance (PKI root-CA generation in particular is not idempotent); each
// docker-compose product gets exactly one call, matching the dev
// containers' one-shot-per-test-run lifecycle.
func SetupProduct(t *testing.T, addr, rootToken string) Fixture {
	t.Helper()
	ctx := context.Background()
	c := NewRootClient(t, addr, rootToken)

	setupKVMount(t, ctx, c)
	setupPKI(t, ctx, c)
	setupDatabase(t, ctx, c)
	setupPolicies(t, ctx, c)
	setupTokenRole(t, ctx, c)
	roleID, secretID := setupAppRole(t, ctx, c)
	seedKV(t, ctx, c)

	return Fixture{RoleID: roleID, SecretID: secretID}
}

// Teardown is a documented no-op — see the package doc comment's Teardown
// paragraph. It exists so callers have a symmetric SetupProduct/Teardown
// pair.
func Teardown(t *testing.T, addr, rootToken string) {
	t.Helper()
}

func kvBase(repo string) string {
	return "ci/" + TestOrg + "/" + repo
}

func ensureMount(t *testing.T, ctx context.Context, c *api.Client, path string, input *api.MountInput) {
	t.Helper()
	mounts, err := c.Sys().ListMountsWithContext(ctx)
	if err != nil {
		t.Fatalf("integration: list mounts: %v", err)
	}
	if _, ok := mounts[path+"/"]; ok {
		return
	}
	if err := c.Sys().MountWithContext(ctx, path, input); err != nil {
		t.Fatalf("integration: mount %s: %v", path, err)
	}
}

func ensureAuth(t *testing.T, ctx context.Context, c *api.Client, path, authType string) {
	t.Helper()
	mounts, err := c.Sys().ListAuthWithContext(ctx)
	if err != nil {
		t.Fatalf("integration: list auth: %v", err)
	}
	if _, ok := mounts[path+"/"]; ok {
		return
	}
	if err := c.Sys().EnableAuthWithOptionsWithContext(ctx, path, &api.EnableAuthOptions{Type: authType}); err != nil {
		t.Fatalf("integration: enable auth %s: %v", path, err)
	}
}

func setupKVMount(t *testing.T, ctx context.Context, c *api.Client) {
	t.Helper()
	ensureMount(t, ctx, c, "kv", &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	})
}

// setupPKI enables pki and configures a root CA + a short-TTL issuing
// role, per the literal Task 13 ask. It is NOT the $ref deref target (see
// DerefRefPath) — it remains available for any direct-client PKI
// assertions Task 14 wants.
func setupPKI(t *testing.T, ctx context.Context, c *api.Client) {
	t.Helper()
	ensureMount(t, ctx, c, "pki", &api.MountInput{
		Type:   "pki",
		Config: api.MountConfigInput{MaxLeaseTTL: "87600h"},
	})

	if _, err := c.Logical().WriteWithContext(ctx, "pki/root/generate/internal", map[string]interface{}{
		"common_name": "ironbark-itest.local",
		"ttl":         "87600h",
	}); err != nil {
		t.Fatalf("integration: pki root CA: %v", err)
	}

	if _, err := c.Logical().WriteWithContext(ctx, "pki/roles/short", map[string]interface{}{
		"allowed_domains":  "itest.local",
		"allow_subdomains": true,
		"max_ttl":          "1h",
		"ttl":              "30s",
	}); err != nil {
		t.Fatalf("integration: pki role: %v", err)
	}
}

// setupDatabase enables the database secrets engine and points it at the
// docker-compose "postgres" service: the real $ref deref+lease target
// (DerefRefPath). GET database/creds/readonly is confirmed live (docker
// run + curl, not assumed) to return 200 with a real lease_id, and
// sys/leases/revoke against that lease_id to return 204 — exactly the
// deref+lease+lease-dies-with-token shape SPEC §9.3 asks for.
func setupDatabase(t *testing.T, ctx context.Context, c *api.Client) {
	t.Helper()
	ensureMount(t, ctx, c, "database", &api.MountInput{Type: "database"})

	if _, err := c.Logical().WriteWithContext(ctx, "database/config/pg", map[string]interface{}{
		"plugin_name":    "postgresql-database-plugin",
		"allowed_roles":  "readonly",
		"connection_url": "postgresql://{{username}}:{{password}}@postgres:5432/postgres?sslmode=disable",
		"username":       "vaultadmin",
		"password":       "vaultpw",
	}); err != nil {
		t.Fatalf("integration: database config: %v", err)
	}

	if _, err := c.Logical().WriteWithContext(ctx, "database/roles/readonly", map[string]interface{}{
		"db_name":             "pg",
		"creation_statements": `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE postgres TO "{{name}}";`,
		"default_ttl":         "30s",
		"max_ttl":             "1h",
	}); err != nil {
		t.Fatalf("integration: database role: %v", err)
	}
}

// pathCap is one ACL `path` stanza: an exact path (never a trailing "*"
// glob — see the setupPolicies doc comment on why exact paths are
// required for tier isolation to hold) and its capabilities.
type pathCap struct {
	path string
	caps []string
}

// policyHCL renders grants as Vault/OpenBao ACL policy HCL. Every path is
// an exact match (no "*" suffix): a trailing glob on e.g.
// "kv/data/ci/itest/repo1/*" would ALSO match
// "kv/data/ci/itest/repo1/push/main/*" (Vault's glob has no path-segment
// semantics — "*" matches any characters including "/", same rule SPEC
// §2.3 notes for allowed_policies_glob), which would silently defeat the
// P1-vs-P2 tier isolation the fixture exists to test. Since the fixture's
// KV entries are a small fixed set, enumerating each exact path costs
// nothing and keeps isolation airtight.
func policyHCL(grants []pathCap) string {
	var b strings.Builder
	for _, g := range grants {
		quoted := make([]string, len(g.caps))
		for i, capability := range g.caps {
			quoted[i] = strconv.Quote(capability)
		}
		b.WriteString("path " + strconv.Quote(g.path) + " {\n  capabilities = [" + strings.Join(quoted, ", ") + "]\n}\n\n")
	}
	return b.String()
}

func mustPutPolicy(t *testing.T, ctx context.Context, c *api.Client, name, rules string) {
	t.Helper()
	if err := c.Sys().PutPolicyWithContext(ctx, name, rules); err != nil {
		t.Fatalf("integration: put policy %s: %v", name, err)
	}
}

func setupPolicies(t *testing.T, ctx context.Context, c *api.Client) {
	t.Helper()

	repo1Base := kvBase(RepoOnboarded)
	repo1Event := repo1Base + "/push"
	repo1Branch := repo1Event + "/" + Branch

	mustPutPolicy(t, ctx, c, "ci/itest/repo1/push", policyHCL([]pathCap{
		{"kv/metadata/" + repo1Base, []string{"list"}},
		{"kv/metadata/" + repo1Event, []string{"list"}},
		{"kv/data/" + repo1Base + "/general1", []string{"read"}},
		{"kv/data/" + repo1Base + "/shorthand1", []string{"read"}},
		{"kv/data/" + repo1Base + "/dup", []string{"read"}},
		{"kv/data/" + repo1Base + "/nonstring", []string{"read"}},
		{"kv/data/" + repo1Base + "/pinned", []string{"read"}},
		{"kv/data/" + repo1Base + "/dbref", []string{"read"}},
		{"kv/data/" + repo1Base + "/.identity", []string{"read"}},
		{"kv/data/" + repo1Event + "/eventonly", []string{"read"}},
		{DerefRefPath, []string{"read"}},
	}))

	mustPutPolicy(t, ctx, c, "ci/itest/repo1/push/main", policyHCL([]pathCap{
		{"kv/metadata/" + repo1Branch, []string{"list"}},
		{"kv/data/" + repo1Branch + "/dup", []string{"read"}},
		{"kv/data/" + repo1Branch + "/branchonly", []string{"read"}},
	}))

	repo3Base := kvBase(RepoSuppression)
	mustPutPolicy(t, ctx, c, "ci/itest/repo3/push", policyHCL([]pathCap{
		{"kv/metadata/" + repo3Base, []string{"list"}},
		{"kv/data/" + repo3Base + "/.config", []string{"read"}},
	}))

	repo4Base := kvBase(RepoMalformedIdentity)
	mustPutPolicy(t, ctx, c, "ci/itest/repo4/push", policyHCL([]pathCap{
		{"kv/metadata/" + repo4Base, []string{"list"}},
		{"kv/data/" + repo4Base + "/.identity", []string{"read"}},
	}))

	// ironbark's own AppRole policy: create+update on the mint-against-
	// role path only. No KV read, no policy read, nothing else.
	mustPutPolicy(t, ctx, c, "ironbark-agent", policyHCL([]pathCap{
		{"auth/token/create/ci", []string{"create", "update"}},
	}))
}

// setupTokenRole writes auth/token/roles/ci EXACTLY per SPEC §3.1.
//
// token_explicit_max_ttl, NOT token_ttl, bounds a role-minted token's
// lifetime (integration-verified 2026-07-16, SPEC §3.1's corrected note):
// the token-store role endpoint silently drops token_ttl, and a token
// minted with no request TTL then inherits the token auth mount's
// default_lease_ttl (32 days by default) instead. token_explicit_max_ttl
// is a hard, unrenewable expiry cap the role backend does honor on both
// products — kept short (90s) here so Task 14's lease-expiry test has a
// real deadline to observe.
func setupTokenRole(t *testing.T, ctx context.Context, c *api.Client) {
	t.Helper()
	if _, err := c.Logical().WriteWithContext(ctx, "auth/token/roles/ci", map[string]interface{}{
		"allowed_policies_glob":   []string{"ci/*"},
		"token_type":              "service",
		"orphan":                  true,
		"renewable":               false,
		"token_no_default_policy": false,
		"token_explicit_max_ttl":  "90s",
	}); err != nil {
		t.Fatalf("integration: token role ci: %v", err)
	}
}

// setupAppRole enables approle, creates role "ironbark" carrying only the
// ironbark-agent policy (setupPolicies), and returns its role_id/secret_id.
func setupAppRole(t *testing.T, ctx context.Context, c *api.Client) (roleID, secretID string) {
	t.Helper()
	ensureAuth(t, ctx, c, "approle", "approle")

	if _, err := c.Logical().WriteWithContext(ctx, "auth/approle/role/ironbark", map[string]interface{}{
		"token_policies": []string{"ironbark-agent"},
		"token_type":     "service",
		"token_ttl":      "1h",
		"token_max_ttl":  "4h",
	}); err != nil {
		t.Fatalf("integration: approle role ironbark: %v", err)
	}

	roleIDSecret, err := c.Logical().ReadWithContext(ctx, "auth/approle/role/ironbark/role-id")
	if err != nil || roleIDSecret == nil {
		t.Fatalf("integration: approle role-id: %v", err)
	}
	roleID, ok := roleIDSecret.Data["role_id"].(string)
	if !ok {
		t.Fatalf("integration: approle role-id: unexpected response shape %#v", roleIDSecret.Data)
	}

	secretIDSecret, err := c.Logical().WriteWithContext(ctx, "auth/approle/role/ironbark/secret-id", nil)
	if err != nil || secretIDSecret == nil {
		t.Fatalf("integration: approle secret-id: %v", err)
	}
	secretID, ok = secretIDSecret.Data["secret_id"].(string)
	if !ok {
		t.Fatalf("integration: approle secret-id: unexpected response shape %#v", secretIDSecret.Data)
	}

	return roleID, secretID
}

// seedKV writes every fixture KV entry described in the package doc
// comment.
func seedKV(t *testing.T, ctx context.Context, c *api.Client) {
	t.Helper()
	kv := c.KVv2("kv")

	put := func(path string, data map[string]interface{}) {
		t.Helper()
		if _, err := kv.Put(ctx, path, data); err != nil {
			t.Fatalf("integration: kv put %s: %v", path, err)
		}
	}

	repo1 := kvBase(RepoOnboarded)
	put(repo1+"/general1", map[string]interface{}{"user": "baseuser", "pass": "basepass"})
	put(repo1+"/shorthand1", map[string]interface{}{"value": "base-shorthand-value"})
	put(repo1+"/dup", map[string]interface{}{"value": "base-dup-value"})
	put(repo1+"/nonstring", map[string]interface{}{"count": 3, "label": "valid-sibling"})
	put(repo1+"/pinned", map[string]interface{}{"value": "pinned-value"})
	if err := kv.PutMetadata(ctx, repo1+"/pinned", api.KVMetadataPutInput{
		CustomMetadata: map[string]interface{}{
			"ironbark_images": "alpine,golang",
			"ironbark_events": "push,cron",
		},
	}); err != nil {
		t.Fatalf("integration: kv metadata pinned: %v", err)
	}
	put(repo1+"/dbref", map[string]interface{}{"$ref": DerefRefPath})
	put(repo1+"/.identity", map[string]interface{}{"forge_remote_id": ForgeRemoteIDRepo1})
	put(repo1+"/push/eventonly", map[string]interface{}{"value": "event-tier-value"})
	put(repo1+"/push/"+Branch+"/dup", map[string]interface{}{"value": "branch-dup-value"})
	put(repo1+"/push/"+Branch+"/branchonly", map[string]interface{}{"value": "branch-tier-value"})

	repo3 := kvBase(RepoSuppression)
	put(repo3+"/.config", map[string]interface{}{"vault_token": "false"})

	repo4 := kvBase(RepoMalformedIdentity)
	put(repo4+"/.identity", map[string]interface{}{"forge_remote_id": 12345})
}

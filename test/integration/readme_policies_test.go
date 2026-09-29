//go:build integration

// TestReadmeTierPolicies pins the README "Tier policies" examples: each
// block must appear in README.md byte-for-byte (drift guard), and, installed
// verbatim, each must grant its own tier's keys and nothing from any other
// tier — on both products.
package integration

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

// readmePullRequestPolicy and readmePushMainPolicy are the README's tier
// examples, verbatim.
const readmePullRequestPolicy = `# ci/acme/widgets/pull_request   (repo-wide base tier + pull_request event tier)
path "kv/data/ci/acme/widgets/+"                 { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/"              { capabilities = ["list"] }
path "kv/data/ci/acme/widgets/pull_request/+"    { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/pull_request/" { capabilities = ["list"] }
`

const readmePushMainPolicy = `# ci/acme/widgets/push/main      (branch tier only)
path "kv/data/ci/acme/widgets/push/main/+"       { capabilities = ["read"] }
path "kv/metadata/ci/acme/widgets/push/main/"    { capabilities = ["list"] }
`

// oldReadmePullRequestPolicy is the README's pre-fix pull_request example,
// kept only as a regression witness: its repo-root "*" also reads the
// push/main tier.
const oldReadmePullRequestPolicy = `# ci/acme/widgets/pull_request
path "kv/data/ci/acme/widgets/*" {
  capabilities = ["read"]
}
path "kv/metadata/ci/acme/widgets/*" {
  capabilities = ["list"]
}
`

// readmeTierBase is the KV path (under the kv mount) of the README
// example's base tier.
const readmeTierBase = "ci/acme/widgets"

func TestReadmeTierPolicies(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	for name, block := range map[string]string{"pull_request": readmePullRequestPolicy, "push/main": readmePushMainPolicy} {
		if !strings.Contains(string(readme), block) {
			t.Errorf("README.md does not contain the %s tier example verbatim:\n%s", name, block)
		}
	}

	for _, p := range products {
		t.Run(p.name, func(t *testing.T) {
			ctx := context.Background()
			root := NewRootClient(t, p.addr, p.rootToken)
			seedReadmeTiers(t, ctx, root)

			pr := tokenWithPolicy(t, ctx, root, "readme-pull-request", readmePullRequestPolicy)
			pm := tokenWithPolicy(t, ctx, root, "readme-push-main", readmePushMainPolicy)
			old := tokenWithPolicy(t, ctx, root, "readme-old-pull-request", oldReadmePullRequestPolicy)

			assertReadmeTierMatrix(t, ctx, pr, pm)

			// Regression witness: the old example reads the branch tier.
			if st := kvGetStatus(ctx, old, "kv/data/"+readmeTierBase+"/push/main/main_key"); st != http.StatusOK {
				t.Errorf("old pull_request example GET main_key = %d, want 200 (witness)", st)
			}
		})
	}
}

// seedReadmeTiers writes one key per README tier (base, pull_request
// event, push event, push/main branch).
func seedReadmeTiers(t *testing.T, ctx context.Context, root *api.Client) {
	t.Helper()
	ensureMount(t, ctx, root, "kv", &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}})
	for _, k := range []string{"base_key", "pull_request/pr_key", "push/push_key", "push/main/main_key"} {
		if _, err := root.KVv2("kv").Put(ctx, readmeTierBase+"/"+k, map[string]interface{}{"value": k}); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
}

// assertReadmeTierMatrix checks the corrected README tiers' 200/403 matrix:
// each token reads exactly its own tier's keys.
func assertReadmeTierMatrix(t *testing.T, ctx context.Context, pr, pm *api.Client) {
	t.Helper()
	d := "kv/data/" + readmeTierBase + "/"
	cases := []struct {
		tok  *api.Client
		who  string
		path string
		want int
	}{
		{pr, "pull_request", d + "base_key", http.StatusOK},
		{pr, "pull_request", d + "pull_request/pr_key", http.StatusOK},
		{pr, "pull_request", d + "push/push_key", http.StatusForbidden},
		{pr, "pull_request", d + "push/main/main_key", http.StatusForbidden},
		{pm, "push/main", d + "push/main/main_key", http.StatusOK},
		{pm, "push/main", d + "base_key", http.StatusForbidden},
		{pm, "push/main", d + "pull_request/pr_key", http.StatusForbidden},
		{pm, "push/main", d + "push/push_key", http.StatusForbidden},
	}
	for _, c := range cases {
		if st := kvGetStatus(ctx, c.tok, c.path); st != c.want {
			t.Errorf("%s token GET %s = %d, want %d", c.who, c.path, st, c.want)
		}
	}
	if st := kvListStatus(ctx, pr, "kv/metadata/"+readmeTierBase+"/push/main"); st != http.StatusForbidden {
		t.Errorf("pull_request token LIST push/main = %d, want 403", st)
	}
	if st := kvListStatus(ctx, pr, "kv/metadata/"+readmeTierBase); st != http.StatusOK {
		t.Errorf("pull_request token LIST base = %d, want 200", st)
	}
	if st := kvListStatus(ctx, pm, "kv/metadata/"+readmeTierBase+"/push/main"); st != http.StatusOK {
		t.Errorf("push/main token LIST push/main = %d, want 200", st)
	}
}

// tokenWithPolicy installs rules as policy name and returns a client
// holding a root-created token with only that policy.
func tokenWithPolicy(t *testing.T, ctx context.Context, root *api.Client, name, rules string) *api.Client {
	t.Helper()
	return tokenWithPolicies(t, ctx, root, map[string]string{name: rules})
}

// tokenWithPolicies installs every name→rules policy and returns a client
// holding one root-created token carrying exactly those policies.
func tokenWithPolicies(t *testing.T, ctx context.Context, root *api.Client, policies map[string]string) *api.Client {
	t.Helper()
	names := make([]string, 0, len(policies))
	for name, rules := range policies {
		mustPutPolicy(t, ctx, root, name, rules)
		names = append(names, name)
	}
	sec, err := root.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{Policies: names, TTL: "10m"})
	if err != nil {
		t.Fatalf("create token %v: %v", names, err)
	}
	c, err := root.Clone()
	if err != nil {
		t.Fatalf("clone client: %v", err)
	}
	c.SetToken(sec.Auth.ClientToken)
	return c
}

// kvGetStatus is the HTTP status of a GET on path (200 on success).
func kvGetStatus(ctx context.Context, c *api.Client, path string) int {
	s, err := c.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return statusOf(err)
	}
	if s == nil {
		return http.StatusNotFound
	}
	return http.StatusOK
}

// kvListStatus is the HTTP status of a LIST on path (200 on success).
func kvListStatus(ctx context.Context, c *api.Client, path string) int {
	s, err := c.Logical().ListWithContext(ctx, path)
	if err != nil {
		return statusOf(err)
	}
	if s == nil {
		return http.StatusNotFound
	}
	return http.StatusOK
}

func statusOf(err error) int {
	var re *api.ResponseError
	if errors.As(err, &re) {
		return re.StatusCode
	}
	return -1
}

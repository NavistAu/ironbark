//go:build integration

// Attribute isolation (design §4, §8): tier policies on kv/ reach no
// attribute data whatever glob they use; one attribute policy reaches
// exactly its own prefix; the corrected README tiers stay isolated; and a
// mis-set or missing attribute mount is handled at startup and in the
// sweep. Every assertion runs on Vault and OpenBao.
package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/vaultx"
)

// isoTierPolicies are ordinary tier policies on kv/, from tightly scoped
// to careless, none of which may reach the attribute mount.
var isoTierPolicies = map[string]string{
	"iso-readme-pull-request":     readmePullRequestPolicy,
	"iso-readme-push-main":        readmePushMainPolicy,
	"iso-readme-old-pull-request": oldReadmePullRequestPolicy,
	"iso-repo-root": `path "kv/data/ci/itest/attrs/*" { capabilities = ["read"] }
path "kv/metadata/ci/itest/attrs/*" { capabilities = ["list"] }
`,
	"iso-ci-root": `path "kv/data/ci/*" { capabilities = ["read"] }
path "kv/metadata/ci/*" { capabilities = ["list"] }
`,
	"iso-kv-star": `path "kv/*" { capabilities = ["read", "list"] }
`,
	"iso-plus": `path "kv/+/ci/itest/attrs/*" { capabilities = ["read", "list"] }
path "kv/data/+/+/+/*" { capabilities = ["read"] }
path "kv/metadata/+/+/+/*" { capabilities = ["list"] }
`,
}

// attrStarPolicy is the trailing-"*" form of rel's attribute policy.
func attrStarPolicy(rel string) string {
	data := AttrMount + "/data/" + attrKVBase + "/" + rel + "/"
	meta := AttrMount + "/metadata/" + attrKVBase + "/" + rel + "/"
	return policyHCL([]pathCap{
		{data + "*", []string{"read"}},
		{meta + "*", []string{"list"}},
		{meta, []string{"list"}},
	})
}

func attrMetaPath(rel string) string      { return AttrMount + "/metadata/" + attrKVBase + "/" + rel }
func attrDataPath(rel, key string) string { return AttrMount + "/data/" + attrKeyPath(rel, key) }

// allAttrPaths is every attribute prefix, for a sweep that tries them all.
func allAttrPaths() []string {
	out := make([]string, len(attrShapes))
	for i, s := range attrShapes {
		out[i] = attrKVBase + "/" + s.rel
	}
	return out
}

// sweptNames sweeps every attribute prefix plus the manual tiers as token.
func sweptNames(t *testing.T, ctx context.Context, vc *vaultx.Client, token string) []string {
	t.Helper()
	res, err := vc.SweepWithAttributes(ctx, token, attrIdentity("", ""), false, allAttrPaths())
	if err != nil {
		t.Fatalf("SweepWithAttributes: %v", err)
	}
	names := make([]string, len(res.Secrets))
	for i, s := range res.Secrets {
		names[i] = s.Name
	}
	return names
}

func TestAttributeIsolation(t *testing.T) {
	for _, p := range products {
		t.Run(p.name, func(t *testing.T) {
			ctx := t.Context()
			fx := SetupProduct(t, p.addr, p.rootToken)
			root := NewRootClient(t, p.addr, p.rootToken)
			setupAttrFixture(t, ctx, root)
			vc := newAttrVaultxClient(t, ctx, p.addr, fx, AttrMount)

			t.Run("tier_policies_reach_no_attribute_data", func(t *testing.T) {
				for name, rules := range isoTierPolicies {
					t.Run(name, func(t *testing.T) {
						tok := tokenWithPolicy(t, ctx, root, name, rules)
						for _, s := range attrShapes {
							if st := kvListStatus(ctx, tok, attrMetaPath(s.rel)); st != http.StatusForbidden {
								t.Errorf("LIST %s = %d, want 403", s.rel, st)
							}
							if st := kvGetStatus(ctx, tok, attrDataPath(s.rel, s.key)); st != http.StatusForbidden {
								t.Errorf("GET %s/%s = %d, want 403", s.rel, s.key, st)
							}
						}
						for _, key := range []string{"dup", "nested/deep"} {
							if st := kvGetStatus(ctx, tok, attrDataPath(".target/a", key)); st != http.StatusForbidden {
								t.Errorf("GET .target/a/%s = %d, want 403", key, st)
							}
						}
						for _, n := range sweptNames(t, ctx, vc, tok.Token()) {
							if strings.HasPrefix(n, "k_") {
								t.Errorf("sweep returned attribute secret %s", n)
							}
						}
					})
				}
			})

			t.Run("one_attribute_policy_reaches_only_its_prefix", func(t *testing.T) {
				for i, own := range attrShapes {
					forms := map[string]string{
						"plus": own.policyName, // installed by the fixture
						"star": "iso-star-" + strconv.Itoa(i),
					}
					mustPutPolicy(t, ctx, root, forms["star"], attrStarPolicy(own.rel))
					for form, policyName := range forms {
						t.Run(own.rel+"/"+form, func(t *testing.T) {
							tok := tokenFor(t, ctx, root, policyName)
							if st := kvGetStatus(ctx, tok, attrDataPath(own.rel, own.key)); st != http.StatusOK {
								t.Errorf("GET own key = %d, want 200", st)
							}
							if keys := listKeys(t, ctx, tok, attrMetaPath(own.rel)); !contains(keys, own.key) {
								t.Errorf("LIST own prefix = %v, want it to include %s", keys, own.key)
							}
							for _, other := range attrShapes {
								if other.rel == own.rel {
									continue
								}
								if st := kvListStatus(ctx, tok, attrMetaPath(other.rel)); st != http.StatusForbidden {
									t.Errorf("LIST %s = %d, want 403", other.rel, st)
								}
								if st := kvGetStatus(ctx, tok, attrDataPath(other.rel, other.key)); st != http.StatusForbidden {
									t.Errorf("GET %s/%s = %d, want 403", other.rel, other.key, st)
								}
							}
							if own.rel != ".target/a" {
								return
							}
							// Only the "*" form reaches a key nested below the
							// prefix (design §4); the sweep never descends.
							want := http.StatusForbidden
							if form == "star" {
								want = http.StatusOK
							}
							if st := kvGetStatus(ctx, tok, attrDataPath(own.rel, "nested/deep")); st != want {
								t.Errorf("GET nested/deep = %d, want %d", st, want)
							}
							for _, n := range sweptNames(t, ctx, vc, tok.Token()) {
								if strings.Contains(n, "deep") || strings.Contains(n, "nested") {
									t.Errorf("sweep returned nested key as %s", n)
								}
							}
						})
					}
				}
			})

			t.Run("readme_tiers_isolated", func(t *testing.T) {
				seedReadmeTiers(t, ctx, root)
				pr := tokenWithPolicy(t, ctx, root, "readme-pull-request", readmePullRequestPolicy)
				pm := tokenWithPolicy(t, ctx, root, "readme-push-main", readmePushMainPolicy)
				assertReadmeTierMatrix(t, ctx, pr, pm)
			})
		})
	}
}

// tokenFor returns a client holding a root-created token carrying only the
// existing policy name.
func tokenFor(t *testing.T, ctx context.Context, root *api.Client, name string) *api.Client {
	t.Helper()
	sec, err := root.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{Policies: []string{name}, TTL: "10m"})
	if err != nil {
		t.Fatalf("create token %s: %v", name, err)
	}
	c, err := root.Clone()
	if err != nil {
		t.Fatalf("clone client: %v", err)
	}
	c.SetToken(sec.Auth.ClientToken)
	return c
}

func buildIronbarkBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ironbark")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/navistau/ironbark/cmd/ironbark").CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/ironbark: %v\n%s", err, out)
	}
	return bin
}

func TestAttrMountStartup(t *testing.T) {
	t.Run("overlapping_mounts_fail_startup", func(t *testing.T) {
		bin := buildIronbarkBinary(t)
		pub, err := os.ReadFile("../../internal/wpsign/testdata/dev-ed25519.pub")
		if err != nil {
			t.Fatalf("read public key: %v", err)
		}
		cases := []struct{ kvMount, attrMount string }{
			{"", "kv"}, {"", "kv/attrs"}, {"", "/kv/"}, {"kv/ci", "kv"},
		}
		for _, c := range cases {
			env := []string{
				"PATH=" + os.Getenv("PATH"),
				"IRONBARK_WOODPECKER_PUBLIC_KEY=" + string(pub),
				"IRONBARK_VAULT_ADDR=http://127.0.0.1:1",
				"IRONBARK_VAULT_ROLE_ID=role-id",
				"IRONBARK_VAULT_SECRET_ID=secret-id",
				"IRONBARK_LISTEN_ADDR=127.0.0.1:0",
				"IRONBARK_ATTR_MOUNT=" + c.attrMount,
			}
			if c.kvMount != "" {
				env = append(env, "IRONBARK_KV_MOUNT="+c.kvMount)
			}
			cmd := exec.Command(bin)
			cmd.Env = env
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Errorf("KV_MOUNT=%q ATTR_MOUNT=%q: err = %v, want exit 1", c.kvMount, c.attrMount, err)
			}
			if !strings.Contains(stderr.String(), "IRONBARK_ATTR_MOUNT") {
				t.Errorf("KV_MOUNT=%q ATTR_MOUNT=%q: stderr %q does not name IRONBARK_ATTR_MOUNT", c.kvMount, c.attrMount, stderr.String())
			}
		}
	})

	for _, p := range products {
		t.Run(p.name+"/missing_attr_mount_is_baseline", func(t *testing.T) {
			ctx := t.Context()
			fx := SetupProduct(t, p.addr, p.rootToken)
			setupAttrFixture(t, ctx, NewRootClient(t, p.addr, p.rootToken))
			vc := newAttrVaultxClient(t, ctx, p.addr, fx, "ironbark-absent")
			res := broker.New(vc, "ci", "").Handle(ctx, attrIdentity("a", "alice"))
			if res.Status != 200 {
				t.Fatalf("Status = %d, want 200", res.Status)
			}
			got := secretMap(res)
			wantKeys(t, got, "tier_base", "tier_event", "dup")
			if got["dup"] != "tier-dup" {
				t.Errorf("dup = %q, want tier-dup", got["dup"])
			}
		})
	}
}

//go:build integration

package integration

import (
	"context"
	"sort"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/vaultx"
)

// TestAttrFixture smoke-tests the attribute fixture: an escaped target
// prefix is stored as one segment, not a nested path.
func TestAttrFixture(t *testing.T) {
	for _, p := range products {
		t.Run(p.name, func(t *testing.T) {
			ctx := t.Context()
			SetupProduct(t, p.addr, p.rootToken)
			root := NewRootClient(t, p.addr, p.rootToken)
			setupAttrFixture(t, ctx, root)

			keys := listKeys(t, ctx, root, AttrMount+"/metadata/"+attrKVBase+"/.target/")
			if want := []string{"a%2fb/", "a/"}; !equalStrings(keys, want) {
				t.Errorf("LIST .target/ = %v, want %v", keys, want)
			}
		})
	}
}

// listKeys LISTs path as c and returns the keys, sorted.
func listKeys(t *testing.T, ctx context.Context, c *api.Client, path string) []string {
	t.Helper()
	s, err := c.Logical().ListWithContext(ctx, path)
	if err != nil {
		t.Fatalf("LIST %s: %v", path, err)
	}
	if s == nil {
		return nil
	}
	raw, _ := s.Data["keys"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, k := range raw {
		out = append(out, k.(string))
	}
	sort.Strings(out)
	return out
}

// newAttrVaultxClient is newVaultxClient with the attribute mount set and
// the startup canary passed (the broker's mint gate).
func newAttrVaultxClient(t *testing.T, ctx context.Context, addr string, fx Fixture, attrMount string) *vaultx.Client {
	t.Helper()
	c, err := vaultx.New(vaultx.Config{
		Addr:      addr,
		RoleID:    fx.RoleID,
		SecretID:  fx.SecretID,
		TokenRole: "ci",
		KVMount:   "kv",
		KVPrefix:  "ci",
		AttrMount: attrMount,
	})
	if err != nil {
		t.Fatalf("vaultx.New: %v", err)
	}
	if err := c.Login(ctx); err != nil {
		t.Fatalf("vaultx Login: %v", err)
	}
	if err := c.RunCanary(ctx, canaryPrefix); err != nil {
		t.Fatalf("RunCanary: %v", err)
	}
	return c
}

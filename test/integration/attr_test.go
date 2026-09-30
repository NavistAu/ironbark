//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/forge"
	"github.com/navistau/ironbark/internal/identity"
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

// attrIdentity is a manual pipeline of itest/attrs with target and actor.
func attrIdentity(target, actor string) identity.Identity {
	return identity.Identity{Org: TestOrg, Repo: RepoAttrs, Event: attrEvent, Target: target, Actor: actor,
		Commit: "c", PipelineNumber: 1}
}

// secretMap is a Result's secrets by name, vault_token excluded.
func secretMap(res broker.Result) map[string]string {
	m := map[string]string{}
	for _, s := range res.Secrets {
		if s.Name != "vault_token" {
			m[s.Name] = s.Value
		}
	}
	return m
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func wantKeys(t *testing.T, got map[string]string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if g := sortedKeys(got); !equalStrings(g, want) {
		t.Errorf("secrets = %v, want %v", g, want)
	}
}

func TestAttributes(t *testing.T) {
	priv, pub := loadE2EKeys(t)
	for _, p := range products {
		t.Run(p.name, func(t *testing.T) {
			ctx := t.Context()
			fx := SetupProduct(t, p.addr, p.rootToken)
			root := NewRootClient(t, p.addr, p.rootToken)
			setupAttrFixture(t, ctx, root)
			vc := newAttrVaultxClient(t, ctx, p.addr, fx, AttrMount)
			ff := newFakeForge(t)

			t.Run("dot_and_pct_accepted", func(t *testing.T) {
				name := attrP1 + "/.target/a%2fb"
				got, err := root.Sys().GetPolicyWithContext(ctx, name)
				if err != nil || got == "" {
					t.Fatalf("read policy %s: %q, %v", name, got, err)
				}
				pols, err := root.Sys().ListPoliciesWithContext(ctx)
				if err != nil {
					t.Fatalf("list policies: %v", err)
				}
				found := false
				for _, n := range pols {
					found = found || n == name
				}
				if !found {
					t.Errorf("policy list lacks %s verbatim", name)
				}
				sec, err := root.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{Policies: []string{name}, TTL: "5m"})
				if err != nil {
					t.Fatalf("create token: %v", err)
				}
				if !contains(sec.Auth.Policies, name) {
					t.Errorf("token policies = %v, want %s verbatim", sec.Auth.Policies, name)
				}
			})

			t.Run("target_only_grant", func(t *testing.T) {
				res := broker.New(vc, "ci", "").Handle(ctx, attrIdentity("a", "bob"))
				if res.Status != 200 {
					t.Fatalf("Status = %d", res.Status)
				}
				got := secretMap(res)
				if _, ok := got["k_target_a"]; !ok {
					t.Errorf("k_target_a missing from %v", sortedKeys(got))
				}
				if got["dup"] != "attr-dup" {
					t.Errorf("dup = %q, want attr-dup (attribute beats tier)", got["dup"])
				}
				for _, k := range []string{"k_ta_a_alice", "k_tt_a_ops"} {
					if _, ok := got[k]; ok {
						t.Errorf("%s leaked to bob", k)
					}
				}
			})

			t.Run("conjunction_needs_actor", func(t *testing.T) {
				res := broker.New(vc, "ci", "").Handle(ctx, attrIdentity("a/b", "alice"))
				if res.Status != 200 {
					t.Fatalf("Status = %d", res.Status)
				}
				wantKeys(t, secretMap(res), "k_ta_ab_alice", "k_ta_a_alice", "k_target_ab", "k_target_a",
					"k_actor", "tier_base", "tier_event", "dup")
			})

			t.Run("teams_via_fake_forge", func(t *testing.T) {
				ff.set(0, 0)
				brk := broker.New(vc, "ci", "", broker.WithTeamResolver(forge.NewGitea(ff.URL, "forge-token", 2*time.Second, nil)))
				res := brk.Handle(ctx, attrIdentity("a/b", "alice"))
				if res.Status != 200 {
					t.Fatalf("Status = %d", res.Status)
				}
				wantKeys(t, secretMap(res), "k_ta_ab_alice", "k_ta_a_alice", "k_tt_a_ops", "k_target_ab", "k_target_a",
					"k_actor", "k_team", "tier_base", "tier_event", "dup")
				if !equalStrings(res.Audit.Teams, []string{"ops"}) {
					t.Errorf("Audit.Teams = %v, want [ops]", res.Audit.Teams)
				}
			})

			t.Run("overflow_drops_only_attributes", func(t *testing.T) {
				ff.set(0, 0)
				brk := broker.New(vc, "ci", "", broker.WithMaxPolicies(3),
					broker.WithTeamResolver(forge.NewGitea(ff.URL, "forge-token", 2*time.Second, nil)))
				res := brk.Handle(ctx, attrIdentity("a/b", "alice"))
				if res.Status != 200 {
					t.Fatalf("Status = %d", res.Status)
				}
				want := []string{attrP1, attrP1 + "/.target/a", attrP1 + "/.actor/alice"}
				if !equalStrings(res.Audit.PoliciesRequested, want) {
					t.Errorf("PoliciesRequested = %v, want %v", res.Audit.PoliciesRequested, want)
				}
				wantKeys(t, secretMap(res), "k_target_a", "k_actor", "tier_base", "tier_event", "dup")
				if len(res.Audit.PoliciesDropped) == 0 {
					t.Error("PoliciesDropped empty")
				}
				for _, d := range res.Audit.PoliciesDropped {
					if d == attrP1 || d == attrP1+"/.actor/alice" {
						t.Errorf("dropped %s", d)
					}
				}
			})

			for _, c := range []struct {
				name   string
				delay  time.Duration
				status int
			}{
				{"team_timeout_fails_closed", 2 * time.Second, 0},
				{"team_500_fails_closed", 0, http.StatusInternalServerError},
			} {
				t.Run(c.name, func(t *testing.T) {
					ff.set(c.delay, c.status)
					defer ff.set(0, 0)
					brk := broker.New(vc, "ci", "", broker.WithTeamResolver(forge.NewGitea(ff.URL, "forge-token", 200*time.Millisecond, nil)))
					start := time.Now()
					res := brk.Handle(ctx, attrIdentity("a", "alice"))
					if d := time.Since(start); d >= 1500*time.Millisecond {
						t.Errorf("Handle took %v, want < 1.5s", d)
					}
					if res.Status != 200 {
						t.Fatalf("Status = %d, want 200", res.Status)
					}
					if res.Audit.TeamsError == "" {
						t.Error("Audit.TeamsError empty")
					}
					got := secretMap(res)
					for _, k := range []string{"k_tt_a_ops", "k_team"} {
						if _, ok := got[k]; ok {
							t.Errorf("%s granted after a failed team lookup", k)
						}
					}
					for _, k := range []string{"k_target_a", "k_actor"} {
						if _, ok := got[k]; !ok {
							t.Errorf("%s missing from %v", k, sortedKeys(got))
						}
					}
				})
			}

			t.Run("e2e_manual_payload", func(t *testing.T) {
				stack := newE2EStackWith(t, ctx, p.addr, fx, pub, AttrMount, identity.Options{TargetVar: "DEPLOY_TO"})
				body, err := json.Marshal(map[string]interface{}{
					"repo": map[string]interface{}{"full_name": TestOrg + "/" + RepoAttrs, "forge_remote_id": "attrs-id"},
					"pipeline": map[string]interface{}{"event": "manual", "branch": "main", "number": 3, "commit": "c",
						"author": "carol", "sender": "", "variables": map[string]string{"DEPLOY_TO": "a"}},
				})
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				resp, err := http.DefaultClient.Do(signedRequest(t, stack.server.URL, body, priv))
				if err != nil {
					t.Fatalf("do: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("Status = %d", resp.StatusCode)
				}
				var rb e2eResponseBody
				if err := json.NewDecoder(resp.Body).Decode(&rb); err != nil {
					t.Fatalf("decode: %v", err)
				}
				if _, ok := findE2ESecret(rb.Secrets, "k_target_a"); !ok {
					t.Errorf("k_target_a missing from %v", e2eSecretNames(rb.Secrets))
				}
			})
		})
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

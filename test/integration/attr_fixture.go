//go:build integration

// Pipeline-attribute fixture (design 2026-09-30-pipeline-attributes §4, §8):
// the ironbark-owned attribute mount seeded at every attribute shape, the
// matching attribute policies, and a fake Gitea-family forge for team
// lookups. setupAttrFixture assumes SetupProduct has run (kv mount, token
// role, AppRole) and is idempotent.
//
//	org=itest, repo=attrs (RepoAttrs), event=manual
//	  kv:        ci/itest/attrs/{tier_base, dup="tier-dup"}
//	             ci/itest/attrs/manual/tier_event
//	  ironbark:  itest/attrs/manual/<rel>/<key> for every attrShapes row,
//	             plus dup="attr-dup" at .target/a and the unswept nested
//	             key .target/a/nested/deep
//	  policies:  ci/itest/attrs/manual (P1) — both ordinary tiers, "+" form
//	             ci/itest/attrs/manual/<rel> — one per attrShapes row,
//	             "+" form on the ironbark mount
package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	RepoAttrs  = "attrs"
	AttrMount  = "ironbark"
	attrEvent  = "manual"
	attrKVBase = TestOrg + "/" + RepoAttrs + "/" + attrEvent // path in the attribute mount
	attrP1     = "ci/" + TestOrg + "/" + RepoAttrs + "/" + attrEvent
)

// attrShape is one seeded attribute prefix: its Rel (relative to P1 and to
// attrKVBase), the unique key stored under it, and its policy name.
type attrShape struct {
	rel        string
	key        string
	policyName string
}

func shape(rel, key string) attrShape {
	return attrShape{rel: rel, key: key, policyName: attrP1 + "/" + rel}
}

// attrShapes is every seeded attribute prefix. Key names are unique so a
// leak is identifiable.
var attrShapes = []attrShape{
	shape(".target/a", "k_target_a"),
	shape(".target/a%2fb", "k_target_ab"),
	shape(".target-actor/a/alice", "k_ta_a_alice"),
	shape(".target-team/a/ops", "k_tt_a_ops"),
	shape(".target-actor/a%2fb/alice", "k_ta_ab_alice"),
	shape(".actor/alice", "k_actor"),
	shape(".team/ops", "k_team"),
	shape(".actor/bob", "k_actor_bob"),
}

// attrKeyPath is the path of key under rel in the attribute mount,
// relative to the mount.
func attrKeyPath(rel, key string) string { return attrKVBase + "/" + rel + "/" + key }

// attrPlusPolicy is the documented attribute policy for rel: read on the
// prefix's plain keys ("+" is one segment), list on its exact metadata path.
func attrPlusPolicy(rel string) string {
	return policyHCL([]pathCap{
		{AttrMount + "/data/" + attrKVBase + "/" + rel + "/+", []string{"read"}},
		{AttrMount + "/metadata/" + attrKVBase + "/" + rel + "/", []string{"list"}},
	})
}

func setupAttrFixture(t *testing.T, ctx context.Context, root *api.Client) {
	t.Helper()
	ensureMount(t, ctx, root, AttrMount, &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}})

	// The api client sends each path as URL.Path, so the "%" of an escaped
	// segment travels as "%25" and is stored literally (the same encoding
	// the sweep uses).
	put := func(mount, path, value string) {
		t.Helper()
		if _, err := root.KVv2(mount).Put(ctx, path, map[string]interface{}{"value": value}); err != nil {
			t.Fatalf("seed %s/%s: %v", mount, path, err)
		}
	}
	tierBase := "ci/" + TestOrg + "/" + RepoAttrs
	put("kv", tierBase+"/tier_base", "tier-base")
	put("kv", tierBase+"/dup", "tier-dup")
	put("kv", tierBase+"/"+attrEvent+"/tier_event", "tier-event")
	for _, s := range attrShapes {
		put(AttrMount, attrKeyPath(s.rel, s.key), s.key+"-value")
	}
	put(AttrMount, attrKeyPath(".target/a", "dup"), "attr-dup")
	put(AttrMount, attrKeyPath(".target/a", "nested/deep"), "deep-value")

	mustPutPolicy(t, ctx, root, attrP1, policyHCL([]pathCap{
		{"kv/data/" + tierBase + "/+", []string{"read"}},
		{"kv/metadata/" + tierBase + "/", []string{"list"}},
		{"kv/data/" + tierBase + "/" + attrEvent + "/+", []string{"read"}},
		{"kv/metadata/" + tierBase + "/" + attrEvent + "/", []string{"list"}},
	}))
	for _, s := range attrShapes {
		mustPutPolicy(t, ctx, root, s.policyName, attrPlusPolicy(s.rel))
	}
}

// fakeForge serves the two Gitea endpoints the team resolver calls for
// itest/attrs: one team, "ops" (id 1), whose members are settable.
type fakeForge struct {
	*httptest.Server

	mu      sync.Mutex
	members map[string]bool
	delay   time.Duration
	status  int // non-zero: every response uses this status
}

func newFakeForge(t *testing.T) *fakeForge {
	t.Helper()
	f := &fakeForge{members: map[string]bool{"alice": true}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeForge) set(delay time.Duration, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay, f.status = delay, status
}

func (f *fakeForge) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	delay, status, members := f.delay, f.status, f.members
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	switch {
	case r.URL.Path == "/api/v1/repos/"+TestOrg+"/"+RepoAttrs+"/teams":
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{{"id": 1, "name": "ops"}})
	case strings.HasPrefix(r.URL.Path, "/api/v1/teams/1/members/") && members[strings.TrimPrefix(r.URL.Path, "/api/v1/teams/1/members/")]:
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

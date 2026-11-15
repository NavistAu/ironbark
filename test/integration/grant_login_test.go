//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/navistau/ironbark/internal/vaultx"
)

func grantConn(t *testing.T) *vaultx.Conn {
	t.Helper()
	c, err := vaultx.NewConn(grantAddr, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGrantLogin(t *testing.T) {
	g := GetGrant(t)
	c := grantConn(t)
	org, repo := "acme", uniq("lg")
	key := org + "/" + repo + "#4711"
	login := func(role string, r Req) (vaultx.Token, error) {
		r.Org, r.Repo = org, repo
		if r.ID == "" {
			r.ID = "4711"
		}
		return c.LoginJWT(context.Background(), "jwt", role, g.JWT(t, r))
	}
	refused := func(err error) bool {
		var re *vaultx.RefusedError
		return errors.As(err, &re)
	}

	// string, glob and list bound_claims in one role
	g.Role(t, "lg-multi", map[string]any{
		"repo_key": []string{key, org + "/never#*"},
		"event":    []string{"push", "deployment"},
		"branch":   "release%2f*", // escaped glob (spec §5.3)
		"env":      "staging",
	}, []string{"ci-project", "ci-env"}, nil)
	ok := Req{Branch: "release/1", Env: "staging", Source: "branch"}
	if _, err := login("lg-multi", ok); err != nil {
		t.Fatalf("all claims match: %v", err)
	}
	t.Run("event list refuses tag", func(t *testing.T) {
		r := ok
		r.Event = "tag"
		if _, err := login("lg-multi", r); !refused(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("second list value admits deployment", func(t *testing.T) {
		r := ok
		r.Event = "deployment"
		if _, err := login("lg-multi", r); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("glob refuses other branch", func(t *testing.T) {
		r := ok
		r.Branch = "main"
		if _, err := login("lg-multi", r); !refused(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("string refuses other env", func(t *testing.T) {
		r := ok
		r.Env = "prod"
		if _, err := login("lg-multi", r); !refused(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("repo_key with a changed forge id is refused", func(t *testing.T) {
		r := ok
		r.ID = "9999"
		if _, err := login("lg-multi", r); !refused(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing bound claim is refused", func(t *testing.T) {
		r := ok
		r.Branch, r.Env = "", "staging" // no branch claim at all
		if _, err := login("lg-multi", r); !refused(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing role is refused", func(t *testing.T) {
		if _, err := login("lg-no-such-role", ok); !refused(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad signature is an error, not a refusal", func(t *testing.T) {
		_, err := c.LoginJWT(context.Background(), "jwt", "lg-multi", "abc.def.ghi")
		if err == nil || refused(err) {
			t.Fatalf("err = %v", err)
		}
	})

	// per-login assertions; the offending token is revoked
	assertRevoked := func(t *testing.T, role string, over map[string]any) {
		t.Helper()
		g.Role(t, role, map[string]any{"repo_key": []string{key}}, []string{"ci-project"}, over)
		_, err := login(role, Req{})
		var ae *vaultx.AssertionError
		if !errors.As(err, &ae) {
			t.Fatalf("err = %v, want AssertionError", err)
		}
		// service tokens: the accessor no longer resolves once revoked
		if ae.Accessor != "" {
			if _, err := g.Root.Auth().Token().LookupAccessor(ae.Accessor); err == nil {
				t.Fatalf("token %s still live after assertion failure", ae.Accessor)
			}
		}
		t.Logf("assertion: %v (accessor %q)", ae, ae.Accessor)
	}
	t.Run("role without explicit max ttl", func(t *testing.T) {
		assertRevoked(t, "lg-nomax", map[string]any{"token_explicit_max_ttl": nil})
	})
	t.Run("batch role", func(t *testing.T) {
		assertRevoked(t, "lg-batch", map[string]any{"token_type": "batch"})
	})
	t.Run("revoked token is dead", func(t *testing.T) {
		// Same role as lg-nomax, but log in raw so the token is in hand, then
		// run the same revoke the assertion path runs.
		jwt := g.JWT(t, Req{Org: org, Repo: repo, ID: "4711"})
		tok, err := g.LoginRaw("lg-nomax", jwt)
		if err != nil {
			t.Fatal(err)
		}
		if g.Code(tok, "auth/token/lookup-self") != 200 {
			t.Fatal("token should be live before revoke")
		}
		if err := c.RevokeSelf(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
		if got := g.Code(tok, "auth/token/lookup-self"); got != 403 {
			t.Fatalf("lookup after revoke = %d, want 403", got)
		}
	})
}

//go:build integration

package integration

// Spike findings (design §18.2) as tests. Each runs on OpenBao 2.7.0 with
// voidstar views and on Vault 1.20 over plain KV v2 (the spec claims OpenBao
// only; Vault results are informational).

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/jwtsign"
	"github.com/navistau/ironbark/internal/vaultx"
)

func TestGrantSpike(t *testing.T) {
	for _, p := range []struct {
		name string
		get  func(*testing.T) *Grant
	}{{"openbao", GetGrant}, {"vault", GetVault}} {
		t.Run(p.name, func(t *testing.T) {
			g := p.get(t)
			conn, err := vaultx.NewConn(g.Addr, nil)
			if err != nil {
				t.Fatal(err)
			}
			s := &spike{t: t, g: g, c: conn, org: "acme", repo: uniq("sp")}
			s.repoKey = s.org + "/" + s.repo + "#1"
			t.Run("levels", s.levels)
			t.Run("groups", s.groups)
			t.Run("escaped team", s.escapedTeam)
			t.Run("slash claim", s.slashClaim)
			t.Run("same sub race", s.sameSubRace)
			t.Run("absent claim", s.absentClaim)
			t.Run("clock skew and unknown key", s.skewAndKey)
		})
	}
}

type spike struct {
	t       *testing.T
	g       *Grant
	c       *vaultx.Conn
	org     string
	repo    string
	repoKey string
}

func (s *spike) rel(p string) string { return s.org + "/" + s.repo + "/" + p }

func (s *spike) role(t *testing.T, name string, policies ...string) {
	s.g.Role(t, name, map[string]any{"repo_key": []string{s.repoKey}}, policies, nil)
}

func (s *spike) req(env, target string, teams ...string) Req {
	return Req{Org: s.org, Repo: s.repo, ID: "1", Env: env, Source: "variable", Target: target, Teams: teams}
}

func (s *spike) login(t *testing.T, role string, r Req) string {
	t.Helper()
	tok, err := s.c.LoginJWT(context.Background(), "jwt", role, s.g.JWT(t, r))
	if err != nil {
		t.Fatal(err)
	}
	return tok.Value
}

func (s *spike) want(t *testing.T, tok, rel string, code int) {
	t.Helper()
	if got := s.g.Code(tok, s.g.Data(s.rel(rel))); got != code {
		t.Errorf("read %s = %d, want %d", rel, got, code)
	}
}

func (s *spike) levels(t *testing.T) {
	for _, p := range []string{"r", "staging/e", "staging/web/w", "staging/web/api/a", "staging/web/cli/c",
		"staging/web/api/deep/x", "prod/p"} {
		s.g.Secret(t, s.rel(p), "v")
	}
	s.role(t, "sp-levels", "ci-project", "ci-env", "ci-target")
	tok := s.login(t, "sp-levels", s.req("staging", "web/api"))
	for _, p := range []string{"r", "staging/e", "staging/web/w", "staging/web/api/a"} {
		s.want(t, tok, p, 200)
	}
	// one level away: a sibling, a level below the target, another env
	for _, p := range []string{"staging/web/cli/c", "staging/web/api/deep/x", "prod/p"} {
		s.want(t, tok, p, 403)
	}
	if c := s.g.Code(tok, s.g.Data(s.org+"/other"+s.repo+"/r")); c != 403 {
		t.Errorf("another repo = %d", c)
	}
}

// groupPolicy grants read on one literal level below the templated env.
func (s *spike) groupPolicy(t *testing.T, name, level string) {
	m := func(c string) string { return "{{identity.entity.aliases." + s.g.Accessor + ".metadata." + c + "}}" }
	pol := `path "` + s.g.Mount + `/data/pipelines/` + m("org") + "/" + m("repo") + "/" + m("env") + "/" + level + `/+" { capabilities = ["read"] }` + "\n"
	if err := s.g.Root.Sys().PutPolicy(name, pol); err != nil {
		t.Fatal(err)
	}
}

func (s *spike) groups(t *testing.T) {
	s.g.Secret(t, s.rel("staging/gated/x"), "v")
	team := s.org + "/" + uniq("deployers")
	s.groupPolicy(t, "sp-grp-"+s.repo, "gated")
	s.g.Group(t, "sp-grp-"+s.repo, []string{"sp-grp-" + s.repo}, team)
	s.g.Role(t, "sp-grp", map[string]any{"repo_key": []string{s.repoKey}}, []string{"ci-project", "ci-env"},
		map[string]any{"groups_claim": "teams"})

	with := s.login(t, "sp-grp", s.req("staging", "", team))
	s.want(t, with, "staging/gated/x", 200)
	other := s.login(t, "sp-grp", s.req("staging", "", s.org+"/"+uniq("nobody")))
	s.want(t, other, "staging/gated/x", 403)

	// FINDING (fixed in jwtsign, 404eeae): a role with groups_claim set refuses
	// a JWT with no `teams` claim at all, as a plain login error. jwtsign now
	// always sends `teams`, as [] when there are none, and that logs in with no
	// groups. Both halves are checked here.
	tok := s.login(t, "sp-grp", s.req("staging", ""))
	s.want(t, tok, "staging/gated/x", 403)
	c := s.g.Claims(s.req("staging", ""))
	if ts, ok := c["teams"].([]string); !ok || len(ts) != 0 {
		t.Errorf("jwtsign teams claim with no teams = %#v, want an empty list", c["teams"])
	}
	delete(c, "teams")
	j, _ := s.g.Signer.Sign(c)
	_, err := s.c.LoginJWT(context.Background(), "jwt", "sp-grp", j)
	var ref *vaultx.RefusedError
	if err == nil || errors.As(err, &ref) || !strings.Contains(err.Error(), `"teams" claim not found`) {
		t.Errorf("absent teams claim: err = %v, want a plain login error", err)
	}
}

func (s *spike) escapedTeam(t *testing.T) {
	s.g.Secret(t, s.rel("staging/upper/x"), "v")
	s.g.Secret(t, s.rel("staging/lower/x"), "v")
	raw := "Team" + uniq("")
	escaped := identity.Esc(s.org) + "/" + identity.Esc(raw) // what forge.QualifiedTeams sends
	lowered := s.org + "/" + strings.ToLower(raw)            // a case-folded alias
	if escaped == lowered {
		t.Fatal("escaping should keep case variants distinct")
	}
	s.groupPolicy(t, "sp-up-"+s.repo, "upper")
	s.groupPolicy(t, "sp-lo-"+s.repo, "lower")
	s.g.Group(t, "sp-up-"+s.repo, []string{"sp-up-" + s.repo}, escaped)
	s.g.Group(t, "sp-lo-"+s.repo, []string{"sp-lo-" + s.repo}, lowered)
	tok := s.login(t, "sp-grp", s.req("staging", "", escaped))
	s.want(t, tok, "staging/upper/x", 200)
	s.want(t, tok, "staging/lower/x", 403)
}

func (s *spike) slashClaim(t *testing.T) {
	s.role(t, "sp-slash", "ci-project", "ci-env", "ci-target")
	s.g.Secret(t, s.rel("r2"), "v")
	claims := s.g.Claims(s.req("staging", "web"))
	claims["t1"] = "web/../../prod" // hand-built: never emitted by ironbark
	claims["sub"] = "ib-slash-" + s.repo
	jwt, err := s.g.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	// Raw login: the token has no ACL, so ironbark's own lookup-self assertion
	// fails on it (it errors, and the token cannot be revoked by itself either).
	tokV, err := s.g.LoginRaw("sp-slash", jwt)
	if err != nil {
		t.Fatal(err)
	}
	tok := struct{ Value string }{tokV}
	if s.g.Mount == "kv" {
		// Vault renders the slash and keeps the ACL (informational, not claimed).
		t.Logf("vault: r2=%d web=%d lookup-self=%d", s.g.Code(tok.Value, s.g.Data(s.rel("r2"))),
			s.g.Code(tok.Value, s.g.Data(s.rel("staging/web/x"))), s.g.Code(tok.Value, "auth/token/lookup-self"))
		return
	}
	// OpenBao refuses to build the ACL: every read 403s, even lookup-self.
	if _, err := s.c.LoginJWT(context.Background(), "jwt", "sp-slash", jwt); err == nil {
		t.Error("vaultx login should fail its lookup-self assertion on an ACL-less token")
	}
	// FINDING: the status is 400 ("Forbidden"), not 403, so the walk sees a hard
	// error (fails closed) rather than a skippable 403.
	for _, p := range []string{s.g.Data(s.rel("r2")), s.g.Data(s.rel("staging/web/x")), "auth/token/lookup-self"} {
		if c := s.g.Code(tok.Value, p); c != 400 {
			t.Errorf("read %s = %d, want 400 (no ACL)", p, c)
		}
	}
}

func TestEscNeverEmitsPolicyMetacharacters(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	const alphabet = "abcXYZ019/*+%._-# \t\n\x00é世🙂\\{}[]?"
	rs := []rune(alphabet)
	for i := 0; i < 5000; i++ {
		n := r.Intn(24)
		var b strings.Builder
		for j := 0; j < n; j++ {
			if r.Intn(4) == 0 {
				b.WriteByte(byte(r.Intn(256)))
			} else {
				b.WriteRune(rs[r.Intn(len(rs))])
			}
		}
		if e := identity.Esc(b.String()); strings.ContainsAny(e, "/*+") {
			t.Fatalf("Esc(%q) = %q contains a policy metacharacter", b.String(), e)
		}
	}
}

func (s *spike) sameSubRace(t *testing.T) {
	s.g.Secret(t, s.rel("staging/web/w"), "v")
	s.g.Secret(t, s.rel("staging/cli/c"), "v")
	s.role(t, "sp-race", "ci-project", "ci-env", "ci-target")
	login := func(target, sub string) string {
		c := s.g.Claims(s.req("staging", target))
		if sub != "" {
			c["sub"] = sub
		}
		j, err := s.g.Signer.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := s.c.LoginJWT(context.Background(), "jwt", "sp-race", j)
		if err != nil {
			t.Fatal(err)
		}
		return tok.Value
	}
	// fixed sub: the second login rewrites the alias metadata under the first token
	fixed := "ib-fixed-" + s.repo
	a := login("web", fixed)
	s.want(t, a, "staging/web/w", 200)
	login("cli", fixed)
	s.want(t, a, "staging/cli/c", 200) // token A now reads B's target
	s.want(t, a, "staging/web/w", 403) // and lost its own
	// §5.4 sub: different grants, different entities, no interference
	a2 := login("web", "")
	login("cli", "")
	s.want(t, a2, "staging/web/w", 200)
	s.want(t, a2, "staging/cli/c", 403)
}

func (s *spike) absentClaim(t *testing.T) {
	s.g.Secret(t, s.rel("r3"), "v")
	s.g.Secret(t, s.rel("staging/e3"), "v")
	s.g.Secret(t, s.rel("staging/web/w3"), "v")
	s.role(t, "sp-absent", "ci-project", "ci-env", "ci-target")
	// no env at all
	tok := s.login(t, "sp-absent", s.req("", ""))
	s.want(t, tok, "r3", 200)
	s.want(t, tok, "staging/e3", 403)
	s.want(t, tok, "staging/web/w3", 403)
	// env but no target: the target stanzas render empty
	tok = s.login(t, "sp-absent", s.req("staging", ""))
	s.want(t, tok, "staging/e3", 200)
	s.want(t, tok, "staging/web/w3", 403)
}

func (s *spike) skewAndKey(t *testing.T) {
	s.role(t, "sp-skew", "ci-project")
	shifted := func(d time.Duration) string {
		c := s.g.Claims(s.req("", ""))
		for _, k := range []string{"iat", "nbf", "exp"} {
			c[k] = c[k].(int64) + int64(d/time.Second)
		}
		j, err := s.g.Signer.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	_, other, _, err := genKey()
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := jwtsign.LoadKey(other)
	if err != nil {
		t.Fatal(err)
	}
	strangerJWT, err := stranger.Sign(s.g.Claims(s.req("", "")))
	if err != nil {
		t.Fatal(err)
	}
	for name, j := range map[string]string{
		"clock ahead beyond leeway":  shifted(10 * time.Minute),
		"clock behind beyond leeway": shifted(-10 * time.Minute),
		"key not in the mount":       strangerJWT,
	} {
		_, err := s.c.LoginJWT(context.Background(), "jwt", "sp-skew", j)
		var ref *vaultx.RefusedError
		if err == nil || errors.As(err, &ref) {
			t.Errorf("%s: err = %v, want a plain login error", name, err)
		}
	}
	// within leeway still works
	if _, err := s.c.LoginJWT(context.Background(), "jwt", "sp-skew", shifted(30*time.Second)); err != nil {
		t.Errorf("30s ahead should be inside leeway: %v", err)
	}
}

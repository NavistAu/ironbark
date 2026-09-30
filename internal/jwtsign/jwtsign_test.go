package jwtsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/facts"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/selector"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func key3072(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

func pkcs1PEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func pkcs8PEM(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestLoadKey(t *testing.T) {
	k := key3072(t)
	for name, in := range map[string][]byte{"pkcs1": pkcs1PEM(k), "pkcs8": pkcs8PEM(t, k), "surrounding whitespace": append([]byte("\n  "), pkcs1PEM(k)...)} {
		s, err := LoadKey(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		sum := sha256.Sum256(der)
		if s.KID() != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: kid = %s", name, s.KID())
		}
	}
}

func TestLoadKeyRejects(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubOnly := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: func() []byte { d, _ := x509.MarshalPKIXPublicKey(&key3072(t).PublicKey); return d }()})
	cases := map[string][]byte{
		"2048 bits":   pkcs1PEM(small),
		"not pem":     []byte("nope"),
		"empty":       nil,
		"public only": pubOnly,
		"bad der":     pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("junk")}),
	}
	for name, in := range cases {
		s, err := LoadKey(in)
		if err == nil || s != nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := LoadKey(pkcs1PEM(small)); err == nil || !strings.Contains(err.Error(), "3072") {
		t.Errorf("err = %v", err)
	}
}

func split(t *testing.T, tok string) (hdr, claims map[string]any, signed string, sig []byte) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("not raw base64url: %v", err)
		}
		return b
	}
	if err := json.Unmarshal(dec(parts[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(dec(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	return hdr, claims, parts[0] + "." + parts[1], dec(parts[2])
}

func TestSignVerifies(t *testing.T) {
	k := key3072(t)
	s, err := LoadKey(pkcs1PEM(k))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Sign(map[string]any{"iss": "ironbark", "n": 1})
	if err != nil {
		t.Fatal(err)
	}
	hdr, claims, signed, sig := split(t, tok)
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" || hdr["kid"] != s.KID() {
		t.Errorf("header = %v", hdr)
	}
	if claims["iss"] != "ironbark" {
		t.Errorf("claims = %v", claims)
	}
	sum := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	sum[0] ^= 1
	if rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig) == nil {
		t.Error("signature verifies over different data")
	}
}

var now = time.Unix(1_790_000_000, 0)

func fullFacts() facts.Facts {
	return facts.Facts{
		Org: "acme", Repo: "mono", RepoKey: "acme/mono#4711", Event: "manual",
		Branch: "main", Ref: "refs/heads/main", BranchProtected: "true",
		Actor: "carol", Pipeline: "17",
	}
}

func target(t *testing.T, s string) selector.Target {
	t.Helper()
	tg, reason := selector.ParseTarget(s)
	if reason != "" {
		t.Fatal(reason)
	}
	return tg
}

func TestClaimsFull(t *testing.T) {
	c := Claims(fullFacts(), "prod", "variable", target(t, "web/api"), []string{"acme/deployers", "acme/ops"}, now)
	want := map[string]any{
		"iss": "ironbark", "aud": "ironbark",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Unix() + 60,
		"org": "acme", "repo": "mono", "repo_key": "acme/mono#4711",
		"event": "manual", "branch": "main", "ref": "refs%2fheads%2fmain", "branch_protected": "true",
		"actor": "carol", "teams": []string{"acme/deployers", "acme/ops"},
		"env": "prod", "env_source": "variable",
		"target": "web/api", "t1": "web", "t2": "api",
		"pipeline": "17",
	}
	for k, v := range want {
		if !reflect.DeepEqual(c[k], v) {
			t.Errorf("claim %s = %#v, want %#v", k, c[k], v)
		}
	}
	if sub, _ := c["sub"].(string); !regexp.MustCompile(`^ib-[0-9a-f]{40}$`).MatchString(sub) {
		t.Errorf("sub = %v", c["sub"])
	}
	if jti, _ := c["jti"].(string); !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(jti) {
		t.Errorf("jti = %v", c["jti"])
	}
	for _, k := range []string{"t3", "t4", "t5", "t6", "t7", "t8"} {
		if _, ok := c[k]; ok {
			t.Errorf("claim %s present beyond target depth", k)
		}
	}
	if c["exp"].(int64)-c["iat"].(int64) != 60 {
		t.Error("exp-iat != 60")
	}
}

func TestClaimsJTIUnique(t *testing.T) {
	a := Claims(fullFacts(), "", "", selector.Target{}, nil, now)["jti"]
	b := Claims(fullFacts(), "", "", selector.Target{}, nil, now)["jti"]
	if a == b {
		t.Error("jti repeated")
	}
}

func TestClaimsAbsentMeansOmitted(t *testing.T) {
	f := facts.Facts{Org: "acme", Repo: "mono", RepoKey: "acme/mono#4711", Event: "pull_request", Pipeline: "3"}
	c := Claims(f, "", "", selector.Target{}, nil, now)
	for _, k := range []string{"branch", "ref", "branch_protected", "actor", "env", "env_source", "target", "t1", "t2", "t3"} {
		if _, ok := c[k]; ok {
			t.Errorf("claim %s present: %#v", k, c[k])
		}
	}
	for _, k := range []string{"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "org", "repo", "repo_key", "event", "pipeline"} {
		if _, ok := c[k]; !ok {
			t.Errorf("claim %s missing", k)
		}
	}
	// teams is always sent, [] when there are none (groups_claim needs it).
	if tm, ok := c["teams"].([]string); !ok || len(tm) != 0 {
		t.Errorf("teams = %#v, want []", c["teams"])
	}
	f.Actor = "x"
	// env without target: no target claims.
	c = Claims(f, "prod", "branch", selector.Target{}, nil, now)
	if c["env"] != "prod" || c["env_source"] != "branch" {
		t.Errorf("%v", c)
	}
	if _, ok := c["target"]; ok {
		t.Error("target present")
	}
}

func TestClaimsEightSegments(t *testing.T) {
	c := Claims(fullFacts(), "prod", "variable", target(t, "1/2/3/4/5/6/7/8"), nil, now)
	for i, s := range []string{"1", "2", "3", "4", "5", "6", "7", "8"} {
		k := "t" + string(rune('1'+i))
		if c[k] != s {
			t.Errorf("%s = %v", k, c[k])
		}
	}
	if c["target"] != "1/2/3/4/5/6/7/8" {
		t.Errorf("target = %v", c["target"])
	}
}

func TestClaimsHostileValuesEscaped(t *testing.T) {
	hostile := []string{"a/b", "a*b", "a+b", "a%2fb", ".hidden", "Main", "..", "rel/1/rc", "a b", "é"}
	for _, h := range hostile {
		f := fullFacts()
		f.Branch, f.Actor, f.Ref = h, h, "refs/heads/"+h
		team := identity.Esc("acme") + "/" + identity.Esc(h) // as the forge layer builds it
		c := Claims(f, "prod", "variable", target(t, "web"), []string{team}, now)
		for _, k := range []string{"branch", "actor", "ref"} {
			v, _ := c[k].(string)
			if strings.ContainsAny(v, "/*+") || strings.HasPrefix(v, ".") || v != strings.ToLower(v) {
				t.Errorf("%q: claim %s = %q is not escaped", h, k, v)
			}
		}
		if c["branch"] != identity.Esc(h) || c["actor"] != identity.Esc(h) || c["ref"] != identity.Esc("refs/heads/"+h) {
			t.Errorf("%q: %v %v %v", h, c["branch"], c["actor"], c["ref"])
		}
		teams := c["teams"].([]string)
		if len(teams) != 1 || strings.Count(teams[0], "/") != 1 || strings.ContainsAny(teams[0], "*+") {
			t.Errorf("%q: teams = %v", h, teams)
		}
	}
	// org/repo are escaped too.
	f := fullFacts()
	f.Org, f.Repo = "a b", ".r"
	c := Claims(f, "", "", selector.Target{}, nil, now)
	if c["org"] != "a%20b" || c["repo"] != "%2er" {
		t.Errorf("org/repo = %v %v", c["org"], c["repo"])
	}
}

func TestSub(t *testing.T) {
	base := Sub("acme", "mono", "prod", target(t, "web"), []string{"acme/a", "acme/b"})

	// Stable across everything that is not an input.
	f1, f2 := fullFacts(), fullFacts()
	f2.Actor, f2.Event, f2.Pipeline, f2.Branch = "someone-else", "push", "99", "other"
	tg, teams := target(t, "web"), []string{"acme/a", "acme/b"}
	s1 := Claims(f1, "prod", "variable", tg, teams, now)["sub"]
	s2 := Claims(f2, "prod", "branch", tg, teams, now.Add(time.Hour))["sub"]
	if s1 != base || s2 != base {
		t.Errorf("sub not stable: %v %v %v", base, s1, s2)
	}
	// Team order does not matter.
	if got := Sub("acme", "mono", "prod", tg, []string{"acme/b", "acme/a"}); got != base {
		t.Errorf("team order changed sub")
	}

	// Sensitive to every grant input.
	diffs := map[string]string{
		"env":       Sub("acme", "mono", "staging", tg, teams),
		"target":    Sub("acme", "mono", "prod", target(t, "web/api"), teams),
		"no target": Sub("acme", "mono", "prod", selector.Target{}, teams),
		"teams":     Sub("acme", "mono", "prod", tg, []string{"acme/a"}),
		"no teams":  Sub("acme", "mono", "prod", tg, nil),
		"org":       Sub("other", "mono", "prod", tg, teams),
		"repo":      Sub("acme", "other", "prod", tg, teams),
	}
	seen := map[string]string{base: "base"}
	for name, s := range diffs {
		if prev, dup := seen[s]; dup {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[s] = name
	}
	// Field boundaries are unambiguous.
	if Sub("ab", "c", "", selector.Target{}, nil) == Sub("a", "bc", "", selector.Target{}, nil) {
		t.Error("org/repo boundary ambiguous")
	}
	if !regexp.MustCompile(`^ib-[0-9a-f]{40}$`).MatchString(base) {
		t.Errorf("sub = %q", base)
	}
}

func TestDiscoveryClaims(t *testing.T) {
	c := DiscoveryClaims(fullFacts(), now)
	if tm, ok := c["teams"].([]string); !ok || len(tm) != 0 {
		t.Errorf("discovery teams = %#v, want []", c["teams"])
	}
	for _, k := range []string{"env", "env_source", "target", "t1"} {
		if _, ok := c[k]; ok {
			t.Errorf("discovery claim %s present", k)
		}
	}
	for _, k := range []string{"sub", "org", "repo", "repo_key", "branch", "branch_protected", "event", "actor"} {
		if _, ok := c[k]; !ok {
			t.Errorf("discovery claim %s missing", k)
		}
	}
	if c["sub"] != Sub("acme", "mono", "", selector.Target{}, nil) {
		t.Error("discovery sub is not the env-less sub")
	}
}

func TestClaimsEmptyTeamsEncodesAsArray(t *testing.T) {
	b, err := json.Marshal(DiscoveryClaims(fullFacts(), now))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"teams":[]`) {
		t.Errorf("teams not encoded as []: %s", b)
	}
}

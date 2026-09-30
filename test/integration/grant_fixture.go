//go:build integration

package integration

// Grant-model fixture (plan task 3.1): one OpenBao 2.7.0 dev instance with the
// voidstar plugin (mount vs/), KV v2 (kv/), the database engine on the compose
// Postgres, a jwt auth mount trusting a keypair generated at test start, the
// three level policies from levels.RenderPolicies, and helpers to write roles,
// views, level metadata, groups and database roles. Everything is fake data on
// a throwaway container.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/navistau/ironbark/internal/facts"
	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/jwtsign"
	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/selector"
)

const (
	grantAddr     = "http://127.0.0.1:8300"
	grantTemplate = "vs/data/pipelines/{repo}/{env}/{target...}"
)

// Grant is the shared grant-model fixture.
type Grant struct {
	Root     *api.Client
	Accessor string // jwt mount accessor
	Tmpl     grantcfg.Template
	Signer   *jwtsign.Signer
	Key      *rsa.PrivateKey
	PubPEM   string
}

var (
	grantOnce sync.Once
	grantFix  *Grant
	grantErr  error
)

// GetGrant provisions the fixture once per test binary.
func GetGrant(t *testing.T) *Grant {
	t.Helper()
	grantOnce.Do(func() { grantFix, grantErr = setupGrant() })
	if grantErr != nil {
		t.Fatalf("grant fixture: %v", grantErr)
	}
	return grantFix
}

func genKey() (*rsa.PrivateKey, []byte, string, error) {
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, "", err
	}
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, nil, "", err
	}
	return k, priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func setupGrant() (*Grant, error) {
	c, err := api.NewClient(&api.Config{Address: grantAddr})
	if err != nil {
		return nil, err
	}
	c.SetToken("root")
	g := &Grant{Root: c}
	if g.Tmpl, err = grantcfg.ParseTemplate(grantTemplate); err != nil {
		return nil, err
	}
	var priv []byte
	if g.Key, priv, g.PubPEM, err = genKey(); err != nil {
		return nil, err
	}
	if g.Signer, err = jwtsign.LoadKey(priv); err != nil {
		return nil, err
	}
	for i := 0; ; i++ {
		if h, err := c.Sys().Health(); err == nil && !h.Sealed {
			break
		}
		if i > 60 {
			return nil, fmt.Errorf("openbao at %s not healthy", grantAddr)
		}
		time.Sleep(time.Second)
	}
	bin, err := os.ReadFile("plugins/openbao-plugin-secrets-voidstar")
	if err != nil {
		return nil, fmt.Errorf("voidstar plugin missing (run build-voidstar.sh): %w", err)
	}
	sum := sha256.Sum256(bin)
	steps := []struct {
		path string
		body map[string]any
	}{
		{"sys/plugins/catalog/secret/vs", map[string]any{"sha256": hex.EncodeToString(sum[:]), "command": "openbao-plugin-secrets-voidstar"}},
		{"sys/mounts/vs", map[string]any{"type": "vs"}},
		{"sys/mounts/kv", map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}},
		{"sys/mounts/database", map[string]any{"type": "database"}},
		{"sys/auth/approle", map[string]any{"type": "approle"}},
		{"sys/auth/jwt", map[string]any{"type": "jwt"}},
		{"sys/policies/acl/voidstar-loopback", map[string]any{"policy": `path "kv/data/*" { capabilities = ["read"] }`}},
		{"auth/approle/role/voidstar-loopback", map[string]any{"token_policies": "voidstar-loopback", "secret_id_num_uses": 0, "secret_id_ttl": 0}},
		{"database/config/pg", map[string]any{
			"plugin_name": "postgresql-database-plugin", "allowed_roles": "*",
			"connection_url": "postgresql://{{username}}:{{password}}@postgres:5432/postgres?sslmode=disable",
			"username":       "vaultadmin", "password": "vaultpw"}},
		{"auth/jwt/config", map[string]any{"bound_issuer": jwtsign.Issuer, "jwt_validation_pubkeys": g.PubPEM}},
	}
	for _, s := range steps {
		// Mounts already in use: the container outlived an earlier test binary.
		if _, err := c.Logical().Write(s.path, s.body); err != nil && !strings.Contains(err.Error(), "already in use") {
			return nil, fmt.Errorf("write %s: %w", s.path, err)
		}
	}
	rid, err := c.Logical().Read("auth/approle/role/voidstar-loopback/role-id")
	if err != nil {
		return nil, err
	}
	sid, err := c.Logical().Write("auth/approle/role/voidstar-loopback/secret-id", nil)
	if err != nil {
		return nil, err
	}
	if _, err := c.Logical().Write("vs/admin/config", map[string]any{
		"role_id": rid.Data["role_id"], "secret_id": sid.Data["secret_id"], "api_addr": "http://127.0.0.1:8200"}); err != nil {
		return nil, err
	}
	auths, err := c.Sys().ListAuth()
	if err != nil {
		return nil, err
	}
	g.Accessor = auths["jwt/"].Accessor
	project, env, target := levels.RenderPolicies(g.Tmpl, g.Accessor)
	dyn := "path \"database/creds/{{identity.entity.aliases." + g.Accessor + ".metadata.env}}\" { capabilities = [\"read\"] }\n" +
		"path \"database/creds/{{identity.entity.aliases." + g.Accessor + ".metadata.env}}-{{identity.entity.aliases." + g.Accessor + ".metadata.t1}}\" { capabilities = [\"read\"] }\n"
	for name, rules := range map[string]string{"ci-project": project, "ci-env": env, "ci-target": target, "ci-dynamic": dyn} {
		if err := c.Sys().PutPolicy(name, rules); err != nil {
			return nil, fmt.Errorf("policy %s: %w", name, err)
		}
	}
	return g, nil
}

// Write writes body at path as root and fails the test on error.
func (g *Grant) Write(t *testing.T, path string, body map[string]any) {
	t.Helper()
	if _, err := g.Root.Logical().Write(path, body); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Role writes a jwt auth role. Defaults are the §5.5 token contract; over
// overrides or extends the body (a nil value deletes the default).
func (g *Grant) Role(t *testing.T, name string, boundClaims map[string]any, policies []string, over map[string]any) {
	t.Helper()
	body := map[string]any{
		"role_type": "jwt", "user_claim": "sub", "bound_audiences": []string{jwtsign.Audience},
		"bound_claims_type": "glob", "bound_claims": boundClaims,
		"claim_mappings": map[string]string{"org": "org", "repo": "repo", "env": "env",
			"t1": "t1", "t2": "t2", "t3": "t3", "t4": "t4", "t5": "t5", "t6": "t6", "t7": "t7", "t8": "t8"},
		"token_policies": policies, "token_type": "service", "token_ttl": "15m", "token_explicit_max_ttl": "15m",
	}
	for k, v := range over {
		if v == nil {
			delete(body, k)
		} else {
			body[k] = v
		}
	}
	g.Write(t, "auth/jwt/role/"+name, body)
}

// KV writes a KV v2 secret under kv/ (an upstream a fetch view points at).
func (g *Grant) KV(t *testing.T, path string, data map[string]any) {
	t.Helper()
	g.Write(t, "kv/data/"+path, map[string]any{"data": data})
}

// View writes a voidstar mapping (admin/map/<view>).
func (g *Grant) View(t *testing.T, view string, m map[string]any) {
	t.Helper()
	g.Write(t, "vs/admin/map/"+view, m)
}

// Level writes level metadata (admin/level/<prefix>).
func (g *Grant) Level(t *testing.T, prefix string, md map[string]string) {
	t.Helper()
	g.Write(t, "vs/admin/level/"+prefix, map[string]any{"custom_metadata": md})
}

// Group creates an external group carrying policies, with one alias name on
// the jwt mount (the value a `teams` claim entry must equal).
func (g *Grant) Group(t *testing.T, name string, policies []string, alias string) {
	t.Helper()
	r, err := g.Root.Logical().Write("identity/group", map[string]any{"name": name, "type": "external", "policies": policies})
	if err != nil {
		t.Fatalf("group %s: %v", name, err)
	}
	g.Write(t, "identity/group-alias", map[string]any{"name": alias, "mount_accessor": g.Accessor, "canonical_id": r.Data["id"]})
}

// DBRole writes a database role named name (the <env>-<t1> convention).
func (g *Grant) DBRole(t *testing.T, name string) {
	t.Helper()
	g.Write(t, "database/roles/"+name, map[string]any{
		"db_name": "pg", "default_ttl": "1h", "max_ttl": "1h",
		"creation_statements": `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';`})
}

// Req describes one pipeline's facts for a login.
type Req struct {
	Org, Repo, ID string // ID is the forge remote id
	Event, Branch string
	Protected     string // "true"/"false"; "" defaults to "true" when Branch is set
	Actor         string
	Env, Source   string
	Target        string // slash-joined, as the operator writes it
	Teams         []string
	Pipeline      string
}

// Claims builds the §5.2 claim set for r through jwtsign.
func (g *Grant) Claims(r Req) map[string]any {
	f := facts.Facts{Org: r.Org, Repo: r.Repo, RepoKey: fmt.Sprintf("%s/%s#%s", r.Org, r.Repo, r.ID),
		Event: r.Event, Actor: r.Actor, Pipeline: r.Pipeline}
	if f.Event == "" {
		f.Event = "push"
	}
	if f.Pipeline == "" {
		f.Pipeline = "1"
	}
	if r.Branch != "" {
		f.Branch, f.Ref = r.Branch, "refs/heads/"+r.Branch
		f.BranchProtected = r.Protected
		if f.BranchProtected == "" {
			f.BranchProtected = "true"
		}
	}
	var tgt selector.Target
	if r.Target != "" {
		tgt, _ = selector.ParseTarget(r.Target)
	}
	return jwtsign.Claims(f, r.Env, r.Source, tgt, r.Teams, time.Now())
}

// JWT signs the claims for r.
func (g *Grant) JWT(t *testing.T, r Req) string {
	t.Helper()
	s, err := g.Signer.Sign(g.Claims(r))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// LoginRaw logs in with the raw API and returns the client token.
func (g *Grant) LoginRaw(role, jwt string) (string, error) {
	c, err := g.Root.Clone()
	if err != nil {
		return "", err
	}
	c.SetToken("")
	s, err := c.Logical().Write("auth/jwt/login", map[string]any{"role": role, "jwt": jwt})
	if err != nil {
		return "", err
	}
	return s.Auth.ClientToken, nil
}

// As returns a client authenticated with token.
func (g *Grant) As(token string) *api.Client {
	c, _ := g.Root.Clone()
	c.SetToken(token)
	return c
}

// Code reads path with token and returns the HTTP status (0 on transport error).
func (g *Grant) Code(token, path string) int {
	_, err := g.As(token).Logical().Read(path)
	if err == nil {
		return 200
	}
	if re, ok := err.(*api.ResponseError); ok {
		return re.StatusCode
	}
	return 0
}

// CodeList is Code for LIST.
func (g *Grant) CodeList(token, path string) int {
	_, err := g.As(token).Logical().List(path)
	if err == nil {
		return 200
	}
	if re, ok := err.(*api.ResponseError); ok {
		return re.StatusCode
	}
	return 0
}

// Esc-safe helper for tests that need repo names unique per test.
func uniq(prefix string) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(prefix) + hex.EncodeToString(b[:])
}

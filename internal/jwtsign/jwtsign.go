// Package jwtsign builds and signs the JWT ironbark presents to OpenBao's JWT
// auth backend (design §5): RS256 with the standard library only.
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
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/navistau/ironbark/internal/facts"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/selector"
)

const (
	minKeyBits = 3072
	// Audience and issuer are fixed (§5.2): the mount's bound_issuer and the
	// role's bound_audiences.
	Issuer   = "ironbark"
	Audience = "ironbark"
	lifetime = 60 * time.Second
)

// Signer signs RS256 JWTs with one RSA key.
type Signer struct {
	key *rsa.PrivateKey
	kid string
}

// LoadKey parses a PEM RSA private key (PKCS#1 or PKCS#8), refusing keys under
// 3072 bits. kid is the hex SHA-256 of the public key's PKIX DER (§5.1).
func LoadKey(pemBytes []byte) (*Signer, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(string(pemBytes))))
	if block == nil {
		return nil, errors.New("jwtsign: signing key is not PEM")
	}
	var k *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		var err error
		if k, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("jwtsign: parse PKCS#1 key: %w", err)
		}
	case "PRIVATE KEY":
		v, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("jwtsign: parse PKCS#8 key: %w", err)
		}
		var ok bool
		if k, ok = v.(*rsa.PrivateKey); !ok {
			return nil, errors.New("jwtsign: signing key is not RSA")
		}
	default:
		return nil, fmt.Errorf("jwtsign: unsupported PEM block %q", block.Type)
	}
	if bits := k.N.BitLen(); bits < minKeyBits {
		return nil, fmt.Errorf("jwtsign: RSA key is %d bits, need at least %d", bits, minKeyBits)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("jwtsign: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return &Signer{key: k, kid: hex.EncodeToString(sum[:])}, nil
}

// KID is the key id placed in the JWT header, for correlation only.
func (s *Signer) KID() string { return s.kid }

// Sign returns the compact RS256 JWS of claims.
func (s *Signer) Sign(claims map[string]any) (string, error) {
	hdr, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.kid})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signed := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signed + "." + enc.EncodeToString(sig), nil
}

// Claims builds the claim set of design §5.2. Absent facts are omitted, never
// sent empty, except teams: it is always sent (possibly []), because OpenBao
// refuses a login on a role with groups_claim when the claim is missing.
// teams are already esc(org)/esc(team) (forge.QualifiedTeams) and are sent as
// given, sorted. env "" means no environment (and then no
// env_source, target or t1..t8).
func Claims(f facts.Facts, env, envSource string, t selector.Target, teams []string, now time.Time) map[string]any {
	org, repo := identity.Esc(f.Org), identity.Esc(f.Repo)
	iat := now.Unix()
	c := map[string]any{
		"iss": Issuer, "aud": Audience,
		"sub": Sub(org, repo, env, t, teams),
		"iat": iat, "nbf": iat, "exp": iat + int64(lifetime/time.Second),
		"jti":      jti(),
		"org":      org,
		"repo":     repo,
		"repo_key": f.RepoKey,
		"event":    f.Event,
		"pipeline": f.Pipeline,
	}
	set := func(k, v string) {
		if v != "" {
			c[k] = v
		}
	}
	if f.Branch != "" {
		c["branch"] = identity.Esc(f.Branch)
		set("ref", identity.Esc(f.Ref))
		set("branch_protected", f.BranchProtected)
	}
	if f.Actor != "" {
		c["actor"] = identity.Esc(f.Actor)
	}
	c["teams"] = sortedCopy(teams)
	if env != "" {
		c["env"] = env
		set("env_source", envSource)
		if len(t.Escaped) > 0 {
			c["target"] = t.Joined()
			for i, seg := range t.Escaped {
				c["t"+strconv.Itoa(i+1)] = seg
			}
		}
	}
	return c
}

// DiscoveryClaims is the reduced claim set of the discovery login (§9.1
// step 4): no env, no target, teams [].
func DiscoveryClaims(f facts.Facts, now time.Time) map[string]any {
	return Claims(f, "", "", selector.Target{}, nil, now)
}

// Sub derives the entity-alias key (§5.4). org and repo are the escaped
// claim values. Only inputs that feed alias metadata or group membership are
// hashed, so actor, event, branch and pipeline never change it.
func Sub(org, repo, env string, t selector.Target, teams []string) string {
	// An env-less login carries no target (Claims omits it), so the hash must
	// not see one either.
	target := ""
	if env != "" {
		target = t.Joined()
	}
	sum := sha256.Sum256([]byte(org + "\n" + repo + "\n" + env + "\n" + target + "\n" + strings.Join(sortedCopy(teams), ",")))
	return "ib-" + hex.EncodeToString(sum[:])[:40]
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func jti() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("jwtsign: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

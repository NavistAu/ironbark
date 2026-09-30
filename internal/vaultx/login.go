package vaultx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// Conn is an unauthenticated connection to OpenBao. ironbark holds no OpenBao
// credential (design §5.1): every call carries the token it is given, and the
// signed JWT is the only credential ever presented.
type Conn struct {
	api *api.Client
}

// NewConn builds a Conn for addr. tls may be nil.
func NewConn(addr string, tls *api.TLSConfig) (*Conn, error) {
	cfg := api.DefaultConfig()
	cfg.Address = addr
	if tls != nil {
		if err := cfg.ConfigureTLS(tls); err != nil {
			return nil, fmt.Errorf("vaultx: tls: %w", err)
		}
	}
	c, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vaultx: new client: %w", err)
	}
	c.ClearToken()
	return &Conn{api: c}, nil
}

// Token is a pipeline token from a successful login.
type Token struct {
	Value    string
	Accessor string
	TTL      time.Duration
}

// RefusedError means OpenBao refused the login by role configuration: the
// role does not exist, or the claims fail its bound_claims. Nothing is wrong
// with ironbark or the transport; the run simply may not act here.
type RefusedError struct{ Msg string }

func (e *RefusedError) Error() string { return "vaultx: login refused: " + e.Msg }

// AssertionError means the login succeeded but the token breaks the §5.5
// contract (service, orphan, explicit max TTL). The token has been revoked.
type AssertionError struct{ Role, Reason, Accessor string }

func (e *AssertionError) Error() string {
	return fmt.Sprintf("vaultx: role %q token contract violated: %s", e.Role, e.Reason)
}

// LoginJWT is POST auth/<mount>/login (design §5.5). A missing role or a bound
// claim mismatch is a *RefusedError; a bad signature, expiry or transport
// failure is a plain error. On success the §5.5 assertions run and any
// violation revokes the token and returns an *AssertionError.
func (c *Conn) LoginJWT(ctx context.Context, mount, role, jwt string) (Token, error) {
	req := c.api.NewRequest(http.MethodPost, "/v1/auth/"+strings.Trim(mount, "/")+"/login")
	if err := req.SetJSONBody(map[string]string{"role": role, "jwt": jwt}); err != nil {
		return Token{}, err
	}
	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		var re *api.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusBadRequest {
			for _, e := range re.Errors {
				if strings.Contains(e, "could not be found") || strings.Contains(e, "error validating claims") {
					return Token{}, &RefusedError{Msg: e}
				}
			}
		}
		return Token{}, fmt.Errorf("vaultx: login as %q: %w", role, err)
	}
	defer resp.Body.Close()
	var parsed struct {
		Auth *struct {
			ClientToken   string `json:"client_token"`
			Accessor      string `json:"accessor"`
			LeaseDuration int    `json:"lease_duration"`
			TokenType     string `json:"token_type"`
			Orphan        bool   `json:"orphan"`
		} `json:"auth"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil || parsed.Auth == nil || parsed.Auth.ClientToken == "" {
		return Token{}, fmt.Errorf("vaultx: login as %q: response has no auth", role)
	}
	a := parsed.Auth
	tok := Token{Value: a.ClientToken, Accessor: a.Accessor, TTL: time.Duration(a.LeaseDuration) * time.Second}

	reason := ""
	switch {
	case a.TokenType != "service":
		reason = fmt.Sprintf("token_type is %q, want service", a.TokenType)
	case !a.Orphan:
		reason = "token is not an orphan"
	default:
		max, err := c.explicitMaxTTL(ctx, tok.Value)
		if err != nil {
			_ = c.RevokeSelf(ctx, tok.Value)
			return Token{}, fmt.Errorf("vaultx: login as %q: lookup-self: %w", role, err)
		}
		if max <= 0 {
			reason = "explicit_max_ttl is not set"
		}
	}
	if reason != "" {
		_ = c.RevokeSelf(ctx, tok.Value)
		return Token{}, &AssertionError{Role: role, Reason: reason, Accessor: tok.Accessor}
	}
	return tok, nil
}

func (c *Conn) explicitMaxTTL(ctx context.Context, token string) (int64, error) {
	req := c.api.NewRequest(http.MethodGet, "/v1/auth/token/lookup-self")
	req.ClientToken = token
	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var parsed struct {
		Data struct {
			ExplicitMaxTTL json.Number `json:"explicit_max_ttl"`
		} `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return 0, err
	}
	n, _ := parsed.Data.ExplicitMaxTTL.Int64()
	return n, nil
}

// RevokeSelf is POST auth/token/revoke-self as token; leases it parents go
// with it.
func (c *Conn) RevokeSelf(ctx context.Context, token string) error {
	req := c.api.NewRequest(http.MethodPost, "/v1/auth/token/revoke-self")
	req.ClientToken = token
	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("vaultx: revoke-self: %w", err)
	}
	return resp.Body.Close()
}

// Healthy reports whether OpenBao answers sys/health as initialised and
// unsealed (200; standbyok makes a standby answer 200 too). It is /readyz's
// only signal: ironbark holds no session to keep alive. No retries: a probe
// must answer promptly.
func (c *Conn) Healthy(ctx context.Context) bool {
	cl, err := c.api.Clone()
	if err != nil {
		return false
	}
	cl.SetMaxRetries(0)
	req := cl.NewRequest(http.MethodGet, "/v1/sys/health")
	req.Params.Set("standbyok", "true")
	resp, err := cl.RawRequestWithContext(ctx, req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return err == nil && resp.StatusCode == http.StatusOK
}

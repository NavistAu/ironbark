// This file (Task 8) owns minting and revocation: MintToken (SPEC §3.2)
// and RevokeSelf (SPEC §3.4). canary.go builds the SPEC §3.5 startup
// canary on top of both.
package vaultx

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Mint is the result of a successful mint (SPEC §3.2): the token and its
// properties exactly as Vault/OpenBao reported them, not reconstructed
// from the request — the token role, not the request, governs
// TTL/type/orphan (SPEC §3.2, §3.3).
type Mint struct {
	Token     string
	Accessor  string
	TokenType string
	TTL       time.Duration
	Renewable bool
	// Orphan is nil when the mint response's auth block omits "orphan"
	// (SPEC §3.5 cycle-2 G2-3: exposure unverified either way — the
	// canary skips that assertion in that case, and the integration test
	// is the definitive orphan check regardless).
	Orphan   *bool
	Warnings []string
}

// mintAuthResponse mirrors the auth/token/create response's "auth" block.
// api.SecretAuth (the vault/api SDK's typed struct) does not expose
// token_type at all and exposes orphan as a plain bool (no way to detect
// omission), so the mint response is decoded into this ironbark-local
// struct instead of api.Secret/api.SecretAuth.
type mintAuthResponse struct {
	ClientToken   string `json:"client_token"`
	Accessor      string `json:"accessor"`
	TokenType     string `json:"token_type"`
	Renewable     bool   `json:"renewable"`
	Orphan        *bool  `json:"orphan"`
	LeaseDuration int    `json:"lease_duration"`
}

type mintResponse struct {
	Warnings []string          `json:"warnings"`
	Auth     *mintAuthResponse `json:"auth"`
}

// MintToken performs POST auth/token/create/<TokenRole> (SPEC §3.2),
// authenticated as ironbark's own AppRole session token (c.api's default
// token). Only policies, meta, and display_name are sent — ttl,
// num_uses, and type are deliberately omitted so the token role config
// governs them (SPEC §3.2, R§7.4: num_uses is unsuitable for ironbark's
// tokens; every API request routed with a token consumes a use).
func (c *Client) MintToken(ctx context.Context, policies []string, meta map[string]string, displayName string) (Mint, error) {
	req := c.api.NewRequest(http.MethodPost, "/v1/auth/token/create/"+c.cfg.TokenRole)
	if err := req.SetJSONBody(map[string]interface{}{
		"policies":     policies,
		"meta":         meta,
		"display_name": displayName,
	}); err != nil {
		return Mint{}, fmt.Errorf("vaultx: mint: encode request: %w", err)
	}

	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		return Mint{}, fmt.Errorf("vaultx: mint: %w", err)
	}
	defer resp.Body.Close()

	var parsed mintResponse
	if err := resp.DecodeJSON(&parsed); err != nil {
		return Mint{}, fmt.Errorf("vaultx: mint: decode response: %w", err)
	}
	if parsed.Auth == nil || parsed.Auth.ClientToken == "" {
		return Mint{}, fmt.Errorf("vaultx: mint: response has no auth")
	}

	return Mint{
		Token:     parsed.Auth.ClientToken,
		Accessor:  parsed.Auth.Accessor,
		TokenType: parsed.Auth.TokenType,
		TTL:       time.Duration(parsed.Auth.LeaseDuration) * time.Second,
		Renewable: parsed.Auth.Renewable,
		Orphan:    parsed.Auth.Orphan,
		Warnings:  parsed.Warnings,
	}, nil
}

// RevokeSelf performs POST auth/token/revoke-self (SPEC §3.4)
// authenticated AS token — the minted pipeline/canary token, NOT
// ironbark's own AppRole session token. c.api.NewRequest defaults
// ClientToken to c.api's own token; overriding it on this one *Request
// value (never on c.api itself) sends the minted token as X-Vault-Token
// for this call only, leaving ironbark's own session token on c.api
// untouched for every other call.
func (c *Client) RevokeSelf(ctx context.Context, token string) error {
	req := c.api.NewRequest(http.MethodPost, "/v1/auth/token/revoke-self")
	req.ClientToken = token

	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("vaultx: revoke-self: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

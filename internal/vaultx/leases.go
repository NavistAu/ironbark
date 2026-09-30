// This file owns lease revocation for callers that hold no minted
// pipeline token to cascade-revoke from — CLIENT-SPEC §1.4's `ib run`,
// which revokes the leases it used directly, authenticated as the
// caller's own token.
package vaultx

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
)

// RevokeLeases revokes each lease in ids via PUT sys/leases/revoke
// (CLIENT-SPEC §1.4), authenticated as token — the caller's own token,
// never c.api's own default (ironbark's AppRole session) token, and never
// auth/token/revoke-self, which would revoke the caller's actual Vault
// session rather than a lease. Every ID is attempted regardless of
// earlier failures; the returned slice holds one error per failed ID (in
// the order encountered), or nil when every revoke succeeds.
func (c *Client) RevokeLeases(ctx context.Context, token string, ids []string) []error {
	var errs []error
	for _, id := range ids {
		req := c.api.NewRequest(http.MethodPut, "/v1/sys/leases/revoke")
		req.ClientToken = token
		if err := req.SetJSONBody(map[string]interface{}{"lease_id": id}); err != nil {
			errs = append(errs, fmt.Errorf("vaultx: revoke lease %s: encode request: %w", id, err))
			continue
		}

		resp, err := c.api.RawRequestWithContext(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("vaultx: revoke lease %s: %w", id, err))
			continue
		}
		resp.Body.Close()
	}
	return errs
}

// ErrTokenRejected is returned by CheckToken when Vault answers 403 to the
// token's own lookup-self: the token is expired, revoked or invalid.
var ErrTokenRejected = errors.New("vaultx: token rejected by Vault")

// CheckToken asks Vault to look up token itself (auth/token/lookup-self,
// which every token may call). A 403 means the token is no good
// (ErrTokenRejected); 404 is treated as fine (a Vault without the route
// cannot tell us otherwise), and any other failure is a plain error.
func (c *Client) CheckToken(ctx context.Context, token string) error {
	req := c.api.NewRequest(http.MethodGet, "/v1/auth/token/lookup-self")
	req.ClientToken = token
	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		var respErr *api.ResponseError
		if errors.As(err, &respErr) {
			switch respErr.StatusCode {
			case http.StatusForbidden:
				return ErrTokenRejected
			case http.StatusNotFound:
				return nil
			}
		}
		return fmt.Errorf("vaultx: lookup-self: %w", err)
	}
	resp.Body.Close()
	return nil
}

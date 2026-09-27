// This file owns lease revocation for callers that hold no minted
// pipeline token to cascade-revoke from — CLIENT-SPEC §1.4's `ib run`,
// which revokes the leases it used directly, authenticated as the
// caller's own token.
package vaultx

import (
	"context"
	"fmt"
	"net/http"
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

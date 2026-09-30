package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/vaultx"
	"github.com/navistau/ironbark/internal/walk"
)

// errTokenRejected means OpenBao answered 403 to the token's own lookup-self:
// it is expired, revoked or invalid.
var errTokenRejected = errors.New("token rejected by Vault")

// leaseAPI is the two calls ib makes outside the walk, both as the caller's
// own token: revoking the leases a walk took (CLIENT-SPEC §1.4), and asking
// OpenBao whether the token itself is any good.
type leaseAPI struct {
	api   *api.Client
	token string
}

// newVault builds the walk client and lease API for one caller token.
func newVault(addr string, tls *api.TLSConfig, token string) (walk.Client, *leaseAPI, error) {
	conn, err := vaultx.NewConn(addr, tls)
	if err != nil {
		return nil, nil, err
	}
	cfg := api.DefaultConfig()
	cfg.Address = addr
	if tls != nil {
		if err := cfg.ConfigureTLS(tls); err != nil {
			return nil, nil, err
		}
	}
	c, err := api.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}
	c.ClearToken()
	return conn.As(token), &leaseAPI{api: c, token: token}, nil
}

// Revoke revokes each lease with PUT sys/leases/revoke. Every id is tried;
// the result holds one error per failure.
func (l *leaseAPI) Revoke(ctx context.Context, ids []string) []error {
	var errs []error
	for _, id := range ids {
		req := l.api.NewRequest(http.MethodPut, "/v1/sys/leases/revoke")
		req.ClientToken = l.token
		if err := req.SetJSONBody(map[string]interface{}{"lease_id": id}); err != nil {
			errs = append(errs, fmt.Errorf("revoke lease %s: %w", id, err))
			continue
		}
		resp, err := l.api.RawRequestWithContext(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("revoke lease %s: %w", id, err))
			continue
		}
		resp.Body.Close()
	}
	return errs
}

// CheckToken looks the token up. 403 is errTokenRejected; 404 is treated as
// fine.
func (l *leaseAPI) CheckToken(ctx context.Context) error {
	req := l.api.NewRequest(http.MethodGet, "/v1/auth/token/lookup-self")
	req.ClientToken = l.token
	resp, err := l.api.RawRequestWithContext(ctx, req)
	if err != nil {
		var re *api.ResponseError
		if errors.As(err, &re) {
			switch re.StatusCode {
			case http.StatusForbidden:
				return errTokenRejected
			case http.StatusNotFound:
				return nil
			}
		}
		return fmt.Errorf("lookup-self: %w", err)
	}
	resp.Body.Close()
	return nil
}

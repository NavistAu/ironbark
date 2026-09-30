package vaultx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/vault/api"
)

// ErrForbidden and ErrNotFound classify a 403 and a 404. The walk skips both
// (design §8.2); every other failure is a plain error.
var (
	ErrForbidden = errors.New("permission denied")
	ErrNotFound  = errors.New("not found")
)

// Secret is the part of a read response the walk uses. Data is the response's
// top-level "data" object: for a voidstar or KV v2 view it holds "data",
// "metadata" and (voidstar) "voidstar"; for a dynamic engine it is the flat
// credential.
type Secret struct {
	LeaseID string
	Data    map[string]json.RawMessage
}

// newReq is api.NewRequest that keeps a trailing slash: the client cleans the
// path, but level metadata is addressed by the slash (design §8.1).
func (c *Conn) newReq(method, path string) *api.Request {
	req := c.api.NewRequest(method, "/v1/"+path)
	if strings.HasSuffix(path, "/") && !strings.HasSuffix(req.URL.Path, "/") {
		req.URL.Path += "/"
	}
	return req
}

func classify(err error, what string) error {
	var re *api.ResponseError
	if errors.As(err, &re) {
		switch re.StatusCode {
		case http.StatusForbidden:
			return fmt.Errorf("%s: %w", what, ErrForbidden)
		case http.StatusNotFound:
			return fmt.Errorf("%s: %w", what, ErrNotFound)
		}
	}
	return fmt.Errorf("vaultx: %s: %w", what, err)
}

// Read is GET path as token.
func (c *Conn) Read(ctx context.Context, token, path string) (*Secret, error) {
	req := c.newReq(http.MethodGet, path)
	req.ClientToken = token
	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, classify(err, "GET "+path)
	}
	defer resp.Body.Close()
	var parsed struct {
		LeaseID string                     `json:"lease_id"`
		Data    map[string]json.RawMessage `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return nil, fmt.Errorf("vaultx: GET %s: decode: %w", path, err)
	}
	return &Secret{LeaseID: parsed.LeaseID, Data: parsed.Data}, nil
}

// List is LIST path as token, returning the keys (directories end in "/").
func (c *Conn) List(ctx context.Context, token, path string) ([]string, error) {
	req := c.newReq("LIST", path)
	req.ClientToken = token
	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, classify(err, "LIST "+path)
	}
	defer resp.Body.Close()
	var parsed struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return nil, fmt.Errorf("vaultx: LIST %s: decode: %w", path, err)
	}
	return parsed.Data.Keys, nil
}

// ReadLevelMetadata reads a level's own custom_metadata: GET on its metadata
// path with a trailing slash (design §8.1). 200 gives the map; 404 means the
// level has none (found=false, no error); 403 or anything else is an error.
func (c *Conn) ReadLevelMetadata(ctx context.Context, token, path string) (md map[string]string, found bool, err error) {
	req := c.newReq(http.MethodGet, path)
	req.ClientToken = token
	resp, err := c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		if e := classify(err, "GET "+path); errors.Is(e, ErrNotFound) {
			return nil, false, nil
		} else {
			return nil, false, e
		}
	}
	defer resp.Body.Close()
	var parsed struct {
		Data struct {
			CustomMetadata map[string]string `json:"custom_metadata"`
		} `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return nil, false, fmt.Errorf("vaultx: GET %s: decode: %w", path, err)
	}
	return parsed.Data.CustomMetadata, true, nil
}

// Session is a Conn bound to one pipeline token: the client the walk reads
// through.
type Session struct {
	c     *Conn
	token string
}

// As binds token to the connection.
func (c *Conn) As(token string) *Session { return &Session{c: c, token: token} }

func (s *Session) Token() string { return s.token }
func (s *Session) Read(ctx context.Context, path string) (*Secret, error) {
	return s.c.Read(ctx, s.token, path)
}
func (s *Session) List(ctx context.Context, path string) ([]string, error) {
	return s.c.List(ctx, s.token, path)
}
func (s *Session) LevelMetadata(ctx context.Context, path string) (map[string]string, bool, error) {
	return s.c.ReadLevelMetadata(ctx, s.token, path)
}

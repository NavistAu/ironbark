package main

// A minimal fake Vault HTTP server for cmd/ib's own tests. Mirrors
// internal/vaultx/sweep_test.go's fakeKV (unexported there, so not
// importable across the package boundary): per-path programmable
// status/body, keyed on the literal request path, plus a recorder for
// PUT sys/leases/revoke calls.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

type fakeVault struct {
	mu        sync.Mutex
	responses map[string]fakeVaultResp
	revokes   []string
}

type fakeVaultResp struct {
	status int
	body   string
}

func newFakeVault() *fakeVault {
	return &fakeVault{responses: make(map[string]fakeVaultResp)}
}

func (f *fakeVault) set(path string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[path] = fakeVaultResp{status: status, body: body}
}

func (f *fakeVault) revokedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revokes...)
}

func (f *fakeVault) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/sys/leases/revoke" {
			var body struct {
				LeaseID string `json:"lease_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.revokes = append(f.revokes, body.LeaseID)
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}

		f.mu.Lock()
		resp, ok := f.responses[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errors":[]}`)
			return
		}
		w.WriteHeader(resp.status)
		fmt.Fprint(w, resp.body)
	}
}

// --- wire-shape body builders (mirror internal/vaultx/sweep.go's decode structs) ---

func listBody(keys []string) string {
	var wire struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	wire.Data.Keys = keys
	b, _ := json.Marshal(wire)
	return string(b)
}

func entryBody(fields map[string]interface{}, customMeta map[string]string) string {
	var wire struct {
		Data struct {
			Data     map[string]interface{} `json:"data"`
			Metadata struct {
				CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
			} `json:"metadata"`
		} `json:"data"`
	}
	wire.Data.Data = fields
	wire.Data.Metadata.CustomMetadata = customMeta
	b, _ := json.Marshal(wire)
	return string(b)
}

// derefBody builds a flat (non-KV2-shaped) dereference-target response —
// the dynamic-engine shape (e.g. database/creds/*) — with a lease_id.
func derefBody(fields map[string]interface{}, leaseID string) string {
	var wire struct {
		LeaseID string                 `json:"lease_id,omitempty"`
		Data    map[string]interface{} `json:"data"`
	}
	wire.LeaseID = leaseID
	wire.Data = fields
	b, _ := json.Marshal(wire)
	return string(b)
}

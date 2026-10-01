package main

// A minimal fake Vault HTTP server for cmd/ib's own tests. Mirrors
// internal/vaultx/sweep_test.go's fakeKV (unexported there, so not
// importable across the package boundary): per-path programmable
// status/body, keyed on the literal request path (a LIST under "LIST "; a level
// entry's metadata read has none), plus a recorder for PUT sys/leases/revoke calls.

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

// setList programs the LIST of a mount-relative path (a request path and its level-metadata
// GET share the trailing-slash path, so they are keyed apart).
func (f *fakeVault) setList(path string, keys ...string) {
	f.set("LIST /v1/"+path, 200, listBody(keys))
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

		key := r.URL.Path
		if r.Method == "LIST" || r.URL.Query().Get("list") == "true" {
			key = "LIST " + key
		}
		f.mu.Lock()
		resp, ok := f.responses[key]
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

// levelMetaBody is a level-entry read: GET on a metadata path (no
// trailing slash).
func levelMetaBody(custom map[string]string) string {
	b, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{"custom_metadata": custom}})
	return string(b)
}

// resolveBody is a voidstar view in mode=resolve pointing at target, with the
// mapping's custom_metadata.
func resolveBody(target string, customMeta map[string]string) string {
	b, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{
		"data":     map[string]interface{}{},
		"metadata": map[string]interface{}{"custom_metadata": customMeta},
		"voidstar": map[string]interface{}{"mode": "resolve", "path": target},
	}})
	return string(b)
}

// markerBody is a metadata-only view (the vault_token marker).
func markerBody() string {
	b, _ := json.Marshal(map[string]interface{}{"data": map[string]interface{}{
		"data":     map[string]interface{}{},
		"metadata": map[string]interface{}{"custom_metadata": map[string]string{}},
		"voidstar": map[string]interface{}{"mode": "metadata"},
	}})
	return string(b)
}

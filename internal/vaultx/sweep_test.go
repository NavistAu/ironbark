package vaultx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/navistau/ironbark/internal/identity"
)

// fakeKV fakes just enough of a KV v2 mount (plus arbitrary "any mount"
// deref targets) for the SPEC §4 sweep/deref/directive reads: per-path
// programmable status/body, and call-counted + token-recorded requests so
// tests can assert exactly which paths were hit, how many times, and with
// which X-Vault-Token (SPEC §4.1: sweep reads must authenticate as the
// minted token, never ironbark's own session token).
type fakeKV struct {
	mu        sync.Mutex
	calls     map[string]int
	lastToken map[string]string
	responses map[string]fakeKVResp
}

type fakeKVResp struct {
	status int
	body   string
}

func newFakeKV() *fakeKV {
	return &fakeKV{
		calls:     make(map[string]int),
		lastToken: make(map[string]string),
		responses: make(map[string]fakeKVResp),
	}
}

func (f *fakeKV) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls[r.URL.Path]++
		f.lastToken[r.URL.Path] = r.Header.Get("X-Vault-Token")
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

func (f *fakeKV) set(path string, status int, body string) {
	f.mu.Lock()
	f.responses[path] = fakeKVResp{status: status, body: body}
	f.mu.Unlock()
}

func (f *fakeKV) callCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakeKV) tokenFor(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastToken[path]
}

// --- wire-shape body builders (mirror sweep.go's decode structs) ---

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

// derefKV2Body builds a KV v2 wire-shaped deref target response: the
// outer "data" envelope itself nests "data"/"metadata", the shape
// isKV2Shaped (sweep.go) detects — e.g. KV v2 read via $ref, or a
// voidstar view. metadata may be nil (still marshals as a present "{}"
// object, satisfying the shape check).
func derefKV2Body(fields, metadata map[string]interface{}) string {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	var wire struct {
		Data struct {
			Data     map[string]interface{} `json:"data"`
			Metadata map[string]interface{} `json:"metadata"`
		} `json:"data"`
	}
	wire.Data.Data = fields
	wire.Data.Metadata = metadata
	b, _ := json.Marshal(wire)
	return string(b)
}

// --- fixtures ---

func sweepTestIdentity() identity.Identity {
	return identity.Identity{Org: "acme", Repo: "widgets", Event: "push", Branch: "feat"}
}

const (
	sweepBase   = "ci/acme/widgets"
	sweepEvent  = "ci/acme/widgets/push"
	sweepBranch = "ci/acme/widgets/push/feat" // esc("feat") == "feat"
)

func metaPath(tier string) string           { return "/v1/kv/metadata/" + tier }
func dataEntryPath(tier, key string) string { return "/v1/kv/data/" + tier + "/" + key }

func newSweepClient(t *testing.T, fv *fakeKV) *Client {
	t.Helper()
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)

	c, err := New(testConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func secretNames(secrets []SweptSecret) []string {
	names := make([]string, len(secrets))
	for i, s := range secrets {
		names[i] = s.Name
	}
	return names
}

func findSecret(t *testing.T, secrets []SweptSecret, name string) SweptSecret {
	t.Helper()
	for _, s := range secrets {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("secret %q not found in %v", name, secretNames(secrets))
	return SweptSecret{}
}

// TestSweep_TierIndependence proves SPEC §4.1's "each prefix LISTed
// independently" rule: base LIST 403 and event LIST 404 must not abort
// the sweep or hide the branch tier's secrets.
func TestSweep_TierIndependence(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepBase), http.StatusForbidden, `{"errors":["denied"]}`)
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBranch), http.StatusOK, listBody([]string{"foo"}))
	fv.set(dataEntryPath(sweepBranch, "foo"), http.StatusOK, entryBody(map[string]interface{}{"value": "bar"}, nil))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), true)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "foo" || res.Secrets[0].Value != "bar" {
		t.Fatalf("Secrets = %+v, want [{foo bar}]", res.Secrets)
	}
}

// TestSweep_Precedence proves SPEC §4.2's most-specific-first collision
// rule directly: the same entry name at base and branch tiers must
// resolve to the branch tier's value.
func TestSweep_Precedence(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBranch), http.StatusOK, listBody([]string{"token"}))
	fv.set(dataEntryPath(sweepBranch, "token"), http.StatusOK, entryBody(map[string]interface{}{"value": "branch-val"}, nil))
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"token"}))
	fv.set(dataEntryPath(sweepBase, "token"), http.StatusOK, entryBody(map[string]interface{}{"value": "base-val"}, nil))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), true)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 1 {
		t.Fatalf("Secrets = %+v, want exactly 1 (branch wins the collision)", res.Secrets)
	}
	if got := res.Secrets[0].Value; got != "branch-val" {
		t.Errorf("token value = %q, want %q (branch, most specific, must win)", got, "branch-val")
	}
	// The base tier's data GET must still have been made (independent
	// LIST/GET per tier) even though its value loses the collision.
	if fv.callCount(dataEntryPath(sweepBase, "token")) != 1 {
		t.Errorf("base tier data GET call count = %d, want 1", fv.callCount(dataEntryPath(sweepBase, "token")))
	}
}

// TestSweep_DotSkip proves dot-prefixed LIST entries are never read as
// secrets, and never even GET'd (SPEC §4.1).
func TestSweep_DotSkip(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{".identity", ".config", ".weird", "real"}))
	fv.set(dataEntryPath(sweepBase, "real"), http.StatusOK, entryBody(map[string]interface{}{"value": "v"}, nil))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "real" {
		t.Fatalf("Secrets = %+v, want exactly [{real v}]", res.Secrets)
	}
	for _, dotKey := range []string{".identity", ".config", ".weird"} {
		if n := fv.callCount(dataEntryPath(sweepBase, dotKey)); n != 0 {
			t.Errorf("GET call count for dot-prefixed key %q = %d, want 0 (never read)", dotKey, n)
		}
	}
}

// TestSweep_Forms exercises SPEC §4.2's three entry forms plus the name
// normalization/validation and string-only rules, all at the base tier.
func TestSweep_Forms(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{
		"shorthand", "general", "e-dash", "bad name!", "goodsib", "nonstring",
	}))
	fv.set(dataEntryPath(sweepBase, "shorthand"), http.StatusOK, entryBody(map[string]interface{}{"value": "v1"}, nil))
	fv.set(dataEntryPath(sweepBase, "general"), http.StatusOK, entryBody(map[string]interface{}{"user": "u", "pass": "p"}, nil))
	fv.set(dataEntryPath(sweepBase, "e-dash"), http.StatusOK, entryBody(map[string]interface{}{"value": "v2"}, nil))
	fv.set(dataEntryPath(sweepBase, "bad name!"), http.StatusOK, entryBody(map[string]interface{}{"value": "x"}, nil))
	fv.set(dataEntryPath(sweepBase, "goodsib"), http.StatusOK, entryBody(map[string]interface{}{"value": "y"}, nil))
	fv.set(dataEntryPath(sweepBase, "nonstring"), http.StatusOK, entryBody(map[string]interface{}{"count": 3, "name": "ok"}, nil))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	want := map[string]string{
		"shorthand":      "v1",
		"general_user":   "u",
		"general_pass":   "p",
		"e_dash":         "v2",
		"goodsib":        "y",
		"nonstring_name": "ok",
	}
	// The exact-count check pins down that "bad name!" (invalid final
	// name: contains a space and "!") contributed zero secrets, alongside
	// the named lookups below for everything that should be present.
	if len(res.Secrets) != len(want) {
		t.Fatalf("Secrets = %v, want names %v", secretNames(res.Secrets), want)
	}
	for name, value := range want {
		got := findSecret(t, res.Secrets, name)
		if got.Value != value {
			t.Errorf("secret %q value = %q, want %q", name, got.Value, value)
		}
	}
	for _, s := range res.Secrets {
		if s.Name == "nonstring_count" {
			t.Errorf("unwanted secret %q present (non-string field must be skipped)", "nonstring_count")
		}
	}
}

// TestSweep_Forms_GeneralFormInvalidFieldNameSiblingSurvives proves SPEC
// §4.2's invalid-name rule is a per-FIELD skip within a general-form
// entry, not a whole-entry skip: one field with an unmappable name
// (contains ".") is dropped, but a valid sibling field from the SAME
// entry still produces a secret.
func TestSweep_Forms_GeneralFormInvalidFieldNameSiblingSurvives(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"mixed"}))
	fv.set(dataEntryPath(sweepBase, "mixed"), http.StatusOK, entryBody(map[string]interface{}{"good": "v1", "bad.field": "v2"}, nil))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if len(res.Secrets) != 1 {
		t.Fatalf("Secrets = %v, want exactly [mixed_good] (bad.field's name is invalid and must be dropped alone)", secretNames(res.Secrets))
	}
	got := findSecret(t, res.Secrets, "mixed_good")
	if got.Value != "v1" {
		t.Errorf("mixed_good value = %q, want %q", got.Value, "v1")
	}
	for _, s := range res.Secrets {
		if s.Name != "mixed_good" {
			t.Errorf("unwanted secret %q present (bad.field's invalid name must not survive)", s.Name)
		}
	}
}

// TestSweep_Deref_Success proves SPEC §4.3 pointer dereference: the
// entry's fields flatten as <entry>_<field>, and a non-empty lease_id on
// the deref response sets LeasesCreated.
func TestSweep_Deref_Success(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"ptr"}))
	fv.set(dataEntryPath(sweepBase, "ptr"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "aws/creds/deploy"}, nil))
	fv.set("/v1/aws/creds/deploy", http.StatusOK, derefBody(map[string]interface{}{"user": "du", "pass": "dp"}, "lease-123"))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if !res.LeasesCreated {
		t.Errorf("LeasesCreated = false, want true (deref response carried a non-empty lease_id)")
	}
	if len(res.Secrets) != 2 {
		t.Fatalf("Secrets = %+v, want 2 (ptr_user, ptr_pass)", res.Secrets)
	}
	if got := findSecret(t, res.Secrets, "ptr_user").Value; got != "du" {
		t.Errorf("ptr_user = %q, want %q", got, "du")
	}
	if got := findSecret(t, res.Secrets, "ptr_pass").Value; got != "dp" {
		t.Errorf("ptr_pass = %q, want %q", got, "dp")
	}
}

// TestSweep_Deref_403SkipsEntry proves a deref 403 skips the entry
// without error and without setting LeasesCreated.
func TestSweep_Deref_403SkipsEntry(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"ptr"}))
	fv.set(dataEntryPath(sweepBase, "ptr"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "aws/creds/deploy"}, nil))
	fv.set("/v1/aws/creds/deploy", http.StatusForbidden, `{"errors":["denied"]}`)

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 0 {
		t.Errorf("Secrets = %+v, want none (deref 403 skips the entry)", res.Secrets)
	}
	if res.LeasesCreated {
		t.Errorf("LeasesCreated = true, want false")
	}
}

// TestSweep_Deref_500ReturnsTypedError proves any other deref failure
// aborts the sweep with a plain (non-ErrMalformedDirective) error — the
// broker maps this to revoke+502 (SPEC §4.3).
func TestSweep_Deref_500ReturnsTypedError(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"ptr"}))
	fv.set(dataEntryPath(sweepBase, "ptr"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "aws/creds/deploy"}, nil))
	fv.set("/v1/aws/creds/deploy", http.StatusInternalServerError, `{"errors":["boom"]}`)

	c := newSweepClient(t, fv)
	_, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err == nil {
		t.Fatalf("Sweep: expected error, got nil")
	}
	if errors.Is(err, ErrMalformedDirective) {
		t.Errorf("Sweep error wraps ErrMalformedDirective, want a plain read-error class")
	}
}

// TestSweep_Deref_KV2Unwrap_SingleField proves a KV v2-shaped deref
// target (e.g. a voidstar view, or KV v2 itself) with a single "value"
// field classifies via the SPEC §4.2 shorthand rule after unwrap: the
// secret is named after the entry alone, "ptr", not "ptr_value" — unlike
// the flat-response path, which never applies shorthand naming.
func TestSweep_Deref_KV2Unwrap_SingleField(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"ptr"}))
	fv.set(dataEntryPath(sweepBase, "ptr"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "vs/data/widgets/prod-token"}, nil))
	fv.set("/v1/vs/data/widgets/prod-token", http.StatusOK, derefKV2Body(
		map[string]interface{}{"value": "shh"},
		map[string]interface{}{"version": 3},
	))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 1 {
		t.Fatalf("Secrets = %+v, want exactly 1", res.Secrets)
	}
	got := res.Secrets[0]
	if got.Name != "ptr" {
		t.Errorf("secret name = %q, want %q (KV v2 single-field shorthand names the entry alone)", got.Name, "ptr")
	}
	if got.Value != "shh" {
		t.Errorf("secret value = %q, want %q", got.Value, "shh")
	}
}

// TestSweep_Deref_KV2Unwrap_MultiField proves a KV v2-shaped deref
// target's multi-field inner data map flattens as key_f1, key_f2 — the
// SPEC §4.2 general form, applied post-unwrap.
func TestSweep_Deref_KV2Unwrap_MultiField(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"ptr"}))
	fv.set(dataEntryPath(sweepBase, "ptr"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "vs/data/widgets/db-creds"}, nil))
	fv.set("/v1/vs/data/widgets/db-creds", http.StatusOK, derefKV2Body(
		map[string]interface{}{"user": "u", "pass": "p"},
		map[string]interface{}{"version": 1, "custom_metadata": map[string]interface{}{"owner": "someone-else"}},
	))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 2 {
		t.Fatalf("Secrets = %+v, want 2 (ptr_user, ptr_pass)", res.Secrets)
	}
	if got := findSecret(t, res.Secrets, "ptr_user").Value; got != "u" {
		t.Errorf("ptr_user = %q, want %q", got, "u")
	}
	if got := findSecret(t, res.Secrets, "ptr_pass").Value; got != "p" {
		t.Errorf("ptr_pass = %q, want %q", got, "p")
	}
	// The deref target's own "metadata" block (including its
	// custom_metadata) must never surface as a secret or override the
	// entry's own pins — only the swept entry's own KV v2
	// custom_metadata drives pins (SPEC §4.6).
	for _, s := range res.Secrets {
		if s.Name == "ptr_metadata" || s.Name == "ptr_version" {
			t.Errorf("unwanted secret %q present (deref target's metadata block must not flatten)", s.Name)
		}
	}
}

// TestSweep_Deref_FlatSTSUnchanged is a regression test: a flat
// dynamic-engine response (no "metadata" key — the pre-existing
// aws/sts-shaped case) must NOT be detected as KV v2-shaped and must keep
// its exact prior behavior — general-form key_field flattening, never
// single-name shorthand, even for a single-field response.
func TestSweep_Deref_FlatSTSUnchanged(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"sts", "single"}))
	fv.set(dataEntryPath(sweepBase, "sts"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "aws/sts/deploy"}, nil))
	fv.set("/v1/aws/sts/deploy", http.StatusOK, derefBody(map[string]interface{}{
		"access_key": "ak", "secret_key": "sk", "security_token": "st",
	}, "lease-sts-1"))
	fv.set(dataEntryPath(sweepBase, "single"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "aws/creds/single-field"}, nil))
	// Flat response with exactly one field, named "value" — must still
	// flatten as "single_value", NOT be shorthand-named "single": shorthand
	// classification only ever applies post-KV2-unwrap.
	fv.set("/v1/aws/creds/single-field", http.StatusOK, derefBody(map[string]interface{}{"value": "solo"}, ""))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if !res.LeasesCreated {
		t.Errorf("LeasesCreated = false, want true (flat sts deref carried a non-empty lease_id)")
	}
	want := map[string]string{
		"sts_access_key":     "ak",
		"sts_secret_key":     "sk",
		"sts_security_token": "st",
		"single_value":       "solo",
	}
	if len(res.Secrets) != len(want) {
		t.Fatalf("Secrets = %v, want names %v", secretNames(res.Secrets), want)
	}
	for name, value := range want {
		got := findSecret(t, res.Secrets, name)
		if got.Value != value {
			t.Errorf("secret %q value = %q, want %q", name, got.Value, value)
		}
	}
}

// TestSweep_Deref_KV2Unwrap_ValueWithMetadataSiblings proves the
// single-field convention: a KV v2-shaped deref target whose inner map
// carries a string "value" field PLUS metadata siblings (the shape 1P-
// style field-engine views return: id/title/type/updated_at/staleness
// flags) yields ONE secret named for the entry — the siblings never
// flatten. Regression for the 2026-08-19 production failure where the
// strict exactly-one-key shorthand test flattened such a view into
// E_id/E_title/… and the expected secret name never existed.
func TestSweep_Deref_KV2Unwrap_ValueWithMetadataSiblings(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"ptr"}))
	fv.set(dataEntryPath(sweepBase, "ptr"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "vs/data/widgets/token"}, nil))
	fv.set("/v1/vs/data/widgets/token", http.StatusOK, derefKV2Body(
		map[string]interface{}{
			"value":               "s3cr3t",
			"id":                  "abc123",
			"title":               "widgets token",
			"type":                "CONCEALED",
			"updated_at":          "2026-08-19T00:00:00Z",
			"replica_age_seconds": 42,
			"stale":               false,
			"stale_suspect":       false,
		},
		map[string]interface{}{"version": 1},
	))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 1 {
		t.Fatalf("Secrets = %+v, want exactly 1 (ptr)", res.Secrets)
	}
	if got := findSecret(t, res.Secrets, "ptr").Value; got != "s3cr3t" {
		t.Errorf("ptr = %q, want %q", got, "s3cr3t")
	}
}

// TestSweep_Deref_AmbiguousDataFieldDoesNotMisfire proves the ambiguous
// case the shape check exists for: a flat dynamic-engine response that
// happens to carry a field literally named "data" must not be
// misdetected as KV v2-shaped. Only a STRING "data" field is exercised
// here (an object-valued "data" field would still require a paired
// "metadata" object to trip detection — isKV2Shaped's own doc comment
// covers that half); the point here is that the mere presence of the
// name "data" is not itself the signal.
func TestSweep_Deref_AmbiguousDataFieldDoesNotMisfire(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"weird"}))
	fv.set(dataEntryPath(sweepBase, "weird"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "database/creds/weird"}, nil))
	// No "metadata" key at all — just a dynamic secret whose engine
	// happens to name one of its own fields "data".
	fv.set("/v1/database/creds/weird", http.StatusOK, derefBody(map[string]interface{}{
		"data": "not-actually-kv2", "username": "u",
	}, ""))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 2 {
		t.Fatalf("Secrets = %+v, want 2 (weird_data, weird_username — flat general-form flattening, no misfire)", res.Secrets)
	}
	if got := findSecret(t, res.Secrets, "weird_data").Value; got != "not-actually-kv2" {
		t.Errorf("weird_data = %q, want %q", got, "not-actually-kv2")
	}
	if got := findSecret(t, res.Secrets, "weird_username").Value; got != "u" {
		t.Errorf("weird_username = %q, want %q", got, "u")
	}
}

// TestSweep_NoChainRule proves SPEC §4.3's "pointers followed exactly one
// level" rule: a deref response that is itself exactly {"$ref": ...} is
// never re-dereferenced, and its "$ref" field fails name validation so
// the entry yields no secrets.
func TestSweep_NoChainRule(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"ptr"}))
	fv.set(dataEntryPath(sweepBase, "ptr"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "first-hop"}, nil))
	fv.set("/v1/first-hop", http.StatusOK, derefBody(map[string]interface{}{"$ref": "second-hop"}, ""))
	// second-hop is intentionally never registered — if the implementation
	// ever chased the chain, this call would hit the fake's unregistered-
	// path 404 default and still not blow up the test, so the call-count
	// assertion below is the load-bearing one, not a forced failure here.

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 0 {
		t.Errorf("Secrets = %+v, want none (deref result's own \"$ref\" field fails name validation)", res.Secrets)
	}
	if got := fv.callCount("/v1/second-hop"); got != 0 {
		t.Errorf("second-hop deref call count = %d, want 0 (no chain — deref result is never re-examined for $ref)", got)
	}
	if got := fv.callCount("/v1/first-hop"); got != 1 {
		t.Errorf("first-hop deref call count = %d, want 1", got)
	}
}

// TestSweep_LexicographicDeterminism proves SPEC §4.2's "lexicographic
// within a level" rule makes same-tier name collisions deterministic:
// "a-b" sorts before "a_b" (raw byte order), both normalize to "a_b", so
// "a-b"'s value must win.
func TestSweep_LexicographicDeterminism(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	// Deliberately unsorted in the fake's LIST response — the
	// implementation must sort before reading, not rely on LIST order.
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"a_b", "a-b"}))
	fv.set(dataEntryPath(sweepBase, "a-b"), http.StatusOK, entryBody(map[string]interface{}{"value": "dash-val"}, nil))
	fv.set(dataEntryPath(sweepBase, "a_b"), http.StatusOK, entryBody(map[string]interface{}{"value": "underscore-val"}, nil))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 1 {
		t.Fatalf("Secrets = %+v, want exactly 1 (a-b and a_b collide after normalization)", res.Secrets)
	}
	if got := res.Secrets[0].Value; got != "dash-val" {
		t.Errorf("a_b value = %q, want %q (\"a-b\" < \"a_b\" lexicographically, processed first, wins)", got, "dash-val")
	}
}

// TestSweep_Pins proves SPEC §4.6: custom_metadata on the swept entry's
// own data-GET response drives the returned secrets' Images/Events pins.
func TestSweep_Pins(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"pinned"}))
	fv.set(dataEntryPath(sweepBase, "pinned"), http.StatusOK, entryBody(
		map[string]interface{}{"value": "v"},
		map[string]string{"ironbark_images": "img1, img2", "ironbark_events": "push,cron"},
	))

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	s := findSecret(t, res.Secrets, "pinned")
	if got := s.Images; len(got) != 2 || got[0] != "img1" || got[1] != "img2" {
		t.Errorf("Images = %v, want [img1 img2]", got)
	}
	if got := s.Events; len(got) != 2 || got[0] != "push" || got[1] != "cron" {
		t.Errorf("Events = %v, want [push cron]", got)
	}
}

// TestSweep_AnyListFailureReturnsTypedError proves SPEC §4.1's "any other
// status" rule for LIST: a 500 aborts the sweep with a plain error.
func TestSweep_AnyListFailureReturnsTypedError(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusInternalServerError, `{"errors":["boom"]}`)

	c := newSweepClient(t, fv)
	_, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err == nil {
		t.Fatalf("Sweep: expected error, got nil")
	}
	if errors.Is(err, ErrMalformedDirective) {
		t.Errorf("Sweep error wraps ErrMalformedDirective, want a plain read-error class")
	}
}

// TestSweep_UsesMintedTokenNotOwnSession proves every sweep read
// authenticates as the passed-in minted token, never c.api's own default
// (ironbark's AppRole session) token — mirroring
// TestRevokeSelf_UsesMintedTokenNotOwnSession's style.
func TestSweep_UsesMintedTokenNotOwnSession(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"foo"}))
	fv.set(dataEntryPath(sweepBase, "foo"), http.StatusOK, entryBody(map[string]interface{}{"value": "bar"}, nil))

	c := newSweepClient(t, fv)
	c.api.SetToken("ironbark-own-session-token")

	const mintedToken = "minted-pipeline-token"
	if _, err := c.Sweep(context.Background(), mintedToken, sweepTestIdentity(), false); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	for _, path := range []string{metaPath(sweepEvent), metaPath(sweepBase), dataEntryPath(sweepBase, "foo")} {
		if got := fv.tokenFor(path); got != mintedToken {
			t.Errorf("X-Vault-Token for %s = %q, want minted token %q", path, got, mintedToken)
		}
	}
	if c.api.Token() != "ironbark-own-session-token" {
		t.Errorf("api.Client default token = %q after Sweep, want unchanged ironbark session token", c.api.Token())
	}
}

// TestSweep_BranchfulTrueEmptyBranchExcludesBranchTier proves SPEC §4.1
// item 1's gate is really "branchful AND non-empty branch", not
// "branchful" alone: branchful=true with id.Branch == "" must not issue
// a branch-tier LIST at all. Note: base+"/"+event+"/"+esc("") would
// path.Clean down to the SAME URL as the event tier itself (Go's
// net/url path.Join strips the trailing slash esc("") leaves behind),
// so a wrongly-included empty-branch tier is not observable as a
// distinct request — it manifests as a second, redundant call to the
// event tier's own LIST path, which is what this test asserts against.
func TestSweep_BranchfulTrueEmptyBranchExcludesBranchTier(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"foo"}))
	fv.set(dataEntryPath(sweepBase, "foo"), http.StatusOK, entryBody(map[string]interface{}{"value": "bar"}, nil))

	id := sweepTestIdentity()
	id.Branch = ""

	c := newSweepClient(t, fv)
	res, err := c.Sweep(context.Background(), "minted-token", id, true)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	if got := fv.callCount(metaPath(sweepEvent)); got != 1 {
		t.Errorf("event-tier LIST call count = %d, want exactly 1 (branchful=true but id.Branch==\"\" must exclude the branch tier, not just deduplicate it)", got)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Name != "foo" {
		t.Fatalf("Secrets = %v, want exactly [foo] (from the event/base tiers only)", secretNames(res.Secrets))
	}
}

// --- ReadIdentity (SPEC §4.4) ---

func TestReadIdentity_Valid(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".identity"), http.StatusOK, entryBody(map[string]interface{}{"forge_remote_id": "12345"}, nil))

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if err != nil {
		t.Fatalf("ReadIdentity: %v", err)
	}
	if got == nil || *got != "12345" {
		t.Fatalf("ReadIdentity = %v, want &\"12345\"", got)
	}
}

// TestReadIdentity_MalformedJSON proves an undecodable 200 body on
// .identity is ErrMalformedDirective, not a plain read error — the
// broker's fork depends on this: malformed .identity is an identity
// mismatch (204), never a 502 (SPEC §4.4 C1's fail-closed rule).
func TestReadIdentity_MalformedJSON(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".identity"), http.StatusOK, `not json`)

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if got != nil {
		t.Errorf("ReadIdentity id = %v, want nil", got)
	}
	if !errors.Is(err, ErrMalformedDirective) {
		t.Errorf("ReadIdentity err = %v, want ErrMalformedDirective", err)
	}
}

func TestReadIdentity_MalformedNonString(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".identity"), http.StatusOK, entryBody(map[string]interface{}{"forge_remote_id": 7}, nil))

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if got != nil {
		t.Errorf("ReadIdentity id = %v, want nil", got)
	}
	if !errors.Is(err, ErrMalformedDirective) {
		t.Errorf("ReadIdentity err = %v, want ErrMalformedDirective", err)
	}
}

func TestReadIdentity_MalformedEmpty(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".identity"), http.StatusOK, entryBody(map[string]interface{}{"forge_remote_id": ""}, nil))

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if got != nil {
		t.Errorf("ReadIdentity id = %v, want nil", got)
	}
	if !errors.Is(err, ErrMalformedDirective) {
		t.Errorf("ReadIdentity err = %v, want ErrMalformedDirective", err)
	}
}

func TestReadIdentity_MalformedMissing(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".identity"), http.StatusOK, entryBody(map[string]interface{}{}, nil))

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if got != nil {
		t.Errorf("ReadIdentity id = %v, want nil", got)
	}
	if !errors.Is(err, ErrMalformedDirective) {
		t.Errorf("ReadIdentity err = %v, want ErrMalformedDirective", err)
	}
}

func TestReadIdentity_AbsentReturnsNilNil(t *testing.T) {
	fv := newFakeKV() // .identity path left unregistered -> 404

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if got != nil || err != nil {
		t.Errorf("ReadIdentity = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestReadIdentity_UnreadableReturnsNilNil(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".identity"), http.StatusForbidden, `{"errors":["denied"]}`)

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if got != nil || err != nil {
		t.Errorf("ReadIdentity = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestReadIdentity_OtherFailureReturnsPlainError(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".identity"), http.StatusInternalServerError, `{"errors":["boom"]}`)

	c := newSweepClient(t, fv)
	got, err := c.ReadIdentity(context.Background(), "minted-token", sweepBase)
	if got != nil {
		t.Errorf("ReadIdentity id = %v, want nil", got)
	}
	if err == nil {
		t.Fatalf("ReadIdentity: expected error, got nil")
	}
	if errors.Is(err, ErrMalformedDirective) {
		t.Errorf("ReadIdentity error wraps ErrMalformedDirective, want a plain read-error class")
	}
}

// --- ReadConfig (SPEC §4.5) ---

func TestReadConfig_Success(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".config"), http.StatusOK, entryBody(map[string]interface{}{"vault_token": "false"}, nil))

	c := newSweepClient(t, fv)
	got, err := c.ReadConfig(context.Background(), "minted-token", sweepBase)
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if got["vault_token"] != "false" {
		t.Errorf("ReadConfig = %v, want {vault_token: false}", got)
	}
}

func TestReadConfig_NonFlatStringMap(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".config"), http.StatusOK, entryBody(map[string]interface{}{"vault_token_images": []string{"a", "b"}}, nil))

	c := newSweepClient(t, fv)
	got, err := c.ReadConfig(context.Background(), "minted-token", sweepBase)
	if got != nil {
		t.Errorf("ReadConfig = %v, want nil", got)
	}
	if !errors.Is(err, ErrMalformedDirective) {
		t.Errorf("ReadConfig err = %v, want ErrMalformedDirective", err)
	}
}

func TestReadConfig_AbsentReturnsNilNil(t *testing.T) {
	fv := newFakeKV() // .config path left unregistered -> 404

	c := newSweepClient(t, fv)
	got, err := c.ReadConfig(context.Background(), "minted-token", sweepBase)
	if got != nil || err != nil {
		t.Errorf("ReadConfig = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestReadConfig_OtherFailureReturnsPlainError(t *testing.T) {
	fv := newFakeKV()
	fv.set(dataEntryPath(sweepBase, ".config"), http.StatusInternalServerError, `{"errors":["boom"]}`)

	c := newSweepClient(t, fv)
	got, err := c.ReadConfig(context.Background(), "minted-token", sweepBase)
	if got != nil {
		t.Errorf("ReadConfig = %v, want nil", got)
	}
	if err == nil {
		t.Fatalf("ReadConfig: expected error, got nil")
	}
	if errors.Is(err, ErrMalformedDirective) {
		t.Errorf("ReadConfig error wraps ErrMalformedDirective, want a plain read-error class")
	}
}

// --- Metrics seam (WithMetrics) ---

// countingMetrics is a race-safe fake Metrics that records call counts,
// for TestSweep_MetricsSeam to assert exact IncSweepRead/IncDerefRead
// counts.
type countingMetrics struct {
	mu         sync.Mutex
	sweepReads int
	derefReads int
}

func (m *countingMetrics) IncSweepRead() {
	m.mu.Lock()
	m.sweepReads++
	m.mu.Unlock()
}

func (m *countingMetrics) IncDerefRead() {
	m.mu.Lock()
	m.derefReads++
	m.mu.Unlock()
}

func (m *countingMetrics) counts() (sweepReads, derefReads int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sweepReads, m.derefReads
}

var _ Metrics = (*countingMetrics)(nil)

// TestSweep_MetricsSeam proves the WithMetrics seam: every successful
// per-entry data-GET increments IncSweepRead (including a pointer entry's
// own read of its "$ref" definition), and every successful pointer
// dereference additionally increments IncDerefRead. Five entries are
// listed at the base tier: three plain (shorthand-form) secrets and two
// pointers, each dereferencing successfully — so IncSweepRead must be
// called exactly 5 times (one per entry actually read) and IncDerefRead
// exactly 2 times (one per successful deref).
func TestSweep_MetricsSeam(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"a", "b", "c", "p1", "p2"}))
	fv.set(dataEntryPath(sweepBase, "a"), http.StatusOK, entryBody(map[string]interface{}{"value": "va"}, nil))
	fv.set(dataEntryPath(sweepBase, "b"), http.StatusOK, entryBody(map[string]interface{}{"value": "vb"}, nil))
	fv.set(dataEntryPath(sweepBase, "c"), http.StatusOK, entryBody(map[string]interface{}{"value": "vc"}, nil))
	fv.set(dataEntryPath(sweepBase, "p1"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "aws/creds/one"}, nil))
	fv.set(dataEntryPath(sweepBase, "p2"), http.StatusOK, entryBody(map[string]interface{}{"$ref": "aws/creds/two"}, nil))
	fv.set("/v1/aws/creds/one", http.StatusOK, derefBody(map[string]interface{}{"user": "u1"}, "lease-1"))
	fv.set("/v1/aws/creds/two", http.StatusOK, derefBody(map[string]interface{}{"user": "u2"}, "lease-2"))

	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)

	cm := &countingMetrics{}
	c, err := New(testConfig(srv.URL), WithMetrics(cm))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Secrets) != 5 {
		t.Fatalf("Secrets = %+v, want 5 (a, b, c, p1_user, p2_user)", res.Secrets)
	}

	sweepReads, derefReads := cm.counts()
	if sweepReads != 5 {
		t.Errorf("IncSweepRead call count = %d, want 5 (one per entry actually read: a, b, c, p1, p2)", sweepReads)
	}
	if derefReads != 2 {
		t.Errorf("IncDerefRead call count = %d, want 2 (one per successful pointer dereference: p1, p2)", derefReads)
	}
}

// TestSweep_MetricsSeam_NilSafeWithoutOption proves the zero value (no
// WithMetrics option) leaves Sweep fully nil-safe — the existing
// (pre-Task-11-amendment) behavior every other test in this file relies
// on.
func TestSweep_MetricsSeam_NilSafeWithoutOption(t *testing.T) {
	fv := newFakeKV()
	fv.set(metaPath(sweepEvent), http.StatusNotFound, `{"errors":[]}`)
	fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"a"}))
	fv.set(dataEntryPath(sweepBase, "a"), http.StatusOK, entryBody(map[string]interface{}{"value": "va"}, nil))

	c := newSweepClient(t, fv) // no WithMetrics
	if _, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), false); err != nil {
		t.Fatalf("Sweep: %v (must not panic/error with metrics unset)", err)
	}
}

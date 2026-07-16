// This file (Task 9) owns the SPEC §4 sweep/deref/directive READ layer:
// Sweep (§4.1–§4.3, §4.6), ReadIdentity (§4.4), and ReadConfig (§4.5). It
// reads KV v2 data authenticated AS the minted pipeline token (the token
// argument passed into every function here — never c.token, ironbark's
// own AppRole session token on c.api), via the same per-request
// req.ClientToken override technique mint.go's RevokeSelf established.
//
// Scope: this is READ + CLASSIFY only. It never decides an HTTP outcome
// (204/502/revoke) — it returns data and, on failure, one of two error
// classes the broker (Task 10) tells apart with errors.Is:
//
//   - ErrMalformedDirective: a directive entry (.identity/.config) exists
//     but is shaped wrong (SPEC §4.4/§4.5's fail-closed rules).
//   - any other non-nil error: a plain Vault-side read failure (5xx,
//     timeout, malformed LIST/GET/deref response) — SPEC §4.1/§4.3's
//     "any other status" case.
//
// 403/404 are never errors here: SPEC §4.1 makes partial visibility THE
// tiering mechanism, so every LIST/GET/deref silently skips that
// level/entry on 403/404 (vaultGet's found=false, err=nil case).
package vaultx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/vault/api"

	"ironbark/internal/identity"
)

// ErrMalformedDirective indicates a .identity or .config entry exists but
// is shaped wrong (SPEC §4.4, §4.5). Detect with errors.Is; the wrapped
// detail names the specific malformation.
var ErrMalformedDirective = errors.New("vaultx: malformed directive")

// SweptSecret is one secret produced by Sweep (SPEC §4.2). Events empty
// means no per-secret event pin was set via custom_metadata (SPEC §4.6);
// the broker applies the request's own event as the default pin in that
// case — Sweep never invents a default here.
type SweptSecret struct {
	Name   string
	Value  string
	Images []string
	Events []string
}

// SweepResult is Sweep's result: the flattened, deduplicated secrets
// (SPEC §4.2) and whether any pointer dereference (SPEC §4.3) created a
// lease (a non-empty lease_id on a 200 deref response).
type SweepResult struct {
	Secrets       []SweptSecret
	LeasesCreated bool
}

// validNameRe is the SPEC §4.2 final-name validator, applied AFTER
// lowercasing and "-"→"_" mapping (normalizeName). Any other character
// makes the name invalid.
var validNameRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// sweepAccumulator collects Sweep's result across tiers/entries. seen
// implements SPEC §4.2's first-writer-wins collision rule: since Sweep
// visits tiers most-specific-first (branch, event, base) and keys
// lexicographically within a tier, "first writer wins" is exactly
// "insert into seen if absent, otherwise discard" applied in that visit
// order — no separate precedence logic needed.
type sweepAccumulator struct {
	seen          map[string]bool
	secrets       []SweptSecret
	leasesCreated bool
}

// add implements SPEC §4.2's name validation and first-writer-wins
// collision rule for one candidate secret. A rejected candidate (invalid
// name or a collision) is silently dropped: SPEC calls for a warning log
// here, but this package has no logging infrastructure yet (canary.go's
// runCanary made the same call for revoke-failure logging) — the discard
// IS the "logged and skipped" outcome until a later task wires §8
// observability.
func (sw *sweepAccumulator) add(name, value string, images, events []string) {
	if !validNameRe.MatchString(name) {
		return
	}
	if sw.seen[name] {
		return
	}
	sw.seen[name] = true
	sw.secrets = append(sw.secrets, SweptSecret{Name: name, Value: value, Images: images, Events: events})
}

// normalizeName applies SPEC §4.2's name normalization: lowercase, then
// "-"→"_". The result still needs validNameRe validation — normalization
// alone does not guarantee a valid name (any other character survives
// unmapped and fails validation downstream).
func normalizeName(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "-", "_")
}

// stringField reports whether raw (a field's JSON-decoded value) is a
// JSON string, decoding it if so. A missing field (raw == nil) or any
// non-string JSON value (number, bool, array, object, null) returns
// ("", false) — SPEC §4.2/§4.3's "values must be JSON strings" rule,
// enforced identically for direct entries and deref results.
func stringField(raw json.RawMessage) (string, bool) {
	if raw == nil {
		return "", false
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	return v, true
}

// splitTrimCommaList splits a SPEC §4.6 comma-separated custom_metadata
// value, trimming whitespace around each element.
func splitTrimCommaList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

// entryPins extracts the SPEC §4.6 per-secret pins from a swept entry's
// own KV v2 custom_metadata block (read from the same data-GET response
// that supplied the entry's fields — no fallback metadata-GET, SPEC
// §4.6/G3). A nil customMeta (block absent) yields no pins (both nil).
func entryPins(customMeta map[string]string) (images, events []string) {
	if v, ok := customMeta["ironbark_images"]; ok {
		images = splitTrimCommaList(v)
	}
	if v, ok := customMeta["ironbark_events"]; ok {
		events = splitTrimCommaList(v)
	}
	return images, events
}

// vaultGet issues a GET (optionally as a KV v2 LIST, via list=true) to
// path, authenticated as token via the per-request req.ClientToken
// override (mint.go's RevokeSelf pattern) — never touching c.api's own
// default token (ironbark's AppRole session). It classifies the SPEC
// §4.1 tri-state outcome:
//
//   - found=false, err=nil: 403 or 404 — skip this level/entry.
//   - found=false, err!=nil: any other status, or a transport failure —
//     the caller must propagate this as Sweep/ReadIdentity/ReadConfig's
//     own typed failure (broker: revoke+502).
//   - found=true, err=nil: 200 — resp is positioned for the caller to
//     decode; the caller owns closing resp.Body.
func (c *Client) vaultGet(ctx context.Context, token, path string, list bool) (resp *api.Response, found bool, err error) {
	req := c.api.NewRequest(http.MethodGet, "/v1/"+path)
	if list {
		req.Params.Set("list", "true")
	}
	req.ClientToken = token

	resp, err = c.api.RawRequestWithContext(ctx, req)
	if err != nil {
		var respErr *api.ResponseError
		if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusForbidden || respErr.StatusCode == http.StatusNotFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("vaultx: sweep: GET %s: %w", path, err)
	}
	return resp, true, nil
}

// ReadIdentity performs the SPEC §4.4 .identity read: GET
// <mount>/data/<base>/.identity, authenticated as token. Return contract:
//
//   - absent (404) or unreadable (403): (nil, nil) — binding not enforced.
//   - exists and forge_remote_id is a non-empty JSON string: (&id, nil).
//   - exists but malformed (forge_remote_id missing, non-string, or
//     empty): (nil, ErrMalformedDirective) — the broker treats this as an
//     identity mismatch (204), never as "not enforced" (SPEC §4.4 C1).
//   - any other read failure (5xx, timeout): (nil, plain error) — the
//     broker maps this to 502.
//
// This function only reads and classifies; it does not compare the
// result against the payload's own forge_remote_id — that comparison,
// and the 204/502 outcome, belong to the broker (Task 10).
func (c *Client) ReadIdentity(ctx context.Context, token, base string) (*string, error) {
	path := c.cfg.KVMount + "/data/" + base + "/.identity"
	resp, found, err := c.vaultGet(ctx, token, path, false)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	defer resp.Body.Close()

	var parsed struct {
		Data struct {
			Data struct {
				ForgeRemoteID json.RawMessage `json:"forge_remote_id"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return nil, fmt.Errorf("%w: .identity: decode response: %v", ErrMalformedDirective, err)
	}

	id, ok := stringField(parsed.Data.Data.ForgeRemoteID)
	if !ok || id == "" {
		return nil, fmt.Errorf("%w: .identity: forge_remote_id missing, non-string, or empty", ErrMalformedDirective)
	}
	return &id, nil
}

// ReadConfig performs the SPEC §4.5 .config read: GET
// <mount>/data/<base>/.config, authenticated as token. Return contract:
//
//   - absent (404) or unreadable (403): (nil, nil) — defaults apply.
//   - exists and is a flat string map: (map, nil), unfiltered — this
//     function does not interpret vault_token/vault_token_images; the
//     broker does.
//   - exists but is not a flat string map (any non-string field value):
//     (nil, ErrMalformedDirective) — SPEC §4.5 C1: malformed config is a
//     502, NOT a silent fall-back to defaults (unlike .identity's 204).
//   - any other read failure (5xx, timeout): (nil, plain error) — 502.
func (c *Client) ReadConfig(ctx context.Context, token, base string) (map[string]string, error) {
	path := c.cfg.KVMount + "/data/" + base + "/.config"
	resp, found, err := c.vaultGet(ctx, token, path, false)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	defer resp.Body.Close()

	var parsed struct {
		Data struct {
			Data map[string]json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return nil, fmt.Errorf("%w: .config: decode response: %v", ErrMalformedDirective, err)
	}

	out := make(map[string]string, len(parsed.Data.Data))
	for k, raw := range parsed.Data.Data {
		v, ok := stringField(raw)
		if !ok {
			return nil, fmt.Errorf("%w: .config: key %q is not a string", ErrMalformedDirective, k)
		}
		out[k] = v
	}
	return out, nil
}

// Base returns the SPEC §2.4 KV base path `<KVPrefix>/<org>/<repo>` for id.
// Sweep uses it as the common prefix for all three tiers; the broker (Task
// 10) uses the same method to read <base>/.identity and <base>/.config, so
// the base-path computation has exactly one implementation.
func (c *Client) Base(id identity.Identity) string {
	return c.cfg.KVPrefix + "/" + id.Org + "/" + id.Repo
}

// Sweep performs the SPEC §4.1–§4.3, §4.6 sweep: it LISTs each applicable
// KV v2 prefix independently, most specific first (branch, then event,
// then base — branchful is true only when the caller's event is
// branchful AND id.Branch is non-empty; combined with id.Branch != ""
// here per SPEC §4.1 item 1), reads each plain (non-directory,
// non-dot-prefixed) key found, classifies it into the SPEC §4.2 pointer/
// shorthand/general form, and flattens it into named secrets — all
// authenticated as token, the minted pipeline token (never c.token).
//
// A LIST/GET/deref 403/404 skips that level/entry (SPEC §4.1 partial
// visibility). Any other failure aborts the whole sweep and returns a
// plain (non-ErrMalformedDirective) error — the broker maps this to
// revoke+502.
func (c *Client) Sweep(ctx context.Context, token string, id identity.Identity, branchful bool) (SweepResult, error) {
	base := c.Base(id)

	var tiers []string
	if branchful && id.Branch != "" {
		tiers = append(tiers, base+"/"+id.Event+"/"+identity.Esc(id.Branch))
	}
	tiers = append(tiers, base+"/"+id.Event, base)

	sw := &sweepAccumulator{seen: make(map[string]bool)}
	for _, tierPath := range tiers {
		if err := c.sweepTier(ctx, token, tierPath, sw); err != nil {
			return SweepResult{}, err
		}
	}

	return SweepResult{Secrets: sw.secrets, LeasesCreated: sw.leasesCreated}, nil
}

// sweepTier LISTs one SPEC §4.1 prefix and reads its plain keys in
// lexicographic order (SPEC §4.2's "lexicographic within a level", the
// half of first-writer-wins determinism this file owns — most-specific-
// first across tiers is Sweep's tiers slice order).
func (c *Client) sweepTier(ctx context.Context, token, tierPath string, sw *sweepAccumulator) error {
	keys, err := c.listTierKeys(ctx, token, tierPath)
	if err != nil {
		return err
	}
	sort.Strings(keys)

	for _, key := range keys {
		if err := c.sweepEntry(ctx, token, tierPath, key, sw); err != nil {
			return err
		}
	}
	return nil
}

// listTierKeys performs one SPEC §4.1 LIST (<mount>/metadata/<tierPath>)
// and returns only its plain keys: directory entries (trailing "/",
// never descended — deeper nesting is not swept, a documented v1
// constraint) and dot-prefixed entries (never secrets at any level, SPEC
// §4.1) are filtered out here, before the caller ever sees them.
func (c *Client) listTierKeys(ctx context.Context, token, tierPath string) ([]string, error) {
	path := c.cfg.KVMount + "/metadata/" + tierPath
	resp, found, err := c.vaultGet(ctx, token, path, true)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	defer resp.Body.Close()

	var parsed struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return nil, fmt.Errorf("vaultx: sweep: LIST %s: decode response: %w", path, err)
	}

	keys := make([]string, 0, len(parsed.Data.Keys))
	for _, k := range parsed.Data.Keys {
		if strings.HasSuffix(k, "/") || strings.HasPrefix(k, ".") {
			continue
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// sweepEntry reads one plain KV key (GET <mount>/data/<tierPath>/<key>)
// and dispatches it through the SPEC §4.2 pointer/shorthand/general
// classification, adding whatever secrets it yields to sw. A 403/404 on
// the entry's own GET skips it entirely (no secrets, no error).
func (c *Client) sweepEntry(ctx context.Context, token, tierPath, key string, sw *sweepAccumulator) error {
	dataPath := c.cfg.KVMount + "/data/" + tierPath + "/" + key
	resp, found, err := c.vaultGet(ctx, token, dataPath, false)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if c.metrics != nil {
		c.metrics.IncSweepRead()
	}
	defer resp.Body.Close()

	var parsed struct {
		Data struct {
			Data     map[string]json.RawMessage `json:"data"`
			Metadata struct {
				CustomMetadata map[string]string `json:"custom_metadata"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return fmt.Errorf("vaultx: sweep: GET %s: decode response: %w", dataPath, err)
	}

	images, events := entryPins(parsed.Data.Metadata.CustomMetadata)
	d := parsed.Data.Data

	switch {
	case isPointerForm(d):
		refPath, ok := stringField(d["$ref"])
		if !ok {
			// "$ref" present but not a JSON string: not the SPEC §4.2
			// pointer shape ("exactly {"$ref": "<path>"}"); no other form
			// applies either (the map has exactly one key, "$ref", which
			// fails validNameRe on its own as a shorthand/general name)
			// so the entry yields no secrets.
			return nil
		}
		return c.sweepDeref(ctx, token, key, refPath, images, events, sw)

	case isShorthandForm(d):
		v, ok := stringField(d["value"])
		if !ok {
			return nil // non-string shorthand value: skip with warning
		}
		sw.add(normalizeName(key), v, images, events)
		return nil

	default:
		fields := sortedFieldNames(d)
		for _, f := range fields {
			v, ok := stringField(d[f])
			if !ok {
				continue // non-string field: skip with warning, siblings survive
			}
			sw.add(normalizeName(key)+"_"+normalizeName(f), v, images, events)
		}
		return nil
	}
}

// isPointerForm reports whether d is exactly {"$ref": <anything>} (SPEC
// §4.2). The value's type (must be a JSON string to actually dereference)
// is checked by the caller via stringField.
func isPointerForm(d map[string]json.RawMessage) bool {
	if len(d) != 1 {
		return false
	}
	_, ok := d["$ref"]
	return ok
}

// isShorthandForm reports whether d is exactly {"value": <anything>}
// (SPEC §4.2).
func isShorthandForm(d map[string]json.RawMessage) bool {
	if len(d) != 1 {
		return false
	}
	_, ok := d["value"]
	return ok
}

// sortedFieldNames returns d's keys sorted, for deterministic general-
// form field processing (not itself SPEC-required — only same-tier KEY
// order is, per §4.2 — but free to make deterministic and testable).
func sortedFieldNames(d map[string]json.RawMessage) []string {
	names := make([]string, 0, len(d))
	for f := range d {
		names = append(names, f)
	}
	sort.Strings(names)
	return names
}

// sweepDeref performs the SPEC §4.3 pointer dereference for entry key
// (GET refPath, any mount, authenticated as token) and flattens the
// result's .data fields as key_f, applying the entry's own pins (images,
// events — read from key's own KV v2 custom_metadata, never the deref
// target's) to every field it yields. A 403/404 skips the entry (no
// secrets, no error). The deref result is never re-examined for its own
// "$ref"/"value" shape (SPEC §4.3's no-chain rule) — its fields are
// always flattened via the general-form path, unconditionally.
func (c *Client) sweepDeref(ctx context.Context, token, key, refPath string, images, events []string, sw *sweepAccumulator) error {
	resp, found, err := c.vaultGet(ctx, token, refPath, false)
	if err != nil {
		return fmt.Errorf("vaultx: sweep: deref %s: %w", refPath, err)
	}
	if !found {
		return nil
	}
	if c.metrics != nil {
		c.metrics.IncDerefRead()
	}
	defer resp.Body.Close()

	var parsed struct {
		LeaseID string                     `json:"lease_id"`
		Data    map[string]json.RawMessage `json:"data"`
	}
	if err := resp.DecodeJSON(&parsed); err != nil {
		return fmt.Errorf("vaultx: sweep: deref %s: decode response: %w", refPath, err)
	}

	if parsed.LeaseID != "" {
		sw.leasesCreated = true
	}

	for _, f := range sortedFieldNames(parsed.Data) {
		v, ok := stringField(parsed.Data[f])
		if !ok {
			continue // non-string deref field: skip with warning, siblings survive
		}
		sw.add(normalizeName(key)+"_"+normalizeName(f), v, images, events)
	}
	return nil
}

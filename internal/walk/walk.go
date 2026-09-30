package walk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/vaultx"
)

// Level outcomes, as recorded in Result.Levels and the audit line.
const (
	LevelRead        = "read"
	LevelSkipped403  = "skipped_403"
	LevelSkipped404  = "skipped_404"
	reservedStatus   = "ironbark_status"
	vaultTokenName   = "vault_token"
	pinsKey          = "ironbark_images"
	ignoredEventsKey = "ironbark_events"
)

var validName = regexp.MustCompile(`^[a-z0-9_]+$`)

// Secret is one name the walk produced.
type Secret struct {
	Name   string
	Value  string
	Level  string   // label of the level it came from
	Images []string // pins from the mapping (or KV entry) that produced it
}

// Result is what the walk found. Secrets is sorted by name.
type Result struct {
	Secrets []Secret
	// Levels records every level's outcome by label (design §10 audit).
	Levels map[string]string
	// SkippedEntries names entries that answered 403/404 or whose resolve
	// target did, as "<level>/<key>".
	SkippedEntries []string
	// IgnoredEvents names entries still carrying ironbark_events (§8.4).
	IgnoredEvents []string
	Warnings      []string
}

// ViewError is a broken view: the read of a level entry failed (other than
// 403/404, e.g. a voidstar quarantine 502) or its answer would not decode.
// Entry is "<level>/<key>" (design §9.3).
type ViewError struct {
	Entry string
	Err   error
}

func (e *ViewError) Error() string { return "walk: view " + e.Entry + ": " + e.Err.Error() }
func (e *ViewError) Unwrap() error { return e.Err }

// Resolver reads the engine path a resolve mapping points at (§7).
type Resolver func(ctx context.Context, path string) (*vaultx.Secret, error)

// Options tunes a walk.
type Options struct {
	// Resolve overrides how a resolve mapping's target is read. Nil is the
	// intended behaviour: a plain read with the pipeline token, so the lease
	// parents to that token and is revoked with it. One hop only: the
	// response is never itself treated as a pointer.
	Resolve Resolver
}

// Walk is the §8.2 walk over lv (shallow to deep) as the client's token.
func Walk(ctx context.Context, c Client, lv []levels.Level, opt Options) (Result, error) {
	res := Result{Levels: map[string]string{}}
	if opt.Resolve == nil {
		opt.Resolve = c.Read
	}
	best := map[string]int{} // name -> level index of the value held
	held := map[string]Secret{}

	for li, l := range lv {
		keys, err := c.List(ctx, l.Metadata)
		switch {
		case errors.Is(err, vaultx.ErrForbidden):
			res.Levels[l.Label] = LevelSkipped403
			continue
		case errors.Is(err, vaultx.ErrNotFound):
			res.Levels[l.Label] = LevelSkipped404
			continue
		case err != nil:
			return res, fmt.Errorf("walk: list %s: %w", l.Metadata, err)
		}
		res.Levels[l.Label] = LevelRead
		sort.Strings(keys) // bytewise
		for _, key := range keys {
			if strings.HasSuffix(key, "/") {
				continue
			}
			entry := l.Label + "/" + key
			sec, err := c.Read(ctx, l.Data+key)
			if errors.Is(err, vaultx.ErrForbidden) || errors.Is(err, vaultx.ErrNotFound) {
				res.SkippedEntries = append(res.SkippedEntries, entry)
				continue
			}
			if err != nil {
				return res, &ViewError{Entry: entry, Err: fmt.Errorf("read %s%s: %w", l.Data, key, err)}
			}
			v, err := parseView(sec)
			if err != nil {
				return res, &ViewError{Entry: entry, Err: fmt.Errorf("read %s%s: %w", l.Data, key, err)}
			}
			if _, ok := v.meta[ignoredEventsKey]; ok {
				res.IgnoredEvents = append(res.IgnoredEvents, entry)
			}
			pins := splitPins(v.meta[pinsKey])

			put := func(name, value string) {
				if name == reservedStatus {
					res.Warnings = append(res.Warnings, entry+": name "+reservedStatus+" is reserved, skipped")
					return
				}
				if !validName.MatchString(name) {
					res.Warnings = append(res.Warnings, entry+": "+fmt.Sprintf("%q", name)+" is not a valid name, skipped")
					return
				}
				if at, ok := best[name]; ok && at == li {
					res.Warnings = append(res.Warnings, entry+": name "+name+" clashes within level "+l.Label+", first key wins")
					return
				}
				best[name] = li
				held[name] = Secret{Name: name, Value: value, Level: l.Label, Images: pins}
			}

			if key == vaultTokenName {
				if v.mode == "metadata" || len(v.data) == 0 {
					put(vaultTokenName, c.Token())
				} else {
					res.Warnings = append(res.Warnings, entry+": vault_token carries data, skipped")
				}
				continue
			}

			payload, flat := v.data, false
			if v.mode == "resolve" {
				rs, err := opt.Resolve(ctx, v.path)
				if errors.Is(err, vaultx.ErrForbidden) || errors.Is(err, vaultx.ErrNotFound) {
					res.SkippedEntries = append(res.SkippedEntries, entry)
					continue
				}
				if err != nil {
					return res, fmt.Errorf("walk: resolve %s -> %s: %w", entry, v.path, err)
				}
				payload, flat = rs.Data, true
				if inner, ok := kv2Inner(payload); ok {
					payload, flat = inner, false
				}
			}
			flatten(key, payload, flat, put, func(msg string) { res.Warnings = append(res.Warnings, entry+": "+msg) })
		}
	}
	for _, s := range held {
		res.Secrets = append(res.Secrets, s)
	}
	sort.Slice(res.Secrets, func(i, j int) bool { return res.Secrets[i].Name < res.Secrets[j].Name })
	return res, nil
}

// view is a parsed view read.
type view struct {
	data map[string]json.RawMessage
	meta map[string]string
	mode string // "" (fetch or plain KV), "resolve", "metadata"
	path string // resolve target
}

func parseView(s *vaultx.Secret) (view, error) {
	var v view
	if raw, ok := s.Data["data"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &v.data); err != nil {
			return v, fmt.Errorf("decode data: %w", err)
		}
	}
	if raw, ok := s.Data["metadata"]; ok && string(raw) != "null" {
		var m struct {
			Custom map[string]string `json:"custom_metadata"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return v, fmt.Errorf("decode metadata: %w", err)
		}
		v.meta = m.Custom
	}
	if raw, ok := s.Data["voidstar"]; ok && string(raw) != "null" {
		var m struct {
			Mode string `json:"mode"`
			Path string `json:"path"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return v, fmt.Errorf("decode voidstar: %w", err)
		}
		v.mode, v.path = m.Mode, m.Path
	}
	return v, nil
}

// kv2Inner unwraps a KV v2-shaped response body (a "data" and a "metadata"
// object side by side), as a resolve target on a KV mount returns.
func kv2Inner(d map[string]json.RawMessage) (map[string]json.RawMessage, bool) {
	rd, okd := d["data"]
	rm, okm := d["metadata"]
	if !okd || !okm {
		return nil, false
	}
	var inner, meta map[string]json.RawMessage
	if json.Unmarshal(rd, &inner) != nil || json.Unmarshal(rm, &meta) != nil {
		return nil, false
	}
	return inner, true
}

func normalize(s string) string { return strings.ReplaceAll(strings.ToLower(s), "-", "_") }

func str(raw json.RawMessage) (string, bool) {
	var s string
	if raw == nil || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// flatten applies the SPEC §4.2 names. A KV entry holding exactly {"value": s}
// is the secret named for the key; otherwise each string field is key_field
// in sorted order. A flat engine response (flat=true) is always key_field.
// Non-string fields are skipped with a warning.
func flatten(key string, d map[string]json.RawMessage, flat bool, put func(name, value string), warn func(string)) {
	base := normalize(key)
	if !flat && len(d) == 1 {
		if raw, ok := d["value"]; ok {
			if v, ok := str(raw); ok {
				put(base, v)
			} else {
				warn("value is not a string, skipped")
			}
			return
		}
	}
	fields := make([]string, 0, len(d))
	for f := range d {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		v, ok := str(d[f])
		if !ok {
			warn("field " + fmt.Sprintf("%q", f) + " is not a string, skipped")
			continue
		}
		put(base+"_"+normalize(f), v)
	}
}

func splitPins(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

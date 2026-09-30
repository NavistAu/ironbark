package walk

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/vaultx"
)

// tree is a Client over metadata-path listings and data-path reads.
type tree struct {
	lists map[string]any // metadata path -> []string | error
	reads map[string]any // data path -> *vaultx.Secret | error
	order []string       // every read, in order
}

func (f *tree) Token() string { return "PIPE" }
func (f *tree) List(_ context.Context, p string) ([]string, error) {
	switch v := f.lists[p].(type) {
	case nil:
		return nil, vaultx.ErrNotFound
	case error:
		return nil, v
	case []string:
		return append([]string(nil), v...), nil
	}
	panic("bad fake")
}
func (f *tree) Read(_ context.Context, p string) (*vaultx.Secret, error) {
	f.order = append(f.order, p)
	switch v := f.reads[p].(type) {
	case nil:
		return nil, vaultx.ErrNotFound
	case error:
		return nil, v
	case *vaultx.Secret:
		return v, nil
	}
	panic("bad fake")
}
func (f *tree) LevelMetadata(context.Context, string) (map[string]string, bool, error) {
	return nil, false, nil
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// kv builds a view/KV read: fields, custom_metadata, optional voidstar mode/path.
func kv(fields map[string]any, meta map[string]string, vs ...string) *vaultx.Secret {
	d := map[string]json.RawMessage{"data": raw(fields), "metadata": raw(map[string]any{"custom_metadata": meta})}
	if len(vs) > 0 {
		m := map[string]string{"mode": vs[0]}
		if len(vs) > 1 {
			m["path"] = vs[1]
		}
		d["voidstar"] = raw(m)
	}
	return &vaultx.Secret{Data: d}
}

func lvls() []levels.Level {
	return []levels.Level{
		{Label: ".", Data: "d/r/", Metadata: "m/r/"},
		{Label: "prod", Data: "d/r/prod/", Metadata: "m/r/prod/"},
		{Label: "prod/web", Data: "d/r/prod/web/", Metadata: "m/r/prod/web/"},
	}
}

func byName(r Result) map[string]Secret {
	m := map[string]Secret{}
	for _, s := range r.Secrets {
		m[s.Name] = s
	}
	return m
}

func warned(r Result, sub string) bool {
	for _, w := range r.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestWalkSkipsUnreadableLevelsAndReadsDeeper(t *testing.T) {
	f := &tree{
		lists: map[string]any{"m/r/": []string{"a"}, "m/r/prod/": vaultx.ErrForbidden /* prod hidden */, "m/r/prod/web/": []string{"w"}},
		reads: map[string]any{"d/r/a": kv(map[string]any{"value": "A"}, nil), "d/r/prod/web/w": kv(map[string]any{"value": "W"}, nil)},
	}
	r, err := Walk(context.Background(), f, lvls(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Levels, map[string]string{".": LevelRead, "prod": LevelSkipped403, "prod/web": LevelRead}) {
		t.Fatalf("levels = %v", r.Levels)
	}
	if g := byName(r); g["a"].Value != "A" || g["w"].Value != "W" || len(g) != 2 {
		t.Fatalf("secrets = %+v", r.Secrets)
	}
	// a 404 level is recorded too
	f.lists["m/r/prod/"] = nil
	delete(f.lists, "m/r/prod/")
	r, _ = Walk(context.Background(), f, lvls(), Options{})
	if r.Levels["prod"] != LevelSkipped404 {
		t.Fatalf("levels = %v", r.Levels)
	}
}

func TestWalkBytewiseOrderAndDirectories(t *testing.T) {
	f := &tree{
		lists: map[string]any{"m/r/": []string{"b", "sub/", "B", "a_b", "a"}},
		reads: map[string]any{
			"d/r/a": kv(map[string]any{"b": "first"}, nil), "d/r/a_b": kv(map[string]any{"value": "second"}, nil),
			"d/r/b": kv(map[string]any{"value": "b"}, nil), "d/r/B": kv(map[string]any{"value": "upper"}, nil),
		},
	}
	r, err := Walk(context.Background(), f, lvls()[:1], Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"d/r/B", "d/r/a", "d/r/a_b", "d/r/b"}; !reflect.DeepEqual(f.order, want) {
		t.Fatalf("read order = %v, want %v (bytewise, no directory)", f.order, want)
	}
	// "a" field b -> a_b comes first; key a_b clashes and loses; B lowercases to b and wins over b (first)
	g := byName(r)
	if g["a_b"].Value != "first" || g["b"].Value != "upper" {
		t.Fatalf("secrets = %+v", r.Secrets)
	}
	if !warned(r, "clashes within level") {
		t.Fatalf("no clash warning: %v", r.Warnings)
	}
}

func TestWalkDeepestWins(t *testing.T) {
	f := &tree{
		lists: map[string]any{"m/r/": []string{"db"}, "m/r/prod/": []string{"db"}, "m/r/prod/web/": []string{"db"}},
		reads: map[string]any{
			"d/r/db": kv(map[string]any{"value": "repo"}, nil), "d/r/prod/db": kv(map[string]any{"value": "env"}, nil),
			"d/r/prod/web/db": kv(map[string]any{"value": "web"}, map[string]string{pinsKey: "img/a, img/b"}),
		},
	}
	r, _ := Walk(context.Background(), f, lvls(), Options{})
	s := byName(r)["db"]
	if s.Value != "web" || s.Level != "prod/web" || !reflect.DeepEqual(s.Images, []string{"img/a", "img/b"}) {
		t.Fatalf("db = %+v", s)
	}
	if warned(r, "clash") {
		t.Fatalf("cross-level override must not warn: %v", r.Warnings)
	}
}

func TestWalkEntryErrors(t *testing.T) {
	f := &tree{
		lists: map[string]any{"m/r/": []string{"a", "b", "c"}},
		reads: map[string]any{"d/r/a": vaultx.ErrForbidden, "d/r/c": kv(map[string]any{"value": "C"}, nil)},
	}
	r, err := Walk(context.Background(), f, lvls()[:1], Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.SkippedEntries, []string{"./a", "./b"}) || byName(r)["c"].Value != "C" {
		t.Fatalf("skipped = %v secrets = %+v", r.SkippedEntries, r.Secrets)
	}
	f.reads["d/r/b"] = errors.New("boom")
	if _, err := Walk(context.Background(), f, lvls()[:1], Options{}); err == nil {
		t.Fatal("a non-403/404 read error must fail the walk")
	}
	f.lists["m/r/"] = errors.New("boom")
	if _, err := Walk(context.Background(), f, lvls()[:1], Options{}); err == nil {
		t.Fatal("a non-403/404 list error must fail the walk")
	}
}

func TestWalkNamesAndFlattening(t *testing.T) {
	f := &tree{
		lists: map[string]any{"m/r/": []string{"Api-Key", "creds", "num", "ironbark_status", "bad$key"}},
		reads: map[string]any{
			"d/r/Api-Key":         kv(map[string]any{"value": "k"}, nil),
			"d/r/creds":           kv(map[string]any{"User": "u", "pass-word": "p", "n": 3}, nil),
			"d/r/num":             kv(map[string]any{"value": 3}, nil),
			"d/r/ironbark_status": kv(map[string]any{"value": "x"}, nil),
			"d/r/bad$key":         kv(map[string]any{"value": "x"}, nil),
		},
	}
	r, _ := Walk(context.Background(), f, lvls()[:1], Options{})
	g := byName(r)
	want := map[string]string{"api_key": "k", "creds_user": "u", "creds_pass_word": "p"}
	got := map[string]string{}
	for n, s := range g {
		got[n] = s.Value
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %v", got)
	}
	for _, w := range []string{"reserved", "not a valid name", "not a string"} {
		if !warned(r, w) {
			t.Errorf("no %q warning in %v", w, r.Warnings)
		}
	}
}

func TestWalkVaultTokenMarker(t *testing.T) {
	mk := func(s *vaultx.Secret) Result {
		f := &tree{lists: map[string]any{"m/r/": []string{"vault_token"}}, reads: map[string]any{"d/r/vault_token": s}}
		r, err := Walk(context.Background(), f, lvls()[:1], Options{})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// voidstar metadata-only mapping, with pins
	r := mk(kv(map[string]any{}, map[string]string{pinsKey: "x/img"}, "metadata"))
	if s := byName(r)["vault_token"]; s.Value != "PIPE" || !reflect.DeepEqual(s.Images, []string{"x/img"}) {
		t.Fatalf("metadata marker = %+v", r.Secrets)
	}
	// plain KV v2 empty entry
	if r := mk(kv(map[string]any{}, nil)); byName(r)["vault_token"].Value != "PIPE" {
		t.Fatalf("empty KV marker = %+v", r.Secrets)
	}
	// an entry carrying data is never a token
	r = mk(kv(map[string]any{"value": "real"}, nil))
	if len(r.Secrets) != 0 || !warned(r, "vault_token carries data") {
		t.Fatalf("data entry = %+v %v", r.Secrets, r.Warnings)
	}
}

func TestWalkIgnoredEvents(t *testing.T) {
	f := &tree{lists: map[string]any{"m/r/": []string{"a"}},
		reads: map[string]any{"d/r/a": kv(map[string]any{"value": "A"}, map[string]string{ignoredEventsKey: "push"})}}
	r, _ := Walk(context.Background(), f, lvls()[:1], Options{})
	if !reflect.DeepEqual(r.IgnoredEvents, []string{"./a"}) || byName(r)["a"].Value != "A" {
		t.Fatalf("r = %+v", r)
	}
}

func TestWalkResolveHook(t *testing.T) {
	f := &tree{
		lists: map[string]any{"m/r/": []string{"aws", "gone"}},
		reads: map[string]any{
			"d/r/aws":   kv(map[string]any{}, map[string]string{pinsKey: "x/deploy"}, "resolve", "aws/creds/prod"),
			"d/r/gone":  kv(map[string]any{}, nil, "resolve", "aws/creds/none"),
		},
	}
	var asked []string
	opt := Options{Resolve: func(_ context.Context, p string) (*vaultx.Secret, error) {
		asked = append(asked, p)
		if p == "aws/creds/none" {
			return nil, vaultx.ErrForbidden
		}
		return &vaultx.Secret{LeaseID: "L", Data: map[string]json.RawMessage{
			"access_key": raw("AK"), "secret_key": raw("SK"), "ttl": raw(3600)}}, nil
	}}
	r, err := Walk(context.Background(), f, lvls()[:1], opt)
	if err != nil {
		t.Fatal(err)
	}
	g := byName(r)
	if g["aws_access_key"].Value != "AK" || g["aws_secret_key"].Value != "SK" || len(g) != 2 {
		t.Fatalf("secrets = %+v", r.Secrets)
	}
	for _, n := range []string{"aws_access_key", "aws_secret_key"} {
		if !reflect.DeepEqual(g[n].Images, []string{"x/deploy"}) {
			t.Errorf("%s pins = %v", n, g[n].Images)
		}
	}
	if !reflect.DeepEqual(r.SkippedEntries, []string{"./gone"}) {
		t.Fatalf("skipped = %v", r.SkippedEntries)
	}
	// hard error fails the walk
	opt.Resolve = func(context.Context, string) (*vaultx.Secret, error) { return nil, errors.New("engine down") }
	if _, err := Walk(context.Background(), f, lvls()[:1], opt); err == nil {
		t.Fatal("resolve error must fail the walk")
	}
	// no resolver: warned and skipped
	r, err = Walk(context.Background(), f, lvls()[:1], Options{})
	if err != nil || len(r.Secrets) != 0 || !warned(r, "no resolver") {
		t.Fatalf("r = %+v err %v", r, err)
	}
}

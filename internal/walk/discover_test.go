package walk

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/vaultx"
)

// fake is a Client over a map of paths. A missing metadata entry is 404 for
// level metadata; deny lists paths that answer 403.
type fake struct {
	lists map[string][]string
	md    map[string]map[string]string
	deny  map[string]bool
}

func (f *fake) Token() string { return "T" }
func (f *fake) List(_ context.Context, p string) ([]string, error) {
	if f.deny[p] {
		return nil, vaultx.ErrForbidden
	}
	k, ok := f.lists[p]
	if !ok {
		return nil, vaultx.ErrNotFound
	}
	return k, nil
}
func (f *fake) Read(context.Context, string) (*vaultx.Secret, error) { return nil, vaultx.ErrNotFound }
func (f *fake) LevelMetadata(_ context.Context, p string) (map[string]string, bool, error) {
	if f.deny[p] {
		return nil, false, vaultx.ErrForbidden
	}
	m, ok := f.md[p]
	return m, ok, nil
}

func tmpl(t *testing.T) grantcfg.Template {
	t.Helper()
	tm, err := grantcfg.ParseTemplate("vs/data/pipelines/{repo}/{env}/{target...}")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

const rp = "vs/metadata/pipelines/acme/mono/"

func TestDiscover(t *testing.T) {
	f := &fake{
		lists: map[string][]string{rp: {"db", "prod", "prod/", "staging", "Bad"}},
		md: map[string]map[string]string{
			rp + "db":      {"owner": "x"},
			rp + "prod":    {"branches": "main"},
			rp + "staging": {"branches": "release/*,staging"},
			rp + "Bad":     {"branches": "main"},
		},
	}
	cases := []struct {
		branch string
		want   []string
	}{
		{"main", []string{"prod"}},
		{"release/1", []string{"staging"}},
		{"feature", nil},
		{"", nil},
	}
	for _, tc := range cases {
		d, err := Discover(context.Background(), f, tmpl(t), "acme", "mono", tc.branch)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(d.Claimants, tc.want) {
			t.Errorf("branch %q: claimants %v, want %v", tc.branch, d.Claimants, tc.want)
		}
	}
}

func TestDiscoverTwoClaimants(t *testing.T) {
	f := &fake{
		lists: map[string][]string{rp: {"a", "b"}},
		md:    map[string]map[string]string{rp + "a": {"branches": "main"}, rp + "b": {"branches": "m*"}},
	}
	d, err := Discover(context.Background(), f, tmpl(t), "acme", "mono", "main")
	if err != nil || !reflect.DeepEqual(d.Claimants, []string{"a", "b"}) {
		t.Fatalf("d = %+v, err %v", d, err)
	}
}

func TestDiscoverNoRepoLevelIsNoEnvironments(t *testing.T) {
	d, err := Discover(context.Background(), &fake{}, tmpl(t), "acme", "mono", "main")
	if err != nil || len(d.Claimants) != 0 {
		t.Fatalf("d = %+v, err %v", d, err)
	}
}

func TestDiscoverHiddenLevelIsAnError(t *testing.T) {
	f := &fake{
		lists: map[string][]string{rp: {"a", "b"}},
		md:    map[string]map[string]string{rp + "a": {"branches": "main"}},
		deny:  map[string]bool{rp + "b": true},
	}
	if _, err := Discover(context.Background(), f, tmpl(t), "acme", "mono", "main"); err == nil || !errors.Is(err, vaultx.ErrForbidden) {
		t.Fatalf("err = %v", err)
	}
	f = &fake{deny: map[string]bool{rp: true}}
	if _, err := Discover(context.Background(), f, tmpl(t), "acme", "mono", "main"); err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("list 403 err = %v", err)
	}
}

func TestDiscoverLevelWithoutMetadataNeverClaims(t *testing.T) {
	f := &fake{lists: map[string][]string{rp: {"dev", "dev/"}}}
	d, err := Discover(context.Background(), f, tmpl(t), "acme", "mono", "main")
	if err != nil || len(d.Claimants) != 0 {
		t.Fatalf("d = %+v, err %v", d, err)
	}
}

func TestDiscoverReadsOnlyGrammarEntries(t *testing.T) {
	f := &fake{
		lists: map[string][]string{rp: {"Bad", "prod/"}},
		deny:  map[string]bool{rp + "Bad": true, rp + "prod/": true},
	}
	d, err := Discover(context.Background(), f, tmpl(t), "acme", "mono", "main")
	if err != nil || len(d.Claimants) != 0 {
		t.Fatalf("d = %+v, err %v", d, err)
	}
}

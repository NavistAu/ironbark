package forge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "s3cret-forge-token"

// fakeGitea serves the two Gitea endpoints. teams is the repo's team list
// (raw JSON), members maps team id → member logins, and status overrides
// a path's response status.
type fakeGitea struct {
	teamsJSON string
	members   map[string][]string
	status    map[string]int
	delay     time.Duration

	mu       sync.Mutex
	paths    []string // RawPath-or-Path per request
	authHdrs []string
}

func (f *fakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	p := r.URL.EscapedPath()
	f.paths = append(f.paths, p)
	f.authHdrs = append(f.authHdrs, r.Header.Get("Authorization"))
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-r.Context().Done():
			return
		}
	}
	if st, ok := f.status[p]; ok {
		w.WriteHeader(st)
		return
	}
	if strings.HasSuffix(p, "/teams") {
		_, _ = w.Write([]byte(f.teamsJSON))
		return
	}
	// /api/v1/teams/{id}/members/{login}
	parts := strings.Split(strings.TrimPrefix(p, "/api/v1/teams/"), "/members/")
	login, _ := url.PathUnescape(parts[1])
	for _, m := range f.members[parts[0]] {
		if m == login {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func newFake(t *testing.T, f *fakeGitea) (*Gitea, *fakeGitea) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return NewGitea(srv.URL, testToken, time.Second, nil), f
}

const twoTeams = `[{"id":1,"name":"ops"},{"id":2,"name":"dev"}]`

func TestGiteaTeams_Member(t *testing.T) {
	g, f := newFake(t, &fakeGitea{teamsJSON: twoTeams, members: map[string][]string{"1": {"a/b"}}})
	got, err := g.Teams(context.Background(), "acme", "widgets", "a/b")
	if err != nil {
		t.Fatalf("Teams: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"ops"}) {
		t.Errorf("Teams = %v, want [ops]", got)
	}
	wantPaths := []string{"/api/v1/repos/acme/widgets/teams", "/api/v1/teams/1/members/a%2Fb", "/api/v1/teams/2/members/a%2Fb"}
	if !reflect.DeepEqual(f.paths, wantPaths) {
		t.Errorf("paths = %v, want %v", f.paths, wantPaths)
	}
	for _, h := range f.authHdrs {
		if h != "token "+testToken {
			t.Errorf("Authorization = %q", h)
		}
	}
}

func TestGiteaTeams_ZeroTeams(t *testing.T) {
	g, _ := newFake(t, &fakeGitea{teamsJSON: `[]`})
	got, err := g.Teams(context.Background(), "acme", "widgets", "alice")
	if err != nil || len(got) != 0 {
		t.Errorf("Teams = %v, %v; want empty, nil", got, err)
	}
}

func TestGiteaTeams_Errors(t *testing.T) {
	cases := []struct {
		name string
		f    *fakeGitea
	}{
		{"repo teams 404", &fakeGitea{status: map[string]int{"/api/v1/repos/acme/widgets/teams": 404}}},
		{"repo teams 500", &fakeGitea{status: map[string]int{"/api/v1/repos/acme/widgets/teams": 500}}},
		{"malformed json", &fakeGitea{teamsJSON: `[{"id":`}},
		{"membership 500", &fakeGitea{teamsJSON: twoTeams, members: map[string][]string{"1": {"alice"}},
			status: map[string]int{"/api/v1/teams/2/members/alice": 500}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, _ := newFake(t, c.f)
			got, err := g.Teams(context.Background(), "acme", "widgets", "alice")
			if err == nil {
				t.Fatalf("Teams = %v, want error", got)
			}
			if got != nil {
				t.Errorf("Teams returned %v with an error, want nil", got)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error %q contains the token", err)
			}
		})
	}
}

func TestGiteaTeams_Timeout(t *testing.T) {
	srv := httptest.NewServer(&fakeGitea{teamsJSON: twoTeams, delay: 2 * time.Second})
	t.Cleanup(srv.Close)
	g := NewGitea(srv.URL, testToken, 50*time.Millisecond, nil)
	start := time.Now()
	_, err := g.Teams(context.Background(), "acme", "widgets", "alice")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d >= time.Second {
		t.Errorf("Teams took %v, want < 1s", d)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error %q contains the token", err)
	}
}

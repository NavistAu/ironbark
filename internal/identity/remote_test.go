package identity

import (
	"errors"
	"testing"
)

func TestParseRemote(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		wantOrg  string
		wantRepo string
		wantErr  bool
	}{
		{
			name:     "https with .git suffix, mixed case",
			url:      "https://git.example.com/Acme/Widgets.git",
			wantOrg:  "acme",
			wantRepo: "widgets",
		},
		{
			name:     "https with port, no .git suffix",
			url:      "https://git.example.com:8443/acme/widgets",
			wantOrg:  "acme",
			wantRepo: "widgets",
		},
		{
			name:     "ssh scheme with user and port",
			url:      "ssh://git@git.example.com:2222/acme/widgets.git",
			wantOrg:  "acme",
			wantRepo: "widgets",
		},
		{
			name:     "scp-like with user",
			url:      "git@git.example.com:acme/widgets.git",
			wantOrg:  "acme",
			wantRepo: "widgets",
		},
		{
			name:     "scp-like without user",
			url:      "git.example.com:acme/widgets",
			wantOrg:  "acme",
			wantRepo: "widgets",
		},
		{
			name:    "empty string",
			url:     "",
			wantErr: true,
		},
		{
			name:    "https with a single path segment",
			url:     "https://git.example.com/widgets",
			wantErr: true,
		},
		{
			name:    "local path, no host",
			url:     "/local/path/repo",
			wantErr: true,
		},
		{
			name:    "file scheme",
			url:     "file:///x/y",
			wantErr: true,
		},
		{
			name:    "org outside the identity charset",
			url:     "https://git.example.com/ac!me/widgets",
			wantErr: true,
		},
		{
			name:    "repo outside the identity charset (space)",
			url:     "https://git.example.com/acme/wid gets",
			wantErr: true,
		},
		{
			name:    "org is a path-traversal segment",
			url:     "https://git.example.com/../widgets",
			wantErr: true,
		},
		{
			name:    "repo is a path-traversal segment",
			url:     "https://git.example.com/acme/..",
			wantErr: true,
		},
		{
			name:    "scp-like host that is really an absolute local path",
			url:     "/local/path:acme/widgets",
			wantErr: true,
		},
		{
			name:    "scp-like host that is really a relative local path",
			url:     "./local:acme/widgets",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			org, repo, err := ParseRemote(c.url)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseRemote(%q) = (%q, %q, nil), want error", c.url, org, repo)
				}
				if !errors.Is(err, ErrInvalidRemote) {
					t.Errorf("ParseRemote(%q) error = %v, want wrapping ErrInvalidRemote", c.url, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRemote(%q): %v", c.url, err)
			}
			if org != c.wantOrg || repo != c.wantRepo {
				t.Errorf("ParseRemote(%q) = (%q, %q), want (%q, %q)", c.url, org, repo, c.wantOrg, c.wantRepo)
			}
		})
	}
}

package identity

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    Identity
		wantErr error
	}{
		{
			name: "valid payload",
			body: `{
				"repo": {"full_name": "Acme/Widgets", "forge_remote_id": "42"},
				"pipeline": {"event": "PUSH", "branch": "Main", "number": 7, "commit": "abc"}
			}`,
			want: Identity{
				Org:            "acme",
				Repo:           "widgets",
				Event:          "push",
				Branch:         "Main",
				ForgeRemoteID:  "42",
				Commit:         "abc",
				PipelineNumber: 7,
			},
		},
		{
			name:    "full_name no slash",
			body:    `{"repo": {"full_name": "noslash"}, "pipeline": {"event": "push"}}`,
			wantErr: ErrMalformed,
		},
		{
			name:    "full_name too many slashes",
			body:    `{"repo": {"full_name": "a/b/c"}, "pipeline": {"event": "push"}}`,
			wantErr: ErrMalformed,
		},
		{
			name:    "full_name empty org",
			body:    `{"repo": {"full_name": "/x"}, "pipeline": {"event": "push"}}`,
			wantErr: ErrMalformed,
		},
		{
			name:    "full_name empty repo",
			body:    `{"repo": {"full_name": "x/"}, "pipeline": {"event": "push"}}`,
			wantErr: ErrMalformed,
		},
		{
			name:    "missing repo",
			body:    `{"pipeline": {"event": "push"}}`,
			wantErr: ErrMalformed,
		},
		{
			name:    "missing full_name",
			body:    `{"repo": {}, "pipeline": {"event": "push"}}`,
			wantErr: ErrMalformed,
		},
		{
			name:    "missing pipeline.event",
			body:    `{"repo": {"full_name": "a/b"}, "pipeline": {}}`,
			wantErr: ErrMalformed,
		},
		{
			name: "missing branch is OK",
			body: `{"repo": {"full_name": "a/b"}, "pipeline": {"event": "push"}}`,
			want: Identity{
				Org:    "a",
				Repo:   "b",
				Event:  "push",
				Branch: "",
			},
		},
		{
			name: "empty branch is OK",
			body: `{"repo": {"full_name": "a/b"}, "pipeline": {"event": "push", "branch": ""}}`,
			want: Identity{
				Org:    "a",
				Repo:   "b",
				Event:  "push",
				Branch: "",
			},
		},
		{
			name: "netrc ignored",
			body: `{
				"repo": {"full_name": "a/b"},
				"pipeline": {"event": "push"},
				"netrc": {"machine": "example.com", "login": "u", "password": "p"}
			}`,
			want: Identity{
				Org:    "a",
				Repo:   "b",
				Event:  "push",
				Branch: "",
			},
		},
		{
			name:    "truncated JSON",
			body:    `{"repo": {"full_name": "a/b"`,
			wantErr: ErrMalformed,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse([]byte(c.body))

			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("Parse() err = %v, want wrapping %v", err, c.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Parse() unexpected err = %v", err)
			}
			if got != c.want {
				t.Fatalf("Parse() = %+v, want %+v", got, c.want)
			}
		})
	}
}

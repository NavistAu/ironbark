package gitenv

import (
	"reflect"
	"testing"
)

// defaultTracked is "Tracked = main, develop unless stated" per the plan's
// table (docs/plans/2026-09-28-m3-ib-client.md, Task 5).
var defaultTracked = []string{"main", "develop"}

func TestCascade(t *testing.T) {
	want := []string{
		"dev", "develop", "development", "test", "testing", "qa", "uat",
		"stage", "staging", "preprod", "trunk", "main", "master", "prod",
		"production", "live",
	}
	if !reflect.DeepEqual(Cascade, want) {
		t.Errorf("Cascade = %v, want %v", Cascade, want)
	}
}

func TestSelect(t *testing.T) {
	cases := []struct {
		name       string
		in         SelectInput
		wantBranch string
		wantRule   string
		wantErr    *SelectError
	}{
		{
			name:       "override hit",
			in:         SelectInput{Override: "develop", Tracked: defaultTracked},
			wantBranch: "develop",
			wantRule:   "override",
		},
		{
			name:    "override miss",
			in:      SelectInput{Override: "stage", Tracked: defaultTracked},
			wantErr: &SelectError{Kind: "not-tracked"},
		},
		{
			name:       "direct",
			in:         SelectInput{Current: "main", Tracked: defaultTracked},
			wantBranch: "main",
			wantRule:   "direct",
		},
		{
			name: "nearest",
			in: SelectInput{
				Current:  "feat/x",
				Tracked:  defaultTracked,
				Distance: map[string]int{"develop": 3, "main": 13},
			},
			wantBranch: "develop",
			wantRule:   "nearest",
		},
		{
			name: "tie to cascade",
			in: SelectInput{
				Current:  "fix/y",
				Tracked:  defaultTracked,
				Distance: map[string]int{"develop": 2, "main": 2},
			},
			wantBranch: "develop",
			wantRule:   "cascade",
		},
		{
			name: "tie to reflog",
			in: SelectInput{
				Current:    "fix/y",
				Tracked:    defaultTracked,
				Distance:   map[string]int{"develop": 2, "main": 2},
				ReflogFrom: "main",
			},
			wantBranch: "main",
			wantRule:   "reflog",
		},
		{
			name: "detached tie skips reflog",
			in: SelectInput{
				Detached:   true,
				Tracked:    defaultTracked,
				Distance:   map[string]int{"develop": 0, "main": 0},
				ReflogFrom: "main",
			},
			wantBranch: "develop",
			wantRule:   "cascade",
		},
		{
			name: "tie off cascade list is ambiguous",
			in: SelectInput{
				Tracked:  []string{"alpha", "beta"},
				Distance: map[string]int{"alpha": 1, "beta": 1},
			},
			wantErr: &SelectError{Kind: "ambiguous", Candidates: map[string]int{"alpha": 1, "beta": 1}},
		},
		{
			name: "no ancestor",
			in: SelectInput{
				Current: "orphan",
				Tracked: defaultTracked,
			},
			wantErr: &SelectError{Kind: "no-ancestor"},
		},
		{
			name:       "no branch tiers at all",
			in:         SelectInput{Tracked: nil},
			wantBranch: "",
			wantRule:   "no-branch-tiers",
		},
		{
			name:    "no branch tiers with override",
			in:      SelectInput{Tracked: nil, Override: "main"},
			wantErr: &SelectError{Kind: "override-without-tiers"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Select(c.in)

			if c.wantErr != nil {
				if err == nil {
					t.Fatalf("Select(%+v) = %+v, nil; want error %+v", c.in, got, c.wantErr)
				}
				serr, ok := err.(*SelectError)
				if !ok {
					t.Fatalf("Select(%+v) error type = %T, want *SelectError", c.in, err)
				}
				if serr.Kind != c.wantErr.Kind {
					t.Errorf("Select(%+v) error Kind = %q, want %q", c.in, serr.Kind, c.wantErr.Kind)
				}
				if c.wantErr.Candidates != nil && !reflect.DeepEqual(serr.Candidates, c.wantErr.Candidates) {
					t.Errorf("Select(%+v) error Candidates = %v, want %v", c.in, serr.Candidates, c.wantErr.Candidates)
				}
				return
			}

			if err != nil {
				t.Fatalf("Select(%+v) unexpected error: %v", c.in, err)
			}
			if got.Branch != c.wantBranch {
				t.Errorf("Select(%+v).Branch = %q, want %q", c.in, got.Branch, c.wantBranch)
			}
			if got.Rule != c.wantRule {
				t.Errorf("Select(%+v).Rule = %q, want %q", c.in, got.Rule, c.wantRule)
			}
		})
	}
}

// TestSelectErrorImplementsError just documents/asserts SelectError
// satisfies the error interface with a non-empty message for every Kind.
func TestSelectErrorImplementsError(t *testing.T) {
	kinds := []string{"not-tracked", "ambiguous", "no-ancestor", "override-without-tiers"}
	for _, k := range kinds {
		e := &SelectError{Kind: k, Candidates: map[string]int{"a": 1}}
		if e.Error() == "" {
			t.Errorf("SelectError{Kind:%q}.Error() is empty", k)
		}
	}
}

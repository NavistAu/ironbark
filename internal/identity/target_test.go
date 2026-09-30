package identity

import (
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in          string
		wantTarget  string
		wantInvalid bool
	}{
		{"", "", false},
		{"api", "api", false},
		{"a/b/c", "a/b/c", false},
		{"a/b/c/d/e/f/g/h", "a/b/c/d/e/f/g/h", false},
		{"a/b/c/d/e/f/g/h/i", "", true},
		{"/a", "", true},
		{"a/", "", true},
		{"a//b", "", true},
		{"/", "", true},
		{strings.Repeat("x", 256), strings.Repeat("x", 256), false},
		{strings.Repeat("x", 257), "", true},
		// "." and ".." are ordinary values: Esc makes them safe segments.
		{".", ".", false},
		{"..", "..", false},
		{"a/..", "a/..", false},
		{"Prod/EU", "Prod/EU", false},
	}
	for _, c := range cases {
		got, invalid := ParseTarget(c.in)
		if got != c.wantTarget || invalid != c.wantInvalid {
			t.Errorf("ParseTarget(%q) = (%q, %v), want (%q, %v)", c.in, got, invalid, c.wantTarget, c.wantInvalid)
		}
	}
}

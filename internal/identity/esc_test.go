package identity

import (
	"strings"
	"testing"
)

func TestEsc(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase passthrough", "main", "main"},
		{"uppercase byte encoded", "Main", "%4dain"},
		{"slash encoded", "feature/foo", "feature%2ffoo"},
		{"single dot", ".", "%2e"},
		{"double dot", "..", "%2e."},
		{"leading dot with suffix", ".foo", "%2efoo"},
		{"percent always encoded", "%4dain", "%254dain"},
		{"allowed punctuation passthrough", "a_b-c.d", "a_b-c.d"},
		{"multibyte utf8", "\xc3\xbc", "%c3%bc"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Esc(c.input)
			if got != c.expected {
				t.Errorf("Esc(%q) = %q, want %q", c.input, got, c.expected)
			}
		})
	}
}

// unescape is a test-local percent-decoder: the inverse of Esc's
// per-byte "%" + two lowercase hex digits encoding. Used to prove
// injectivity via round-trip: unescape(Esc(s)) == s for all s.
func unescape(t *testing.T, s string) string {
	t.Helper()

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			t.Fatalf("truncated percent-escape in %q at %d", s, i)
		}
		hi := unhex(t, s[i+1])
		lo := unhex(t, s[i+2])
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String()
}

func unhex(t *testing.T, c byte) byte {
	t.Helper()

	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		t.Fatalf("invalid hex digit %q", c)
		return 0
	}
}

func FuzzEscInjective(f *testing.F) {
	seeds := []string{
		"main", "Main", "feature/foo", ".", "..", ".foo",
		"%4dain", "a_b-c.d", "\xc3\xbc", "", "%", "...", "A/B/C",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		out := Esc(s)

		if strings.ContainsRune(out, '/') {
			t.Fatalf("Esc(%q) = %q contains '/'", s, out)
		}
		for i := 0; i < len(out); i++ {
			if out[i] >= 'A' && out[i] <= 'Z' {
				t.Fatalf("Esc(%q) = %q contains uppercase byte", s, out)
			}
		}
		if strings.HasPrefix(out, ".") {
			t.Fatalf("Esc(%q) = %q starts with '.'", s, out)
		}

		if got := unescape(t, out); got != s {
			t.Fatalf("round-trip failed: unescape(Esc(%q)) = %q, want %q", s, got, s)
		}
	})
}

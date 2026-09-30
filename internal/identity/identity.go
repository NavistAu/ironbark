// Package identity holds the injective esc() encoding of attacker-chosen
// names into path and claim segments, the ErrMalformed sentinel, and git
// remote parsing.
package identity

import (
	"errors"
	"strings"
)

// ErrMalformed indicates a payload that could not be parsed into an
// Identity; callers map it to HTTP 400. Use errors.Is to detect it and
// errors.Unwrap (or the error's message) for detail.
var ErrMalformed = errors.New("malformed identity payload")

// Identity is the minimal repo/event/branch identity that ib's legacy sweep
// (internal/vaultx) still takes. ironbark itself no longer builds one: its
// facts are internal/facts. Removed with the legacy sweep in phase 5.
type Identity struct {
	Org    string
	Repo   string
	Event  string
	Branch string
}

// Esc percent-encodes s per SPEC §2.2, applied bytewise to the original
// input bytes: every byte outside [a-z0-9._-] is encoded as "%" plus two
// lowercase hex digits; "%" itself is always encoded; and a leading "."
// is always encoded. The result is all-lowercase, a single path segment
// (never contains "/"), never dot-prefixed, injective, and stable.
func Esc(s string) string {
	const hex = "0123456789abcdef"

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 && c == '.' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
			continue
		}
		if isUnescaped(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}

	return b.String()
}

// isUnescaped reports whether c is in [a-z0-9._-] and is not '%'.
func isUnescaped(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '-':
		return true
	default:
		return false
	}
}

// Package identity holds payload identity extraction and encoding for
// ironbark: deriving org/repo/event/branch from a verified Woodpecker
// payload, and injectively encoding attacker-chosen branch names into
// Vault policy-name and KV-path segments (Parse arrives in a later task).
package identity

import "strings"

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

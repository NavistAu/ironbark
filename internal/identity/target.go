package identity

import "strings"

// Target grammar limits (design §1).
const (
	maxTargetBytes    = 256
	maxTargetSegments = 8
)

// ParseTarget applies the target grammar: a "/"-separated path of at most
// 8 non-empty segments and 256 bytes. "" is no target (not invalid). A
// value violating the grammar yields ("", true); the caller then requests
// no target policies and audits target_invalid. Case and "."/".." are kept:
// Esc makes every value a safe segment.
func ParseTarget(s string) (target string, invalid bool) {
	if s == "" {
		return "", false
	}
	if len(s) > maxTargetBytes {
		return "", true
	}
	segs := strings.Split(s, "/")
	if len(segs) > maxTargetSegments {
		return "", true
	}
	for _, seg := range segs {
		if seg == "" {
			return "", true
		}
	}
	return s, false
}

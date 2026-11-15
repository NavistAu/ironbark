// Package selector holds ironbark's selector logic: the environment and
// target grammars, branch-pattern claimants, and the target cascade (design
// §4.5, §4.6). Selectors choose paths; they never entitle (§3.4).
package selector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/navistau/ironbark/internal/identity"
)

// Target grammar limits (design §4.6).
const (
	maxTargetBytes    = 256
	maxTargetSegments = 8
)

var envRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidEnv reports whether s is an acceptable environment name (§4.5).
func ValidEnv(s string) bool { return envRE.MatchString(s) }

// Target is a parsed target: each segment is a level. The zero value is no
// target.
type Target struct {
	Segments []string // as given, case kept
	Escaped  []string // identity.Esc of each segment
}

// Joined is the escaped segments joined by "/" (the JWT `target` claim).
func (t Target) Joined() string { return strings.Join(t.Escaped, "/") }

// ParseTarget applies the target grammar (§4.6). "" is no target and not
// invalid. A violation returns the zero Target and a non-empty reason; the
// caller reports outcome=invalid, target_invalid. Segments that are exactly
// "." or ".." are refused (operator ruling); dotted names such as ".hidden"
// or "srv.talos" are ordinary and escaped per segment.
func ParseTarget(s string) (Target, string) {
	if s == "" {
		return Target{}, ""
	}
	if len(s) > maxTargetBytes {
		return Target{}, fmt.Sprintf("more than %d bytes", maxTargetBytes)
	}
	segs := strings.Split(s, "/")
	if len(segs) > maxTargetSegments {
		return Target{}, fmt.Sprintf("more than %d segments", maxTargetSegments)
	}
	esc := make([]string, len(segs))
	for i, seg := range segs {
		switch seg {
		case "":
			return Target{}, "empty segment"
		case ".", "..":
			return Target{}, fmt.Sprintf("dot segment %q", seg)
		}
		esc[i] = identity.Esc(seg)
	}
	return Target{Segments: segs, Escaped: esc}, ""
}

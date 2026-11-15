package selector

import (
	"path"
	"sort"
	"strings"
)

// ParseBranches splits a level's `branches` metadata (§4.5): entries are
// separated by ",", trimmed of surrounding spaces, empties dropped. Entries
// that are not valid path.Match patterns are returned as malformed and match
// nothing.
func ParseBranches(s string) (patterns, malformed []string) {
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			malformed = append(malformed, p)
			continue
		}
		patterns = append(patterns, p)
	}
	return patterns, malformed
}

// Claimants returns the levels (name -> raw `branches` metadata) that claim
// branch, sorted. Every level is tested; nothing is resolved by order or
// specificity, so two claimants are the caller's conflict to report. Matching
// is bytewise on the branch as the forge spells it. A level name outside the
// environment grammar never claims and is returned in outsideGrammar; a level
// with a malformed pattern is returned in malformed (its other patterns still
// apply). Both are sorted. An empty branch claims nothing.
func Claimants(branch string, levels map[string]string) (claimants, outsideGrammar, malformed []string) {
	for name, raw := range levels {
		if !ValidEnv(name) {
			outsideGrammar = append(outsideGrammar, name)
			continue
		}
		patterns, bad := ParseBranches(raw)
		if len(bad) > 0 {
			malformed = append(malformed, name)
		}
		if branch == "" {
			continue
		}
		for _, p := range patterns {
			if ok, err := path.Match(p, branch); err == nil && ok {
				claimants = append(claimants, name)
				break
			}
		}
	}
	sort.Strings(claimants)
	sort.Strings(outsideGrammar)
	sort.Strings(malformed)
	return claimants, outsideGrammar, malformed
}

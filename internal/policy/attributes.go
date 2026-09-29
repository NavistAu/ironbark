package policy

import (
	"sort"
	"strings"

	"github.com/navistau/ironbark/internal/identity"
)

// AttrKind is the shape of one attribute policy name (design §3).
type AttrKind int

// The five attribute shapes. Each Rel has a fixed segment count: target,
// actor and team 2; target-actor and target-team 3.
const (
	KindTargetActor AttrKind = iota
	KindTargetTeam
	KindTarget
	KindActor
	KindTeam
)

// Attr is one attribute policy name, relative to P1.
type Attr struct {
	Kind  AttrKind
	Depth int    // target depth in segments; 0 for actor/team
	Team  string // esc(team); "" unless a team kind
	Rel   string // e.g. ".target-team/a%2fb/ops"
}

// TargetPrefixes returns the "/"-prefixes of target, shallowest first:
// "a/b/c" → [a a/b a/b/c]; "" → nil.
func TargetPrefixes(target string) []string {
	if target == "" {
		return nil
	}
	segs := strings.Split(target, "/")
	out := make([]string, len(segs))
	for i := range segs {
		out[i] = strings.Join(segs[:i+1], "/")
	}
	return out
}

// Attributes returns id's attribute policy names in the design §4 sweep
// order, most specific first: for each target prefix T, deepest first,
// .target-actor/<esc T>/<esc actor> then .target-team/<esc T>/<esc team>
// per team; then .target/<esc T> deepest first; then .actor/<esc actor>;
// then .team/<esc team>. Each prefix is escaped whole, so it is one
// segment. Teams are escaped, emptied and duplicate names dropped, and
// ordered by esc(team) bytes. The policy name is P1 + "/" + Rel.
//
// Teams are only resolved when id.Actor is non-empty (the broker's job),
// so Attributes does not re-check that.
func Attributes(id identity.Identity, teams []string) []Attr {
	var prefixes []string
	if !id.TargetInvalid {
		prefixes = TargetPrefixes(id.Target)
	}
	actor := ""
	if id.Actor != "" {
		actor = identity.Esc(id.Actor)
	}
	escTeams := escapeTeams(teams)

	out := make([]Attr, 0)
	for i := len(prefixes) - 1; i >= 0; i-- {
		t, depth := identity.Esc(prefixes[i]), i+1
		if actor != "" {
			out = append(out, Attr{Kind: KindTargetActor, Depth: depth, Rel: ".target-actor/" + t + "/" + actor})
		}
		for _, tm := range escTeams {
			out = append(out, Attr{Kind: KindTargetTeam, Depth: depth, Team: tm, Rel: ".target-team/" + t + "/" + tm})
		}
	}
	for i := len(prefixes) - 1; i >= 0; i-- {
		out = append(out, Attr{Kind: KindTarget, Depth: i + 1, Rel: ".target/" + identity.Esc(prefixes[i])})
	}
	if actor != "" {
		out = append(out, Attr{Kind: KindActor, Rel: ".actor/" + actor})
	}
	for _, tm := range escTeams {
		out = append(out, Attr{Kind: KindTeam, Team: tm, Rel: ".team/" + tm})
	}
	return out
}

// escapeTeams escapes teams, drops empty names and duplicates, and sorts
// by escaped byte order.
func escapeTeams(teams []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, tm := range teams {
		if tm == "" {
			continue
		}
		e := identity.Esc(tm)
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// AttrKVPath is rel's KV prefix in the attribute mount:
// "<org>/<repo>/<event>/<rel>" (design §4).
func AttrKVPath(id identity.Identity, rel string) string {
	return id.Org + "/" + id.Repo + "/" + id.Event + "/" + rel
}

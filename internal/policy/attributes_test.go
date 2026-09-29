package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/identity"
)

func rels(as []Attr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Rel
	}
	return out
}

func manualID(target, actor string) identity.Identity {
	return identity.Identity{Org: testOrg, Repo: testRepo, Event: "manual", Target: target, Actor: actor}
}

func TestTargetPrefixes(t *testing.T) {
	cases := map[string][]string{
		"":      nil,
		"a":     {"a"},
		"a/b/c": {"a", "a/b", "a/b/c"},
	}
	for in, want := range cases {
		if got := TargetPrefixes(in); !reflect.DeepEqual(got, want) {
			t.Errorf("TargetPrefixes(%q) = %v, want %v", in, got, want)
		}
	}
}

// exampleRels is the design §4 sweep order for manual, target a/b, actor
// alice, teams [ops, dev].
var exampleRels = []string{
	".target-actor/a%2fb/alice", ".target-team/a%2fb/dev", ".target-team/a%2fb/ops",
	".target-actor/a/alice", ".target-team/a/dev", ".target-team/a/ops",
	".target/a%2fb", ".target/a", ".actor/alice", ".team/dev", ".team/ops",
}

func TestAttributes_Order(t *testing.T) {
	got := Attributes(manualID("a/b", "alice"), []string{"ops", "dev"})
	if !reflect.DeepEqual(rels(got), exampleRels) {
		t.Fatalf("Rels = %v\nwant %v", rels(got), exampleRels)
	}
	wantKind := []AttrKind{KindTargetActor, KindTargetTeam, KindTargetTeam, KindTargetActor, KindTargetTeam, KindTargetTeam,
		KindTarget, KindTarget, KindActor, KindTeam, KindTeam}
	wantDepth := []int{2, 2, 2, 1, 1, 1, 2, 1, 0, 0, 0}
	wantTeam := []string{"", "dev", "ops", "", "dev", "ops", "", "", "", "dev", "ops"}
	for i, a := range got {
		if a.Kind != wantKind[i] || a.Depth != wantDepth[i] || a.Team != wantTeam[i] {
			t.Errorf("attr %d (%s) = kind %v depth %d team %q, want %v %d %q",
				i, a.Rel, a.Kind, a.Depth, a.Team, wantKind[i], wantDepth[i], wantTeam[i])
		}
	}
}

func TestAttributes_Subsets(t *testing.T) {
	deploy := identity.Identity{Org: testOrg, Repo: testRepo, Event: "deployment", Target: "prod"}
	invalid := manualID("", "alice")
	invalid.TargetInvalid = true
	cases := []struct {
		name  string
		id    identity.Identity
		teams []string
		want  []string
	}{
		{"target only", deploy, nil, []string{".target/prod"}},
		{"actor only", manualID("", "alice"), nil, []string{".actor/alice"}},
		{"neither", manualID("", ""), nil, []string{}},
		{"invalid target", invalid, nil, []string{".actor/alice"}},
		{"duplicate and empty teams", manualID("", "alice"), []string{"ops", "ops", ""}, []string{".actor/alice", ".team/ops"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rels(Attributes(c.id, c.teams)); !reflect.DeepEqual(got, c.want) {
				t.Errorf("Rels = %v, want %v", got, c.want)
			}
		})
	}
}

// shapeSegments is the fixed segment count of each Kind's Rel.
var shapeSegments = map[AttrKind]int{KindTarget: 2, KindActor: 2, KindTeam: 2, KindTargetActor: 3, KindTargetTeam: 3}

func TestAttributes_HostileValuesEscaped(t *testing.T) {
	cases := []struct {
		name  string
		id    identity.Identity
		teams []string
		want  []string
	}{
		{"actor dot-dot slash", manualID("", "../x"), nil, []string{".actor/%2e.%2fx"}},
		{"team uppercase", manualID("", "alice"), []string{"Ops"}, []string{".actor/alice", ".team/%4fps"}},
		{"team percent", manualID("", "alice"), []string{"a%b"}, []string{".actor/alice", ".team/a%25b"}},
		{"target named like a segment", manualID(".target", ""), nil, []string{".target/%2etarget"}},
		{"target smuggling a segment", manualID("a/.actor/x", ""), nil,
			[]string{".target/a%2f.actor%2fx", ".target/a%2f.actor", ".target/a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Attributes(c.id, c.teams)
			if !reflect.DeepEqual(rels(got), c.want) {
				t.Fatalf("Rels = %v, want %v", rels(got), c.want)
			}
			for _, a := range got {
				if n := len(strings.Split(a.Rel, "/")); n != shapeSegments[a.Kind] {
					t.Errorf("%s has %d segments, want %d", a.Rel, n, shapeSegments[a.Kind])
				}
				want := "acme/widgets/manual/" + a.Rel
				if p := AttrKVPath(c.id, a.Rel); p != want {
					t.Errorf("AttrKVPath = %q, want %q", p, want)
				}
			}
		})
	}
}

func isPathPrefix(a, b string) bool {
	return a == b || strings.HasPrefix(b, a+"/")
}

func TestAttributes_NoPrefixNesting(t *testing.T) {
	var names []string
	var p1 string
	for _, target := range []string{"a", "a/b", "target", ".target"} {
		for _, actor := range []string{"alice", "target"} {
			id := manualID(target, actor)
			p1 = Derive(id, testPrefix)[0]
			for _, a := range Attributes(id, []string{"ops", "actor"}) {
				if n := len(strings.Split(a.Rel, "/")); n != shapeSegments[a.Kind] {
					t.Errorf("%s has %d segments, want %d", a.Rel, n, shapeSegments[a.Kind])
				}
				names = append(names, p1+"/"+a.Rel)
			}
		}
	}
	var p2s []string
	for _, br := range []string{"target", "actor", "team", ".target", "main"} {
		p2s = append(p2s, p1+"/"+identity.Esc(br))
	}
	for i, a := range names {
		for j, b := range names {
			if i != j && a != b && isPathPrefix(a, b) {
				t.Errorf("%s is a path-prefix of %s", a, b)
			}
		}
		for _, p2 := range p2s {
			if isPathPrefix(a, p2) || isPathPrefix(p2, a) {
				t.Errorf("%s and P2 %s nest", a, p2)
			}
		}
	}
}

func TestAttrKVPath(t *testing.T) {
	if got := AttrKVPath(manualID("", ""), ".target/a"); got != "acme/widgets/manual/.target/a" {
		t.Errorf("AttrKVPath = %q", got)
	}
}

func TestCap(t *testing.T) {
	attrs := Attributes(manualID("a/b", "alice"), []string{"ops", "dev"})
	base := []string{"ci/acme/widgets/manual"}
	allTT := []string{".target-team/a%2fb/ops", ".target-team/a%2fb/dev", ".target-team/a/ops", ".target-team/a/dev"}
	cat := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	cases := []struct {
		max         int
		wantKept    []string
		wantDropped []string
	}{
		{64, exampleRels, nil},
		{12, exampleRels, nil},
		{11, nil, []string{".target-team/a%2fb/ops"}},
		{9, nil, []string{".target-team/a%2fb/ops", ".target-team/a%2fb/dev", ".target-team/a/ops"}},
		{5, []string{".target/a%2fb", ".target/a", ".actor/alice", ".team/dev"},
			cat(allTT, []string{".target-actor/a%2fb/alice", ".target-actor/a/alice", ".team/ops"})},
		{3, []string{".target/a", ".actor/alice"},
			cat(allTT, []string{".target-actor/a%2fb/alice", ".target-actor/a/alice", ".team/ops", ".team/dev", ".target/a%2fb"})},
	}
	for _, c := range cases {
		kept, dropped := Cap(base, attrs, c.max)
		if len(dropped)+len(c.wantDropped) > 0 && !reflect.DeepEqual(rels(dropped), c.wantDropped) {
			t.Errorf("max=%d dropped = %v, want %v", c.max, rels(dropped), c.wantDropped)
		}
		if len(base)+len(kept) > c.max {
			t.Errorf("max=%d kept %d attrs over the cap", c.max, len(kept))
		}
		if c.wantKept != nil && !reflect.DeepEqual(rels(kept), c.wantKept) {
			t.Errorf("max=%d kept = %v, want %v", c.max, rels(kept), c.wantKept)
		}
	}

	// A branchful base of two plus the never-dropped actor fits max=3.
	pushID := identity.Identity{Org: testOrg, Repo: testRepo, Event: "push", Branch: "main", Actor: "alice"}
	kept, dropped := Cap(Derive(pushID, testPrefix), Attributes(pushID, nil), 3)
	if len(dropped) != 0 || !reflect.DeepEqual(rels(kept), []string{".actor/alice"}) {
		t.Errorf("push/main max=3: kept %v dropped %v", rels(kept), rels(dropped))
	}
}

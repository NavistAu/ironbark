package broker

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/identity"
)

type fakeResolver struct {
	teams []string
	err   error
	calls [][3]string
}

func (f *fakeResolver) Teams(_ context.Context, org, repo, login string) ([]string, error) {
	f.calls = append(f.calls, [3]string{org, repo, login})
	return f.teams, f.err
}

const p1Manual = "ci/acme/widgets/manual"

func manualIdentity(target, actor string) identity.Identity {
	return identity.Identity{Org: "acme", Repo: "widgets", Event: "manual", Target: target, Actor: actor,
		ForgeRemoteID: "forge-123", Commit: "deadbeef", PipelineNumber: 7}
}

func okVault() *mockVault {
	return &mockVault{canaryOK: true, base: "ci/acme/widgets", mintResult: serviceMint("tok")}
}

func prefixed(prefix string, rels ...string) []string {
	out := make([]string, len(rels))
	for i, r := range rels {
		out[i] = prefix + "/" + r
	}
	return out
}

var noTeamRels = []string{
	".target-actor/a%2fb/alice", ".target-actor/a/alice", ".target/a%2fb", ".target/a", ".actor/alice",
}

func TestHandleAttr_BackwardsCompatible(t *testing.T) {
	mv := okVault()
	res := New(mv, "ci", "").Handle(context.Background(), testIdentity())
	if res.Status != 200 {
		t.Fatalf("Status = %d", res.Status)
	}
	if !reflect.DeepEqual(mv.mintPolicies, []string{wantP1, wantP2}) {
		t.Errorf("policies = %v", mv.mintPolicies)
	}
	if len(mv.sweepAttrPaths) != 0 {
		t.Errorf("attrPaths = %v, want none", mv.sweepAttrPaths)
	}
	a := res.Audit
	if a.Teams != nil || a.TeamsError != "" || a.PoliciesDropped != nil {
		t.Errorf("new audit fields set: %+v", a)
	}
}

func TestHandleAttr_TargetAndActorNoResolver(t *testing.T) {
	mv := okVault()
	res := New(mv, "ci", "").Handle(context.Background(), manualIdentity("a/b", "alice"))
	if res.Status != 200 {
		t.Fatalf("Status = %d", res.Status)
	}
	want := append([]string{p1Manual}, prefixed(p1Manual, noTeamRels...)...)
	if !reflect.DeepEqual(mv.mintPolicies, want) || !reflect.DeepEqual(res.Audit.PoliciesRequested, want) {
		t.Errorf("policies = %v\nwant %v", mv.mintPolicies, want)
	}
	if wantPaths := prefixed("acme/widgets/manual", noTeamRels...); !reflect.DeepEqual(mv.sweepAttrPaths, wantPaths) {
		t.Errorf("attrPaths = %v\nwant %v", mv.sweepAttrPaths, wantPaths)
	}
}

func TestHandleAttr_TeamsResolved(t *testing.T) {
	mv := okVault()
	r := &fakeResolver{teams: []string{"ops"}}
	res := New(mv, "ci", "", WithTeamResolver(r)).Handle(context.Background(), manualIdentity("a", "alice"))
	if len(r.calls) != 1 || r.calls[0] != [3]string{"acme", "widgets", "alice"} {
		t.Errorf("resolver calls = %v", r.calls)
	}
	for _, n := range []string{p1Manual + "/.team/ops", p1Manual + "/.target-team/a/ops"} {
		if !contains(mv.mintPolicies, n) {
			t.Errorf("policies %v missing %s", mv.mintPolicies, n)
		}
	}
	if !reflect.DeepEqual(res.Audit.Teams, []string{"ops"}) {
		t.Errorf("Audit.Teams = %v", res.Audit.Teams)
	}
}

func TestHandleAttr_NoActorNoLookup(t *testing.T) {
	mv := okVault()
	r := &fakeResolver{teams: []string{"ops"}}
	id := manualIdentity("prod", "")
	id.Event = "deployment"
	New(mv, "ci", "", WithTeamResolver(r)).Handle(context.Background(), id)
	if len(r.calls) != 0 {
		t.Errorf("resolver called %v for an empty actor", r.calls)
	}
}

func TestHandleAttr_LookupFailsClosed(t *testing.T) {
	mv := okVault()
	r := &fakeResolver{teams: []string{"ops"}, err: errors.New("forge: status 500")}
	res := New(mv, "ci", "", WithTeamResolver(r)).Handle(context.Background(), manualIdentity("a", "alice"))
	if res.Status != 200 {
		t.Fatalf("Status = %d, want 200", res.Status)
	}
	for _, n := range mv.mintPolicies {
		if strings.Contains(n, "/.team/") || strings.Contains(n, "/.target-team/") {
			t.Errorf("team policy %s requested after a failed lookup", n)
		}
	}
	if res.Audit.TeamsError == "" || res.Audit.Teams != nil {
		t.Errorf("Audit Teams/TeamsError = %v/%q", res.Audit.Teams, res.Audit.TeamsError)
	}
	for _, n := range []string{p1Manual + "/.target/a", p1Manual + "/.actor/alice"} {
		if !contains(mv.mintPolicies, n) {
			t.Errorf("policies %v missing %s", mv.mintPolicies, n)
		}
	}
}

func TestHandleAttr_CanaryFailedNoLookup(t *testing.T) {
	mv := okVault()
	mv.canaryOK = false
	r := &fakeResolver{teams: []string{"ops"}}
	res := New(mv, "ci", "", WithTeamResolver(r)).Handle(context.Background(), manualIdentity("a", "alice"))
	if len(r.calls) != 0 {
		t.Errorf("resolver called on a failed canary")
	}
	if !reflect.DeepEqual(res.Audit.PoliciesRequested, []string{p1Manual}) {
		t.Errorf("PoliciesRequested = %v, want P1 only", res.Audit.PoliciesRequested)
	}
}

func TestHandleAttr_MaxPolicies(t *testing.T) {
	mv := okVault()
	r := &fakeResolver{teams: []string{"ops", "dev"}}
	res := New(mv, "ci", "", WithTeamResolver(r), WithMaxPolicies(3)).Handle(context.Background(), manualIdentity("a/b", "alice"))
	want := []string{p1Manual, p1Manual + "/.target/a", p1Manual + "/.actor/alice"}
	if !reflect.DeepEqual(mv.mintPolicies, want) {
		t.Errorf("policies = %v, want %v", mv.mintPolicies, want)
	}
	wantDropped := prefixed(p1Manual,
		".target-team/a%2fb/ops", ".target-team/a%2fb/dev", ".target-team/a/ops", ".target-team/a/dev",
		".target-actor/a%2fb/alice", ".target-actor/a/alice", ".team/ops", ".team/dev", ".target/a%2fb")
	if !reflect.DeepEqual(res.Audit.PoliciesDropped, wantDropped) {
		t.Errorf("PoliciesDropped = %v\nwant %v", res.Audit.PoliciesDropped, wantDropped)
	}
	if len(mv.sweepAttrPaths) != 2 {
		t.Errorf("attrPaths = %v, want 2", mv.sweepAttrPaths)
	}
}

func TestHandleAttr_Unonboarded(t *testing.T) {
	id := manualIdentity("a", "alice")
	all := append([]string{p1Manual}, prefixed(p1Manual, ".target-actor/a/alice", ".target/a", ".actor/alice")...)

	mv := okVault()
	mv.mintResult.Warnings = warningsFor(all...)
	if res := New(mv, "ci", "").Handle(context.Background(), id); res.Status != 204 || res.Outcome != OutcomeUnonboarded {
		t.Errorf("all warned: Status/Outcome = %d/%s, want 204/unonboarded", res.Status, res.Outcome)
	}

	mv = okVault()
	mv.mintResult.Warnings = warningsFor(p1Manual)
	if res := New(mv, "ci", "").Handle(context.Background(), id); res.Status != 200 {
		t.Errorf("only P1 warned: Status = %d, want 200", res.Status)
	}
}

func TestHandleAttr_InvalidTarget(t *testing.T) {
	mv := okVault()
	id := manualIdentity("", "alice")
	id.TargetInvalid = true
	New(mv, "ci", "").Handle(context.Background(), id)
	if want := []string{p1Manual, p1Manual + "/.actor/alice"}; !reflect.DeepEqual(mv.mintPolicies, want) {
		t.Errorf("policies = %v, want %v", mv.mintPolicies, want)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

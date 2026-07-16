package policy

import (
	"reflect"
	"testing"

	"ironbark/internal/identity"
)

const (
	testPrefix = "ci"
	testOrg    = "acme"
	testRepo   = "widgets"
)

func TestDerive(t *testing.T) {
	cases := []struct {
		name   string
		event  string
		branch string
		want   []string
	}{
		{"push/main", "push", "main", []string{
			"ci/acme/widgets/push",
			"ci/acme/widgets/push/main",
		}},
		{"push/Main uppercase", "push", "Main", []string{
			"ci/acme/widgets/push",
			"ci/acme/widgets/push/%4dain",
		}},
		{"push/empty branch", "push", "", []string{
			"ci/acme/widgets/push",
		}},
		{"pull_request/main", "pull_request", "main", []string{
			"ci/acme/widgets/pull_request",
			"ci/acme/widgets/pull_request/main",
		}},
		{"tag/empty", "tag", "", []string{
			"ci/acme/widgets/tag",
		}},
		{"manual/main never branchful", "manual", "main", []string{
			"ci/acme/widgets/manual",
		}},
		{"deployment/prod never branchful", "deployment", "prod", []string{
			"ci/acme/widgets/deployment",
		}},
		{"cron/nightly", "cron", "nightly", []string{
			"ci/acme/widgets/cron",
			"ci/acme/widgets/cron/nightly",
		}},
		{"cron/empty", "cron", "", []string{
			"ci/acme/widgets/cron",
		}},
		{"release/v1", "release", "v1", []string{
			"ci/acme/widgets/release",
			"ci/acme/widgets/release/v1",
		}},
		{"pull_request_closed/fix-bug slash branch", "pull_request_closed", "fix/bug", []string{
			"ci/acme/widgets/pull_request_closed",
			"ci/acme/widgets/pull_request_closed/fix%2fbug",
		}},
		{"push/feature-foo slash branch", "push", "feature/foo", []string{
			"ci/acme/widgets/push",
			"ci/acme/widgets/push/feature%2ffoo",
		}},
		{"pull_request/Main uppercase", "pull_request", "Main", []string{
			"ci/acme/widgets/pull_request",
			"ci/acme/widgets/pull_request/%4dain",
		}},
		{"tag/main branch ignored, tag never branchful", "tag", "main", []string{
			"ci/acme/widgets/tag",
		}},
		{"unknown event", "someday_event", "main", []string{
			"ci/acme/widgets/someday_event",
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := identity.Identity{Org: testOrg, Repo: testRepo, Event: c.event, Branch: c.branch}
			got := Derive(id, testPrefix)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Derive(%+v, %q) = %v, want %v", id, testPrefix, got, c.want)
			}
		})
	}
}

// TestDeriveMatrix is the full matrix per SPEC §9.2: all known events ×
// all branch shapes, asserting P2 presence tracks Branchful(event) &&
// branch != "", with the escaped segment equal to identity.Esc(branch).
func TestDeriveMatrix(t *testing.T) {
	events := []string{
		"push", "pull_request", "pull_request_closed", "tag",
		"release", "deployment", "cron", "manual",
	}
	branches := []string{"", "main", "Main", "feature/foo"}

	for _, event := range events {
		for _, branch := range branches {
			id := identity.Identity{Org: testOrg, Repo: testRepo, Event: event, Branch: branch}
			got := Derive(id, testPrefix)

			p1 := "ci/acme/widgets/" + event
			wantP2 := Branchful(event) && branch != ""

			if !wantP2 {
				want := []string{p1}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("Derive(event=%q, branch=%q) = %v, want %v", event, branch, got, want)
				}
				continue
			}

			want := []string{p1, p1 + "/" + identity.Esc(branch)}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Derive(event=%q, branch=%q) = %v, want %v", event, branch, got, want)
			}
		}
	}
}

func TestBranchful(t *testing.T) {
	branchfulEvents := []string{"push", "pull_request", "pull_request_closed", "release", "cron"}
	for _, e := range branchfulEvents {
		if !Branchful(e) {
			t.Errorf("Branchful(%q) = false, want true", e)
		}
	}

	notBranchfulEvents := []string{"tag", "manual", "deployment", "someday_event"}
	for _, e := range notBranchfulEvents {
		if Branchful(e) {
			t.Errorf("Branchful(%q) = true, want false", e)
		}
	}
}

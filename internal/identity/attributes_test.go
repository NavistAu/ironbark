package identity

// Payload fixtures in testdata/payloads/ are constructed from source
// (Woodpecker v3.18.0 server/model/pipeline.go JSON tags, generic values);
// plan Task 23 replaces the rows verified on real pipelines with redacted
// captures.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func loadPayload(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "payloads", name+".json"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// attrs is the attribute projection of an Identity under test.
type attrs struct {
	Actor         string
	Target        string
	TargetInvalid bool
	CodeAuthor    string
}

func TestParseAttributes(t *testing.T) {
	forges := []string{"none", "gitea", "github", "bitbucket"}
	// want returns the expected attributes for a fixture under actorForge.
	cases := []struct {
		fixture string
		want    func(actorForge string) attrs
	}{
		{"gitea-push", func(f string) attrs {
			a := attrs{CodeAuthor: "alice"}
			if f != "none" {
				a.Actor = "alice"
			}
			return a
		}},
		{"gitea-tag", func(f string) attrs {
			a := attrs{CodeAuthor: "alice"}
			if f != "none" {
				a.Actor = "alice"
			}
			return a
		}},
		{"gitea-pull-request", func(f string) attrs {
			a := attrs{CodeAuthor: "bob"}
			if f != "none" {
				a.Actor = "bob"
			}
			return a
		}},
		{"gitea-manual", func(string) attrs { return attrs{Actor: "carol", Target: "api/eu"} }},
		{"gitea-manual-no-target", func(string) attrs { return attrs{Actor: "carol"} }},
		{"gitea-promotion", func(string) attrs { return attrs{Target: "prod"} }},
		{"github-deployment", func(string) attrs { return attrs{Target: "production"} }},
		{"gitlab-release", func(f string) attrs {
			a := attrs{CodeAuthor: "Jane Doe"}
			if f != "none" {
				a.Actor = "Jane Doe"
			}
			return a
		}},
		{"gitlab-push", func(string) attrs { return attrs{} }},
		{"cron", func(string) attrs { return attrs{} }},
		{"unknown-event", func(string) attrs { return attrs{} }},
	}
	for _, c := range cases {
		body := loadPayload(t, c.fixture)
		for _, f := range forges {
			t.Run(c.fixture+"/"+f, func(t *testing.T) {
				id, err := Parse(body, Options{ActorForge: f, TargetVar: "DEPLOY_TO"})
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				got := attrs{id.Actor, id.Target, id.TargetInvalid, id.CodeAuthor}
				if want := c.want(f); got != want {
					t.Errorf("attrs = %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestParseAttributes_TargetVar(t *testing.T) {
	body := loadPayload(t, "gitea-manual")
	for _, tv := range []string{"TARGET", ""} {
		id, err := Parse(body, Options{TargetVar: tv})
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if id.Target != "" || id.TargetInvalid {
			t.Errorf("TargetVar=%q: Target/TargetInvalid = %q/%v, want empty/false", tv, id.Target, id.TargetInvalid)
		}
	}
}

func TestParseAttributes_InvalidTarget(t *testing.T) {
	body := strings.Replace(string(loadPayload(t, "gitea-manual")), `"api/eu"`, `"a//b"`, 1)
	id, err := Parse([]byte(body), Options{TargetVar: "DEPLOY_TO"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if id.Target != "" || !id.TargetInvalid {
		t.Errorf("Target/TargetInvalid = %q/%v, want empty/true", id.Target, id.TargetInvalid)
	}
}

func TestParsePayloadFacts(t *testing.T) {
	id, err := Parse(loadPayload(t, "gitea-promotion"), Options{TargetVar: "DEPLOY_TO"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := PayloadFacts{
		Sender:        "alice",
		Author:        "alice",
		DeployTo:      "prod",
		DeployTask:    "migrate",
		ReviewedBy:    "",
		VariableNames: []string{"BUILD_MODE", "DEPLOY_TO"},
	}
	if !reflect.DeepEqual(id.Payload, want) {
		t.Errorf("Payload = %+v, want %+v", id.Payload, want)
	}
}

package selector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/navistau/ironbark/internal/facts"
)

func payload(t *testing.T, name string, edit func(p map[string]any)) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "facts", "testdata", "payloads", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if edit == nil {
		return b
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	edit(d["pipeline"].(map[string]any))
	if b, err = json.Marshal(d); err != nil {
		t.Fatal(err)
	}
	return b
}

func sel(t *testing.T, body []byte) (Target, string, string) {
	t.Helper()
	f, err := facts.Build(context.Background(), body, nil, facts.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return SelectTarget(f, body, "DEPLOY_TO")
}

func TestSelectTargetPerEvent(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		edit    func(p map[string]any)
		segs    []string
		source  string
	}{
		{"manual variable", "gitea-manual", nil, []string{"api", "eu"}, "variable"},
		{"manual without variable", "gitea-manual-no-target", nil, nil, ""},
		{"deployment field", "gitea-promotion", nil, []string{"prod"}, "deploy_to"},
		{"deployment inherited DEPLOY_TO ignored", "gitea-promotion", func(p map[string]any) { p["deploy_to"] = "" }, nil, ""},
		{"deployment field wins over inherited variable", "gitea-promotion", func(p map[string]any) { p["deploy_to"] = "web" }, []string{"web"}, "deploy_to"},
		{"push trailer", "gitea-push-trailer", nil, []string{"web", "api"}, "trailer"},
		{"push without trailer", "gitea-push", nil, nil, ""},
		{"push ignores deploy_to field", "gitea-push", func(p map[string]any) { p["deploy_to"] = "web" }, nil, ""},
		{"push ignores variables", "gitea-push", func(p map[string]any) { p["variables"] = map[string]string{"DEPLOY_TO": "web"} }, nil, ""},
		{"manual ignores trailer", "gitea-manual-no-target", func(p map[string]any) { p["message"] = "x\n\nDeploy-To: web\n" }, nil, ""},
		{"manual ignores deploy_to field", "gitea-manual-no-target", func(p map[string]any) { p["deploy_to"] = "web" }, nil, ""},
		{"tag ignores trailer", "gitea-tag", func(p map[string]any) { p["message"] = "x\n\nDeploy-To: web\n" }, nil, ""},
		{"pull_request ignores trailer", "gitea-pull-request", func(p map[string]any) { p["message"] = "x\n\nDeploy-To: web\n" }, nil, ""},
		{"cron has no target", "cron", func(p map[string]any) { p["variables"] = map[string]string{"DEPLOY_TO": "web"} }, nil, ""},
		{"deployment trailer ignored", "gitea-promotion", func(p map[string]any) { p["deploy_to"] = ""; p["message"] = "x\n\nDeploy-To: web\n" }, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg, source, invalid := sel(t, payload(t, c.fixture, c.edit))
			if invalid != "" {
				t.Fatalf("invalid: %s", invalid)
			}
			if !reflect.DeepEqual(tg.Segments, c.segs) || source != c.source {
				t.Errorf("target %v source %q; want %v %q", tg.Segments, source, c.segs, c.source)
			}
		})
	}
}

func TestSelectTargetEscapesSegments(t *testing.T) {
	tg, _, _ := sel(t, payload(t, "gitea-manual", func(p map[string]any) {
		p["variables"] = map[string]string{"DEPLOY_TO": "Web/.hidden"}
	}))
	if tg.Joined() != "%57eb/%2ehidden" {
		t.Errorf("joined = %q", tg.Joined())
	}
}

func TestSelectTargetInvalidNeverFallsBack(t *testing.T) {
	bad := []string{".", "..", "a/../b", "a/.", "/a", "a//b", "1/2/3/4/5/6/7/8/9"}
	for _, v := range bad {
		tg, source, invalid := sel(t, payload(t, "gitea-manual", func(p map[string]any) {
			p["variables"] = map[string]string{"DEPLOY_TO": v}
		}))
		if invalid == "" || source != "variable" || len(tg.Segments) != 0 {
			t.Errorf("manual %q: %+v %q %q", v, tg, source, invalid)
		}
		tg, source, invalid = sel(t, payload(t, "gitea-promotion", func(p map[string]any) { p["deploy_to"] = v }))
		if invalid == "" || source != "deploy_to" || len(tg.Segments) != 0 {
			t.Errorf("deployment %q: %+v %q %q", v, tg, source, invalid)
		}
		tg, source, invalid = sel(t, payload(t, "gitea-push", func(p map[string]any) { p["message"] = "x\n\nDeploy-To: " + v + "\n" }))
		if invalid == "" || source != "trailer" || len(tg.Segments) != 0 {
			t.Errorf("trailer %q: %+v %q %q", v, tg, source, invalid)
		}
	}
}

func TestSelectTargetCustomVarName(t *testing.T) {
	body := payload(t, "gitea-manual", func(p map[string]any) { p["variables"] = map[string]string{"WHAT": "web", "DEPLOY_TO": "other"} })
	f, _ := facts.Build(context.Background(), body, nil, facts.Config{})
	tg, source, _ := SelectTarget(f, body, "WHAT")
	if !reflect.DeepEqual(tg.Segments, []string{"web"}) || source != "variable" {
		t.Errorf("%v %q", tg.Segments, source)
	}
}

func TestTrailer(t *testing.T) {
	cases := []struct {
		name, msg string
		segs      []string
		source    string
		invalid   bool
	}{
		{"one", "subject\n\nDeploy-To: web\n", []string{"web"}, "trailer", false},
		{"one no final newline", "subject\n\nDeploy-To: web", []string{"web"}, "trailer", false},
		{"crlf", "subject\r\n\r\nDeploy-To: web\r\n", []string{"web"}, "trailer", false},
		{"value trimmed", "subject\n\nDeploy-To:   web/api  \n", []string{"web", "api"}, "trailer", false},
		{"no space after colon", "subject\n\nDeploy-To:web\n", []string{"web"}, "trailer", false},
		{"none", "subject\n\nbody text\n", nil, "", false},
		{"subject only", "Deploy-To: web\n", nil, "", false},
		{"empty message", "", nil, "", false},
		{"two", "subject\n\nDeploy-To: web\nDeploy-To: api\n", nil, "", false},
		{"two case-variants", "subject\n\nDeploy-To: web\ndeploy-to: api\n", nil, "", false},
		{"not in final block", "subject\n\nDeploy-To: web\n\nSigned-off-by: A <a@b>\n", nil, "", false},
		{"final block has prose", "subject\n\nDeploy-To: web\nplease review\n", nil, "", false},
		{"final block among others", "subject\n\nSigned-off-by: A <a@b>\nDeploy-To: web\nReviewed-by: B <b@c>\n", []string{"web"}, "trailer", false},
		{"token case-insensitive", "subject\n\ndeploy-to: web\n", []string{"web"}, "trailer", false},
		{"different token", "subject\n\nDeploy-Tox: web\nDeployTo: web\n", nil, "", false},
		{"trailing blank lines", "subject\n\nDeploy-To: web\n\n\n", []string{"web"}, "trailer", false},
		{"empty value is invalid", "subject\n\nDeploy-To:\n", nil, "trailer", true},
		{"continuation line kept out", "subject\n\nDeploy-To: web\n  more\n", []string{"web"}, "trailer", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg, source, invalid := sel(t, payload(t, "gitea-push", func(p map[string]any) { p["message"] = c.msg }))
			if (invalid != "") != c.invalid || source != c.source || !reflect.DeepEqual(tg.Segments, c.segs) {
				t.Errorf("target %v source %q invalid %q; want %v %q invalid=%v", tg.Segments, source, invalid, c.segs, c.source, c.invalid)
			}
		})
	}
}

func TestTrailerFixture(t *testing.T) {
	tg, source, invalid := sel(t, payload(t, "gitea-push-trailer", nil))
	if invalid != "" || source != "trailer" || tg.Joined() != "web/api" {
		t.Errorf("%v %q %q", tg, source, invalid)
	}
}

func TestIgnoreWithoutEnv(t *testing.T) {
	tg, _ := ParseTarget("web/api")
	if got, ignored := IgnoreWithoutEnv(tg, ""); ignored != true || len(got.Segments) != 0 {
		t.Errorf("%+v %v", got, ignored)
	}
	if got, ignored := IgnoreWithoutEnv(tg, "prod"); ignored || !reflect.DeepEqual(got, tg) {
		t.Errorf("%+v %v", got, ignored)
	}
	if got, ignored := IgnoreWithoutEnv(Target{}, ""); ignored || len(got.Segments) != 0 {
		t.Errorf("no target: %+v %v", got, ignored)
	}
}

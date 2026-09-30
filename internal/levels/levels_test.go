package levels

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/grantcfg"
)

var update = flag.Bool("update", false, "rewrite golden policy files")

func tmpl(t *testing.T, s string) grantcfg.Template {
	t.Helper()
	tm, err := grantcfg.ParseTemplate(s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

const stdTmpl = "vs/data/pipelines/{repo}/{env}/{target...}"

func TestLevels(t *testing.T) {
	tm := tmpl(t, stdTmpl)
	cases := []struct {
		name         string
		env          string
		target       []string
		labels       []string
		lastData     string
		lastMetadata string
	}{
		{"no env", "", nil, []string{"."}, "vs/data/pipelines/acme/mono/", "vs/metadata/pipelines/acme/mono/"},
		{"no env ignores target", "", []string{"web"}, []string{"."}, "vs/data/pipelines/acme/mono/", "vs/metadata/pipelines/acme/mono/"},
		{"env", "prod", nil, []string{".", "prod"}, "vs/data/pipelines/acme/mono/prod/", "vs/metadata/pipelines/acme/mono/prod/"},
		{"target", "prod", []string{"web"}, []string{".", "prod", "prod/web"}, "vs/data/pipelines/acme/mono/prod/web/", "vs/metadata/pipelines/acme/mono/prod/web/"},
		{"nested target", "prod", []string{"web", "api"}, []string{".", "prod", "prod/web", "prod/web/api"}, "vs/data/pipelines/acme/mono/prod/web/api/", "vs/metadata/pipelines/acme/mono/prod/web/api/"},
		{"dotted segments", "prod", []string{"srv.talos", "svc", "gear"}, []string{".", "prod", "prod/srv.talos", "prod/srv.talos/svc", "prod/srv.talos/svc/gear"}, "vs/data/pipelines/acme/mono/prod/srv.talos/svc/gear/", "vs/metadata/pipelines/acme/mono/prod/srv.talos/svc/gear/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ls := Levels(tm, "acme", "mono", c.env, c.target)
			var labels []string
			for _, l := range ls {
				labels = append(labels, l.Label)
			}
			if !reflect.DeepEqual(labels, c.labels) {
				t.Fatalf("labels = %v, want %v", labels, c.labels)
			}
			last := ls[len(ls)-1]
			if last.Data != c.lastData || last.Metadata != c.lastMetadata {
				t.Errorf("last = %+v", last)
			}
			if ls[0].Data != "vs/data/pipelines/acme/mono/" {
				t.Errorf("repo level = %q", ls[0].Data)
			}
		})
	}
}

func TestLevelsTemplateVariants(t *testing.T) {
	ls := Levels(tmpl(t, "kv/data/{repo}/{env}/{target...}"), "acme", "mono", "prod", []string{"web"})
	if ls[0].Data != "kv/data/acme/mono/" || ls[2].Metadata != "kv/metadata/acme/mono/prod/web/" {
		t.Errorf("%+v", ls)
	}
	ls = Levels(tmpl(t, "vs/data/est/a/b/{repo}/{env}/{target...}"), "acme", "mono", "", nil)
	if ls[0].Data != "vs/data/est/a/b/acme/mono/" {
		t.Errorf("%+v", ls)
	}
}

const acc = "auth_jwt_1a2b3c"

func m(x string) string { return "{{identity.entity.aliases." + acc + ".metadata." + x + "}}" }

func TestRenderPoliciesSpecExample(t *testing.T) {
	project, env, target := RenderPolicies(tmpl(t, stdTmpl), acc)

	wantProject := []string{
		`path "vs/data/pipelines/` + m("org") + `/` + m("repo") + `/+" { capabilities = ["read"] }`,
		`path "vs/metadata/pipelines/` + m("org") + `/` + m("repo") + `/" { capabilities = ["list"] }`,
		`path "vs/metadata/pipelines/` + m("org") + `/` + m("repo") + `/+/" { capabilities = ["read"] }`,
	}
	assertStanzas(t, "project", project, wantProject)

	base := "vs/%s/pipelines/" + m("org") + "/" + m("repo") + "/" + m("env") + "/"
	wantEnv := []string{
		`path "` + strings.Replace(base, "%s", "data", 1) + `+" { capabilities = ["read"] }`,
		`path "` + strings.Replace(base, "%s", "metadata", 1) + `" { capabilities = ["list"] }`,
		`path "` + strings.Replace(base, "%s", "metadata", 1) + `+" { capabilities = ["read"] }`,
	}
	assertStanzas(t, "env", env, wantEnv)

	// The spec's level-2 triple, then the deepest.
	var want []string
	deep := ""
	for d := 1; d <= 8; d++ {
		deep += m("t"+string(rune('0'+d))) + "/"
		want = append(want,
			`path "`+strings.Replace(base, "%s", "data", 1)+deep+`+" { capabilities = ["read"] }`,
			`path "`+strings.Replace(base, "%s", "metadata", 1)+deep+`" { capabilities = ["list"] }`,
			`path "`+strings.Replace(base, "%s", "metadata", 1)+deep+`+" { capabilities = ["read"] }`,
		)
	}
	assertStanzas(t, "target", target, want)
	if n := len(stanzaRE.FindAllString(target, -1)); n != 24 {
		t.Errorf("target policy has %d stanzas, want 24 (8 depths x 3)", n)
	}
}

var stanzaRE = regexp.MustCompile(`(?m)^path "[^"]+" \{ capabilities = \["[a-z]+"\] \}$`)

func assertStanzas(t *testing.T, name, got string, want []string) {
	t.Helper()
	have := stanzaRE.FindAllString(got, -1)
	if !reflect.DeepEqual(have, want) {
		t.Errorf("%s stanzas:\n got %s\nwant %s", name, strings.Join(have, "\n     "), strings.Join(want, "\n     "))
	}
}

func TestRenderPoliciesNoStanzaEndsInStar(t *testing.T) {
	pathRE := regexp.MustCompile(`path "([^"]+)"`)
	for _, ts := range []string{stdTmpl, "kv/data/{repo}/{env}/{target...}", "vs/data/a/b/c/{repo}/{env}/{target...}"} {
		p, e, tg := RenderPolicies(tmpl(t, ts), acc)
		for _, pol := range []string{p, e, tg} {
			for _, m := range pathRE.FindAllStringSubmatch(pol, -1) {
				if strings.HasSuffix(m[1], "*") || strings.Contains(m[1], "*") {
					t.Errorf("template %s: stanza path %q contains *", ts, m[1])
				}
			}
			if !strings.HasSuffix(strings.TrimSpace(pol), "}") {
				t.Errorf("policy does not end in a stanza")
			}
		}
	}
}

func TestRenderPoliciesGolden(t *testing.T) {
	project, env, target := RenderPolicies(tmpl(t, stdTmpl), acc)
	for name, got := range map[string]string{"ci-project.hcl": project, "ci-env.hcl": env, "ci-target.hcl": target} {
		file := filepath.Join("testdata", name)
		if *update {
			if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(want) != got {
			t.Errorf("%s differs from golden (rerun with -update to accept)", name)
		}
	}
}

func TestRenderPoliciesUsesTemplatePrefix(t *testing.T) {
	p, _, _ := RenderPolicies(tmpl(t, "kv/data/{repo}/{env}/{target...}"), acc)
	if !strings.Contains(p, `path "kv/data/`+m("org")+`/`+m("repo")+`/+"`) || !strings.Contains(p, `path "kv/metadata/`) {
		t.Errorf("%s", p)
	}
}

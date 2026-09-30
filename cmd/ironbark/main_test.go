package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func runArgs(t *testing.T, args []string, e map[string]string) (code int, out, errOut string) {
	t.Helper()
	var o, er bytes.Buffer
	code = run(args, env(e), os.ReadFile, &o, &er)
	return code, o.String(), er.String()
}

const dataPath = "vs/data/pipelines/{repo}/{env}/{target...}"

func TestRenderPoliciesMatchesLevelsGolden(t *testing.T) {
	code, out, errOut := runArgs(t, []string{"render-policies", "-accessor", "auth_jwt_1a2b3c"}, map[string]string{"IRONBARK_DATA_PATH": dataPath})
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	// The same golden files internal/levels checks: the subcommand prints
	// exactly RenderPolicies, in project, env, target order.
	var want string
	for _, f := range []string{"ci-project.hcl", "ci-env.hcl", "ci-target.hcl"} {
		b, err := os.ReadFile("../../internal/levels/testdata/" + f)
		if err != nil {
			t.Fatal(err)
		}
		want += string(b) + "\n"
	}
	if out != want {
		t.Errorf("output differs from levels golden:\n%s", out)
	}
}

func TestRenderPoliciesNeedsNoOtherConfig(t *testing.T) {
	// Only IRONBARK_DATA_PATH is set: no key, no vault address, no forge.
	if code, _, e := runArgs(t, []string{"render-policies", "-accessor", "a"}, map[string]string{"IRONBARK_DATA_PATH": dataPath}); code != 0 {
		t.Fatalf("code=%d %s", code, e)
	}
}

func TestRenderPoliciesErrors(t *testing.T) {
	cases := map[string]struct {
		args []string
		env  map[string]string
		want string
	}{
		"no accessor":   {[]string{"render-policies"}, map[string]string{"IRONBARK_DATA_PATH": dataPath}, "-accessor"},
		"no data path":  {[]string{"render-policies", "-accessor", "a"}, nil, "IRONBARK_DATA_PATH"},
		"bad data path": {[]string{"render-policies", "-accessor", "a"}, map[string]string{"IRONBARK_DATA_PATH": "vs/data/{env}"}, "IRONBARK_DATA_PATH"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, e := runArgs(t, c.args, c.env)
			if code == 0 || out != "" || !strings.Contains(e, c.want) {
				t.Errorf("code=%d out=%q err=%q", code, out, e)
			}
		})
	}
}

func TestUnknownSubcommand(t *testing.T) {
	code, _, e := runArgs(t, []string{"frobnicate"}, nil)
	if code != 2 || !strings.Contains(e, "frobnicate") {
		t.Errorf("code=%d err=%q", code, e)
	}
}

func TestServeFailsOnIncompleteConfig(t *testing.T) {
	code, _, e := runArgs(t, nil, map[string]string{"IRONBARK_DATA_PATH": dataPath, "IRONBARK_VAULT_ADDR": "http://x"})
	if code != 1 || !strings.Contains(e, "config") || !strings.Contains(e, "IRONBARK_") {
		t.Errorf("code=%d err=%q", code, e)
	}
}

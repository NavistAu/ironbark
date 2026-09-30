package grantcfg

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func baseEnv(t *testing.T) (map[string]string, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"IRONBARK_WOODPECKER_PUBLIC_KEY": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		"IRONBARK_VAULT_ADDR":            "https://vault.example.com",
		"IRONBARK_DATA_PATH":             "vs/data/pipelines/{repo}/{env}/{target...}",
		"IRONBARK_JWT_SIGNING_KEY":       "PEM-PLACEHOLDER",
	}, pub
}

func getenv(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func readFile(files map[string][]byte) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		b, ok := files[p]
		if !ok {
			return nil, errors.New("no such file: " + p)
		}
		return b, nil
	}
}

func TestLoadDefaults(t *testing.T) {
	env, pub := baseEnv(t)
	cfg, err := Load(getenv(env), readFile(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnvVar != "DEPLOY_ENV" || cfg.TargetVar != "DEPLOY_TO" || cfg.JWTRole != "ci-{env}" || cfg.JWTMount != "jwt" {
		t.Errorf("defaults: %+v", cfg)
	}
	if cfg.ListenAddr != ":8080" || cfg.LogLevel != "info" || cfg.FreshnessWindow != 10*time.Second {
		t.Errorf("plumbing defaults: %+v", cfg)
	}
	if !cfg.WoodpeckerPublicKey.Equal(pub) {
		t.Error("public key not parsed")
	}
	if cfg.JWTSigningKeyPEM != "PEM-PLACEHOLDER" {
		t.Errorf("signing key = %q", cfg.JWTSigningKeyPEM)
	}
	if cfg.ForgeProvider != "none" || cfg.ActorForge != "none" || cfg.ForgeTimeout != 3*time.Second {
		t.Errorf("forge defaults: %+v", cfg)
	}
}

func TestLoadRequired(t *testing.T) {
	for _, name := range []string{"IRONBARK_WOODPECKER_PUBLIC_KEY", "IRONBARK_VAULT_ADDR", "IRONBARK_DATA_PATH", "IRONBARK_JWT_SIGNING_KEY"} {
		t.Run(name, func(t *testing.T) {
			env, _ := baseEnv(t)
			delete(env, name)
			_, err := Load(getenv(env), readFile(nil))
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want mention of %s", err, name)
			}
		})
	}
}

func TestLoadFileVariants(t *testing.T) {
	env, _ := baseEnv(t)
	delete(env, "IRONBARK_JWT_SIGNING_KEY")
	env["IRONBARK_JWT_SIGNING_KEY_FILE"] = "/k.pem"
	cfg, err := Load(getenv(env), readFile(map[string][]byte{"/k.pem": []byte("  FROM-FILE\n")}))
	if err != nil || cfg.JWTSigningKeyPEM != "FROM-FILE" {
		t.Fatalf("cfg=%q err=%v", cfg.JWTSigningKeyPEM, err)
	}

	env["IRONBARK_JWT_SIGNING_KEY"] = "inline"
	if _, err := Load(getenv(env), readFile(map[string][]byte{"/k.pem": []byte("x")})); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("both set: err = %v", err)
	}
	delete(env, "IRONBARK_JWT_SIGNING_KEY")
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_JWT_SIGNING_KEY_FILE") {
		t.Errorf("unreadable: err = %v", err)
	}
	env["IRONBARK_JWT_SIGNING_KEY_FILE"] = "/empty"
	if _, err := Load(getenv(env), readFile(map[string][]byte{"/empty": []byte("\n")})); err == nil || !strings.Contains(err.Error(), "is required") {
		t.Errorf("empty file: err = %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	env, _ := baseEnv(t)
	env["IRONBARK_ENV_VAR"] = "WHERE"
	env["IRONBARK_TARGET_VAR"] = "WHAT"
	env["IRONBARK_JWT_ROLE"] = "{env}-ci"
	env["IRONBARK_JWT_MOUNT"] = "ib"
	env["IRONBARK_FRESHNESS_WINDOW"] = "30s"
	cfg, err := Load(getenv(env), readFile(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnvVar != "WHERE" || cfg.TargetVar != "WHAT" || cfg.JWTRole != "{env}-ci" || cfg.JWTMount != "ib" || cfg.FreshnessWindow != 30*time.Second {
		t.Errorf("%+v", cfg)
	}
	env["IRONBARK_FRESHNESS_WINDOW"] = "soon"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_FRESHNESS_WINDOW") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadSelectorVarClash(t *testing.T) {
	env, _ := baseEnv(t)
	env["IRONBARK_ENV_VAR"] = "X"
	env["IRONBARK_TARGET_VAR"] = "X"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_ENV_VAR") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadRoleTemplate(t *testing.T) {
	env, _ := baseEnv(t)
	env["IRONBARK_JWT_ROLE"] = "{env}"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_JWT_ROLE") {
		t.Errorf("empty no-env role: err = %v", err)
	}
	env["IRONBARK_JWT_ROLE"] = "ci-{env}-{env}"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_JWT_ROLE") {
		t.Errorf("double {env}: err = %v", err)
	}
	env["IRONBARK_JWT_ROLE"] = "ci-{other}"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_JWT_ROLE") {
		t.Errorf("unknown placeholder: err = %v", err)
	}
}

func TestLoadForge(t *testing.T) {
	env, _ := baseEnv(t)
	env["IRONBARK_FORGE_PROVIDER"] = "gitea"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_FORGE_URL") {
		t.Errorf("missing url: %v", err)
	}
	env["IRONBARK_FORGE_URL"] = "not a url"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_FORGE_URL") {
		t.Errorf("bad url: %v", err)
	}
	env["IRONBARK_FORGE_URL"] = "https://git.example.com"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_FORGE_TOKEN") {
		t.Errorf("missing token: %v", err)
	}
	env["IRONBARK_FORGE_TOKEN_FILE"] = "/t"
	cfg, err := Load(getenv(env), readFile(map[string][]byte{"/t": []byte("tok\n")}))
	if err != nil || cfg.ForgeToken != "tok" || len(cfg.Warnings) != 0 {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	env["IRONBARK_ACTOR_FORGE"] = "github"
	if _, err := Load(getenv(env), readFile(map[string][]byte{"/t": []byte("tok")})); err == nil || !strings.Contains(err.Error(), "IRONBARK_ACTOR_FORGE") {
		t.Errorf("actor/provider mismatch: %v", err)
	}
	env["IRONBARK_ACTOR_FORGE"] = "bogus"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_ACTOR_FORGE") {
		t.Errorf("bogus actor: %v", err)
	}
	env["IRONBARK_ACTOR_FORGE"] = "none"
	env["IRONBARK_FORGE_PROVIDER"] = "bogus"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_FORGE_PROVIDER") {
		t.Errorf("bogus provider: %v", err)
	}
	env["IRONBARK_FORGE_PROVIDER"] = "gitea"
	env["IRONBARK_FORGE_TIMEOUT"] = "-1s"
	if _, err := Load(getenv(env), readFile(nil)); err == nil || !strings.Contains(err.Error(), "IRONBARK_FORGE_TIMEOUT") {
		t.Errorf("bad timeout: %v", err)
	}
}

func TestLoadForgeNoneWarns(t *testing.T) {
	env, _ := baseEnv(t)
	cfg, err := Load(getenv(env), readFile(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "branch_protected") {
		t.Errorf("warnings = %v", cfg.Warnings)
	}
}

func TestParseTemplate(t *testing.T) {
	good, err := ParseTemplate("vs/data/pipelines/{repo}/{env}/{target...}")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(good.Prefix, "/"); got != "vs/data/pipelines" {
		t.Errorf("prefix = %q", got)
	}
	if got := good.MetadataPrefix(); strings.Join(got, "/") != "vs/metadata/pipelines" {
		t.Errorf("metadata prefix = %v", got)
	}
	if _, err := ParseTemplate("kv/data/{repo}/{env}/{target...}"); err != nil {
		t.Errorf("no estate segment: %v", err)
	}

	bad := map[string]string{
		"":                            "empty",
		"vs/data/x/{env}/{target...}": "{repo}",
		"vs/data/{repo}/{repo}/{env}/{target...}":        "{repo}",
		"vs/meta/x/{repo}/{env}/{target...}":             "data",
		"vs/x/{repo}/{env}/{target...}":                  "data",
		"{repo}/{env}/{target...}":                       "data",
		"vs/data/x/{repo}/{target...}/{env}":             "order",
		"vs/data/x/{repo}/{env}":                         "{target...}",
		"vs/data/x/{repo}/{target...}":                   "{env}",
		"vs/data/x/{repo}/{env}/{target...}/z":           "last",
		"vs/data/x/{repo}/z/{env}/{target...}":           "adjacent",
		"vs/data/x/{repo}/{env}/{target...}/":            "empty segment",
		"vs/data//x/{repo}/{env}/{target...}":            "empty segment",
		"/vs/data/x/{repo}/{env}/{target...}":            "empty segment",
		"vs/data/pre{repo}/{env}/{target...}":            "whole",
		"vs/data/{other}/{repo}/{env}/{target...}":       "placeholder",
		"vs/data/x/{repo}/{env}/{target}":                "{target...}",
		"vs/data/x/{repo}/{env}/{target...}/{target...}": "exactly once",
		"vs/data/x/{repo}/{env}/{env}/{target...}":       "{env}",
		"vs/data/x/../{repo}/{env}/{target...}":          "..",
	}
	for in, want := range bad {
		_, err := ParseTemplate(in)
		if err == nil {
			t.Errorf("%q accepted", in)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %q lacks %q", in, err, want)
		}
	}
}

func TestRenderRole(t *testing.T) {
	cases := []struct{ tmpl, env, want string }{
		{"ci-{env}", "staging", "ci-staging"},
		{"ci-{env}", "", "ci"},
		{"{env}-ci", "prod", "prod-ci"},
		{"{env}-ci", "", "ci"},
		{"ci.{env}", "prod", "ci.prod"},
		{"ci.{env}", "", "ci"},
		{"ci_{env}", "", "ci"},
		{"{env}", "prod", "prod"},
		{"{env}", "", ""},
		{"ci-{env}-x", "", "ci-x"},
		{"ci", "prod", "ci"},
		{"ci", "", "ci"},
		{"ci--{env}", "", "ci-"},
	}
	for _, c := range cases {
		if got := RenderRole(c.tmpl, c.env); got != c.want {
			t.Errorf("RenderRole(%q,%q) = %q, want %q", c.tmpl, c.env, got, c.want)
		}
	}
}

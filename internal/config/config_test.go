package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// testPub generates a fresh ed25519 keypair and returns the public key
// PEM-encoded (PKIX), matching the shape Woodpecker's own verification
// key ships in (docs/woodpecker-secret-mechanisms.md §3).
func testPub(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return pub, string(pem.EncodeToMemory(block))
}

// baseEnv returns a minimal env satisfying every required var, and the
// generated public key so tests can assert on the parsed value.
func baseEnv(t *testing.T) (map[string]string, ed25519.PublicKey) {
	t.Helper()
	pub, pubPEM := testPub(t)
	return map[string]string{
		"IRONBARK_WOODPECKER_PUBLIC_KEY": pubPEM,
		"IRONBARK_VAULT_ADDR":            "https://vault.example.com",
		"IRONBARK_VAULT_ROLE_ID":         "role-id-value",
		"IRONBARK_VAULT_SECRET_ID":       "secret-id-value",
	}, pub
}

func fakeGetenv(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

func fakeReadFile(files map[string][]byte) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		b, ok := files[path]
		if !ok {
			return nil, errors.New("no such file: " + path)
		}
		return b, nil
	}
}

func TestLoad(t *testing.T) {
	t.Run("defaults applied", func(t *testing.T) {
		env, pub := baseEnv(t)

		cfg, err := Load(fakeGetenv(env), fakeReadFile(nil))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if cfg.ListenAddr != ":8080" {
			t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
		}
		if cfg.TokenRole != "ci" {
			t.Errorf("TokenRole = %q, want ci", cfg.TokenRole)
		}
		if cfg.KVMount != "kv" {
			t.Errorf("KVMount = %q, want kv", cfg.KVMount)
		}
		if cfg.KVPrefix != "ci" {
			t.Errorf("KVPrefix = %q, want ci", cfg.KVPrefix)
		}
		if cfg.PolicyPrefix != "ci" {
			t.Errorf("PolicyPrefix = %q, want ci", cfg.PolicyPrefix)
		}
		if cfg.FreshnessWindow != 10*time.Second {
			t.Errorf("FreshnessWindow = %v, want 10s", cfg.FreshnessWindow)
		}
		if cfg.AdvertiseVaultAddr != "" {
			t.Errorf("AdvertiseVaultAddr = %q, want empty", cfg.AdvertiseVaultAddr)
		}
		if cfg.LogLevel != "info" {
			t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
		}
		if cfg.VaultAddr != "https://vault.example.com" {
			t.Errorf("VaultAddr = %q, want https://vault.example.com", cfg.VaultAddr)
		}
		if cfg.VaultRoleID != "role-id-value" {
			t.Errorf("VaultRoleID = %q, want role-id-value", cfg.VaultRoleID)
		}
		if cfg.VaultSecretID != "secret-id-value" {
			t.Errorf("VaultSecretID = %q, want secret-id-value", cfg.VaultSecretID)
		}
		if !pub.Equal(cfg.WoodpeckerPublicKey) {
			t.Errorf("WoodpeckerPublicKey mismatch")
		}
	})

	t.Run("all overrides applied", func(t *testing.T) {
		env, _ := baseEnv(t)
		env["IRONBARK_LISTEN_ADDR"] = "127.0.0.1:9090"
		env["IRONBARK_TOKEN_ROLE"] = "custom-role"
		env["IRONBARK_KV_MOUNT"] = "secret"
		env["IRONBARK_KV_PREFIX"] = "prefix"
		env["IRONBARK_POLICY_PREFIX"] = "polprefix"
		env["IRONBARK_FRESHNESS_WINDOW"] = "30s"
		env["IRONBARK_ADVERTISE_VAULT_ADDR"] = "https://advertised.example.com"
		env["IRONBARK_LOG_LEVEL"] = "debug"

		cfg, err := Load(fakeGetenv(env), fakeReadFile(nil))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if cfg.ListenAddr != "127.0.0.1:9090" {
			t.Errorf("ListenAddr = %q", cfg.ListenAddr)
		}
		if cfg.TokenRole != "custom-role" {
			t.Errorf("TokenRole = %q", cfg.TokenRole)
		}
		if cfg.KVMount != "secret" {
			t.Errorf("KVMount = %q", cfg.KVMount)
		}
		if cfg.KVPrefix != "prefix" {
			t.Errorf("KVPrefix = %q", cfg.KVPrefix)
		}
		if cfg.PolicyPrefix != "polprefix" {
			t.Errorf("PolicyPrefix = %q", cfg.PolicyPrefix)
		}
		if cfg.FreshnessWindow != 30*time.Second {
			t.Errorf("FreshnessWindow = %v", cfg.FreshnessWindow)
		}
		if cfg.AdvertiseVaultAddr != "https://advertised.example.com" {
			t.Errorf("AdvertiseVaultAddr = %q", cfg.AdvertiseVaultAddr)
		}
		if cfg.LogLevel != "debug" {
			t.Errorf("LogLevel = %q", cfg.LogLevel)
		}
	})

	t.Run("missing required vars error by name", func(t *testing.T) {
		required := []string{
			"IRONBARK_WOODPECKER_PUBLIC_KEY",
			"IRONBARK_VAULT_ADDR",
			"IRONBARK_VAULT_ROLE_ID",
			"IRONBARK_VAULT_SECRET_ID",
		}
		for _, name := range required {
			t.Run(name, func(t *testing.T) {
				env, _ := baseEnv(t)
				delete(env, name)

				_, err := Load(fakeGetenv(env), fakeReadFile(nil))
				if err == nil {
					t.Fatalf("Load: expected error for missing %s, got nil", name)
				}
				if !strings.Contains(err.Error(), name) {
					t.Errorf("Load error = %q, want it to name %s", err.Error(), name)
				}
			})
		}
	})

	t.Run("_FILE variant reads file", func(t *testing.T) {
		cases := []struct {
			varName string
			path    string
			content string
		}{
			{"IRONBARK_WOODPECKER_PUBLIC_KEY", "/etc/secret/pubkey.pem", ""}, // content filled below
			{"IRONBARK_VAULT_ROLE_ID", "/etc/secret/role-id", "role-id-from-file"},
			{"IRONBARK_VAULT_SECRET_ID", "/etc/secret/secret-id", "secret-id-from-file"},
		}

		_, pubPEM := testPub(t)
		cases[0].content = pubPEM

		for _, c := range cases {
			t.Run(c.varName, func(t *testing.T) {
				env, _ := baseEnv(t)
				delete(env, c.varName)
				env[c.varName+"_FILE"] = c.path

				files := map[string][]byte{c.path: []byte(c.content)}

				cfg, err := Load(fakeGetenv(env), fakeReadFile(files))
				if err != nil {
					t.Fatalf("Load: %v", err)
				}

				switch c.varName {
				case "IRONBARK_WOODPECKER_PUBLIC_KEY":
					if len(cfg.WoodpeckerPublicKey) == 0 {
						t.Errorf("WoodpeckerPublicKey not set from file")
					}
				case "IRONBARK_VAULT_ROLE_ID":
					if cfg.VaultRoleID != c.content {
						t.Errorf("VaultRoleID = %q, want %q", cfg.VaultRoleID, c.content)
					}
				case "IRONBARK_VAULT_SECRET_ID":
					if cfg.VaultSecretID != c.content {
						t.Errorf("VaultSecretID = %q, want %q", cfg.VaultSecretID, c.content)
					}
				}
			})
		}
	})

	t.Run("var and _FILE both set errors", func(t *testing.T) {
		names := []string{
			"IRONBARK_WOODPECKER_PUBLIC_KEY",
			"IRONBARK_VAULT_ROLE_ID",
			"IRONBARK_VAULT_SECRET_ID",
		}
		for _, name := range names {
			t.Run(name, func(t *testing.T) {
				env, _ := baseEnv(t)
				env[name+"_FILE"] = "/some/path"

				files := map[string][]byte{"/some/path": []byte("whatever")}

				_, err := Load(fakeGetenv(env), fakeReadFile(files))
				if err == nil {
					t.Fatalf("Load: expected ambiguity error for %s, got nil", name)
				}
				if !strings.Contains(err.Error(), name) {
					t.Errorf("Load error = %q, want it to name %s", err.Error(), name)
				}
			})
		}
	})

	t.Run("_FILE containing only whitespace errors as required", func(t *testing.T) {
		names := []string{
			"IRONBARK_WOODPECKER_PUBLIC_KEY",
			"IRONBARK_VAULT_ROLE_ID",
			"IRONBARK_VAULT_SECRET_ID",
		}
		for _, name := range names {
			t.Run(name, func(t *testing.T) {
				env, _ := baseEnv(t)
				delete(env, name)
				env[name+"_FILE"] = "/some/path"

				files := map[string][]byte{"/some/path": []byte("\n")}

				_, err := Load(fakeGetenv(env), fakeReadFile(files))
				if err == nil {
					t.Fatalf("Load: expected required error for whitespace-only %s_FILE, got nil", name)
				}
				if !strings.Contains(err.Error(), name) {
					t.Errorf("Load error = %q, want it to name %s", err.Error(), name)
				}
			})
		}
	})

	t.Run("env var value is trimmed", func(t *testing.T) {
		env, _ := baseEnv(t)
		env["IRONBARK_VAULT_ROLE_ID"] = "role-id-value\n"

		cfg, err := Load(fakeGetenv(env), fakeReadFile(nil))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.VaultRoleID != "role-id-value" {
			t.Errorf("VaultRoleID = %q, want %q (trailing newline trimmed)", cfg.VaultRoleID, "role-id-value")
		}
	})

	t.Run("bad PEM errors", func(t *testing.T) {
		env, _ := baseEnv(t)
		env["IRONBARK_WOODPECKER_PUBLIC_KEY"] = "not a pem block"

		_, err := Load(fakeGetenv(env), fakeReadFile(nil))
		if err == nil {
			t.Fatalf("Load: expected error for bad PEM, got nil")
		}
		if !strings.Contains(err.Error(), "IRONBARK_WOODPECKER_PUBLIC_KEY") {
			t.Errorf("Load error = %q, want it to name IRONBARK_WOODPECKER_PUBLIC_KEY", err.Error())
		}
	})

	t.Run("malformed PKIX key errors", func(t *testing.T) {
		env, _ := baseEnv(t)
		// A syntactically valid PEM block whose payload is not valid PKIX
		// DER at all — fails at x509.ParsePKIXPublicKey (parse path).
		block := &pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not-a-real-der-payload")}
		env["IRONBARK_WOODPECKER_PUBLIC_KEY"] = string(pem.EncodeToMemory(block))

		_, err := Load(fakeGetenv(env), fakeReadFile(nil))
		if err == nil {
			t.Fatalf("Load: expected error for invalid PKIX key, got nil")
		}
	})

	t.Run("wrong-algorithm PKIX key errors", func(t *testing.T) {
		env, _ := baseEnv(t)
		// A well-formed PKIX public key of the WRONG algorithm (RSA, not
		// ed25519) — parses fine at x509.ParsePKIXPublicKey, so this
		// exercises the ed25519 type-assertion rejection path instead.
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
		env["IRONBARK_WOODPECKER_PUBLIC_KEY"] = string(pem.EncodeToMemory(block))

		_, err = Load(fakeGetenv(env), fakeReadFile(nil))
		if err == nil {
			t.Fatalf("Load: expected error for non-ed25519 PKIX key, got nil")
		}
		if !strings.Contains(err.Error(), "not an ed25519 public key") {
			t.Errorf("Load error = %q, want it to contain %q", err.Error(), "not an ed25519 public key")
		}
		if !strings.Contains(err.Error(), "IRONBARK_WOODPECKER_PUBLIC_KEY") {
			t.Errorf("Load error = %q, want it to name IRONBARK_WOODPECKER_PUBLIC_KEY", err.Error())
		}
	})

	t.Run("bad duration errors", func(t *testing.T) {
		env, _ := baseEnv(t)
		env["IRONBARK_FRESHNESS_WINDOW"] = "not-a-duration"

		_, err := Load(fakeGetenv(env), fakeReadFile(nil))
		if err == nil {
			t.Fatalf("Load: expected error for bad duration, got nil")
		}
		if !strings.Contains(err.Error(), "IRONBARK_FRESHNESS_WINDOW") {
			t.Errorf("Load error = %q, want it to name IRONBARK_FRESHNESS_WINDOW", err.Error())
		}
	})
}

// loadCase is one table row for the pipeline-attribute config vars: env
// overrides on top of baseEnv, and either an error naming wantErrVar or a
// check on the loaded Config.
type loadCase struct {
	name       string
	env        map[string]string
	files      map[string][]byte
	wantErrVar string // non-empty → Load must fail naming this var
	check      func(t *testing.T, cfg Config)
}

func runLoadCases(t *testing.T, cases []loadCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, _ := baseEnv(t)
			for k, v := range c.env {
				env[k] = v
			}
			cfg, err := Load(fakeGetenv(env), fakeReadFile(c.files))
			if c.wantErrVar != "" {
				if err == nil {
					t.Fatalf("Load: expected error naming %s, got nil", c.wantErrVar)
				}
				if !strings.Contains(err.Error(), c.wantErrVar) {
					t.Errorf("Load error = %q, want it to name %s", err.Error(), c.wantErrVar)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.check != nil {
				c.check(t, cfg)
			}
		})
	}
}

func wantAttrMount(want string) func(t *testing.T, cfg Config) {
	return func(t *testing.T, cfg Config) {
		if cfg.AttrMount != want {
			t.Errorf("AttrMount = %q, want %q", cfg.AttrMount, want)
		}
	}
}

func TestLoadAttributeVars(t *testing.T) {
	runLoadCases(t, []loadCase{
		{name: "defaults", check: func(t *testing.T, cfg Config) {
			if cfg.AttrMount != "ironbark" || cfg.TargetVar != "DEPLOY_TO" || cfg.MaxPolicies != 64 {
				t.Errorf("AttrMount/TargetVar/MaxPolicies = %q/%q/%d, want ironbark/DEPLOY_TO/64",
					cfg.AttrMount, cfg.TargetVar, cfg.MaxPolicies)
			}
		}},
		{name: "attr mount equals kv mount", env: map[string]string{"IRONBARK_ATTR_MOUNT": "kv"}, wantErrVar: "IRONBARK_ATTR_MOUNT"},
		{name: "attr mount inside kv mount", env: map[string]string{"IRONBARK_ATTR_MOUNT": "kv/attrs"}, wantErrVar: "IRONBARK_ATTR_MOUNT"},
		{name: "kv mount inside attr mount", env: map[string]string{"IRONBARK_KV_MOUNT": "kv/ci", "IRONBARK_ATTR_MOUNT": "kv"}, wantErrVar: "IRONBARK_ATTR_MOUNT"},
		{name: "attr mount equals kv mount after trim", env: map[string]string{"IRONBARK_ATTR_MOUNT": "/kv/"}, wantErrVar: "IRONBARK_ATTR_MOUNT"},
		{name: "attr mount only slashes", env: map[string]string{"IRONBARK_ATTR_MOUNT": "/"}, wantErrVar: "IRONBARK_ATTR_MOUNT"},
		{name: "attr mount sharing a name prefix is fine", env: map[string]string{"IRONBARK_ATTR_MOUNT": "kvx"}, check: wantAttrMount("kvx")},
		{name: "attr mount trimmed", env: map[string]string{"IRONBARK_ATTR_MOUNT": "/ironbark/"}, check: wantAttrMount("ironbark")},
		{name: "max policies 3", env: map[string]string{"IRONBARK_MAX_POLICIES": "3"}, check: func(t *testing.T, cfg Config) {
			if cfg.MaxPolicies != 3 {
				t.Errorf("MaxPolicies = %d, want 3", cfg.MaxPolicies)
			}
		}},
		{name: "max policies 2", env: map[string]string{"IRONBARK_MAX_POLICIES": "2"}, wantErrVar: "IRONBARK_MAX_POLICIES"},
		{name: "max policies 0", env: map[string]string{"IRONBARK_MAX_POLICIES": "0"}, wantErrVar: "IRONBARK_MAX_POLICIES"},
		{name: "max policies not an integer", env: map[string]string{"IRONBARK_MAX_POLICIES": "abc"}, wantErrVar: "IRONBARK_MAX_POLICIES"},
		{name: "target var", env: map[string]string{"IRONBARK_TARGET_VAR": "TARGET"}, check: func(t *testing.T, cfg Config) {
			if cfg.TargetVar != "TARGET" {
				t.Errorf("TargetVar = %q, want TARGET", cfg.TargetVar)
			}
		}},
	})
}

func wantActorForge(want string) func(t *testing.T, cfg Config) {
	return func(t *testing.T, cfg Config) {
		if cfg.ActorForge != want {
			t.Errorf("ActorForge = %q, want %q", cfg.ActorForge, want)
		}
	}
}

func TestLoadForgeVars(t *testing.T) {
	gitea := map[string]string{
		"IRONBARK_FORGE_PROVIDER": "gitea",
		"IRONBARK_FORGE_URL":      "https://forge.example.test",
		"IRONBARK_FORGE_TOKEN":    "forge-token-value",
	}
	with := func(base map[string]string, kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	without := func(base map[string]string, key string) map[string]string {
		m := with(base)
		delete(m, key)
		return m
	}

	runLoadCases(t, []loadCase{
		{name: "defaults", check: func(t *testing.T, cfg Config) {
			if cfg.ForgeProvider != "none" || cfg.ActorForge != "none" || cfg.ForgeTimeout != 3*time.Second {
				t.Errorf("ForgeProvider/ActorForge/ForgeTimeout = %q/%q/%v, want none/none/3s",
					cfg.ForgeProvider, cfg.ActorForge, cfg.ForgeTimeout)
			}
			if cfg.ForgeURL != "" || cfg.ForgeToken != "" {
				t.Errorf("ForgeURL/ForgeToken = %q/%q, want empty", cfg.ForgeURL, cfg.ForgeToken)
			}
		}},
		{name: "gitea stores url and token", env: gitea, check: func(t *testing.T, cfg Config) {
			if cfg.ForgeProvider != "gitea" || cfg.ForgeURL != "https://forge.example.test" || cfg.ForgeToken != "forge-token-value" {
				t.Errorf("provider/url/token = %q/%q/%q", cfg.ForgeProvider, cfg.ForgeURL, cfg.ForgeToken)
			}
		}},
		{name: "gitea without url", env: without(gitea, "IRONBARK_FORGE_URL"), wantErrVar: "IRONBARK_FORGE_URL"},
		{name: "gitea without token", env: without(gitea, "IRONBARK_FORGE_TOKEN"), wantErrVar: "IRONBARK_FORGE_TOKEN"},
		{name: "gitea token and _FILE both set", env: with(gitea, "IRONBARK_FORGE_TOKEN_FILE", "/t"),
			files: map[string][]byte{"/t": []byte("x")}, wantErrVar: "IRONBARK_FORGE_TOKEN"},
		{name: "gitea token _FILE trimmed", env: with(without(gitea, "IRONBARK_FORGE_TOKEN"), "IRONBARK_FORGE_TOKEN_FILE", "/t"),
			files: map[string][]byte{"/t": []byte("from-file\n")}, check: func(t *testing.T, cfg Config) {
				if cfg.ForgeToken != "from-file" {
					t.Errorf("ForgeToken = %q, want from-file", cfg.ForgeToken)
				}
			}},
		// Maintainer ruling 1 (plan 2026-09-30-pipeline-attributes-plan.md):
		// the actor forge defaults to none even with a gitea team provider.
		{name: "gitea actor forge unset defaults to none", env: gitea, check: wantActorForge("none")},
		{name: "gitea actor forge gitea", env: with(gitea, "IRONBARK_ACTOR_FORGE", "gitea"), check: wantActorForge("gitea")},
		{name: "gitea actor forge github", env: with(gitea, "IRONBARK_ACTOR_FORGE", "github"), wantErrVar: "IRONBARK_FORGE_PROVIDER"},
		{name: "gitea actor forge bitbucket", env: with(gitea, "IRONBARK_ACTOR_FORGE", "bitbucket"), wantErrVar: "IRONBARK_ACTOR_FORGE"},
		{name: "none actor forge github", env: map[string]string{"IRONBARK_ACTOR_FORGE": "github"}, check: wantActorForge("github")},
		{name: "none actor forge bitbucket", env: map[string]string{"IRONBARK_ACTOR_FORGE": "bitbucket"}, check: wantActorForge("bitbucket")},
		{name: "actor forge gitlab", env: map[string]string{"IRONBARK_ACTOR_FORGE": "gitlab"}, wantErrVar: "IRONBARK_ACTOR_FORGE"},
		{name: "actor forge values are exact", env: map[string]string{"IRONBARK_ACTOR_FORGE": "GITEA"}, wantErrVar: "IRONBARK_ACTOR_FORGE"},
		{name: "provider github", env: map[string]string{"IRONBARK_FORGE_PROVIDER": "github"}, wantErrVar: "IRONBARK_FORGE_PROVIDER"},
		{name: "timeout 0s", env: map[string]string{"IRONBARK_FORGE_TIMEOUT": "0s"}, wantErrVar: "IRONBARK_FORGE_TIMEOUT"},
		{name: "timeout abc", env: map[string]string{"IRONBARK_FORGE_TIMEOUT": "abc"}, wantErrVar: "IRONBARK_FORGE_TIMEOUT"},
		{name: "forge url ftp", env: with(gitea, "IRONBARK_FORGE_URL", "ftp://x"), wantErrVar: "IRONBARK_FORGE_URL"},
		{name: "forge url without scheme", env: with(gitea, "IRONBARK_FORGE_URL", "example.test"), wantErrVar: "IRONBARK_FORGE_URL"},
	})
}

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

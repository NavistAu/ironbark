package ibcfg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

func fakeGetenv(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

// baseEnv sets just enough (address + token) for Load to succeed.
func baseEnv() map[string]string {
	return map[string]string{
		"VAULT_ADDR":  "https://vault.example.com",
		"VAULT_TOKEN": "s.base-token",
	}
}

func TestLoadAddrPrecedence(t *testing.T) {
	t.Run("VAULT_ADDR used when BAO_ADDR unset", func(t *testing.T) {
		env := baseEnv()
		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Addr != "https://vault.example.com" {
			t.Errorf("Addr = %q, want VAULT_ADDR value", cfg.Addr)
		}
	})

	t.Run("BAO_ADDR wins when both set", func(t *testing.T) {
		env := baseEnv()
		env["BAO_ADDR"] = "https://bao.example.com"
		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Addr != "https://bao.example.com" {
			t.Errorf("Addr = %q, want BAO_ADDR value", cfg.Addr)
		}
	})

	t.Run("missing address errors", func(t *testing.T) {
		env := baseEnv()
		delete(env, "VAULT_ADDR")
		_, err := Load(fakeGetenv(env), t.TempDir())
		if err == nil {
			t.Fatal("Load: expected error, got nil")
		}
	})
}

func TestLoadTokenPrecedence(t *testing.T) {
	t.Run("VAULT_TOKEN used when BAO_TOKEN unset", func(t *testing.T) {
		env := baseEnv()
		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Token != "s.base-token" {
			t.Errorf("Token = %q, want VAULT_TOKEN value", cfg.Token)
		}
	})

	t.Run("BAO_TOKEN wins when both set", func(t *testing.T) {
		env := baseEnv()
		env["BAO_TOKEN"] = "s.bao-token"
		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Token != "s.bao-token" {
			t.Errorf("Token = %q, want BAO_TOKEN value", cfg.Token)
		}
	})

	t.Run("falls back to home/.vault-token, trimmed", func(t *testing.T) {
		env := baseEnv()
		delete(env, "VAULT_TOKEN")
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("s.file-token\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfg, err := Load(fakeGetenv(env), home)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Token != "s.file-token" {
			t.Errorf("Token = %q, want trimmed file content", cfg.Token)
		}
	})

	t.Run("env vars win over token file", func(t *testing.T) {
		env := baseEnv()
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("s.file-token\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cfg, err := Load(fakeGetenv(env), home)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Token != "s.base-token" {
			t.Errorf("Token = %q, want env value over file", cfg.Token)
		}
	})

	t.Run("missing token errors and mentions ib auth", func(t *testing.T) {
		env := baseEnv()
		delete(env, "VAULT_TOKEN")
		_, err := Load(fakeGetenv(env), t.TempDir())
		if err == nil {
			t.Fatal("Load: expected error, got nil")
		}
		if !strings.Contains(err.Error(), "ib auth") {
			t.Errorf("error %q does not mention `ib auth`", err.Error())
		}
	})
}

func TestLoadTLS(t *testing.T) {
	t.Run("nil when no TLS var set", func(t *testing.T) {
		env := baseEnv()
		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TLS != nil {
			t.Errorf("TLS = %+v, want nil", cfg.TLS)
		}
	})

	t.Run("populated from VAULT_* vars", func(t *testing.T) {
		env := baseEnv()
		env["VAULT_CACERT"] = "/etc/vault/ca.pem"
		env["VAULT_CAPATH"] = "/etc/vault/ca.d"
		env["VAULT_CLIENT_CERT"] = "/etc/vault/client.pem"
		env["VAULT_CLIENT_KEY"] = "/etc/vault/client-key.pem"
		env["VAULT_TLS_SERVER_NAME"] = "vault.internal"
		env["VAULT_SKIP_VERIFY"] = "true"

		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		want := &api.TLSConfig{
			CACert:        "/etc/vault/ca.pem",
			CAPath:        "/etc/vault/ca.d",
			ClientCert:    "/etc/vault/client.pem",
			ClientKey:     "/etc/vault/client-key.pem",
			TLSServerName: "vault.internal",
			Insecure:      true,
		}
		if cfg.TLS == nil || !reflect.DeepEqual(cfg.TLS, want) {
			t.Errorf("TLS = %+v, want %+v", cfg.TLS, want)
		}
	})

	t.Run("BAO_* wins over VAULT_* per field", func(t *testing.T) {
		env := baseEnv()
		env["VAULT_CACERT"] = "/vault/ca.pem"
		env["BAO_CACERT"] = "/bao/ca.pem"

		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TLS == nil || cfg.TLS.CACert != "/bao/ca.pem" {
			t.Errorf("TLS = %+v, want CACert /bao/ca.pem", cfg.TLS)
		}
	})

	t.Run("SKIP_VERIFY alone is enough to populate TLS", func(t *testing.T) {
		env := baseEnv()
		env["BAO_SKIP_VERIFY"] = "false"

		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TLS == nil {
			t.Fatal("TLS = nil, want populated (SKIP_VERIFY set)")
		}
		if cfg.TLS.Insecure {
			t.Errorf("Insecure = true, want false")
		}
	})

	t.Run("invalid SKIP_VERIFY errors", func(t *testing.T) {
		env := baseEnv()
		env["VAULT_SKIP_VERIFY"] = "not-a-bool"

		_, err := Load(fakeGetenv(env), t.TempDir())
		if err == nil {
			t.Fatal("Load: expected error, got nil")
		}
	})
}

func TestLoadLayoutAndBranch(t *testing.T) {
	t.Run("KV defaults", func(t *testing.T) {
		env := baseEnv()
		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.KVMount != "kv" {
			t.Errorf("KVMount = %q, want kv", cfg.KVMount)
		}
		if cfg.KVPrefix != "ci" {
			t.Errorf("KVPrefix = %q, want ci", cfg.KVPrefix)
		}
		if cfg.Branch != "" {
			t.Errorf("Branch = %q, want empty", cfg.Branch)
		}
	})

	t.Run("overrides applied", func(t *testing.T) {
		env := baseEnv()
		env["IB_KV_MOUNT"] = "secret"
		env["IB_KV_PREFIX"] = "prefix"
		env["IB_BRANCH"] = "develop"
		cfg, err := Load(fakeGetenv(env), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.KVMount != "secret" {
			t.Errorf("KVMount = %q, want secret", cfg.KVMount)
		}
		if cfg.KVPrefix != "prefix" {
			t.Errorf("KVPrefix = %q, want prefix", cfg.KVPrefix)
		}
		if cfg.Branch != "develop" {
			t.Errorf("Branch = %q, want develop", cfg.Branch)
		}
	})
}

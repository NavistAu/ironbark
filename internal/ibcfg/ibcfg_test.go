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

		"IRONBARK_DATA_PATH": testDataPath,
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

const testDataPath = "vs/data/pipelines/{repo}/{env}/{target...}"

func writeConfigFile(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".config", "ib")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadGrantSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := Load(fakeGetenv(baseEnv()), t.TempDir())
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.DataPath.Prefix[0] != "vs" || cfg.EnvVar != "DEPLOY_ENV" || cfg.TargetVar != "DEPLOY_TO" || cfg.JWTRole != "ci-{env}" {
			t.Errorf("got %+v", cfg)
		}
	})

	t.Run("data path is required and names itself", func(t *testing.T) {
		env := baseEnv()
		delete(env, "IRONBARK_DATA_PATH")
		_, err := Load(fakeGetenv(env), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "IRONBARK_DATA_PATH") {
			t.Fatalf("err = %v, want one naming IRONBARK_DATA_PATH", err)
		}
	})

	t.Run("bad data path errors", func(t *testing.T) {
		env := baseEnv()
		env["IRONBARK_DATA_PATH"] = "vs/data/{env}"
		if _, err := Load(fakeGetenv(env), t.TempDir()); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestLoadConfigFilePrecedence(t *testing.T) {
	t.Run("file supplies what env lacks", func(t *testing.T) {
		home := t.TempDir()
		writeConfigFile(t, home, "# ib\nBAO_ADDR=https://file.example.com\nIRONBARK_DATA_PATH='"+testDataPath+"'\nIRONBARK_ENV_VAR=MY_ENV\nIRONBARK_TARGET_VAR=MY_TO\nIRONBARK_JWT_ROLE=r-{env}\nUNRELATED=1\n")
		cfg, err := Load(fakeGetenv(map[string]string{"BAO_TOKEN": "s.t"}), home)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Addr != "https://file.example.com" || cfg.EnvVar != "MY_ENV" || cfg.TargetVar != "MY_TO" || cfg.JWTRole != "r-{env}" {
			t.Errorf("got %+v", cfg)
		}
	})

	t.Run("env wins over file, across the BAO/VAULT pair", func(t *testing.T) {
		home := t.TempDir()
		writeConfigFile(t, home, "BAO_ADDR=https://file-bao\nIRONBARK_DATA_PATH="+testDataPath+"\nIRONBARK_ENV_VAR=FILE_ENV\n")
		env := map[string]string{"VAULT_ADDR": "https://env-vault", "VAULT_TOKEN": "t", "IRONBARK_ENV_VAR": "ENV_ENV"}
		cfg, err := Load(fakeGetenv(env), home)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Addr != "https://env-vault" {
			t.Errorf("Addr = %q, want the env VAULT_ADDR over the file BAO_ADDR", cfg.Addr)
		}
		if cfg.EnvVar != "ENV_ENV" {
			t.Errorf("EnvVar = %q, want env value", cfg.EnvVar)
		}
	})

	t.Run("a token in the file is never used", func(t *testing.T) {
		home := t.TempDir()
		writeConfigFile(t, home, "BAO_TOKEN=s.from-file\n")
		env := baseEnv()
		delete(env, "VAULT_TOKEN")
		if _, err := Load(fakeGetenv(env), home); err == nil {
			t.Fatal("expected the no-token error")
		}
	})

	t.Run("missing file is fine", func(t *testing.T) {
		if _, err := Load(fakeGetenv(baseEnv()), t.TempDir()); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	t.Run("malformed file names its line", func(t *testing.T) {
		home := t.TempDir()
		writeConfigFile(t, home, "BAO_ADDR=x\n\nnot a pair\n")
		_, err := Load(fakeGetenv(baseEnv()), home)
		if err == nil || !strings.Contains(err.Error(), "line 3") {
			t.Fatalf("err = %v, want one naming line 3", err)
		}
	})
}

func TestLoadRemovedVars(t *testing.T) {
	cases := map[string]string{
		"IB_KV_MOUNT":  "IRONBARK_DATA_PATH",
		"IB_KV_PREFIX": "IRONBARK_DATA_PATH",
		"IB_BRANCH":    "IB_ENV",
	}
	for name, repl := range cases {
		t.Run(name+" in env", func(t *testing.T) {
			env := baseEnv()
			env[name] = "x"
			_, err := Load(fakeGetenv(env), t.TempDir())
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), repl) {
				t.Fatalf("err = %v, want one naming %s and %s", err, name, repl)
			}
		})
		t.Run(name+" in file", func(t *testing.T) {
			home := t.TempDir()
			writeConfigFile(t, home, name+"=x\n")
			_, err := Load(fakeGetenv(baseEnv()), home)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want one naming %s", err, name)
			}
		})
	}
}

func TestLoadSelection(t *testing.T) {
	env := baseEnv()
	env["IB_ENV"] = "staging"
	env["IB_TARGET"] = "web/api"
	cfg, err := Load(fakeGetenv(env), t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "staging" || cfg.Target != "web/api" {
		t.Errorf("Env, Target = %q, %q", cfg.Env, cfg.Target)
	}
}

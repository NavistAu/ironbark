// Package ibcfg loads ib's own env-var configuration (CLIENT-SPEC §5) —
// distinct from internal/config, the broker's own surface, which
// requires broker-only fields ib has no reason to supply. Load takes
// getenv/home as injected values so tests run without touching the real
// environment or filesystem; production wires os.Getenv and os.UserHomeDir.
package ibcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Config is ib's Vault connection and layout configuration (CLIENT-SPEC
// §5).
type Config struct {
	Addr  string
	Token string
	TLS   *api.TLSConfig

	KVMount  string
	KVPrefix string
	Branch   string
}

// Load builds a Config from the environment (via getenv) and, if no
// token env var is set, the token-helper file at <home>/.vault-token.
// For address, token, and every TLS variable, a BAO_* var is checked
// before its VAULT_* counterpart (CLIENT-SPEC §5.1). It returns an error
// when no address is configured, or when no token is found anywhere
// (env, then file) — that error's message says to run `ib auth`.
func Load(getenv func(string) string, home string) (Config, error) {
	var cfg Config

	cfg.Addr = pick(getenv, "BAO_ADDR", "VAULT_ADDR")
	if cfg.Addr == "" {
		return Config{}, fmt.Errorf("ibcfg: no Vault address set (BAO_ADDR or VAULT_ADDR)")
	}

	cfg.Token = pick(getenv, "BAO_TOKEN", "VAULT_TOKEN")
	if cfg.Token == "" {
		cfg.Token = readTokenFile(home)
	}
	if cfg.Token == "" {
		return Config{}, fmt.Errorf("ibcfg: no Vault token found (BAO_TOKEN, VAULT_TOKEN, or ~/.vault-token); run `ib auth`")
	}

	tls, err := loadTLS(getenv)
	if err != nil {
		return Config{}, err
	}
	cfg.TLS = tls

	cfg.KVMount = withDefault(getenv, "IB_KV_MOUNT", "kv")
	cfg.KVPrefix = withDefault(getenv, "IB_KV_PREFIX", "ci")
	cfg.Branch = getenv("IB_BRANCH")

	return cfg, nil
}

// pick returns getenv(bao) if set, else getenv(vault) — the BAO_*-before-
// VAULT_* precedence CLIENT-SPEC §5.1 applies throughout.
func pick(getenv func(string) string, bao, vault string) string {
	if v := getenv(bao); v != "" {
		return v
	}
	return getenv(vault)
}

// withDefault returns getenv(name) if set, else def.
func withDefault(getenv func(string) string, name, def string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return def
}

// readTokenFile reads and trims <home>/.vault-token, the default Vault/
// OpenBao CLI token-helper location (CLIENT-SPEC §5.1). A missing or
// unreadable file yields "" — the caller treats that the same as no
// token configured.
func readTokenFile(home string) string {
	b, err := os.ReadFile(filepath.Join(home, ".vault-token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// loadTLS builds an *api.TLSConfig from any set BAO_*/VAULT_* TLS
// variable (CACERT, CAPATH, CLIENT_CERT, CLIENT_KEY, TLS_SERVER_NAME,
// SKIP_VERIFY), BAO_* winning per field. It returns nil when none of the
// six variables is set — the underlying Vault API client already reads
// VAULT_* TLS vars for free, so ib only needs to act when a BAO_* value
// is present or when it must merge BAO_* and VAULT_* fields together.
func loadTLS(getenv func(string) string) (*api.TLSConfig, error) {
	caCert := pick(getenv, "BAO_CACERT", "VAULT_CACERT")
	caPath := pick(getenv, "BAO_CAPATH", "VAULT_CAPATH")
	clientCert := pick(getenv, "BAO_CLIENT_CERT", "VAULT_CLIENT_CERT")
	clientKey := pick(getenv, "BAO_CLIENT_KEY", "VAULT_CLIENT_KEY")
	tlsServerName := pick(getenv, "BAO_TLS_SERVER_NAME", "VAULT_TLS_SERVER_NAME")
	skipVerify := pick(getenv, "BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY")

	if caCert == "" && caPath == "" && clientCert == "" && clientKey == "" && tlsServerName == "" && skipVerify == "" {
		return nil, nil
	}

	tls := &api.TLSConfig{
		CACert:        caCert,
		CAPath:        caPath,
		ClientCert:    clientCert,
		ClientKey:     clientKey,
		TLSServerName: tlsServerName,
	}
	if skipVerify != "" {
		insecure, err := strconv.ParseBool(skipVerify)
		if err != nil {
			return nil, fmt.Errorf("ibcfg: invalid SKIP_VERIFY value %q: %w", skipVerify, err)
		}
		tls.Insecure = insecure
	}

	return tls, nil
}

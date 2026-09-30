// Package ibcfg loads ib's own configuration (CLIENT-SPEC §5, design §12.1)
// — distinct from internal/grantcfg, the broker's own surface, which
// requires broker-only fields ib has no reason to supply. Settings come from
// the environment, then from ~/.config/ib/config (a KEY=value file in
// `ib run --env-file` syntax); the environment wins. Load takes getenv/home
// as injected values so tests run without touching the real environment.
package ibcfg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/envfile"
	"github.com/navistau/ironbark/internal/grantcfg"
)

// Config is ib's OpenBao connection and grant-model configuration.
type Config struct {
	Addr  string
	Token string
	TLS   *api.TLSConfig

	// The four grant settings, under ironbark's own names (design §11.1).
	DataPath  grantcfg.Template
	EnvVar    string
	TargetVar string
	JWTRole   string

	// Env and Target are IB_ENV and IB_TARGET; the --env and --target flags
	// override them.
	Env    string
	Target string
}

// removed maps a variable that no longer exists to what replaces it.
var removed = map[string]string{
	"IB_KV_MOUNT":  "IRONBARK_DATA_PATH",
	"IB_KV_PREFIX": "IRONBARK_DATA_PATH",
	"IB_BRANCH":    "IB_ENV",
}

// Load builds a Config. Tokens come only from the environment or the
// token-helper file at <home>/.vault-token, never from the config file. For
// address and every TLS variable a BAO_* var is checked before its VAULT_*
// counterpart, environment before file (CLIENT-SPEC §5.1).
func Load(getenv func(string) string, home string) (Config, error) {
	file, err := readConfigFile(home)
	if err != nil {
		return Config{}, err
	}
	get := func(k string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return file[k]
	}
	// pair is pick across both layers: the environment's BAO_*/VAULT_* pair
	// first, then the file's.
	pair := func(bao, vault string) string {
		if v := pick(getenv, bao, vault); v != "" {
			return v
		}
		return pick(func(k string) string { return file[k] }, bao, vault)
	}
	for name, repl := range removed {
		if get(name) != "" {
			return Config{}, fmt.Errorf("ibcfg: %s is no longer supported; use %s", name, repl)
		}
	}

	var cfg Config
	cfg.Addr = pair("BAO_ADDR", "VAULT_ADDR")
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

	tls, err := loadTLS(pair)
	if err != nil {
		return Config{}, err
	}
	cfg.TLS = tls

	dataPath := get("IRONBARK_DATA_PATH")
	if dataPath == "" {
		return Config{}, fmt.Errorf("ibcfg: IRONBARK_DATA_PATH is required (environment or ~/.config/ib/config)")
	}
	if cfg.DataPath, err = grantcfg.ParseTemplate(dataPath); err != nil {
		return Config{}, fmt.Errorf("ibcfg: IRONBARK_DATA_PATH: %w", err)
	}
	cfg.EnvVar = withDefault(get, "IRONBARK_ENV_VAR", "DEPLOY_ENV")
	cfg.TargetVar = withDefault(get, "IRONBARK_TARGET_VAR", "DEPLOY_TO")
	cfg.JWTRole = withDefault(get, "IRONBARK_JWT_ROLE", "ci-{env}")
	cfg.Env = get("IB_ENV")
	cfg.Target = get("IB_TARGET")

	return cfg, nil
}

// readConfigFile parses <home>/.config/ib/config. A missing file is an empty
// config; a malformed one is an error naming its line.
func readConfigFile(home string) (map[string]string, error) {
	path := filepath.Join(home, ".config", "ib", "config")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ibcfg: %w", err)
	}
	defer f.Close()
	entries, err := envfile.Parse(f)
	if err != nil {
		return nil, fmt.Errorf("ibcfg: %s: %w", path, err)
	}
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[e.Key] = e.Value
	}
	return m, nil
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
func loadTLS(pair func(bao, vault string) string) (*api.TLSConfig, error) {
	caCert := pair("BAO_CACERT", "VAULT_CACERT")
	caPath := pair("BAO_CAPATH", "VAULT_CAPATH")
	clientCert := pair("BAO_CLIENT_CERT", "VAULT_CLIENT_CERT")
	clientKey := pair("BAO_CLIENT_KEY", "VAULT_CLIENT_KEY")
	tlsServerName := pair("BAO_TLS_SERVER_NAME", "VAULT_TLS_SERVER_NAME")
	skipVerify := pair("BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY")

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

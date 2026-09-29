// Package config loads ironbark's runtime configuration from environment
// variables (SPEC §7). There is no config file and no rule tables
// (DEC-0002); every secret-bearing var also accepts a `_FILE` variant
// (DEC-0010) so ESO/k8s can mount the value instead of injecting it
// directly. Load takes getenv/readFile as injected functions so tests run
// without touching the real environment or filesystem; production wires
// os.Getenv and os.ReadFile.
package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is ironbark's full configuration surface (SPEC §7).
type Config struct {
	ListenAddr         string
	VaultAddr          string
	TokenRole          string
	KVMount            string
	KVPrefix           string
	PolicyPrefix       string
	AdvertiseVaultAddr string
	LogLevel           string

	WoodpeckerPublicKey ed25519.PublicKey

	VaultRoleID   string
	VaultSecretID string

	FreshnessWindow time.Duration

	// Pipeline attributes (docs/plans/2026-09-30-pipeline-attributes-design.md).
	AttrMount   string // KV v2 mount holding attribute data; never inside KVMount
	TargetVar   string // manual-run variable naming the target
	MaxPolicies int    // cap on requested policy names (P1, P2, actor never dropped)

	ActorForge    string // "none" | "gitea" | "github" | "bitbucket": whose push-family sender is a login
	ForgeProvider string // "none" | "gitea": team resolution
	ForgeURL      string
	ForgeToken    string
	ForgeTimeout  time.Duration
}

// Load builds a Config from the environment (via getenv) and, for any
// `_FILE`-variant var in use, the filesystem (via readFile). It returns an
// error naming the offending variable on: a missing required var, a var
// and its `_FILE` variant both set (ambiguous — refused rather than
// guessed), an unreadable `_FILE` target, a PEM/PKIX-unparseable public
// key, or an unparseable freshness-window duration.
func Load(getenv func(string) string, readFile func(string) ([]byte, error)) (Config, error) {
	var cfg Config

	pubKeyPEM, err := requiredSecret(getenv, readFile, "IRONBARK_WOODPECKER_PUBLIC_KEY")
	if err != nil {
		return Config{}, err
	}
	cfg.WoodpeckerPublicKey, err = parseEd25519PublicKey(pubKeyPEM)
	if err != nil {
		return Config{}, err
	}

	cfg.VaultAddr, err = required(getenv, "IRONBARK_VAULT_ADDR")
	if err != nil {
		return Config{}, err
	}

	cfg.VaultRoleID, err = requiredSecret(getenv, readFile, "IRONBARK_VAULT_ROLE_ID")
	if err != nil {
		return Config{}, err
	}

	cfg.VaultSecretID, err = requiredSecret(getenv, readFile, "IRONBARK_VAULT_SECRET_ID")
	if err != nil {
		return Config{}, err
	}

	cfg.ListenAddr = withDefault(getenv, "IRONBARK_LISTEN_ADDR", ":8080")
	cfg.TokenRole = withDefault(getenv, "IRONBARK_TOKEN_ROLE", "ci")
	cfg.KVMount = withDefault(getenv, "IRONBARK_KV_MOUNT", "kv")
	cfg.KVPrefix = withDefault(getenv, "IRONBARK_KV_PREFIX", "ci")
	cfg.PolicyPrefix = withDefault(getenv, "IRONBARK_POLICY_PREFIX", "ci")
	cfg.AdvertiseVaultAddr = getenv("IRONBARK_ADVERTISE_VAULT_ADDR")
	cfg.LogLevel = withDefault(getenv, "IRONBARK_LOG_LEVEL", "info")

	freshness := withDefault(getenv, "IRONBARK_FRESHNESS_WINDOW", "10s")
	cfg.FreshnessWindow, err = time.ParseDuration(freshness)
	if err != nil {
		return Config{}, fmt.Errorf("IRONBARK_FRESHNESS_WINDOW: %w", err)
	}

	cfg.AttrMount, err = attrMount(getenv, cfg.KVMount)
	if err != nil {
		return Config{}, err
	}
	cfg.TargetVar = withDefault(getenv, "IRONBARK_TARGET_VAR", "DEPLOY_TO")
	maxPolicies := withDefault(getenv, "IRONBARK_MAX_POLICIES", "64")
	cfg.MaxPolicies, err = strconv.Atoi(maxPolicies)
	if err != nil || cfg.MaxPolicies < 3 {
		return Config{}, fmt.Errorf("IRONBARK_MAX_POLICIES: %q is not an integer >= 3", maxPolicies)
	}

	if err := loadForge(getenv, readFile, &cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// attrMount resolves IRONBARK_ATTR_MOUNT, trimmed of leading and trailing
// "/". Attribute data is isolated from tier policies only because ACL paths
// begin with the mount, so the attribute mount must neither equal nor nest
// with the KV mount (design §4).
func attrMount(getenv func(string) string, kvMount string) (string, error) {
	a := strings.Trim(withDefault(getenv, "IRONBARK_ATTR_MOUNT", "ironbark"), "/")
	if a == "" {
		return "", fmt.Errorf("IRONBARK_ATTR_MOUNT: empty mount path")
	}
	k := strings.Trim(kvMount, "/")
	if a == k || strings.HasPrefix(a, k+"/") || strings.HasPrefix(k, a+"/") {
		return "", fmt.Errorf("IRONBARK_ATTR_MOUNT %q must not equal, contain or be contained in IRONBARK_KV_MOUNT %q", a, k)
	}
	return a, nil
}

// loadForge resolves the IRONBARK_FORGE_* team provider and
// IRONBARK_ACTOR_FORGE (design §2, §7).
func loadForge(getenv func(string) string, readFile func(string) ([]byte, error), cfg *Config) error {
	cfg.ForgeProvider = withDefault(getenv, "IRONBARK_FORGE_PROVIDER", "none")
	if cfg.ForgeProvider != "none" && cfg.ForgeProvider != "gitea" {
		return fmt.Errorf("IRONBARK_FORGE_PROVIDER: %q is not one of none, gitea", cfg.ForgeProvider)
	}

	timeout := withDefault(getenv, "IRONBARK_FORGE_TIMEOUT", "3s")
	d, err := time.ParseDuration(timeout)
	if err != nil || d <= 0 {
		return fmt.Errorf("IRONBARK_FORGE_TIMEOUT: %q is not a positive duration", timeout)
	}
	cfg.ForgeTimeout = d

	// Defaults to none regardless of the team provider: maintainer ruling 1
	// in docs/plans/2026-09-30-pipeline-attributes-plan.md.
	cfg.ActorForge = withDefault(getenv, "IRONBARK_ACTOR_FORGE", "none")
	switch cfg.ActorForge {
	case "none", "gitea", "github", "bitbucket":
	default:
		return fmt.Errorf("IRONBARK_ACTOR_FORGE: %q is not one of none, gitea, github, bitbucket", cfg.ActorForge)
	}

	if cfg.ForgeProvider == "none" {
		return nil
	}
	// One forge namespace: team membership and actor logins come from the
	// same forge.
	if cfg.ActorForge != "gitea" && cfg.ActorForge != "none" {
		return fmt.Errorf("IRONBARK_ACTOR_FORGE %q cannot be used with IRONBARK_FORGE_PROVIDER %q (only gitea or none)",
			cfg.ActorForge, cfg.ForgeProvider)
	}

	cfg.ForgeURL, err = required(getenv, "IRONBARK_FORGE_URL")
	if err != nil {
		return err
	}
	u, err := url.Parse(cfg.ForgeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("IRONBARK_FORGE_URL: %q is not an absolute http(s) URL", cfg.ForgeURL)
	}

	cfg.ForgeToken, err = requiredSecret(getenv, readFile, "IRONBARK_FORGE_TOKEN")
	return err
}

// withDefault returns getenv(name) if set, else def.
func withDefault(getenv func(string) string, name, def string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return def
}

// required returns getenv(name), erroring by name if unset.
func required(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}

// requiredSecret resolves a var that accepts a `_FILE` variant (DEC-0010):
// name or name+"_FILE" may be set, but not both; at least one must be.
// Both paths are trimmed of surrounding whitespace — trailing newlines are
// never meaningful in a role_id/secret_id/PEM, and k8s/ESO secret mounts
// routinely add one — so a value must be non-empty after trimming or it is
// treated as though the var were unset.
func requiredSecret(getenv func(string) string, readFile func(string) ([]byte, error), name string) (string, error) {
	fileName := name + "_FILE"
	val := getenv(name)
	path := getenv(fileName)

	switch {
	case val != "" && path != "":
		return "", fmt.Errorf("%s and %s are both set; set only one", name, fileName)
	case path != "":
		b, err := readFile(path)
		if err != nil {
			return "", fmt.Errorf("%s: %w", fileName, err)
		}
		if trimmed := strings.TrimSpace(string(b)); trimmed != "" {
			return trimmed, nil
		}
		return "", fmt.Errorf("%s is required", name)
	case val != "":
		if trimmed := strings.TrimSpace(val); trimmed != "" {
			return trimmed, nil
		}
		return "", fmt.Errorf("%s is required", name)
	default:
		return "", fmt.Errorf("%s is required", name)
	}
}

// parseEd25519PublicKey PEM/PKIX-decodes Woodpecker's verification key
// (docs/woodpecker-secret-mechanisms.md §3).
func parseEd25519PublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("IRONBARK_WOODPECKER_PUBLIC_KEY: not a valid PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("IRONBARK_WOODPECKER_PUBLIC_KEY: %w", err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("IRONBARK_WOODPECKER_PUBLIC_KEY: not an ed25519 public key")
	}

	return edPub, nil
}

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

	return cfg, nil
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

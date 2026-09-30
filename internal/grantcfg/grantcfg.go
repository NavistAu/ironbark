// Package grantcfg loads ironbark's grant-model configuration from
// environment variables (design §11): the four grant settings, the JWT
// signing plumbing and the kept plumbing vars. Load takes getenv/readFile as
// injected functions so tests never touch the real environment.
package grantcfg

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Config is the grant-model configuration surface.
type Config struct {
	// The four grant settings (§11.1).
	DataPath  Template
	EnvVar    string
	TargetVar string
	JWTRole   string // role template, e.g. "ci-{env}"

	// JWT plumbing (§11.2). The PEM is parsed by internal/jwtsign.
	JWTSigningKeyPEM string
	JWTMount         string

	// Kept plumbing (§11.2).
	ListenAddr          string
	WoodpeckerPublicKey ed25519.PublicKey
	VaultAddr           string
	AdvertiseVaultAddr  string
	FreshnessWindow     time.Duration
	LogLevel            string

	ActorForge    string // "none" | "gitea" | "github" | "bitbucket"
	ForgeProvider string // "none" | "gitea"
	ForgeURL      string
	ForgeToken    string
	ForgeTimeout  time.Duration // bounds each lookup: protection and teams

	// Warnings are startup warnings for the caller to log.
	Warnings []string
}

// Load builds a Config. Errors name the offending variable.
func Load(getenv func(string) string, readFile func(string) ([]byte, error)) (Config, error) {
	var cfg Config
	var err error

	pubKeyPEM, err := requiredSecret(getenv, readFile, "IRONBARK_WOODPECKER_PUBLIC_KEY")
	if err != nil {
		return Config{}, err
	}
	if cfg.WoodpeckerPublicKey, err = parseEd25519PublicKey(pubKeyPEM); err != nil {
		return Config{}, err
	}
	if cfg.VaultAddr, err = required(getenv, "IRONBARK_VAULT_ADDR"); err != nil {
		return Config{}, err
	}

	dataPath, err := required(getenv, "IRONBARK_DATA_PATH")
	if err != nil {
		return Config{}, err
	}
	if cfg.DataPath, err = ParseTemplate(dataPath); err != nil {
		return Config{}, err
	}
	cfg.EnvVar = withDefault(getenv, "IRONBARK_ENV_VAR", "DEPLOY_ENV")
	cfg.TargetVar = withDefault(getenv, "IRONBARK_TARGET_VAR", "DEPLOY_TO")
	if cfg.EnvVar == cfg.TargetVar {
		return Config{}, fmt.Errorf("IRONBARK_ENV_VAR and IRONBARK_TARGET_VAR are both %q", cfg.EnvVar)
	}
	cfg.JWTRole = withDefault(getenv, "IRONBARK_JWT_ROLE", "ci-{env}")
	if err = validRoleTemplate(cfg.JWTRole); err != nil {
		return Config{}, err
	}

	if cfg.JWTSigningKeyPEM, err = requiredSecret(getenv, readFile, "IRONBARK_JWT_SIGNING_KEY"); err != nil {
		return Config{}, err
	}
	cfg.JWTMount = strings.Trim(withDefault(getenv, "IRONBARK_JWT_MOUNT", "jwt"), "/")

	cfg.ListenAddr = withDefault(getenv, "IRONBARK_LISTEN_ADDR", ":8080")
	cfg.AdvertiseVaultAddr = getenv("IRONBARK_ADVERTISE_VAULT_ADDR")
	cfg.LogLevel = withDefault(getenv, "IRONBARK_LOG_LEVEL", "info")
	fw := withDefault(getenv, "IRONBARK_FRESHNESS_WINDOW", "10s")
	if cfg.FreshnessWindow, err = time.ParseDuration(fw); err != nil {
		return Config{}, fmt.Errorf("IRONBARK_FRESHNESS_WINDOW: %w", err)
	}

	if err := loadForge(getenv, readFile, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

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

	cfg.ActorForge = withDefault(getenv, "IRONBARK_ACTOR_FORGE", "none")
	switch cfg.ActorForge {
	case "none", "gitea", "github", "bitbucket":
	default:
		return fmt.Errorf("IRONBARK_ACTOR_FORGE: %q is not one of none, gitea, github, bitbucket", cfg.ActorForge)
	}

	if cfg.ForgeProvider == "none" {
		cfg.Warnings = append(cfg.Warnings, "IRONBARK_FORGE_PROVIDER=none: branch_protected is always \"false\"; no environment is discovered from level metadata and only explicit environments on roles that do not bind branch_protected are reachable")
		return nil
	}
	if cfg.ActorForge != "gitea" && cfg.ActorForge != "none" {
		return fmt.Errorf("IRONBARK_ACTOR_FORGE %q cannot be used with IRONBARK_FORGE_PROVIDER %q (only gitea or none)", cfg.ActorForge, cfg.ForgeProvider)
	}
	if cfg.ForgeURL, err = required(getenv, "IRONBARK_FORGE_URL"); err != nil {
		return err
	}
	u, err := url.Parse(cfg.ForgeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("IRONBARK_FORGE_URL: %q is not an absolute http(s) URL", cfg.ForgeURL)
	}
	cfg.ForgeToken, err = requiredSecret(getenv, readFile, "IRONBARK_FORGE_TOKEN")
	return err
}

func withDefault(getenv func(string) string, name, def string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return def
}

func required(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}

// requiredSecret resolves a var with a `_FILE` variant: exactly one of the
// two, whitespace-trimmed, non-empty after trimming.
func requiredSecret(getenv func(string) string, readFile func(string) ([]byte, error), name string) (string, error) {
	fileName := name + "_FILE"
	val, path := getenv(name), getenv(fileName)
	switch {
	case val != "" && path != "":
		return "", fmt.Errorf("%s and %s are both set; set only one", name, fileName)
	case path != "":
		b, err := readFile(path)
		if err != nil {
			return "", fmt.Errorf("%s: %w", fileName, err)
		}
		val = string(b)
	}
	if v := strings.TrimSpace(val); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is required", name)
}

func parseEd25519PublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("IRONBARK_WOODPECKER_PUBLIC_KEY: not a valid PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("IRONBARK_WOODPECKER_PUBLIC_KEY: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("IRONBARK_WOODPECKER_PUBLIC_KEY: not an ed25519 public key")
	}
	return ed, nil
}

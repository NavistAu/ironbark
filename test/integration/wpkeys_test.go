//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// loadE2EKeys reads the same checked-in test-only Ed25519 keypair
// internal/wpsign's own matrix uses (internal/wpsign/testdata), resolved
// relative to this package's directory since t.Run subtests do not change
// the working directory.
func loadE2EKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	privPEM, err := os.ReadFile("../../internal/wpsign/testdata/dev-ed25519.pem")
	if err != nil {
		t.Fatalf("read test private key: %v", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatalf("decode test private key PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test private key: %v", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("test private key is not ed25519, got %T", privAny)
	}

	pubPEM, err := os.ReadFile("../../internal/wpsign/testdata/dev-ed25519.pub")
	if err != nil {
		t.Fatalf("read test public key: %v", err)
	}
	block, _ = pem.Decode(pubPEM)
	if block == nil {
		t.Fatalf("decode test public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse test public key: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("test public key is not ed25519, got %T", pubAny)
	}

	return priv, pub
}

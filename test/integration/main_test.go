//go:build integration

// Task 13: the ONLY test this file owns is TestConnectivity — proving the
// dockerized dual-product fixture (docker-compose.yml) is reachable and
// unsealed with the root token, for both products, before Task 14 builds
// the full SPEC §9.3 suite on top of it.
//
// Run:
//
//	docker compose -f test/integration/docker-compose.yml up -d
//	# wait for all three services to report healthy (docker compose ps)
//	go test -tags integration ./test/integration -run TestConnectivity -v
//	docker compose -f test/integration/docker-compose.yml down -v
//
// Carried forward for Task 14: verify POST auth/token/revoke-self (SPEC
// §3.4 uses POST for this) actually works against BOTH products — flagged
// in the M1 plan as a Task-14 verification item, not exercised by this
// file (TestConnectivity only proves reachability + a valid root token).
package integration

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

var products = []struct {
	name      string
	addr      string
	rootToken string
}{
	{"vault", "http://127.0.0.1:8200", "root"},
	{"openbao", "http://127.0.0.1:8300", "root"},
}

func TestConnectivity(t *testing.T) {
	for _, p := range products {
		t.Run(p.name, func(t *testing.T) {
			c, err := api.NewClient(&api.Config{Address: p.addr})
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			c.SetToken(p.rootToken)

			health, err := c.Sys().Health()
			if err != nil {
				t.Fatalf("sys/health: %v", err)
			}
			if health.Sealed {
				t.Fatalf("%s: sealed", p.name)
			}
			if !health.Initialized {
				t.Fatalf("%s: not initialized", p.name)
			}

			// Confirms the root token itself is valid and authenticated
			// calls work, not just that the listener answers
			// unauthenticated sys/health.
			if _, err := c.Sys().ListMounts(); err != nil {
				t.Fatalf("%s: authenticated sys/mounts: %v", p.name, err)
			}
		})
	}
}

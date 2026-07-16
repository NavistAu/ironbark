# Test-only Ed25519 keypair

`dev-ed25519.pem` (PKCS#8 private key) and `dev-ed25519.pub` (PKIX public
key) are a throwaway Ed25519 keypair generated for this repository's tests
only:

    openssl genpkey -algorithm ed25519 -out dev-ed25519.pem
    openssl pkey -in dev-ed25519.pem -pubout -out dev-ed25519.pub

They are NOT used by any production Woodpecker or ironbark deployment. Do
not use them outside `internal/wpsign`'s test suite (Task 5's signature
matrix) and the `cmd/ironbark` smoke run (Task 12).

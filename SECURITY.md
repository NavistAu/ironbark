# Security Policy

ironbark mints Vault/OpenBao tokens and handles the secrets it sweeps —
treat any credential-handling bug as a security issue.

## Supported Versions

Only the latest minor release receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest 0.x.y | :white_check_mark: |
| older 0.x.y  | :x: |

## Reporting a Vulnerability

Please report security vulnerabilities privately via
[GitHub Security Advisories](https://github.com/navistau/ironbark/security/advisories/new)
for this repository — do not open a public issue.

We aim to acknowledge reports within **7 days**. Once a fix is available,
we'll coordinate disclosure timing with you.

## Verifying Release Artifacts

Starting with the first public release, published container images are
signed with `cosign` (keyless, GitHub OIDC). The verification invocation
will be documented here and in the README once v0.1.0 ships.

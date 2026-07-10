# ironbark

A [Woodpecker CI](https://woodpecker-ci.org) **secret extension** that federates
pipeline identity to [HashiCorp Vault](https://developer.hashicorp.com/vault) or
[OpenBao](https://openbao.org).

Woodpecker has no pipeline OIDC/id-token, so a pipeline can't present a
verifiable identity to a secrets manager and get short-lived credentials.
ironbark closes that gap using the one seam Woodpecker does provide — the
[secret extension](https://woodpecker-ci.org/docs/usage/extensions/secret-extension):

1. Woodpecker POSTs each pipeline's `{repo, pipeline}` to ironbark, signed
   (RFC-9421 ed25519).
2. ironbark verifies the signature, derives conventional Vault policy names
   from the forge-set `(repo, event, branch)`, and mints a **short-lived,
   narrowly-scoped token** via a Vault token-role — a policy set ironbark
   does not itself hold.
3. With that token — the pipeline's own — it sweeps the repo's conventional
   KV subtree (`kv/ci/<org>/<repo>/…`), dereferences pointer entries into
   dynamic engines (e.g. AWS STS), and returns the values as ordinary
   Woodpecker secrets — **automatically masked**, `from_secret`-addressable —
   plus the token itself for anything interactive.

ironbark is **stateless**: no rule table, no path maps. What a pipeline may
read is decided entirely by which Vault policies and KV entries exist —
onboarding a repo is Vault-side IaC, not broker config. And ironbark holds
**no standing read credential**: its own Vault identity can only create
tokens; every read happens under a per-pipeline, policy-scoped, short-TTL
token, transiently, storing nothing.

> Woodpecker drills wood; ironbark is the hardwood bark that decides, per peck,
> how far in it gets.

## Status

Design phase. See [`docs/DESIGN.md`](docs/DESIGN.md) and the decision log in
[`docs/decisionlog/`](docs/decisionlog/). Nothing is built yet.

## Why not just…

- **…a broker with its own read-everything credential?** A standing, silent
  decryption oracle. ironbark's Vault identity can only *create* tokens;
  every read chain starts with a per-role, audit-logged mint under the
  pipeline's own scoped token.
- **…Vault's Kubernetes auth?** Woodpecker lets a pipeline choose its own pod
  `serviceAccountName`, so k8s-SA identity is not a per-repo boundary.
- **…Woodpecker's native k8s secret refs?** Instance-wide: any repo's pipeline
  can mount any secret in the build namespace.
- **…Forgejo Actions (which has OIDC)?** Its Kubernetes runner still needs a
  privileged Docker-in-Docker sidecar; Woodpecker's k8s backend runs each step as
  an unprivileged pod. See the design doc's context section.

## License

[AGPL-3.0](LICENSE). It's a deployed service; the network-use clause keeps
hosted reuse open-source.

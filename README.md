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
2. ironbark verifies the signature, then maps `(repo, branch, event)` to a policy
   via a declarative table.
3. It mints a **short-lived, narrowly-scoped Vault/OpenBao token** for that
   policy and returns it to the pipeline.

The pipeline then talks to Vault/OpenBao directly with that token. **ironbark
never reads a secret value itself** — it delegates a capability (a scoped token),
not a secret. Vault token-role `allowed_policies` lets it grant a policy it does
not itself hold, so a compromised ironbark mints scoped ephemeral tokens and
nothing more.

> Woodpecker drills wood; ironbark is the hardwood bark that decides, per peck,
> how far in it gets.

## Status

Design phase. See [`docs/DESIGN.md`](docs/DESIGN.md). Nothing is built yet.

## Why not just…

- **…a value-returning broker?** It becomes a standing decryption oracle for
  everything it can read. ironbark returns a token, sees no values.
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

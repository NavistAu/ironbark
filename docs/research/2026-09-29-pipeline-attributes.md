# Pipeline attributes beyond repo/event/branch — findings (2026-09-29)

Status: research notes, not a design. Captured so the findings survive
until a spec is written. The spec waits on the adopting deployment
settling what its CI jobs are (a monorepo with one generic per-unit
deploy job is the leading shape), because that decides what ironbark has
to scope.

## Problem

ironbark derives a pipeline's policies from `repo`, `event` and `branch`
only (`internal/identity/identity.go`, `internal/policy/policy.go`). In a
monorepo every pipeline on the same event+branch receives the same tier:
a docs build on `push` to `main` is granted everything a deploy on `push`
to `main` is. There is no axis for *who* triggered the pipeline or *what*
part of the repository it acts on.

## Finding 1 — the signed payload already carries more

The secret-extension request body is `{repo, pipeline, netrc?}` with
`pipeline` being Woodpecker's whole `model.Pipeline`
(`docs/woodpecker-secret-mechanisms.md` §2, quoting
`server/services/secret/http.go`). `identity.go` parses a handful of
fields; the rest arrive signed and are ignored. From upstream
`server/model/pipeline.go`, the fields relevant to scoping:

| Field | Meaning | Trust |
|---|---|---|
| `sender` | forge login whose action triggered the pipeline (from the forge webhook, or the Woodpecker user for manual/deploy actions) | forge/server-set |
| `reviewed_by`, `reviewed` | who approved the pipeline when the repo requires approval | server-set |
| `deploy_to`, `deploy_task` | target and task of a `deployment` event | caller-chosen free text |
| `variables` | manual/deploy run variables (deploy: extra query params) | caller-chosen |
| `changed_files` | paths changed by the push | forge-computed; content chosen by the pusher |
| `author`, `author_email` | git commit author | **untrusted** (committer-set) |

DESIGN.md §1 states "Woodpecker has no pipeline-level identity token" —
true of a signed JWT — and then treats `full_name, branch, event, commit`
as the whole identity. `sender` was never examined (0 mentions in this
repo before this note). It is the missing *who*.

`Repo.Perm` (per-user pull/push/admin synced from the forge) is tagged
`json:"-"`: never serialised to the extension. No team or group data is
in the payload.

## Finding 2 — `deploy_to` is set by promotion, not by the forge

A `deployment` event is created by promoting an existing pipeline:
`POST /api/repos/{id}/pipelines/{number}?event=deployment&deploy_to=<t>&deploy_task=<k>`
(UI "Deploy", CLI and API all use it; `server/api/pipeline.go`
`PostPipeline`). The repo must have `allow_deploy`. Extra query params
become the run's variables. The target is free text — Woodpecker validates
nothing. Forgejo/Gitea forges have no deployment API feeding Woodpecker
(GitHub does, via webhook). Alone, `deploy_to` is caller-chosen; it
becomes meaningful combined with *who* (`sender` or `reviewed_by`).

## Finding 3 — groups must be resolved outside the payload

Forges have teams (per-repo unit permissions); the payload does not carry
them. Routes:

- **Forge teams API** (Gitea-family): list the repo's teams, check the
  sender's membership, request one conventional policy per team
  (e.g. `ci/<org>/<repo>/team/<team>`). Authority split stays clean —
  forge says who is in which group, Vault says what a group gets — and
  ironbark stays stateless. Costs: a forge read token, a runtime
  dependency (fail closed: no team policies), a trust chain of
  "server-signed sender → forge answer over TLS". Must not assume the
  forge's teams are directory-backed.
- **Vault identity**: people as entities, groups in Vault; mint the
  pipeline token bound to the sender's entity alias
  (`allowed_entity_aliases` on the token role, `entity_alias` at create)
  so group policies and identity templating apply. Unverified against
  the target Vault/OpenBao versions and the orphan-token role.
- **Approval**: `require_approval` + `approval_allowed_users`, keyed on
  `reviewed_by`.

## Finding 4 — Vault composition supports both adding and narrowing

A token's permission is the union of its policies, except an explicit
`deny` in any attached policy wins. Attribute-derived policies can
therefore *add* (a secret only in `…/team/deployers`) or *narrow* (a
policy attached for an attribute value carrying `deny` rules) with no
broker-side state. Conjunctions ("deployer AND target X") need either
combined names (`…/deployment/<target>/team/<team>`) or deny rules.
Requesting a non-existent policy grants nothing (DESIGN §2 step 3), so
extra requested names cost only the mint warnings; the token role's
`allowed_policies_glob` must cover every new shape or the whole mint
fails.

## Open questions for the spec

1. Verify `sender` and `deploy_to` are populated at extension-call time
   (capture one real request body), and what `sender` is on a promoted
   deployment (promoter or original pusher).
2. Naming convention for attribute policies, and escaping of free-text
   values (`deploy_to`, team names) — reuse `identity.Esc`.
3. Which attributes are *trusted enough* to key on; `author` never.
4. Team resolution: forge API vs Vault identity vs both.
5. Conjunction mechanism: combined names vs deny rules.
6. KV sweep layout for attribute tiers (the sweep reads one subtree;
   attribute tiers need paths the sweep will visit).
7. Backwards compatibility: existing `event`/`branch` policies unchanged.
</content>
</invoke>

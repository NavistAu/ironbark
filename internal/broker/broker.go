// Package broker orchestrates one verified request (design §9.1 steps 2-9):
// facts, selectors, the optional discovery login, the team lookup, the
// signed-JWT login and its assertions, the walk, and the response. It never
// fails a pipeline: every verified request yields a response carrying
// ironbark_status (§9.2), and a response carrying nothing else revokes the
// token the request obtained (§9.1). Steps 1-2's signature check belongs to
// internal/httpapi. The broker never logs; it returns what httpapi logs.
package broker

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/navistau/ironbark/internal/facts"
	"github.com/navistau/ironbark/internal/forge"
	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/identity"
	"github.com/navistau/ironbark/internal/jwtsign"
	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/selector"
	"github.com/navistau/ironbark/internal/status"
	"github.com/navistau/ironbark/internal/vaultx"
	"github.com/navistau/ironbark/internal/walk"
)

// Vault is what the broker needs from OpenBao. ironbark holds no OpenBao
// credential: the signed JWT is the only thing it presents.
type Vault interface {
	LoginJWT(ctx context.Context, mount, role, jwt string) (vaultx.Token, error)
	RevokeSelf(ctx context.Context, token string) error
	// Session binds a token for the walk.
	Session(token string) walk.Client
}

// Signer signs the JWT claims; *jwtsign.Signer satisfies it.
type Signer interface {
	Sign(claims map[string]any) (string, error)
}

var _ Signer = (*jwtsign.Signer)(nil)

type connVault struct{ *vaultx.Conn }

func (c connVault) Session(token string) walk.Client { return c.As(token) }

// FromConn adapts a *vaultx.Conn to Vault.
func FromConn(c *vaultx.Conn) Vault { return connVault{c} }

// revokeCleanupTimeout bounds a best-effort revoke. It is not derived from
// the request context: a request that timed out has a cancelled ctx, and
// that is exactly when revocation matters.
const revokeCleanupTimeout = 5 * time.Second

// Config is what the broker takes from ironbark's configuration.
type Config struct {
	Data               grantcfg.Template
	EnvVar, TargetVar  string
	JWTRole, JWTMount  string
	AdvertiseVaultAddr string
	ActorForge         string
}

// Secret is one entry of the response body.
type Secret struct {
	Name   string
	Value  string
	Images []string
}

// Result is Handle's outcome. Status is 200 for every verified request, or
// 400 when the payload cannot yield an identity. Secrets always include
// ironbark_status on a 200.
type Result struct {
	Status       int
	Secrets      []Secret
	Outcome      status.Outcome
	RevokeFailed bool
	// Err is the fault behind an error outcome, for httpapi's error log
	// (a config or availability fault, not a policy outcome).
	Err error
	// Warnings are walk warnings and ignored-pin notes, for the log.
	Warnings []string
	Audit    status.Audit
}

// Broker holds what Handle needs beyond the payload.
type Broker struct {
	vault  Vault
	signer Signer
	lk     forge.Lookups // nil: no forge
	cfg    Config
	now    func() time.Time
	log    *slog.Logger
}

// Option configures a Broker.
type Option func(*Broker)

// WithLookups enables the forge lookups (branch protection, teams).
func WithLookups(lk forge.Lookups) Option { return func(b *Broker) { b.lk = lk } }

// WithLogger sets the logger for the debug "payload attributes" line.
func WithLogger(l *slog.Logger) Option { return func(b *Broker) { b.log = l } }

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option { return func(b *Broker) { b.now = now } }

// New builds a Broker.
func New(v Vault, s Signer, cfg Config, opts ...Option) *Broker {
	b := &Broker{vault: v, signer: s, cfg: cfg, now: time.Now, log: slog.New(slog.DiscardHandler)}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Handle runs §9.1 steps 2-9 for a verified payload body.
func (b *Broker) Handle(ctx context.Context, body []byte) Result {
	f, err := facts.Build(ctx, body, b.lk, facts.Config{ActorForge: b.cfg.ActorForge})
	if err != nil {
		if errors.Is(err, identity.ErrMalformed) {
			return Result{Status: 400, Outcome: status.Error, Err: err}
		}
		return Result{Status: 500, Outcome: status.Error, Err: err}
	}

	b.logPayloadAttributes(ctx, f)

	a := status.Audit{
		TS: b.now(), Org: f.Org, Repo: f.Repo, RepoKey: f.RepoKey, Event: f.Event, Pipeline: f.Pipeline,
		Branch: f.Branch, Ref: f.Ref, BranchProtected: f.BranchProtected, Actor: f.Actor,
	}
	st := status.Status{}
	var token string
	var walked []walk.Secret
	var revokeFailed bool
	var walkRes walk.Result

	// finish builds the response and revokes the request's token when the
	// response carries nothing but ironbark_status (and vault_addr).
	finish := func(out status.Outcome, reason string, cause error) Result {
		st.Outcome, st.Reason = out, reason
		a.Outcome = out
		for _, s := range walked {
			a.SecretsReturned = append(a.SecretsReturned, s.Name)
			if len(s.Images) > 0 {
				a.ImagesRelayed = append(a.ImagesRelayed, s.Name)
			}
			if s.Name == "vault_token" {
				a.VaultTokenIssued = true
			}
		}
		a.Levels = walkRes.Levels
		res := Result{Status: 200, Outcome: out, Err: cause, Warnings: walkWarnings(walkRes), RevokeFailed: revokeFailed}
		names := map[string]string{status.StatusName: ""}
		for _, s := range walked {
			res.Secrets = append(res.Secrets, Secret{Name: s.Name, Value: s.Value, Images: s.Images})
			names[s.Name] = ""
		}
		res.Secrets = append(res.Secrets, Secret{Name: status.StatusName, Value: st.String()})
		if b.cfg.AdvertiseVaultAddr != "" {
			res.Secrets = append(res.Secrets, Secret{Name: status.VaultAddrName, Value: b.cfg.AdvertiseVaultAddr})
			names[status.VaultAddrName] = ""
		}
		if token != "" && status.ShouldRevoke(names) {
			if !b.revoke(token) {
				res.RevokeFailed = true
			}
		}
		res.Audit = a
		return res
	}

	// Step 3: selectors. An invalid explicit selector is status only, before
	// any login.
	env, envSource := "", ""
	if raw := f.Variables[b.cfg.EnvVar]; raw != "" {
		if !selector.ValidEnv(raw) {
			a.EnvInvalid = true
			return finish(status.Invalid, "env_invalid", nil)
		}
		env, envSource = raw, "variable"
	}
	tgt, tgtSource, invalid := selector.SelectTarget(f, body, b.cfg.TargetVar)
	a.TargetSource = tgtSource
	if invalid != "" {
		a.TargetInvalid = true
		st.Env, st.EnvSource = env, envSource
		return finish(status.Invalid, "target_invalid: "+invalid, nil)
	}
	org, repo := identity.Esc(f.Org), identity.Esc(f.Repo)

	// Step 4: discovery, only when no explicit environment and the branch is
	// protected. A no-claimant result keeps the discovery token.
	if env == "" && f.BranchProtected == "true" {
		role := grantcfg.RenderRole(b.cfg.JWTRole, "")
		tok, out, reason, cause := b.login(ctx, role, jwtsign.DiscoveryClaims(f, b.now()))
		st.Role, a.Role = role, role
		if out != "" {
			return finish(out, reason, cause)
		}
		token = tok.Value
		a.DiscoveryLogin = true
		a.TokenAccessor, a.TokenTTL = tok.Accessor, int(tok.TTL/time.Second)
		d, err := walk.Discover(ctx, b.vault.Session(token), b.cfg.Data, org, repo, f.Branch)
		switch {
		case err != nil:
			return finish(status.Error, "discovery", err)
		case len(d.Claimants) > 1:
			a.EnvClaimants = d.Claimants
			st.Levels = d.Claimants
			return finish(status.ConfigError, "env_conflict", nil)
		case len(d.Claimants) == 1:
			a.EnvClaimants = d.Claimants
			env, envSource = d.Claimants[0], "branch"
			// The discovery token is revoked before the environment login.
			revokeFailed = !b.revoke(token)
			token = ""
		}
	}

	a.Target = tgt.Joined() // recorded even when ignored
	tgt, _ = selector.IgnoreWithoutEnv(tgt, env)
	a.Env, a.EnvSource = env, envSource
	st.Env, st.EnvSource = env, envSource
	st.Target = tgt.Joined()

	// Step 5: teams, only with an environment and an actor; fail closed.
	var teams []string
	if env != "" && token == "" {
		teams, err = facts.ResolveTeams(ctx, b.lk, f, env)
		if err != nil {
			teams, a.TeamsError = nil, err.Error()
		}
		a.Teams = teams
	}

	// Steps 6-7: sign and log in with the rendered role, unless the
	// discovery token is being kept.
	role := grantcfg.RenderRole(b.cfg.JWTRole, env)
	st.Role, a.Role = role, role
	if token == "" {
		claims := jwtsign.Claims(f, env, envSource, tgt, teams, b.now())
		a.Sub, _ = claims["sub"].(string)
		a.JTI, _ = claims["jti"].(string)
		tok, out, reason, cause := b.login(ctx, role, claims)
		if out != "" {
			a.EnvRefused = out == status.Refused && envSource == "variable"
			return finish(out, reason, cause)
		}
		token = tok.Value
		a.TokenAccessor, a.TokenTTL = tok.Accessor, int(tok.TTL/time.Second)
	}

	// Step 8: the walk.
	lv := levels.Levels(b.cfg.Data, org, repo, env, tgt.Escaped)
	walkRes, err = walk.Walk(ctx, b.vault.Session(token), lv, walk.Options{})
	if err != nil {
		var ve *walk.ViewError
		if errors.As(err, &ve) {
			a.Entry = ve.Entry
			return finish(status.Error, "view:"+ve.Entry, err)
		}
		return finish(status.Error, "walk", err)
	}
	walked = walkRes.Secrets
	for _, lvl := range lv {
		if o := walkRes.Levels[lvl.Label]; o != walk.LevelRead && o != "" {
			st.Skipped = append(st.Skipped, lvl.Label)
		}
	}
	return finish(status.OK, "", nil)
}

// logPayloadAttributes is the debug line behind the pipeline facts (design
// §10): names only, never variable values or message text.
func (b *Broker) logPayloadAttributes(ctx context.Context, f facts.Facts) {
	if !b.log.Enabled(ctx, slog.LevelDebug) {
		return
	}
	names := make([]string, 0, len(f.Variables))
	for k := range f.Variables {
		names = append(names, k)
	}
	sort.Strings(names)
	b.log.Debug("payload attributes", "event", f.Event, "sender", f.Sender, "author", f.Author,
		"actor", f.Actor, "branch", f.Branch, "variable_names", names)
}

// login signs claims and logs in as role. On failure it returns the outcome
// and reason for the status line; no token is held afterwards.
func (b *Broker) login(ctx context.Context, role string, claims map[string]any) (tok vaultx.Token, out status.Outcome, reason string, cause error) {
	jwt, err := b.signer.Sign(claims)
	if err != nil {
		return tok, status.Error, "sign", err
	}
	tok, err = b.vault.LoginJWT(ctx, b.cfg.JWTMount, role, jwt)
	var refused *vaultx.RefusedError
	var assertion *vaultx.AssertionError
	switch {
	case err == nil:
		return tok, "", "", nil
	case errors.As(err, &refused):
		return tok, status.Refused, "bound_claims", nil
	case errors.As(err, &assertion):
		return tok, status.Error, "assertion: " + assertion.Reason, err
	default:
		return tok, status.Error, "login", err
	}
}

// revoke is a best-effort revoke-self on a detached context.
func (b *Broker) revoke(token string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), revokeCleanupTimeout)
	defer cancel()
	return b.vault.RevokeSelf(ctx, token) == nil
}

func walkWarnings(w walk.Result) []string {
	out := append([]string(nil), w.Warnings...)
	for _, e := range w.IgnoredEvents {
		out = append(out, e+": ironbark_events is ignored; event pins are role bound_claims")
	}
	sort.Strings(out)
	return out
}

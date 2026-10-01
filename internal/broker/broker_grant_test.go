package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/status"
	"github.com/navistau/ironbark/internal/vaultx"
	"github.com/navistau/ironbark/internal/walk"
)

// ---- fakes ----

type fakeSigner struct {
	claims []map[string]any
	err    error
}

func (s *fakeSigner) Sign(c map[string]any) (string, error) {
	s.claims = append(s.claims, c)
	return fmt.Sprintf("jwt%d", len(s.claims)), s.err
}

// fakeVault logs every call so ordering can be asserted. logins maps a role to
// an error (nil = success); a successful login mints token "tok-<role>".
type fakeVault struct {
	calls      []string
	loginErr   map[string]error
	revokeErr  error
	tokens     map[string]*fakeSession // by token
	sessionFor func(token string) *fakeSession
}

func (v *fakeVault) LoginJWT(_ context.Context, _, role, jwt string) (vaultx.Token, error) {
	v.calls = append(v.calls, "login "+role)
	if err := v.loginErr[role]; err != nil {
		return vaultx.Token{}, err
	}
	return vaultx.Token{Value: "tok-" + role, Accessor: "acc-" + role, TTL: 15 * time.Minute}, nil
}

func (v *fakeVault) RevokeSelf(_ context.Context, token string) error {
	v.calls = append(v.calls, "revoke "+token)
	return v.revokeErr
}

func (v *fakeVault) Session(token string) walk.Client {
	v.calls = append(v.calls, "session "+token)
	return v.sessionFor(token)
}

func (v *fakeVault) revoked(token string) bool {
	for _, c := range v.calls {
		if c == "revoke "+token {
			return true
		}
	}
	return false
}

// fakeSession is a walk.Client over maps. lists is keyed by metadata path;
// reads by data/resolve path; md by level-metadata path; errs by path.
type fakeSession struct {
	token string
	lists map[string][]string
	reads map[string]map[string]any
	md    map[string]map[string]string
	errs  map[string]error
}

func (s *fakeSession) Token() string { return s.token }
func (s *fakeSession) List(_ context.Context, p string) ([]string, error) {
	if err := s.errs[p]; err != nil {
		return nil, err
	}
	k, ok := s.lists[p]
	if !ok {
		return nil, vaultx.ErrNotFound
	}
	return k, nil
}
func (s *fakeSession) Read(_ context.Context, p string) (*vaultx.Secret, error) {
	if err := s.errs[p]; err != nil {
		return nil, err
	}
	d, ok := s.reads[p]
	if !ok {
		return nil, vaultx.ErrNotFound
	}
	out := map[string]json.RawMessage{}
	for k, v := range d {
		b, _ := json.Marshal(v)
		out[k] = b
	}
	return &vaultx.Secret{Data: out}, nil
}
func (s *fakeSession) LevelMetadata(_ context.Context, p string) (map[string]string, bool, error) {
	if err := s.errs["md:"+p]; err != nil {
		return nil, false, err
	}
	m, ok := s.md[p]
	return m, ok, nil
}

type fakeForge struct {
	protected    bool
	protErr      error
	teams        []string
	teamsErr     error
	teamCalls    int
	protectCalls int
}

func (f *fakeForge) BranchProtected(context.Context, string, string, string) (bool, error) {
	f.protectCalls++
	return f.protected, f.protErr
}
func (f *fakeForge) QualifiedTeams(context.Context, string, string, string) ([]string, error) {
	f.teamCalls++
	return f.teams, f.teamsErr
}

// ---- harness ----

const dataPath = "vs/data/pipelines/{repo}/{env}/{target...}"

func kvEntry(v string) map[string]any {
	return map[string]any{"data": map[string]any{"value": v}, "metadata": map[string]any{"custom_metadata": map[string]any{}}}
}

type rig struct {
	v  *fakeVault
	s  *fakeSigner
	f  *fakeForge
	b  *Broker
	ss map[string]*fakeSession
}

// newRig: every token gets its own session, defaulting to an empty tree.
func newRig(t *testing.T, advertise string) *rig {
	t.Helper()
	tmpl, err := grantcfg.ParseTemplate(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{v: &fakeVault{loginErr: map[string]error{}}, s: &fakeSigner{}, f: &fakeForge{protected: true}, ss: map[string]*fakeSession{}}
	r.v.sessionFor = func(tok string) *fakeSession {
		if s, ok := r.ss[tok]; ok {
			return s
		}
		s := &fakeSession{token: tok, lists: map[string][]string{}, reads: map[string]map[string]any{}, md: map[string]map[string]string{}, errs: map[string]error{}}
		r.ss[tok] = s
		return s
	}
	r.b = New(r.v, r.s, Config{Data: tmpl, EnvVar: "DEPLOY_ENV", TargetVar: "DEPLOY_TO", JWTRole: "ci-{env}", JWTMount: "jwt",
		AdvertiseVaultAddr: advertise, ActorForge: "gitea"}, WithLookups(r.f))
	return r
}

// tree puts one secret at a level for the token's session.
func (r *rig) tree(token, metaPath, dataPath, key, val string) {
	s := r.v.sessionFor(token)
	s.lists[metaPath] = append(s.lists[metaPath], key)
	s.reads[dataPath+key] = kvEntry(val)
}

type payloadOpts struct {
	event, branch, ref, sender, author, deployTo, message string
	vars                                                  map[string]string
}

func payload(o payloadOpts) []byte {
	if o.event == "" {
		o.event = "push"
	}
	if o.ref == "" && o.branch != "" {
		o.ref = "refs/heads/" + o.branch
	}
	p := map[string]any{
		"repo": map[string]any{"full_name": "Acme/Mono", "forge_remote_id": "7"},
		"pipeline": map[string]any{"event": o.event, "branch": o.branch, "ref": o.ref, "number": 3,
			"sender": o.sender, "author": o.author, "deploy_to": o.deployTo, "message": o.message, "variables": o.vars},
	}
	b, _ := json.Marshal(p)
	return b
}

func lookup(res Result, name string) (Secret, bool) {
	for _, s := range res.Secrets {
		if s.Name == name {
			return s, true
		}
	}
	return Secret{}, false
}

func statusLine(t *testing.T, res Result) string {
	t.Helper()
	s, ok := lookup(res, status.StatusName)
	if !ok {
		t.Fatalf("no ironbark_status in %+v", res.Secrets)
	}
	return s.Value
}

func onlyStatus(res Result) bool {
	for _, s := range res.Secrets {
		if s.Name != status.StatusName && s.Name != status.VaultAddrName {
			return false
		}
	}
	return true
}

const (
	repoMeta = "vs/metadata/pipelines/acme/mono/"
	repoData = "vs/data/pipelines/acme/mono/"
)

// ---- tests: one per §9.3 row and outcome ----

func TestOK_ExplicitEnvWalksAndKeepsToken(t *testing.T) {
	r := newRig(t, "")
	r.tree("tok-ci-prod", repoMeta+"prod/", repoData+"prod/", "db", "FAKE-1")
	r.v.sessionFor("tok-ci-prod").lists[repoMeta] = nil // repo level empty
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "alice", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if res.Status != 200 || res.Outcome != status.OK {
		t.Fatalf("res = %+v", res)
	}
	if s, ok := lookup(res, "db"); !ok || s.Value != "FAKE-1" {
		t.Errorf("secrets = %+v", res.Secrets)
	}
	if got := statusLine(t, res); !strings.Contains(got, "outcome=ok") || !strings.Contains(got, "env=prod") || !strings.Contains(got, "env_source=variable") || !strings.Contains(got, "role=ci-prod") {
		t.Errorf("status = %q", got)
	}
	if r.v.revoked("tok-ci-prod") {
		t.Error("a response with secrets must not revoke")
	}
	if res.Audit.Role != "ci-prod" || res.Audit.Sub == "" || res.Audit.JTI == "" || res.Audit.TokenAccessor != "acc-ci-prod" || res.Audit.TokenTTL != 900 {
		t.Errorf("audit = %+v", res.Audit)
	}
	if !reflect.DeepEqual(res.Audit.SecretsReturned, []string{"db"}) {
		t.Errorf("secrets_returned = %v", res.Audit.SecretsReturned)
	}
}

func TestOK_TeamsOnlyWithEnvAndActor(t *testing.T) {
	r := newRig(t, "")
	r.f.teams = []string{"acme/deployers"}
	r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "alice", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if r.f.teamCalls != 1 || !reflect.DeepEqual(r.s.claims[0]["teams"], []string{"acme/deployers"}) {
		t.Errorf("teamCalls=%d claims=%v", r.f.teamCalls, r.s.claims[0])
	}
	r = newRig(t, "")
	r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "alice"}))
	if r.f.teamCalls != 0 {
		t.Error("no environment: no team lookup")
	}
}

func TestTeamLookupFailsClosed(t *testing.T) {
	r := newRig(t, "")
	r.f.teamsErr = errors.New("forge down")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "alice", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if res.Outcome != status.OK || res.Audit.TeamsError == "" || res.Audit.Teams != nil {
		t.Errorf("res = %+v", res)
	}
	if !reflect.DeepEqual(r.s.claims[0]["teams"], []string{}) {
		t.Errorf("teams claim = %#v, want []", r.s.claims[0]["teams"])
	}
}

func TestDiscovery_OneClaimantRevokesBeforeEnvLogin(t *testing.T) {
	r := newRig(t, "")
	ci := r.v.sessionFor("tok-ci")
	ci.lists[repoMeta] = []string{"prod/", "dev/"}
	ci.md[repoMeta+"prod/"] = map[string]string{"branches": "main"}
	ci.md[repoMeta+"dev/"] = map[string]string{"branches": "dev"}
	r.tree("tok-ci-prod", repoMeta+"prod/", repoData+"prod/", "db", "FAKE")
	res := r.b.Handle(context.Background(), payload(payloadOpts{branch: "main", sender: "alice"}))
	if res.Outcome != status.OK || res.Audit.Env != "prod" || res.Audit.EnvSource != "branch" || !res.Audit.DiscoveryLogin {
		t.Fatalf("res = %+v", res)
	}
	var seq []string
	for _, c := range r.v.calls {
		if strings.HasPrefix(c, "login") || strings.HasPrefix(c, "revoke") {
			seq = append(seq, c)
		}
	}
	if want := []string{"login ci", "revoke tok-ci", "login ci-prod"}; !reflect.DeepEqual(seq, want) {
		t.Errorf("sequence = %v, want %v", seq, want)
	}
	if got := r.s.claims[0]; got["env"] != nil || !reflect.DeepEqual(got["teams"], []string{}) {
		t.Errorf("discovery claims = %v", got)
	}
	if r.v.revoked("tok-ci-prod") {
		t.Error("env token must survive")
	}
}

func TestDiscovery_NoClaimantKeepsDiscoveryToken(t *testing.T) {
	r := newRig(t, "")
	ci := r.v.sessionFor("tok-ci")
	ci.lists[repoMeta] = []string{"prod/", "shared"}
	ci.md[repoMeta+"prod/"] = map[string]string{"branches": "main"}
	ci.reads[repoData+"shared"] = kvEntry("S")
	res := r.b.Handle(context.Background(), payload(payloadOpts{branch: "feature", sender: "alice"}))
	if res.Outcome != status.OK || res.Audit.Env != "" {
		t.Fatalf("res = %+v", res)
	}
	if r.v.revoked("tok-ci") {
		t.Error("kept token must not be revoked")
	}
	if s, ok := lookup(res, "shared"); !ok || s.Value != "S" {
		t.Errorf("secrets = %+v", res.Secrets)
	}
	for _, c := range r.v.calls {
		if c == "login ci-prod" {
			t.Error("no second login")
		}
	}
}

func TestDiscovery_TwoClaimantsConfigError(t *testing.T) {
	r := newRig(t, "")
	ci := r.v.sessionFor("tok-ci")
	ci.lists[repoMeta] = []string{"prod/", "beta/"}
	ci.md[repoMeta+"prod/"] = map[string]string{"branches": "main"}
	ci.md[repoMeta+"beta/"] = map[string]string{"branches": "m*"}
	res := r.b.Handle(context.Background(), payload(payloadOpts{branch: "main"}))
	if res.Outcome != status.ConfigError || !onlyStatus(res) || !r.v.revoked("tok-ci") {
		t.Fatalf("res = %+v calls=%v", res, r.v.calls)
	}
	if got := statusLine(t, res); !strings.Contains(got, "levels=beta,prod") {
		t.Errorf("status = %q", got)
	}
}

func TestDiscovery_MetadataUnreadableIsErrorAndRevokes(t *testing.T) {
	r := newRig(t, "")
	ci := r.v.sessionFor("tok-ci")
	ci.lists[repoMeta] = []string{"prod/"}
	ci.errs["md:"+repoMeta+"prod/"] = errors.New("boom 500")
	res := r.b.Handle(context.Background(), payload(payloadOpts{branch: "main"}))
	if res.Outcome != status.Error || !onlyStatus(res) || !r.v.revoked("tok-ci") || res.Err == nil {
		t.Fatalf("res = %+v", res)
	}
}

func TestDiscovery_SkippedWhenUnprotectedOrForgeDown(t *testing.T) {
	for name, set := range map[string]func(*rig){
		"unprotected": func(r *rig) { r.f.protected = false },
		"forge down":  func(r *rig) { r.f.protErr = errors.New("down") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, "")
			set(r)
			res := r.b.Handle(context.Background(), payload(payloadOpts{branch: "main"}))
			if res.Outcome != status.OK || res.Audit.DiscoveryLogin {
				t.Errorf("res = %+v", res)
			}
			if !reflect.DeepEqual(r.v.calls[:1], []string{"login ci"}) || r.s.claims[0]["branch_protected"] != "false" {
				t.Errorf("calls=%v claims=%v", r.v.calls, r.s.claims[0])
			}
		})
	}
}

func TestPR_RepoLevelOnly(t *testing.T) {
	r := newRig(t, "")
	r.tree("tok-ci", repoMeta, repoData, "shared", "S")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "pull_request", sender: "alice"}))
	if res.Outcome != status.OK || r.f.protectCalls != 0 || res.Audit.DiscoveryLogin {
		t.Fatalf("res = %+v", res)
	}
	if _, ok := lookup(res, "shared"); !ok {
		t.Error("repo level secret missing")
	}
	if _, has := r.s.claims[0]["branch"]; has {
		t.Error("no branch claim on a pull_request")
	}
}

func TestTagRepoLevelOnly(t *testing.T) {
	r := newRig(t, "")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "tag"}))
	if res.Outcome != status.OK || r.v.calls[0] != "login ci" {
		t.Errorf("res=%+v calls=%v", res, r.v.calls)
	}
}

func TestTargetWithoutEnvIgnoredAndRecorded(t *testing.T) {
	r := newRig(t, "")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "feature", author: "alice", vars: map[string]string{"DEPLOY_TO": "web/api"}}))
	if res.Outcome != status.OK || res.Audit.Target != "web/api" || res.Audit.TargetSource != "variable" {
		t.Fatalf("audit = %+v", res.Audit)
	}
	if _, has := r.s.claims[0]["target"]; has {
		t.Error("ignored target must not reach the JWT")
	}
	if got := statusLine(t, res); strings.Contains(got, "target=") {
		t.Errorf("status = %q", got)
	}
}

func TestTargetAndPipelineLoggedEscaped(t *testing.T) {
	r := newRig(t, "")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "feature", author: "alice", vars: map[string]string{"DEPLOY_TO": "Web/api"}}))
	if res.Audit.Target != "%57eb/api" || res.Audit.Pipeline != "3" {
		t.Errorf("audit target=%q pipeline=%q", res.Audit.Target, res.Audit.Pipeline)
	}
}

func TestPromoteDeployToWalksTargetLevels(t *testing.T) {
	r := newRig(t, "")
	r.tree("tok-ci-prod", repoMeta+"prod/", repoData+"prod/", "a", "1")
	r.tree("tok-ci-prod", repoMeta+"prod/web/", repoData+"prod/web/", "b", "2")
	r.tree("tok-ci-prod", repoMeta+"prod/web/api/", repoData+"prod/web/api/", "c", "3")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "deployment", branch: "main", deployTo: "web/api", sender: "bob", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if res.Outcome != status.OK || len(res.Secrets) != 4 {
		t.Fatalf("res = %+v", res)
	}
	if c := r.s.claims[0]; c["target"] != "web/api" || c["t1"] != "web" || c["t2"] != "api" {
		t.Errorf("claims = %v", c)
	}
	if res.Audit.TargetSource != "deploy_to" {
		t.Errorf("source = %q", res.Audit.TargetSource)
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]payloadOpts{
		"env grammar":   {event: "manual", branch: "main", vars: map[string]string{"DEPLOY_ENV": "Prod!"}},
		"target dot":    {event: "manual", branch: "main", vars: map[string]string{"DEPLOY_ENV": "prod", "DEPLOY_TO": "web/../x"}},
		"target dotdot": {event: "deployment", branch: "main", deployTo: "..", vars: map[string]string{"DEPLOY_ENV": "prod"}},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, "")
			res := r.b.Handle(context.Background(), payload(o))
			if res.Outcome != status.Invalid || !onlyStatus(res) || len(r.v.calls) != 0 {
				t.Fatalf("res=%+v calls=%v", res, r.v.calls)
			}
		})
	}
	r := newRig(t, "")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", vars: map[string]string{"DEPLOY_ENV": "Prod!"}}))
	if !res.Audit.EnvInvalid {
		t.Error("env_invalid not audited")
	}
}

func TestRefused_NoSecondRole(t *testing.T) {
	r := newRig(t, "")
	r.v.loginErr["ci-prod"] = &vaultx.RefusedError{Msg: "error validating claims"}
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "feature", author: "a", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if res.Outcome != status.Refused || !onlyStatus(res) || !res.Audit.EnvRefused {
		t.Fatalf("res = %+v", res)
	}
	if !reflect.DeepEqual(r.v.calls, []string{"login ci-prod"}) {
		t.Errorf("calls = %v (no retry, no fallback)", r.v.calls)
	}
	if got := statusLine(t, res); !strings.Contains(got, "reason=bound_claims") || !strings.Contains(got, "role=ci-prod") {
		t.Errorf("status = %q", got)
	}
}

func TestErrorRows(t *testing.T) {
	cases := map[string]func(*rig){
		"openbao unreachable": func(r *rig) { r.v.loginErr["ci-prod"] = errors.New("dial tcp: refused") },
		"jwt rejected":        func(r *rig) { r.v.loginErr["ci-prod"] = errors.New("400 signature is invalid") },
		"slash claim 400":     func(r *rig) { r.v.loginErr["ci-prod"] = errors.New("400 claim contains /") },
		"assertion": func(r *rig) {
			r.v.loginErr["ci-prod"] = &vaultx.AssertionError{Role: "ci-prod", Reason: "token_type is batch"}
		},
		"sign failure": func(r *rig) { r.s.err = errors.New("no key") },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, "")
			set(r)
			res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "a", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
			if res.Outcome != status.Error || !onlyStatus(res) || res.Err == nil {
				t.Fatalf("res = %+v", res)
			}
		})
	}
}

func TestWalkFailureRevokesAndReportsError(t *testing.T) {
	r := newRig(t, "")
	s := r.v.sessionFor("tok-ci-prod")
	s.lists[repoMeta+"prod/"] = []string{"db"}
	s.errs[repoData+"prod/db"] = errors.New("502 view quarantined")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "a", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if res.Outcome != status.Error || !onlyStatus(res) || !r.v.revoked("tok-ci-prod") {
		t.Fatalf("res = %+v", res)
	}
	if got := statusLine(t, res); !strings.Contains(got, "reason=view:prod/db") {
		t.Errorf("status = %q", got)
	}
	if res.Audit.Entry != "prod/db" {
		t.Errorf("audit entry = %q", res.Audit.Entry)
	}
}

func TestOtherWalkFailureStaysReasonWalk(t *testing.T) {
	r := newRig(t, "")
	s := r.v.sessionFor("tok-ci-prod")
	s.errs[repoMeta+"prod/"] = errors.New("boom")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "a", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if got := statusLine(t, res); !strings.Contains(got, "reason=walk") || res.Audit.Entry != "" {
		t.Errorf("status = %q entry = %q", got, res.Audit.Entry)
	}
}

func TestPayloadAttributesDebugLine(t *testing.T) {
	r := newRig(t, "")
	var buf bytes.Buffer
	r.b.log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", sender: "sam", author: "alice", message: "SECRETMSG",
		vars: map[string]string{"DEPLOY_ENV": "prod", "OTHER": "SECRETVAL"}}))
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("log = %q: %v", buf.String(), err)
	}
	if line["msg"] != "payload attributes" || line["event"] != "manual" || line["sender"] != "sam" || line["author"] != "alice" ||
		!reflect.DeepEqual(line["variable_names"], []any{"DEPLOY_ENV", "OTHER"}) {
		t.Errorf("line = %v", line)
	}
	if strings.Contains(buf.String(), "SECRETVAL") || strings.Contains(buf.String(), "SECRETMSG") {
		t.Errorf("a variable value or message reached the log: %s", buf.String())
	}
	buf.Reset()
	r.b.log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "alice"}))
	if buf.Len() != 0 {
		t.Errorf("emitted at info level: %s", buf.String())
	}
}

func TestSkippedLevelsListedAndEmptyOKRevokes(t *testing.T) {
	r := newRig(t, "")
	s := r.v.sessionFor("tok-ci-prod")
	s.errs[repoMeta+"prod/"] = vaultx.ErrForbidden
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "a", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	if res.Outcome != status.OK || !onlyStatus(res) || !r.v.revoked("tok-ci-prod") {
		t.Fatalf("res = %+v calls=%v", res, r.v.calls)
	}
	if got := statusLine(t, res); !strings.Contains(got, ",prod") {
		t.Errorf("status = %q", got)
	}
	if res.Audit.Levels["prod"] != walk.LevelSkipped403 {
		t.Errorf("levels = %v", res.Audit.Levels)
	}
}

func TestVaultAddrNeverKeepsTheToken(t *testing.T) {
	r := newRig(t, "https://bao.example")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "tag"}))
	if s, ok := lookup(res, "vault_addr"); !ok || s.Value != "https://bao.example" {
		t.Errorf("secrets = %+v", res.Secrets)
	}
	if !r.v.revoked("tok-ci") {
		t.Error("status + vault_addr still revokes")
	}
}

func TestRevokeFailureFlagged(t *testing.T) {
	r := newRig(t, "")
	r.v.revokeErr = errors.New("nope")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "tag"}))
	if !res.RevokeFailed || res.Outcome != status.OK {
		t.Errorf("res = %+v", res)
	}
}

func TestVaultTokenMarkerAndImages(t *testing.T) {
	r := newRig(t, "")
	s := r.v.sessionFor("tok-ci-prod")
	s.lists[repoMeta+"prod/"] = []string{"vault_token", "db"}
	s.reads[repoData+"prod/vault_token"] = map[string]any{"data": nil, "metadata": map[string]any{"custom_metadata": map[string]any{"ironbark_images": "deploy:*"}}, "voidstar": map[string]any{"mode": "metadata"}}
	s.reads[repoData+"prod/db"] = kvEntry("x")
	res := r.b.Handle(context.Background(), payload(payloadOpts{event: "manual", branch: "main", author: "a", vars: map[string]string{"DEPLOY_ENV": "prod"}}))
	vt, ok := lookup(res, "vault_token")
	if !ok || vt.Value != "tok-ci-prod" || !reflect.DeepEqual(vt.Images, []string{"deploy:*"}) {
		t.Fatalf("vault_token = %+v", vt)
	}
	if !res.Audit.VaultTokenIssued || !reflect.DeepEqual(res.Audit.ImagesRelayed, []string{"vault_token"}) {
		t.Errorf("audit = %+v", res.Audit)
	}
}

func TestMalformedPayload(t *testing.T) {
	r := newRig(t, "")
	res := r.b.Handle(context.Background(), []byte(`{"repo":{}}`))
	if res.Status != 400 || len(r.v.calls) != 0 {
		t.Errorf("res = %+v", res)
	}
}

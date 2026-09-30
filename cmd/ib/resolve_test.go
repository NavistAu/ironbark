package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"

	"github.com/navistau/ironbark/internal/gitenv"
	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/walk"
)

const (
	rtMeta  = "vs/metadata/pipelines/acme/widgets/"
	rtData  = "vs/data/pipelines/acme/widgets/"
	rtToken = "caller-token"
)

// testVault is a walk client and lease API pointed at a fakeVault, built the
// way production builds them.
type testVault struct {
	client walk.Client
	leases *leaseAPI
}

func newTestVault(t *testing.T, fv *fakeVault) testVault {
	t.Helper()
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)
	c, l, err := newVault(srv.URL, nil, rtToken)
	if err != nil {
		t.Fatalf("newVault: %v", err)
	}
	return testVault{client: c, leases: l}
}

func testTmpl(t *testing.T) grantcfg.Template {
	t.Helper()
	tm, err := grantcfg.ParseTemplate("vs/data/pipelines/{repo}/{env}/{target...}")
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// opts is the common test selection: the "staging" environment named
// explicitly, no target.
func (v testVault) opts(t *testing.T, fx ibFixture, stderr io.Writer) resolveOpts {
	t.Helper()
	return resolveOpts{Runner: gitenv.ExecRunner{Dir: fx.clone}, Client: v.client, Leases: v.leases, Tmpl: testTmpl(t), Env: "staging", Stderr: stderr}
}

func kv(fields map[string]interface{}) string { return entryBody(fields, nil) }

func val(s string) map[string]interface{} { return map[string]interface{}{"value": s} }

// TestResolve_ExplicitEnvWalk: repo and environment levels are read, the
// deeper level wins a clash, and neither vault_token nor ironbark_status is
// ever returned, even from a marker or a real entry.
func TestResolve_ExplicitEnvWalk(t *testing.T) {
	fx := newIBFixture(t, nil)
	fv := newFakeVault()
	fv.setList(rtMeta, "shared", "clash", "vault_token", "ironbark_status", "staging/")
	fv.set("/v1/"+rtData+"shared", 200, kv(val("shared-value")))
	fv.set("/v1/"+rtData+"clash", 200, kv(val("from-repo")))
	fv.set("/v1/"+rtData+"vault_token", 200, markerBody())
	fv.set("/v1/"+rtData+"ironbark_status", 200, kv(val("spoof")))
	fv.setList(rtMeta+"staging/", "clash", "vault_token", "only_staging")
	fv.set("/v1/"+rtData+"staging/clash", 200, kv(val("from-staging")))
	fv.set("/v1/"+rtData+"staging/vault_token", 200, markerBody())
	fv.set("/v1/"+rtData+"staging/only_staging", 200, kv(val("s")))

	var stderr bytes.Buffer
	secrets, leases, sel, err := resolve(context.Background(), newTestVault(t, fv).opts(t, fx, &stderr))
	if err != nil {
		t.Fatalf("resolve: %v (stderr: %s)", err, stderr.String())
	}
	got := map[string]string{}
	for n, s := range secrets {
		got[n] = s.Value
	}
	want := map[string]string{"shared": "shared-value", "clash": "from-staging", "only_staging": "s"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("secrets = %v, want %v", got, want)
	}
	if len(leases) != 0 {
		t.Errorf("leases = %v, want none", leases)
	}
	if sel.Env != "staging" || sel.Rule != gitenv.RuleExplicit {
		t.Errorf("selection = %+v", sel)
	}
	if !strings.Contains(stderr.String(), "ib: env staging (explicit)") {
		t.Errorf("stderr = %q, want the visibility line", stderr.String())
	}
	if strings.Contains(stderr.String(), rtToken) {
		t.Errorf("stderr leaks the token: %q", stderr.String())
	}
}

func discoveryVault() *fakeVault {
	fv := newFakeVault()
	fv.setList(rtMeta, "shared", "prod/", "staging/")
	fv.set("/v1/"+rtMeta+"prod/", 200, levelMetaBody(map[string]string{"branches": "main"}))
	fv.set("/v1/"+rtMeta+"staging/", 200, levelMetaBody(map[string]string{"branches": "release/*"}))
	fv.set("/v1/"+rtData+"shared", 200, kv(val("sv")))
	fv.setList(rtMeta+"prod/", "p")
	fv.set("/v1/"+rtData+"prod/p", 200, kv(val("pv")))
	return fv
}

// TestResolve_DiscoversEnvFromBranch: with no --env the local branch (main)
// is matched against the level metadata the caller can read.
func TestResolve_DiscoversEnvFromBranch(t *testing.T) {
	fx := newIBFixture(t, nil) // clone is on main
	var stderr bytes.Buffer
	o := newTestVault(t, discoveryVault()).opts(t, fx, &stderr)
	o.Env = ""
	secrets, _, sel, err := resolve(context.Background(), o)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if sel.Env != "prod" || sel.Rule != gitenv.RuleBranch {
		t.Errorf("selection = %+v", sel)
	}
	if secrets["p"].Value != "pv" || secrets["shared"].Value != "sv" {
		t.Errorf("secrets = %v", secrets)
	}
	if !strings.Contains(stderr.String(), "ib: env prod (branch)") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestResolve_NoClaimantIsRepoLevelOnly: a branch no level claims is not an
// error; only the repo level is read.
func TestResolve_NoClaimantIsRepoLevelOnly(t *testing.T) {
	fx := newIBFixture(t, nil)
	gitRaw(t, fx.clone, "checkout", "-q", "-b", "wip/thing")
	var stderr bytes.Buffer
	o := newTestVault(t, discoveryVault()).opts(t, fx, &stderr)
	o.Env = ""
	secrets, _, sel, err := resolve(context.Background(), o)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if sel.Env != "" || sel.Rule != gitenv.RuleNone {
		t.Errorf("selection = %+v", sel)
	}
	if len(secrets) != 1 || secrets["shared"].Value != "sv" {
		t.Errorf("secrets = %v, want only the repo level's", secrets)
	}
	if !strings.Contains(stderr.String(), "no environment; repo level only") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestResolve_SeveralClaimantsExit4NamesThem: two levels claim the branch.
func TestResolve_SeveralClaimantsExit4NamesThem(t *testing.T) {
	fx := newIBFixture(t, nil)
	fv := discoveryVault()
	fv.set("/v1/"+rtMeta+"staging/", 200, levelMetaBody(map[string]string{"branches": "main"}))
	o := newTestVault(t, fv).opts(t, fx, io.Discard)
	o.Env = ""
	_, _, _, err := resolve(context.Background(), o)
	var se *gitenv.SelectError
	if !errors.As(err, &se) || se.Kind != "ambiguous" {
		t.Fatalf("err = %v, want an ambiguous SelectError", err)
	}
	if !strings.Contains(err.Error(), "prod") || !strings.Contains(err.Error(), "staging") {
		t.Errorf("error %q must name both levels", err)
	}
	if exitCode(err) != 4 {
		t.Errorf("exit = %d, want 4", exitCode(err))
	}
}

// TestResolve_NestedTarget: --target web/api walks every segment and only
// those; a sibling is never read.
func TestResolve_NestedTarget(t *testing.T) {
	fx := newIBFixture(t, nil)
	fv := newFakeVault()
	fv.setList(rtMeta, "r")
	fv.set("/v1/"+rtData+"r", 200, kv(val("1")))
	fv.setList(rtMeta+"staging/", "e", "web/", "cli/")
	fv.set("/v1/"+rtData+"staging/e", 200, kv(val("2")))
	fv.setList(rtMeta+"staging/web/", "w", "api/")
	fv.set("/v1/"+rtData+"staging/web/w", 200, kv(val("3")))
	fv.setList(rtMeta+"staging/web/api/", "a")
	fv.set("/v1/"+rtData+"staging/web/api/a", 200, kv(val("4")))
	// staging/cli/ is not programmed: reading it would 404 and show up in
	// levels, but the secret names prove it was skipped either way.
	o := newTestVault(t, fv).opts(t, fx, io.Discard)
	o.Target = "web/api"
	secrets, _, sel, err := resolve(context.Background(), o)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, n := range []string{"r", "e", "w", "a"} {
		if secrets[n].Value == "" {
			t.Errorf("missing %q in %v", n, secrets)
		}
	}
	if len(sel.Target.Segments) != 2 {
		t.Errorf("selection = %+v", sel)
	}
}

// TestResolve_ResolveMappingLeaseIsReturned: a resolve mapping is read with
// the caller's token and its lease id comes back for revocation.
func TestResolve_ResolveMappingLeaseIsReturned(t *testing.T) {
	fx, fv := setupGetEnvFixture(t)
	secrets, leases, _, err := resolve(context.Background(), newTestVault(t, fv).opts(t, fx, io.Discard))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if secrets["dbref_username"].Value != "u" || secrets["dbref_password"].Value != "p" {
		t.Errorf("secrets = %v", secrets)
	}
	if len(leases) != 1 || leases[0] != "database/creds/readonly/abc" {
		t.Errorf("leases = %v", leases)
	}
}

// TestResolve_SkippedEntriesStderrLine: an entry the caller cannot read is
// skipped and named once; with none skipped there is no such line.
func TestResolve_SkippedEntriesStderrLine(t *testing.T) {
	fx := newIBFixture(t, nil)
	fv := newFakeVault()
	fv.setList(rtMeta, "ok", "hidden")
	fv.set("/v1/"+rtData+"ok", 200, kv(val("v")))
	fv.set("/v1/"+rtData+"hidden", 403, `{"errors":["permission denied"]}`)
	var stderr bytes.Buffer
	if _, _, _, err := resolve(context.Background(), newTestVault(t, fv).opts(t, fx, &stderr)); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.Contains(stderr.String(), "skipped 1 entries") || !strings.Contains(stderr.String(), "hidden") {
		t.Errorf("stderr = %q", stderr.String())
	}

	fv2 := newFakeVault()
	fv2.setList(rtMeta, "ok")
	fv2.set("/v1/"+rtData+"ok", 200, kv(val("v")))
	stderr.Reset()
	if _, _, _, err := resolve(context.Background(), newTestVault(t, fv2).opts(t, fx, &stderr)); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if strings.Contains(stderr.String(), "skipped") {
		t.Errorf("stderr = %q, want no skipped line", stderr.String())
	}
}

// TestResolve_WalkFailureRevokesPartialLeases: a hard failure after a lease
// was taken revokes it before returning exit 5.
func TestResolve_WalkFailureRevokesPartialLeases(t *testing.T) {
	fx := newIBFixture(t, nil)
	fv := newFakeVault()
	fv.setList(rtMeta, "staging/")
	fv.setList(rtMeta+"staging/", "dbref", "z")
	fv.set("/v1/"+rtData+"staging/dbref", 200, resolveBody("database/creds/readonly", nil))
	fv.set("/v1/database/creds/readonly", 200, derefBody(map[string]interface{}{"username": "u"}, "database/creds/readonly/lease-1"))
	fv.set("/v1/"+rtData+"staging/z", 500, `{"errors":["boom"]}`)

	_, _, _, err := resolve(context.Background(), newTestVault(t, fv).opts(t, fx, io.Discard))
	if err == nil {
		t.Fatal("resolve: expected an error")
	}
	if exitCode(err) != 5 {
		t.Errorf("exitCode = %d, want 5", exitCode(err))
	}
	if got := fv.revokedIDs(); len(got) != 1 || got[0] != "database/creds/readonly/lease-1" {
		t.Errorf("revoked = %v", got)
	}
}

// TestResolve_StaleTokenIsAnError: a token OpenBao rejects (403 everywhere
// and on lookup-self) must not resolve to an empty success.
func TestResolve_StaleTokenIsAnError(t *testing.T) {
	fx := newIBFixture(t, nil)
	fv := newFakeVault()
	fv.set("LIST /v1/"+rtMeta, 403, `{"errors":["permission denied"]}`)
	fv.set("/v1/auth/token/lookup-self", 403, `{"errors":["permission denied"]}`)

	_, _, _, err := resolve(context.Background(), newTestVault(t, fv).opts(t, fx, io.Discard))
	if err == nil {
		t.Fatal("resolve succeeded with a rejected token")
	}
	if got := exitCode(err); got != 2 {
		t.Errorf("exit code = %d, want 2 (err: %v)", got, err)
	}
	if !strings.Contains(err.Error(), "ib auth") {
		t.Errorf("error %q does not point at `ib auth`", err)
	}
}

// TestResolve_StaleTokenDuringDiscovery: the same, when the 403 arrives while
// discovering the environment.
func TestResolve_StaleTokenDuringDiscovery(t *testing.T) {
	fx := newIBFixture(t, nil)
	fv := newFakeVault()
	fv.set("LIST /v1/"+rtMeta, 403, `{"errors":["permission denied"]}`)
	fv.set("/v1/auth/token/lookup-self", 403, `{"errors":["permission denied"]}`)
	o := newTestVault(t, fv).opts(t, fx, io.Discard)
	o.Env = ""
	_, _, _, err := resolve(context.Background(), o)
	if exitCode(err) != 2 {
		t.Errorf("exit = %d, want 2 (err: %v)", exitCode(err), err)
	}
}

func TestReportRevokeErrors(t *testing.T) {
	denied := func() error {
		return fmt.Errorf("vaultx: revoke lease x: %w", &api.ResponseError{StatusCode: 403})
	}
	var buf bytes.Buffer
	reportRevokeErrors(&buf, []error{denied(), denied(), fmt.Errorf("vaultx: revoke lease y: boom")})
	out := buf.String()
	if strings.Count(out, "revoke lease failed") != 1 || !strings.Contains(out, "boom") {
		t.Errorf("non-403 error not reported once: %q", out)
	}
	if !strings.Contains(out, "2 lease(s) not revocable") || strings.Count(out, "\n") != 2 {
		t.Errorf("403s not collapsed to one line: %q", out)
	}

	buf.Reset()
	reportRevokeErrors(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("no errors, got output %q", buf.String())
	}
}

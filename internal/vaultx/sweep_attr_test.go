package vaultx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/navistau/ironbark/internal/identity"
)

func attrMetaPath(p string) string      { return "/v1/ironbark/metadata/" + p }
func attrDataPath(p, key string) string { return "/v1/ironbark/data/" + p + "/" + key }
func (f *fakeKV) requests() []fakeKVReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeKVReq(nil), f.reqs...)
}
func (f *fakeKV) indexOf(path string) int {
	for i, r := range f.requests() {
		if r.path == path {
			return i
		}
	}
	return -1
}

const (
	attrA  = "acme/widgets/push/.target/a"
	attrAB = "acme/widgets/push/.target/a%2fb"
)

func newAttrSweepClient(t *testing.T, fv *fakeKV, attrMount string) *Client {
	t.Helper()
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)
	cfg := testConfig(srv.URL)
	cfg.AttrMount = attrMount
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func sweepAttr(t *testing.T, fv *fakeKV, attrPaths []string) (SweepResult, error) {
	t.Helper()
	c := newAttrSweepClient(t, fv, "ironbark")
	return c.SweepWithAttributes(context.Background(), "minted-token", sweepTestIdentity(), true, attrPaths)
}

func TestSweepWithAttributes_OrderAndPrecedence(t *testing.T) {
	fv := newFakeKV()
	fv.set(attrMetaPath(attrAB), http.StatusOK, listBody([]string{"dup", "only_ab"}))
	fv.set(attrDataPath(attrAB, "dup"), http.StatusOK, entryBody(map[string]interface{}{"value": "from-ab"}, nil))
	fv.set(attrDataPath(attrAB, "only_ab"), http.StatusOK, entryBody(map[string]interface{}{"value": "x"}, nil))
	fv.set(attrMetaPath(attrA), http.StatusOK, listBody([]string{"dup"}))
	fv.set(attrDataPath(attrA, "dup"), http.StatusOK, entryBody(map[string]interface{}{"value": "from-a"}, nil))
	fv.set(metaPath(sweepBranch), http.StatusOK, listBody([]string{"dup"}))
	fv.set(dataEntryPath(sweepBranch, "dup"), http.StatusOK, entryBody(map[string]interface{}{"value": "from-branch"}, nil))

	res, err := sweepAttr(t, fv, []string{attrAB, attrA})
	if err != nil {
		t.Fatalf("SweepWithAttributes: %v", err)
	}
	if got := findSecret(t, res.Secrets, "dup").Value; got != "from-ab" {
		t.Errorf("dup = %q, want from-ab (first given attribute prefix wins)", got)
	}
	iAB, iA, iBranch := fv.indexOf(attrMetaPath(attrAB)), fv.indexOf(attrMetaPath(attrA)), fv.indexOf(metaPath(sweepBranch))
	if iAB < 0 || iAB >= iA || iA >= iBranch {
		t.Errorf("LIST order indexes ab=%d a=%d branch=%d, want ab < a < branch", iAB, iA, iBranch)
	}
	for _, tier := range []string{sweepEvent, sweepBase} {
		if fv.indexOf(metaPath(tier)) < iA {
			t.Errorf("tier %s LISTed before an attribute prefix", tier)
		}
	}
}

func TestSweepWithAttributes_AttrBeatsTier(t *testing.T) {
	fv := newFakeKV()
	fv.set(attrMetaPath(attrA), http.StatusOK, listBody([]string{"dup"}))
	fv.set(attrDataPath(attrA, "dup"), http.StatusOK, entryBody(map[string]interface{}{"value": "attr"}, nil))
	fv.set(metaPath(sweepBranch), http.StatusOK, listBody([]string{"dup"}))
	fv.set(dataEntryPath(sweepBranch, "dup"), http.StatusOK, entryBody(map[string]interface{}{"value": "branch"}, nil))

	res, err := sweepAttr(t, fv, []string{attrA})
	if err != nil {
		t.Fatalf("SweepWithAttributes: %v", err)
	}
	if got := findSecret(t, res.Secrets, "dup").Value; got != "attr" {
		t.Errorf("dup = %q, want attr", got)
	}
}

func TestSweepWithAttributes_AttrListSkipped(t *testing.T) {
	for _, st := range []int{http.StatusForbidden, http.StatusNotFound} {
		fv := newFakeKV()
		fv.set(attrMetaPath(attrA), st, `{"errors":[]}`)
		fv.set(metaPath(sweepBase), http.StatusOK, listBody([]string{"tierkey"}))
		fv.set(dataEntryPath(sweepBase, "tierkey"), http.StatusOK, entryBody(map[string]interface{}{"value": "v"}, nil))

		res, err := sweepAttr(t, fv, []string{attrA})
		if err != nil {
			t.Fatalf("status %d: SweepWithAttributes: %v", st, err)
		}
		findSecret(t, res.Secrets, "tierkey")
	}
}

func TestSweepWithAttributes_AttrList500Aborts(t *testing.T) {
	fv := newFakeKV()
	fv.set(attrMetaPath(attrA), http.StatusInternalServerError, `{"errors":["boom"]}`)
	if _, err := sweepAttr(t, fv, []string{attrA}); err == nil {
		t.Fatal("SweepWithAttributes: want error on attribute LIST 500")
	}
	for _, tier := range []string{sweepBranch, sweepEvent, sweepBase} {
		if n := fv.callCount(metaPath(tier)); n != 0 {
			t.Errorf("tier %s LISTed %d times after the abort", tier, n)
		}
	}
}

func TestSweepWithAttributes_DotAndDirSkipped(t *testing.T) {
	fv := newFakeKV()
	fv.set(attrMetaPath(attrA), http.StatusOK, listBody([]string{".hidden", "dir/", "plain"}))
	fv.set(attrDataPath(attrA, "plain"), http.StatusOK, entryBody(map[string]interface{}{"value": "v"}, nil))
	if _, err := sweepAttr(t, fv, []string{attrA}); err != nil {
		t.Fatalf("SweepWithAttributes: %v", err)
	}
	for _, r := range fv.requests() {
		if strings.Contains(r.path, ".hidden") || strings.Contains(r.path, "/dir") {
			t.Errorf("unexpected read of %s", r.path)
		}
	}
}

// TestSweepWithAttributes_WireEncoding pins how an escaped segment travels:
// the "%" of esc output is sent as "%25", for attribute prefixes exactly as
// for the branch tier.
func TestSweepWithAttributes_WireEncoding(t *testing.T) {
	fv := newFakeKV()
	c := newAttrSweepClient(t, fv, "ironbark")
	id := identity.Identity{Org: "acme", Repo: "widgets", Event: "push", Branch: "feature/foo"}
	if _, err := c.SweepWithAttributes(context.Background(), "minted-token", id, true, []string{attrAB}); err != nil {
		t.Fatalf("SweepWithAttributes: %v", err)
	}
	var sawAttr, sawBranch bool
	for _, r := range fv.requests() {
		if strings.HasPrefix(r.path, "/v1/ironbark/metadata/") {
			sawAttr = true
			if !strings.Contains(r.path, ".target/a%2fb") || !strings.Contains(r.uri, "%252f") {
				t.Errorf("attr LIST path=%q uri=%q", r.path, r.uri)
			}
		}
		if strings.HasPrefix(r.path, "/v1/kv/metadata/ci/acme/widgets/push/feature") {
			sawBranch = true
			if !strings.Contains(r.path, "feature%2ffoo") || !strings.Contains(r.uri, "feature%252ffoo") {
				t.Errorf("branch LIST path=%q uri=%q", r.path, r.uri)
			}
		}
	}
	if !sawAttr || !sawBranch {
		t.Errorf("saw attr LIST %v, branch LIST %v; want both", sawAttr, sawBranch)
	}
}

func TestSweep_NeverTouchesAttrMount(t *testing.T) {
	fv := newFakeKV()
	c := newAttrSweepClient(t, fv, "ironbark")
	if _, err := c.Sweep(context.Background(), "minted-token", sweepTestIdentity(), true); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	for _, r := range fv.requests() {
		if strings.HasPrefix(r.path, "/v1/ironbark/") {
			t.Errorf("Sweep requested %s in the attribute mount", r.path)
		}
	}
}

func TestSweepWithAttributes_NoAttrMountIsAnError(t *testing.T) {
	fv := newFakeKV()
	c := newAttrSweepClient(t, fv, "")
	if _, err := c.SweepWithAttributes(context.Background(), "minted-token", sweepTestIdentity(), true, []string{attrA}); err == nil {
		t.Fatal("want error for attribute paths with no AttrMount")
	}
}

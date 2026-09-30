package httpapi

import (
	"log/slog"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/identity"
)

func manualPayload(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../identity/testdata/payloads/gitea-manual.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func newAttrServer(t *testing.T, h Handler, level slog.Level) (*Server, *syncBuffer) {
	t.Helper()
	_, pub := loadTestKeys(t)
	buf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: level}))
	s := New(h, func() bool { return true }, pub, testWindow, 30*time.Second, time.Now, logger,
		identity.Options{TargetVar: "DEPLOY_TO"})
	return s, buf
}

func attrResult() broker.Result {
	r := okResult()
	r.Audit.PoliciesRequested = []string{"ci/acme/widgets/manual", "ci/acme/widgets/manual/.target/api", "ci/acme/widgets/manual/.actor/carol"}
	r.Audit.PolicyWarnings = []string{"ci/acme/widgets/manual/.target/api"}
	r.Audit.Teams = []string{"ops"}
	r.Audit.PoliciesDropped = []string{"ci/acme/widgets/manual/.team/ops"}
	return r
}

func lineWithMsg(t *testing.T, buf *syncBuffer, msg string) map[string]any {
	t.Helper()
	for _, l := range buf.logLines(t) {
		if l["msg"] == msg {
			return l
		}
	}
	return nil
}

func TestAttr_ParseOptionsReachHandler(t *testing.T) {
	priv, _ := loadTestKeys(t)
	mh := &mockHandler{result: attrResult()}
	s, _ := newAttrServer(t, mh, slog.LevelInfo)
	s.ServeHTTP(httptest.NewRecorder(), signedRequest(t, priv, manualPayload(t)))

	id := mh.wasCalledWith()
	if id.Target != "api/eu" || id.Actor != "carol" {
		t.Errorf("Handle got Target/Actor = %q/%q, want api/eu/carol", id.Target, id.Actor)
	}
}

func TestAttr_AuditLineFields(t *testing.T) {
	priv, _ := loadTestKeys(t)
	s, buf := newAttrServer(t, &mockHandler{result: attrResult()}, slog.LevelInfo)
	s.ServeHTTP(httptest.NewRecorder(), signedRequest(t, priv, manualPayload(t)))

	line := lineWithMsg(t, buf, "request")
	if line == nil {
		t.Fatal("no request audit line")
	}
	want := map[string]any{
		"actor":                    "carol",
		"target":                   "api/eu",
		"target_invalid":           false,
		"code_author":              "",
		"teams":                    []any{"ops"},
		"teams_error":              "",
		"policies_dropped":         []any{"ci/acme/widgets/manual/.team/ops"},
		"policies_requested_count": float64(3),
		"policy_warnings_count":    float64(1),
	}
	for k, v := range want {
		if got, ok := line[k]; !ok || !reflect.DeepEqual(got, v) {
			t.Errorf("audit %s = %#v (present %v), want %#v", k, got, ok, v)
		}
	}
	if lineWithMsg(t, buf, "payload attributes") != nil {
		t.Error("payload debug line emitted at info level")
	}
}

func TestAttr_PayloadDebugLine(t *testing.T) {
	priv, _ := loadTestKeys(t)
	s, buf := newAttrServer(t, &mockHandler{result: attrResult()}, slog.LevelDebug)
	s.ServeHTTP(httptest.NewRecorder(), signedRequest(t, priv, manualPayload(t)))

	line := lineWithMsg(t, buf, "payload attributes")
	if line == nil {
		t.Fatal("no payload attributes debug line")
	}
	if !reflect.DeepEqual(line["variable_names"], []any{"DEPLOY_TO", "OTHER"}) {
		t.Errorf("variable_names = %v", line["variable_names"])
	}
	for _, k := range []string{"event", "sender", "author", "deploy_to", "deploy_task", "reviewed_by", "actor", "target", "target_invalid", "code_author"} {
		if _, ok := line[k]; !ok {
			t.Errorf("payload line missing %s", k)
		}
	}
	// OTHER's value is "x"; no variable value may reach the log.
	if strings.Contains(buf.String(), `"x"`) {
		t.Errorf("a variable value reached the log: %s", buf.String())
	}
}

func TestAttr_RefusedSignatureHasNoAttributeFields(t *testing.T) {
	s, buf := newAttrServer(t, &mockHandler{result: attrResult()}, slog.LevelDebug)
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(manualPayload(t))))
	s.ServeHTTP(httptest.NewRecorder(), req)
	lines := buf.logLines(t)
	if len(lines) == 0 {
		t.Fatal("no log lines")
	}
	for _, l := range lines {
		for _, k := range []string{"actor", "target", "target_invalid", "code_author", "teams", "teams_error",
			"policies_dropped", "policies_requested_count", "policy_warnings_count", "variable_names", "sender", "author"} {
			if _, ok := l[k]; ok {
				t.Errorf("refused-signature log has %s: %v", k, l)
			}
		}
	}
}

func TestUnonboardedLoggedOncePerPipeline(t *testing.T) {
	priv, _ := loadTestKeys(t)
	s, buf := newAttrServer(t, &mockHandler{result: broker.Result{Status: 204, Outcome: broker.OutcomeUnonboarded}}, slog.LevelInfo)
	for i := 0; i < 3; i++ {
		s.ServeHTTP(httptest.NewRecorder(), signedRequest(t, priv, manualPayload(t)))
	}
	n := 0
	for _, l := range buf.logLines(t) {
		if l["msg"] == "request" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("request lines = %d, want 1", n)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `outcome="unonboarded"} 3`) {
		t.Errorf("metrics do not count all 3 unonboarded requests:\n%s", rec.Body.String())
	}
}

func TestOkRequestsAlwaysLogged(t *testing.T) {
	priv, _ := loadTestKeys(t)
	s, buf := newAttrServer(t, &mockHandler{result: attrResult()}, slog.LevelInfo)
	for i := 0; i < 2; i++ {
		s.ServeHTTP(httptest.NewRecorder(), signedRequest(t, priv, manualPayload(t)))
	}
	n := 0
	for _, l := range buf.logLines(t) {
		if l["msg"] == "request" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("request lines = %d, want 2", n)
	}
}

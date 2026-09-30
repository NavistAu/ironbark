// Package httpapi is ironbark's HTTP surface (SPEC §1.1): it wires
// signature verification (internal/wpsign) and request orchestration
// (internal/broker) together behind the routes Woodpecker and operators
// call, and owns the audit line (design §10) and Prometheus metrics.
//
// Reading the body and verifying the signature live here; Handler.Handle
// runs the rest (design §9.1). An invalid signature is 401 with nothing;
// every verified request is 200 with a secrets list that includes
// ironbark_status, except a payload that yields no identity (400).
package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/status"
	"github.com/navistau/ironbark/internal/wpsign"
)

// maxBodyBytes is the SPEC §1.2 step 1 request-body ceiling.
const maxBodyBytes = 1 << 20 // 1 MiB

// Handler is everything the POST / route needs from the broker; the body is
// the verified payload. *broker.Broker satisfies it. A narrow interface so
// tests can mock it without a real OpenBao.
type Handler interface {
	Handle(ctx context.Context, body []byte) broker.Result
}

// Ready reports readiness (/readyz): OpenBao reachable and unsealed.
type Ready func() bool

// Server is ironbark's HTTP surface. Construct with New; it implements
// http.Handler.
type Server struct {
	handler         Handler
	ready           Ready
	pubKey          ed25519.PublicKey
	freshnessWindow time.Duration
	timeout         time.Duration
	now             func() time.Time
	logger          *slog.Logger
	metrics         *metrics
	mux             *http.ServeMux
}

// New builds a Server. timeout is the SPEC §1.2 hard request timeout
// (production: 30s); now is the clock wpsign.Verify checks freshness
// against (production: time.Now), both injectable for tests.
func New(handler Handler, ready Ready, pubKey ed25519.PublicKey, freshnessWindow, timeout time.Duration, now func() time.Time, logger *slog.Logger) *Server {
	s := &Server{
		handler:         handler,
		ready:           ready,
		pubKey:          pubKey,
		freshnessWindow: freshnessWindow,
		timeout:         timeout,
		now:             now,
		logger:          logger,
		metrics:         newMetrics(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /{$}", s.handlePost)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.metrics.registry, promhttp.HandlerOpts{}))
	s.mux = mux

	return s
}

// ServeHTTP satisfies http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.ready != nil && s.ready() {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
}

// handlePost implements SPEC §1.2 steps 1-4 then delegates steps 5-10 to
// Handler.Handle, rendering its Result and emitting the SPEC §8.1 audit
// line.
func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Step 2: verify. Nothing derived from the payload may be trusted or
	// logged before this succeeds (SPEC §8.1) — the audit line below logs
	// only remote_addr + the failure reason.
	if verr := wpsign.Verify(r, body, s.pubKey, s.freshnessWindow, s.now); verr != nil {
		s.logRefusedSignature(r, verr)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// SPEC §1.2 hard request timeout: wraps the broker call so a stuck
	// broker cannot hold the connection past `timeout`, regardless of
	// whether Handler.Handle itself respects context cancellation.
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()
	result := s.callHandler(ctx, body)

	if result.Status == http.StatusBadRequest {
		s.metrics.requestsTotal.WithLabelValues("error").Inc()
		s.logger.Info("payload rejected", "remote_addr", r.RemoteAddr, "outcome", "error", "error", errString(result.Err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.renderResult(w, result)
	s.auditVerified(result)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// callHandler runs handler.Handle in a goroutine and races it against
// ctx's deadline, so a broker that ignores context cancellation still
// yields an answer at the injected timeout. The answer is still a 200
// carrying ironbark_status (outcome=error): design §9.2, ironbark never
// fails a pipeline. On timeout the goroutine is abandoned; the broker
// observes ctx.Done() itself, unwinds and revokes its token.
func (s *Server) callHandler(ctx context.Context, body []byte) broker.Result {
	resultCh := make(chan broker.Result, 1)
	go func() {
		resultCh <- s.handler.Handle(ctx, body)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-ctx.Done():
		line := status.Status{Outcome: status.Error, Reason: "timeout"}.String()
		return broker.Result{
			Status:  http.StatusOK,
			Outcome: status.Error,
			Secrets: []broker.Secret{{Name: status.StatusName, Value: line}},
			Err:     ctx.Err(),
			Audit:   status.Audit{TS: s.now(), Outcome: status.Error},
		}
	}
}

// logRefusedSignature emits the SPEC §8.1 refused-signature audit line:
// remote_addr and reason only — never anything derived from the payload,
// which is untrusted at this point.
func (s *Server) logRefusedSignature(r *http.Request, verr error) {
	var reason wpsign.Reason
	var ve *wpsign.VerifyError
	if errors.As(verr, &ve) {
		reason = ve.Reason
	}

	s.metrics.signatureFailuresTotal.WithLabelValues(string(reason)).Inc()
	s.metrics.requestsTotal.WithLabelValues("refused_signature").Inc()

	s.logger.Info("signature refused",
		"remote_addr", r.RemoteAddr,
		"reason", string(reason),
		"outcome", "refused_signature",
	)
}

// auditVerified emits the verified-request audit line (design §10), every
// field of status.Audit as a top-level attribute, plus error lines for a
// config or availability fault, walk warnings and a failed revoke (SPEC
// §3.4: TTL is the backstop).
func (s *Server) auditVerified(result broker.Result) {
	s.metrics.requestsTotal.WithLabelValues(string(result.Outcome)).Inc()
	if result.Audit.TokenAccessor != "" {
		s.metrics.mintsTotal.Inc()
	}
	a := result.Audit
	var fields map[string]any
	if raw, err := a.JSON(); err == nil {
		_ = json.Unmarshal(raw, &fields)
	}
	delete(fields, "ts")
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := make([]any, 0, 2*len(keys))
	for _, k := range keys {
		args = append(args, k, fields[k])
	}
	s.logger.Info("request", args...)

	for _, w := range result.Warnings {
		s.logger.Warn("walk", "repo_key", a.RepoKey, "warning", w)
	}
	if result.Outcome == status.Error && result.Err != nil {
		s.logger.Error("request failed", "repo_key", a.RepoKey, "role", a.Role, "error", result.Err.Error())
	}
	if result.RevokeFailed {
		s.logger.Error("best-effort token revoke failed after a status-only response (SPEC §3.4); TTL is the backstop",
			"repo_key", a.RepoKey, "token_accessor", a.TokenAccessor)
	}
}

// secretResponse is one response-body secret entry in Woodpecker's
// secret-extension shape. No events field is emitted (event pins are role
// bound_claims); Images is omitted when the secret carries no image pin.
type secretResponse struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Images []string `json:"images,omitempty"`
}

type responseBody struct {
	Secrets []secretResponse `json:"secrets"`
}

// renderResult writes the 200 JSON secrets body. Handler.Handle returns
// only 200 (rendered here) or 400 (handled by the caller).
func (s *Server) renderResult(w http.ResponseWriter, result broker.Result) {
	secrets := make([]secretResponse, 0, len(result.Secrets))
	for _, sec := range result.Secrets {
		secrets = append(secrets, secretResponse{Name: sec.Name, Value: sec.Value, Images: sec.Images})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(responseBody{Secrets: secrets}); err != nil {
		// The 200 status is already committed, so this is observability
		// only (e.g. the client disconnected mid-write).
		s.logger.Debug("failed to encode response body", "error", err)
	}
}

// metrics is ironbark's Prometheus counter set (SPEC §1.1 /metrics). Each
// Server owns its own registry (rather than the global DefaultRegisterer)
// so multiple Servers — one per test — can coexist without a
// double-registration panic.
type metrics struct {
	registry               *prometheus.Registry
	requestsTotal          *prometheus.CounterVec
	signatureFailuresTotal *prometheus.CounterVec
	mintsTotal             prometheus.Counter
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()

	m := &metrics{
		registry: reg,
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironbark_requests_total",
			Help: "Total POST / requests by outcome (ok|refused|invalid|config_error|error|refused_signature).",
		}, []string{"outcome"}),
		signatureFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironbark_signature_failures_total",
			Help: "Total signature verification failures by wpsign.Reason.",
		}, []string{"reason"}),
		mintsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironbark_mints_total",
			Help: "Total OpenBao tokens obtained by JWT login (the final login of each request).",
		}),
	}

	reg.MustRegister(m.requestsTotal, m.signatureFailuresTotal, m.mintsTotal)

	return m
}

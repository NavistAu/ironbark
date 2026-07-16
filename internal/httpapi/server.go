// Package httpapi is ironbark's HTTP surface (SPEC §1.1): it wires
// signature verification (internal/wpsign), payload parsing
// (internal/identity), and request orchestration (internal/broker)
// together behind the routes Woodpecker and operators call, and owns the
// SPEC §8.1 audit line and Prometheus metrics.
//
// Steps 1-4 of SPEC §1.2 (read body, verify signature, parse payload,
// extract identity) live here; Handler.Handle runs steps 5-10.
package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ironbark/internal/broker"
	"ironbark/internal/identity"
	"ironbark/internal/vaultx"
	"ironbark/internal/wpsign"
)

// maxBodyBytes is the SPEC §1.2 step 1 request-body ceiling.
const maxBodyBytes = 1 << 20 // 1 MiB

// Handler is everything the POST / route needs from the broker (SPEC §1.2
// steps 5-10); *broker.Broker satisfies it. A narrow interface so tests
// can mock it without a real Vault.
type Handler interface {
	Handle(ctx context.Context, id identity.Identity) broker.Result
}

// Ready reports readiness (SPEC §1.1 /readyz): Vault session valid AND
// the startup canary passed. In production this is *vaultx.Client.Healthy
// passed directly as a method value — it already has this signature, so
// no adapter is needed.
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

// VaultMetrics returns this Server's metrics as a vaultx.Metrics, for
// Task 12's cmd wiring to pass into vaultx.New(cfg, vaultx.WithMetrics(...))
// when it constructs the *vaultx.Client — the seam that lets
// ironbark_sweep_reads_total / ironbark_deref_reads_total actually
// increment (SPEC §1.1 /metrics).
func (s *Server) VaultMetrics() vaultx.Metrics {
	return s.metrics
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

	// Step 3-4: parse and extract identity. The signature is verified, so
	// the payload is trusted enough to parse; a malformed body past a
	// valid signature is a client bug, not an attack — logged minimally,
	// not the full verified-audit shape (there is no identity to attach
	// it to).
	id, err := identity.Parse(body)
	if err != nil {
		s.metrics.requestsTotal.WithLabelValues("error").Inc()
		s.logger.Info("identity parse failed", "remote_addr", r.RemoteAddr, "outcome", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// SPEC §1.2 hard request timeout: wraps the broker call so a stuck
	// broker cannot hold the connection past `timeout`, regardless of
	// whether Handler.Handle itself respects context cancellation.
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()
	result := s.callHandler(ctx, id)

	s.renderResult(w, result)
	s.auditVerified(id, result)
}

// callHandler runs handler.Handle in a goroutine and races it against
// ctx's deadline, so a broker that ignores context cancellation still
// yields a 502 at the injected timeout (SPEC §1.2: "hard request timeout
// 30s -> 502"). On timeout the goroutine is abandoned; it is expected to
// observe ctx.Done() itself and unwind (the production broker does, via
// the ctx it threads through every Vault call).
func (s *Server) callHandler(ctx context.Context, id identity.Identity) broker.Result {
	resultCh := make(chan broker.Result, 1)
	go func() {
		resultCh <- s.handler.Handle(ctx, id)
	}()

	select {
	case result := <-resultCh:
		return result
	case <-ctx.Done():
		return broker.Result{Status: http.StatusBadGateway, Outcome: broker.OutcomeError}
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

// auditVerified emits the SPEC §8.1 verified-request audit line and, when
// Result.RevokeFailed is set, an additional error-level line (SPEC §3.4).
// Runs for every outcome once the signature and payload have been
// accepted, including a timeout-synthesized 502.
func (s *Server) auditVerified(id identity.Identity, result broker.Result) {
	s.metrics.requestsTotal.WithLabelValues(string(result.Outcome)).Inc()
	if result.Audit.TokenAccessor != "" {
		s.metrics.mintsTotal.Inc()
	}
	if n := len(result.Audit.PolicyWarnings); n > 0 {
		s.metrics.mintWarningsTotal.Add(float64(n))
	}

	s.logger.Info("request",
		"org", id.Org,
		"repo", id.Repo,
		"event", id.Event,
		"branch", id.Branch,
		"pipeline_number", id.PipelineNumber,
		"policies_requested", result.Audit.PoliciesRequested,
		"policy_warnings", result.Audit.PolicyWarnings,
		"secrets_returned", result.Audit.SecretNames,
		"token_accessor", result.Audit.TokenAccessor,
		"token_ttl", result.Audit.TokenTTL,
		"outcome", string(result.Outcome),
	)

	if result.RevokeFailed {
		s.logger.Error("best-effort token revoke failed after a non-200 response (SPEC §3.4); TTL is the backstop",
			"org", id.Org,
			"repo", id.Repo,
			"token_accessor", result.Audit.TokenAccessor,
		)
	}
}

// secretResponse is one SPEC §6 response-body secret entry. Images is
// omitted (not `null`/`[]`) when the secret carries no image pin.
type secretResponse struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Events []string `json:"events"`
	Images []string `json:"images,omitempty"`
}

type responseBody struct {
	Secrets []secretResponse `json:"secrets"`
}

// renderResult writes result per SPEC §6: 200 with the JSON secrets body,
// 204 empty, or 502 empty. Handler.Handle (broker.Broker.Handle) never
// returns any other status.
func (s *Server) renderResult(w http.ResponseWriter, result broker.Result) {
	switch result.Status {
	case http.StatusOK:
		secrets := make([]secretResponse, 0, len(result.Secrets))
		for _, sec := range result.Secrets {
			secrets = append(secrets, secretResponse{
				Name:   sec.Name,
				Value:  sec.Value,
				Events: sec.Events,
				Images: sec.Images,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(responseBody{Secrets: secrets}); err != nil {
			// The 200 status is already committed (WriteHeader above), so
			// this cannot become a different status code — this is
			// observability only, for a truncated/failed response body
			// (e.g. the client disconnected mid-write).
			s.logger.Debug("failed to encode response body", "error", err)
		}
	case http.StatusNoContent:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusBadGateway)
	}
}

// metrics is ironbark's Prometheus counter set (SPEC §1.1 /metrics,
// §10). Each Server owns its own registry (rather than the global
// DefaultRegisterer) so multiple Servers — one per test — can coexist
// without a double-registration panic.
//
// metrics also implements vaultx.Metrics (IncSweepRead/IncDerefRead
// below), adapting sweepReadsTotal/derefReadsTotal onto the interface
// vaultx.Client accepts via vaultx.WithMetrics. Server.VaultMetrics()
// exposes this adapter; Task 12's cmd wiring is what actually threads it
// into vaultx.New, since that's where the *vaultx.Client gets
// constructed — this package only makes the adapter exist and be
// reachable.
type metrics struct {
	registry               *prometheus.Registry
	requestsTotal          *prometheus.CounterVec
	signatureFailuresTotal *prometheus.CounterVec
	mintsTotal             prometheus.Counter
	mintWarningsTotal      prometheus.Counter
	sweepReadsTotal        prometheus.Counter // incremented via IncSweepRead, below.
	derefReadsTotal        prometheus.Counter // incremented via IncDerefRead, below.
}

// IncSweepRead and IncDerefRead satisfy vaultx.Metrics, so *metrics can be
// passed (via Server.VaultMetrics) straight to vaultx.WithMetrics.
func (m *metrics) IncSweepRead() { m.sweepReadsTotal.Inc() }
func (m *metrics) IncDerefRead() { m.derefReadsTotal.Inc() }

var _ vaultx.Metrics = (*metrics)(nil)

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()

	m := &metrics{
		registry: reg,
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironbark_requests_total",
			Help: "Total POST / requests by outcome (ok|unonboarded|identity_mismatch|error|refused_signature).",
		}, []string{"outcome"}),
		signatureFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ironbark_signature_failures_total",
			Help: "Total signature verification failures by wpsign.Reason.",
		}, []string{"reason"}),
		mintsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironbark_mints_total",
			Help: "Total Vault tokens minted.",
		}),
		mintWarningsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironbark_mint_warnings_total",
			Help: "Total nonexistent-policy warnings observed across mints.",
		}),
		sweepReadsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironbark_sweep_reads_total",
			Help: "Total per-entry KV reads performed during sweep.",
		}),
		derefReadsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ironbark_deref_reads_total",
			Help: "Total dynamic-engine dereference reads.",
		}),
	}

	reg.MustRegister(
		m.requestsTotal,
		m.signatureFailuresTotal,
		m.mintsTotal,
		m.mintWarningsTotal,
		m.sweepReadsTotal,
		m.derefReadsTotal,
	)

	return m
}

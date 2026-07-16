// Command ironbark is ironbark's entry point (SPEC §1.3, §3.5, §8): it
// loads config, wires vaultx.Client + broker.Broker + httpapi.Server
// together, starts the Vault session/canary lifecycle goroutine, serves
// HTTP, and shuts down gracefully on SIGTERM/SIGINT. This file is wiring
// only — no business logic lives here.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ironbark/internal/broker"
	"ironbark/internal/config"
	"ironbark/internal/httpapi"
	"ironbark/internal/vaultx"
)

// requestTimeout is the SPEC §1.2 hard request timeout (POST / -> 502 past
// this deadline).
const requestTimeout = 30 * time.Second

// shutdownDrain bounds graceful shutdown's wait for in-flight requests.
const shutdownDrain = 5 * time.Second

func main() {
	cfg, err := config.Load(os.Getenv, os.ReadFile)
	if err != nil {
		// No logger exists yet (its level comes from cfg, which just
		// failed to load) — this is the one line in the program not
		// emitted as structured JSON.
		fmt.Fprintln(os.Stderr, "ironbark: config:", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)}))

	vc, err := vaultx.New(vaultx.Config{
		Addr:      cfg.VaultAddr,
		RoleID:    cfg.VaultRoleID,
		SecretID:  cfg.VaultSecretID,
		TokenRole: cfg.TokenRole,
		KVMount:   cfg.KVMount,
		KVPrefix:  cfg.KVPrefix,
	}, vaultx.WithLogger(logger))
	if err != nil {
		logger.Error("vaultx client init failed", "error", err)
		os.Exit(1)
	}

	brk := broker.New(vc, cfg.PolicyPrefix, cfg.AdvertiseVaultAddr)

	srv := httpapi.New(brk, vc.Healthy, cfg.WoodpeckerPublicKey, cfg.FreshnessWindow, requestTimeout, time.Now, logger)

	// The metrics/vaultx-Client construction cycle (httpapi's registry
	// wants the broker, which wants the Client; the Client wants the
	// registry) is broken here: the Client is built first without
	// metrics, and wired in once srv exists to expose it. SetMetrics is
	// safe here because vc.Run has not started yet (see its doc comment).
	vc.SetMetrics(srv.VaultMetrics())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run performs the AppRole login itself as the first step of its
	// lifecycle, then the startup canary, then renew/re-login/canary-retry
	// for as long as ctx stays open. It is started here, non-blocking: a
	// failed login or a failed canary must not stop ironbark from serving
	// HTTP — /readyz simply reports 503 until Run's retries succeed (SPEC
	// §3.5).
	go vc.Run(ctx, cfg.PolicyPrefix)

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv,
	}

	serveErrCh := make(chan error, 1)
	go func() {
		logger.Info("ironbark listening", "addr", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- err
			return
		}
		serveErrCh <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down", "signal", true)
	case err := <-serveErrCh:
		if err != nil {
			logger.Error("http server error", "error", err)
		}
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownDrain)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}

// parseLogLevel maps config.Config.LogLevel (a free-form string,
// config.Load applies no validation to it) to a slog.Level; an
// unrecognized value defaults to Info rather than erroring, since
// config.Load already accepted it.
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

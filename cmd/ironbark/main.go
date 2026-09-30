// Command ironbark is ironbark's entry point (design §11): it loads the grant
// configuration, wires the JWT signer, OpenBao connection, broker and HTTP
// server together, and shuts down gracefully on SIGTERM/SIGINT. It holds no
// OpenBao credential and runs no login or canary at startup: the signed JWT
// is the only credential ironbark ever presents, per request. This file is
// wiring only — no business logic lives here.
//
// `ironbark render-policies -accessor ACC` prints the three level policies
// for the JWT mount accessor (design §11.3) and needs no OpenBao access.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/navistau/ironbark/internal/broker"
	"github.com/navistau/ironbark/internal/forge"
	"github.com/navistau/ironbark/internal/grantcfg"
	"github.com/navistau/ironbark/internal/httpapi"
	"github.com/navistau/ironbark/internal/jwtsign"
	"github.com/navistau/ironbark/internal/levels"
	"github.com/navistau/ironbark/internal/vaultx"
)

// requestTimeout is the SPEC §1.2 hard request timeout.
const requestTimeout = 30 * time.Second

// shutdownDrain bounds graceful shutdown's wait for in-flight requests.
const shutdownDrain = 5 * time.Second

// readyTimeout bounds one /readyz probe of OpenBao.
const readyTimeout = 2 * time.Second

// version is stamped at build time via -ldflags "-X main.version=$(cat
// VERSION)" (Dockerfile, .woodpecker.yaml, release.yml); "dev" for
// unstamped local builds.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.ReadFile, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, readFile func(string) ([]byte, error), stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "render-policies":
			return renderPolicies(args[1:], getenv, stdout, stderr)
		default:
			fmt.Fprintf(stderr, "ironbark: unknown subcommand %q (only render-policies)\n", args[0])
			return 2
		}
	}
	return serve(getenv, readFile, stderr)
}

// renderPolicies prints the three level policies for an accessor (§11.3).
// Only IRONBARK_DATA_PATH is read: the subcommand needs no other config.
func renderPolicies(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("render-policies", flag.ContinueOnError)
	fs.SetOutput(stderr)
	accessor := fs.String("accessor", "", "accessor of the JWT auth mount (auth_jwt_...)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *accessor == "" {
		fmt.Fprintln(stderr, "ironbark: render-policies: -accessor is required")
		return 2
	}
	tmpl, err := grantcfg.ParseTemplate(getenv("IRONBARK_DATA_PATH"))
	if err != nil {
		fmt.Fprintln(stderr, "ironbark: render-policies:", err)
		return 1
	}
	project, env, target := levels.RenderPolicies(tmpl, *accessor)
	fmt.Fprint(stdout, project+"\n"+env+"\n"+target+"\n")
	return 0
}

func serve(getenv func(string) string, readFile func(string) ([]byte, error), stderr io.Writer) int {
	cfg, err := grantcfg.Load(getenv, readFile)
	if err != nil {
		// No logger exists yet (its level comes from cfg, which just
		// failed to load) — this is the one line in the program not
		// emitted as structured JSON.
		fmt.Fprintln(stderr, "ironbark: config:", err)
		return 1
	}
	signer, err := jwtsign.LoadKey([]byte(cfg.JWTSigningKeyPEM))
	if err != nil {
		fmt.Fprintln(stderr, "ironbark: config: IRONBARK_JWT_SIGNING_KEY:", err)
		return 1
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)}))
	logger.Info("ironbark starting", "version", version, "kid", signer.KID(),
		"actor_forge", cfg.ActorForge, "forge_provider", cfg.ForgeProvider, "jwt_mount", cfg.JWTMount)
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}

	conn, err := vaultx.NewConn(cfg.VaultAddr, nil)
	if err != nil {
		logger.Error("openbao connection init failed", "error", err)
		return 1
	}

	var opts []broker.Option
	if cfg.ForgeProvider == "gitea" {
		opts = append(opts, broker.WithLookups(forge.NewGitea(cfg.ForgeURL, cfg.ForgeToken, cfg.ForgeTimeout, nil)))
	}
	brk := broker.New(broker.FromConn(conn), signer, broker.Config{
		Data: cfg.DataPath, EnvVar: cfg.EnvVar, TargetVar: cfg.TargetVar,
		JWTRole: cfg.JWTRole, JWTMount: cfg.JWTMount,
		AdvertiseVaultAddr: cfg.AdvertiseVaultAddr, ActorForge: cfg.ActorForge,
	}, opts...)

	ready := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
		defer cancel()
		return conn.Healthy(ctx)
	}
	srv := httpapi.New(brk, ready, cfg.WoodpeckerPublicKey, cfg.FreshnessWindow, requestTimeout, time.Now, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	httpServer := &http.Server{Addr: cfg.ListenAddr, Handler: srv}
	serveErrCh := make(chan error, 1)
	go func() {
		logger.Info("ironbark listening", "addr", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- err
			return
		}
		serveErrCh <- nil
	}()

	code := 0
	select {
	case <-ctx.Done():
		logger.Info("shutting down", "signal", true)
	case err := <-serveErrCh:
		if err != nil {
			logger.Error("http server error", "error", err)
			code = 1
		}
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownDrain)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
	return code
}

// parseLogLevel maps the free-form log level to a slog.Level; an
// unrecognized value defaults to Info.
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// mythicd is the Mythic edge server: adaptive proof-of-work challenges,
// rule-based risk scoring, and Ed25519-signed decision tokens.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xeylabs/mythic/server/internal/api"
	"github.com/xeylabs/mythic/server/internal/config"
	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
	"github.com/xeylabs/mythic/server/internal/store"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		// Configuration is security margin: refuse to serve on nonsense
		// rather than silently weakening the deployment (red-team G4).
		slog.New(slog.NewJSONHandler(os.Stdout, nil)).Error("invalid configuration; refusing to start", "err", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	km, err := crypto.LoadOrCreateWithPolicy(cfg.KeyFile, cfg.KeyMaxAge, cfg.KeyRetention, log)
	if err != nil {
		log.Error("key setup failed", "err", err)
		os.Exit(1)
	}
	defer km.Close()
	if len(cfg.Sites) == 0 {
		log.Warn("no MYTHIC_SITES configured: any site key is accepted (dev mode)")
	}

	var st store.Store
	switch cfg.Store {
	case "redis":
		// Multi-node (ADR-0009): the store is the shared state. Fail closed
		// at startup — a verifier that cannot reach its store must not mint
		// tokens from uncounted requests.
		rs, err := store.NewRedis(cfg.RedisAddr, "", cfg.RedisDB, cfg.ChallengeTTL)
		if err != nil {
			log.Error("redis store unavailable; refusing to start", "err", err)
			os.Exit(1)
		}
		defer rs.Close()
		st = rs
		log.Info("store: redis", "addr", cfg.RedisAddr, "db", cfg.RedisDB)
	default:
		m := store.NewMemory(cfg.ChallengeTTL)
		defer m.Close()
		st = m
		log.Info("store: memory (single node — set MYTHIC_STORE=redis for multi-node)")
	}

	srv := api.New(api.Config{
		Sites:        cfg.Sites,
		CORSOrigins:  cfg.CORSOrigins,
		TokenTTL:     cfg.TokenTTL,
		ChallengeTTL: cfg.ChallengeTTL,
		IPWindow:     cfg.IPWindow,
		IPLimit:      cfg.IPLimit,
		TrustProxy:   cfg.TrustProxy,
	}, km, st, risk.New(cfg.Risk), log)

	// ADR-0010: ASN lookup. Empty path = signal disabled (valid).
	// Non-empty path that fails to open = fatal (fail-closed on
	// misconfiguration, not silent degradation).
	asnLookup, err := api.NewASNLookup(cfg.ASNDBPath, log)
	if err != nil {
		log.Error("asn database failed to open", "path", cfg.ASNDBPath, "err", err)
		os.Exit(1)
	}
	if asnLookup != nil {
		defer asnLookup.Close()
		srv.WithASNLookup(asnLookup)
	}

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		// Body/read/write/idle timeouts: without them a slow-reading client
		// holds its connection (and goroutine) indefinitely — the red-team
		// G2 slow-body hold.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("mythicd listening", "addr", cfg.Addr, "kid", km.KeyID())
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown error", "err", err)
	}
}

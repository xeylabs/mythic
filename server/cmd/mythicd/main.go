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
	cfg := config.FromEnv()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	km, err := crypto.LoadOrCreate(cfg.KeyFile)
	if err != nil {
		log.Error("key setup failed", "err", err)
		os.Exit(1)
	}
	if len(cfg.Sites) == 0 {
		log.Warn("no MYTHIC_SITES configured: any site key is accepted (dev mode)")
	}

	st := store.NewMemory(cfg.ChallengeTTL)
	defer st.Close()

	srv := api.New(api.Config{
		Sites:        cfg.Sites,
		CORSOrigins:  cfg.CORSOrigins,
		TokenTTL:     cfg.TokenTTL,
		ChallengeTTL: cfg.ChallengeTTL,
		IPWindow:     cfg.IPWindow,
		IPLimit:      cfg.IPLimit,
		TrustProxy:   cfg.TrustProxy,
	}, km, st, risk.New(cfg.Risk), log)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
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

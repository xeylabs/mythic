// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package config loads mythicd configuration from the environment.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
)

// Config is the full runtime configuration of mythicd.
type Config struct {
	Addr         string
	KeyFile      string        // Ed25519 seed path; empty = ephemeral in-memory key
	Sites        []string      // site-key allowlist; empty = accept any (dev mode)
	CORSOrigins  []string      // allowed browser origins; empty = allow all for /v1 (no credentials are used)
	ChallengeTTL time.Duration // how long an issued challenge stays redeemable
	TokenTTL     time.Duration // lifetime of signed decision tokens
	IPWindow     time.Duration // per-IP request-pressure window
	IPLimit      int64         // max requests per IP inside IPWindow
	TrustProxy   bool          // honor X-Forwarded-For; enable ONLY behind a proxy that overwrites it
	Store        string        // "memory" (default) or "redis" (multi-node, ADR-0009)
	RedisAddr    string        // Redis address for MYTHIC_STORE=redis
	RedisDB      int           // Redis logical DB (default 0)
	KeyMaxAge    time.Duration // active-key lifetime; 0 disables auto-rotation (ADR-0006)
	KeyRetention time.Duration // how long retired keys stay in the JWKS after rotation
	Risk         risk.Config   // risk-engine tuning: thresholds are deployment-side security margin
	LogLevel     slog.Level
}

func FromEnv() (Config, error) {
	c := Config{
		Addr:         env("MYTHIC_ADDR", ":8080"),
		KeyFile:      env("MYTHIC_KEY_FILE", ""),
		Sites:        splitCSV(env("MYTHIC_SITES", "")),
		CORSOrigins:  splitCSV(env("MYTHIC_CORS_ORIGINS", "")),
		ChallengeTTL: envDur("MYTHIC_CHALLENGE_TTL", 3*time.Minute),
		TokenTTL:     envDur("MYTHIC_TOKEN_TTL", 5*time.Minute),
		IPWindow:     envDur("MYTHIC_IP_WINDOW", time.Minute),
		IPLimit:      envInt64("MYTHIC_IP_LIMIT", 120),
		TrustProxy:   envBool("MYTHIC_TRUST_PROXY"),
		Store:        env("MYTHIC_STORE", "memory"),
		RedisAddr:    env("MYTHIC_REDIS_ADDR", "127.0.0.1:6379"),
		RedisDB:      int(envInt64("MYTHIC_REDIS_DB", 0)),
		KeyMaxAge:    envDur("MYTHIC_KEY_MAX_AGE", 720*time.Hour),
		KeyRetention: envDur("MYTHIC_KEY_RETENTION", crypto.DefaultKeyRetention),
		Risk:         riskConfig(),
		LogLevel:     slog.LevelInfo,
	}
	if env("MYTHIC_LOG_LEVEL", "") == "debug" {
		c.LogLevel = slog.LevelDebug
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// validate refuses to serve on settings that silently gut the security
// model. Red-team G4 (2026-09-29): a negative MYTHIC_BASE_DIFFICULTY flowed
// straight into issued challenges and any nonce met the difficulty —
// zero-work tokens from an operator foot-gun.
func (c Config) validate() error {
	if c.Risk.BaseDifficulty < 8 || c.Risk.BaseDifficulty > 30 {
		return fmt.Errorf("MYTHIC_BASE_DIFFICULTY must be within [8,30], got %d", c.Risk.BaseDifficulty)
	}
	if c.Risk.MaxDifficulty < c.Risk.BaseDifficulty || c.Risk.MaxDifficulty > 30 {
		return fmt.Errorf("MYTHIC_MAX_DIFFICULTY must be within [BASE_DIFFICULTY,30], got %d (base %d)", c.Risk.MaxDifficulty, c.Risk.BaseDifficulty)
	}
	if c.Risk.StepUpAt < 0 || c.Risk.HeavyAt < c.Risk.StepUpAt || c.Risk.DenyAt < c.Risk.HeavyAt || c.Risk.DenyAt > 100 {
		return fmt.Errorf("risk thresholds must satisfy 0 ≤ STEP_UP_AT ≤ HEAVY_AT ≤ DENY_AT ≤ 100, got %d/%d/%d",
			c.Risk.StepUpAt, c.Risk.HeavyAt, c.Risk.DenyAt)
	}
	if c.Risk.FastSolvePenalty < 0 || c.Risk.PressurePerReq < 0 || c.Risk.PressureMax < 0 {
		return fmt.Errorf("risk penalties must be non-negative, got fast=%d per_req=%d max=%d",
			c.Risk.FastSolvePenalty, c.Risk.PressurePerReq, c.Risk.PressureMax)
	}
	if c.Risk.FastSolvePenalty > 100 || c.Risk.PressurePerReq > 100 || c.Risk.PressureMax > 100 {
		return fmt.Errorf("risk penalties must be ≤ 100 (the score is a 0-100 contract), got fast=%d per_req=%d max=%d",
			c.Risk.FastSolvePenalty, c.Risk.PressurePerReq, c.Risk.PressureMax)
	}
	if c.IPLimit < 1 {
		return fmt.Errorf("MYTHIC_IP_LIMIT must be ≥ 1, got %d", c.IPLimit)
	}
	if c.IPWindow <= 0 || c.ChallengeTTL <= 0 || c.TokenTTL <= 0 {
		return fmt.Errorf("IP window, challenge TTL and token TTL must be positive, got %v/%v/%v",
			c.IPWindow, c.ChallengeTTL, c.TokenTTL)
	}
	if c.KeyMaxAge < 0 || c.KeyRetention < 0 {
		return fmt.Errorf("key max-age and retention must be non-negative, got %v/%v", c.KeyMaxAge, c.KeyRetention)
	}
	switch c.Store {
	case "", "memory", "redis":
	default:
		return fmt.Errorf("MYTHIC_STORE must be \"memory\" or \"redis\", got %q", c.Store)
	}
	if c.RedisAddr == "" {
		return fmt.Errorf("MYTHIC_REDIS_ADDR must not be empty")
	}
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func envDur(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// riskConfig layers the deployment's risk-engine tuning over the defaults.
// Shipping thresholds as configuration (not just code) keeps each
// deployment's operating margins private — the public repo shows the shape
// of the engine, not necessarily the numbers any real deployment runs.
func riskConfig() risk.Config {
	c := risk.DefaultConfig()
	c.BaseDifficulty = int(envInt64("MYTHIC_BASE_DIFFICULTY", int64(c.BaseDifficulty)))
	c.MaxDifficulty = int(envInt64("MYTHIC_MAX_DIFFICULTY", int64(c.MaxDifficulty)))
	c.DenyAt = int(envInt64("MYTHIC_DENY_AT", int64(c.DenyAt)))
	c.HeavyAt = int(envInt64("MYTHIC_HEAVY_AT", int64(c.HeavyAt)))
	c.StepUpAt = int(envInt64("MYTHIC_STEP_UP_AT", int64(c.StepUpAt)))
	c.FastSolvePenalty = int(envInt64("MYTHIC_FAST_SOLVE_PENALTY", int64(c.FastSolvePenalty)))
	c.PressurePerReq = int(envInt64("MYTHIC_PRESSURE_PER_REQ", int64(c.PressurePerReq)))
	c.PressureMax = int(envInt64("MYTHIC_PRESSURE_MAX", int64(c.PressureMax)))
	return c
}

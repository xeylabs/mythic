// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package config loads xprotectd configuration from the environment.
package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xeylabs/xprotect/server/internal/risk"
)

// Config is the full runtime configuration of xprotectd.
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
	Risk         risk.Config   // risk-engine tuning: thresholds are deployment-side security margin
	LogLevel     slog.Level
}

func FromEnv() Config {
	c := Config{
		Addr:         env("XPROTECT_ADDR", ":8080"),
		KeyFile:      env("XPROTECT_KEY_FILE", ""),
		Sites:        splitCSV(env("XPROTECT_SITES", "")),
		CORSOrigins:  splitCSV(env("XPROTECT_CORS_ORIGINS", "")),
		ChallengeTTL: envDur("XPROTECT_CHALLENGE_TTL", 3*time.Minute),
		TokenTTL:     envDur("XPROTECT_TOKEN_TTL", 5*time.Minute),
		IPWindow:     envDur("XPROTECT_IP_WINDOW", time.Minute),
		IPLimit:      envInt64("XPROTECT_IP_LIMIT", 120),
		TrustProxy:   envBool("XPROTECT_TRUST_PROXY"),
		Risk:         riskConfig(),
		LogLevel:     slog.LevelInfo,
	}
	if env("XPROTECT_LOG_LEVEL", "") == "debug" {
		c.LogLevel = slog.LevelDebug
	}
	return c
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
	c.BaseDifficulty = int(envInt64("XPROTECT_BASE_DIFFICULTY", int64(c.BaseDifficulty)))
	c.MaxDifficulty = int(envInt64("XPROTECT_MAX_DIFFICULTY", int64(c.MaxDifficulty)))
	c.DenyAt = int(envInt64("XPROTECT_DENY_AT", int64(c.DenyAt)))
	c.HeavyAt = int(envInt64("XPROTECT_HEAVY_AT", int64(c.HeavyAt)))
	c.StepUpAt = int(envInt64("XPROTECT_STEP_UP_AT", int64(c.StepUpAt)))
	c.FastSolvePenalty = int(envInt64("XPROTECT_FAST_SOLVE_PENALTY", int64(c.FastSolvePenalty)))
	c.PressurePerReq = int(envInt64("XPROTECT_PRESSURE_PER_REQ", int64(c.PressurePerReq)))
	c.PressureMax = int(envInt64("XPROTECT_PRESSURE_MAX", int64(c.PressureMax)))
	return c
}

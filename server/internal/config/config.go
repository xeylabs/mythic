// Package config loads xprotectd configuration from the environment.
package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
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

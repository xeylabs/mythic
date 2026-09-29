// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package config

import (
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/risk"
)

func TestFromEnvDefaults(t *testing.T) {
	cfg := FromEnv()
	if cfg.Addr != ":8080" {
		t.Fatalf("default addr: %q", cfg.Addr)
	}
	if cfg.IPLimit != 120 {
		t.Fatalf("default ip limit: %d", cfg.IPLimit)
	}
	if cfg.TrustProxy {
		t.Fatal("TrustProxy must default to false (ADR-0005)")
	}
	def := risk.DefaultConfig()
	if cfg.Risk.BaseDifficulty != def.BaseDifficulty {
		t.Fatalf("risk tuning must default to DefaultConfig: %d", cfg.Risk.BaseDifficulty)
	}
	if cfg.KeyMaxAge != 720*time.Hour {
		t.Fatalf("key max age must default to 720h (ADR-0006), got %v", cfg.KeyMaxAge)
	}
	if cfg.KeyRetention != 24*time.Hour {
		t.Fatalf("key retention must default to 24h, got %v", cfg.KeyRetention)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("MYTHIC_ADDR", ":9090")
	t.Setenv("MYTHIC_TRUST_PROXY", "1")
	t.Setenv("MYTHIC_BASE_DIFFICULTY", "22")
	t.Setenv("MYTHIC_MAX_DIFFICULTY", "30")
	t.Setenv("MYTHIC_DENY_AT", "90")
	t.Setenv("MYTHIC_SITES", " alpha, beta ,,")
	t.Setenv("MYTHIC_IP_LIMIT", "7")
	t.Setenv("MYTHIC_KEY_MAX_AGE", "0")
	t.Setenv("MYTHIC_KEY_RETENTION", "2h")

	cfg := FromEnv()
	if cfg.Addr != ":9090" {
		t.Fatalf("addr override: %q", cfg.Addr)
	}
	if !cfg.TrustProxy {
		t.Fatal("TrustProxy=1 must be honored")
	}
	if cfg.Risk.BaseDifficulty != 22 || cfg.Risk.MaxDifficulty != 30 || cfg.Risk.DenyAt != 90 {
		t.Fatalf("risk overrides not applied: %+v", cfg.Risk)
	}
	if len(cfg.Sites) != 2 || cfg.Sites[0] != "alpha" || cfg.Sites[1] != "beta" {
		t.Fatalf("site allowlist parsing: %q", cfg.Sites)
	}
	if cfg.IPLimit != 7 {
		t.Fatalf("ip limit override: %d", cfg.IPLimit)
	}
	if cfg.KeyMaxAge != 0 {
		t.Fatalf("key max age override: %v", cfg.KeyMaxAge)
	}
	if cfg.KeyRetention != 2*time.Hour {
		t.Fatalf("key retention override: %v", cfg.KeyRetention)
	}
}

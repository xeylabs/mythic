// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package config

import (
	"testing"

	"github.com/xeylabs/xprotect/server/internal/risk"
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
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("XPROTECT_ADDR", ":9090")
	t.Setenv("XPROTECT_TRUST_PROXY", "1")
	t.Setenv("XPROTECT_BASE_DIFFICULTY", "22")
	t.Setenv("XPROTECT_MAX_DIFFICULTY", "30")
	t.Setenv("XPROTECT_DENY_AT", "90")
	t.Setenv("XPROTECT_SITES", " alpha, beta ,,")
	t.Setenv("XPROTECT_IP_LIMIT", "7")

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
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package risk_test

import (
	"testing"

	"github.com/xeylabs/mythic/server/internal/risk"
)

func engine() *risk.Engine { return risk.New(risk.DefaultConfig()) }

func hasReason(reasons []string, prefix string) bool {
	for _, r := range reasons {
		if len(r) >= len(prefix) && r[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func TestCleanRequestIsAllowed(t *testing.T) {
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s", Attempts: 1})
	if res.Decision != risk.Allow {
		t.Fatalf("clean request: decision %q score %d reasons %v", res.Decision, res.Score, res.Reasons)
	}
	if res.Score != 0 {
		t.Fatalf("clean request score must be 0, got %d", res.Score)
	}
}

func TestImplausibleSolveTimeIsPenalized(t *testing.T) {
	// ADR-0008: difficulty-18 floor ≈ 4ms (quantile-calibrated). A 1ms round
	// trip is below what any honest worker can do; GPU-class answers trip it.
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 1, Difficulty: 18})
	if !hasReason(res.Reasons, "solve_time_implausible") {
		t.Fatalf("expected solve_time_implausible, got %v", res.Reasons)
	}
	if res.Score != 35 {
		t.Fatalf("fast-solve penalty must be 35, got %d", res.Score)
	}
	if res.Decision != risk.Challenge {
		t.Fatalf("score 35 must step up, got %q", res.Decision)
	}
	if res.Difficulty != 22 {
		t.Fatalf("step-up difficulty must be base+4=22, got %d", res.Difficulty)
	}
}

func TestPlausibleSolveTimeNotPenalized(t *testing.T) {
	// The honest-worker calibration: 10s at difficulty 18 is comfortably
	// above the quantile floor — no penalty, no false positive.
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 10_000, Difficulty: 18})
	if res.Score != 0 {
		t.Fatalf("plausible solve time scored: %v", res.Reasons)
	}
}

func TestFastButHonestWorkerNotPenalized(t *testing.T) {
	// Regression for red-team finding F1: a strong worker finishing 2^18 in
	// ~655ms (measured ~400k H/s) used to be flagged by the 5.2s floor. The
	// quantile floor (4ms) must let it through.
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 655, Difficulty: 18})
	if res.Score != 0 {
		t.Fatalf("fast honest worker scored: %v", res.Reasons)
	}
}

func TestPressureEscalates(t *testing.T) {
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 50})
	if !hasReason(res.Reasons, "challenge_pressure") {
		t.Fatalf("expected challenge_pressure, got %v", res.Reasons)
	}
	if res.Score != 30 {
		t.Fatalf("pressure must cap at 30, got %d", res.Score)
	}
}

func TestAdvisoryHintsHaveCappedWeight(t *testing.T) {
	res := engine().Evaluate(risk.Input{
		IP:       "1.2.3.4",
		Attempts: 1,
		ClientSignals: map[string]any{
			"webdriver":    true,
			"headless":     true,
			"no_languages": true,
		},
	})
	// 15 + 10 + 5 = 30 → step-up but never deny.
	if res.Score != 30 {
		t.Fatalf("advisory sum must be 30, got %d", res.Score)
	}
	if res.Decision != risk.Challenge {
		t.Fatalf("advisory hints alone must not deny, got %q", res.Decision)
	}
}

func TestDenyOnlyFromServerObservedFacts(t *testing.T) {
	cfg := risk.DefaultConfig()
	cfg.FastSolvePenalty = 100 // hostile tuning: prove deny is reachable
	res := risk.New(cfg).Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 1, Difficulty: 18})
	if res.Decision != risk.Deny {
		t.Fatalf("expected deny, got %q", res.Decision)
	}
}

func TestDifficultyNeverExceedsMax(t *testing.T) {
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 1, Difficulty: 30})
	if res.Difficulty > 26 {
		t.Fatalf("difficulty above max: %d", res.Difficulty)
	}
}

// Red-team H3: the score is a 0-100 contract (token claim `risk`). Hostile
// tuning must clamp at the engine, not leak 500 into tokens.
func TestScoreClampedToHundred(t *testing.T) {
	cfg := risk.DefaultConfig()
	cfg.FastSolvePenalty = 500
	res := risk.New(cfg).Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 1, Difficulty: 18})
	if res.Score != 100 {
		t.Fatalf("score must clamp to 100, got %d", res.Score)
	}
	if res.Decision != risk.Deny {
		t.Fatalf("clamped 100 must deny (≥ DenyAt), got %q", res.Decision)
	}
}

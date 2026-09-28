package risk_test

import (
	"testing"

	"github.com/xeylabs/xprotect/server/internal/risk"
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
	// Difficulty 18 floor ≈ 5242ms; claiming a 5ms round trip is impossible.
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 5, Difficulty: 18})
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
	res := engine().Evaluate(risk.Input{IP: "1.2.3.4", Attempts: 1, SolveMillis: 10_000, Difficulty: 18})
	if res.Score != 0 {
		t.Fatalf("plausible solve time scored: %v", res.Reasons)
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package risk_test

import (
	"testing"

	"github.com/xeylabs/mythic/server/internal/risk"
)

// ADR-0011 bypass tests: behavioral signals are advisory with hard caps.

// TestBehaviorNilScoresNothing: no data = zero contribution, not a penalty.
func TestBehaviorNilScoresNothing(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s", Behavior: nil})
	if r.Score != 0 {
		t.Fatalf("nil behavior must score 0, got %d", r.Score)
	}
}

// TestBehaviorHumanLike: human-plausible features score low.
func TestBehaviorHumanLike(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		Behavior: &risk.BehavioralFeatures{
			MousePoints:     50,
			MouseMeanV:      0.5,
			MouseVarV:       0.1, // variable speed = human
			MouseDirChanges: 8,
			MouseCurvature:  1.8, // curvy = human
			KeyDwells:       10,
			KeyMeanDwell:    120, // normal typing
			KeyMeanFlight:   200,
			ScrollEvents:    5,
			ScrollReversals: 1,
		},
	})
	if r.Score != 0 {
		t.Fatalf("human-like behavior must score 0, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestBehaviorBotStraightLine: perfectly straight = scripted.
func TestBehaviorBotStraightLine(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		Behavior: &risk.BehavioralFeatures{
			MousePoints:     50,
			MouseMeanV:      1.0,
			MouseVarV:       0.05,
			MouseDirChanges: 0,    // no turns over 50 points
			MouseCurvature:  1.02, // nearly straight
		},
	})
	// straight (8) + no dir changes (6) = 14
	if r.Score != 14 {
		t.Fatalf("straight-line bot must score 14, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestBehaviorBotTeleport: teleportation = non-human.
func TestBehaviorBotTeleport(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		Behavior: &risk.BehavioralFeatures{
			MousePoints:     10,
			MouseMeanV:      5.0,
			MouseVarV:       0.1,
			MouseDirChanges: 2,
			MouseCurvature:  15.0, // teleport
		},
	})
	if r.Score != 10 {
		t.Fatalf("teleport bot must score 10, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestBehaviorBotNoVariance: constant velocity = scripted.
func TestBehaviorBotNoVariance(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		Behavior: &risk.BehavioralFeatures{
			MousePoints:     30,
			MouseMeanV:      2.0,
			MouseVarV:       0, // exactly constant
			MouseDirChanges: 3,
			MouseCurvature:  1.5,
		},
	})
	if r.Score != 8 {
		t.Fatalf("zero-variance bot must score 8, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestBehaviorCapHolds: combined signals respect the 20-point cap.
func TestBehaviorCapHolds(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		Behavior: &risk.BehavioralFeatures{
			MousePoints:     50,
			MouseMeanV:      1.0,
			MouseVarV:       0,    // +8
			MouseDirChanges: 0,    // +6
			MouseCurvature:  1.01, // +8 → total 22, capped at 20
		},
	})
	if r.Score != 20 {
		t.Fatalf("behavioral cap must hold at 20, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestBehaviorReplayBypass: an attacker replaying recorded human features
// passes. This is the documented bypass — behavioral signals raise the cost
// of automation, they do not prove humanity (ADR-0011).
func TestBehaviorReplayBypass(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	// Attacker recorded a real human session and replays the features:
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		Behavior: &risk.BehavioralFeatures{
			MousePoints:     47,
			MouseMeanV:      0.43,
			MouseVarV:       0.08,
			MouseDirChanges: 7,
			MouseCurvature:  2.1,
			KeyDwells:       8,
			KeyMeanDwell:    110,
			KeyMeanFlight:   180,
		},
	})
	if r.Score != 0 {
		t.Fatalf("replayed human features should pass: got %d", r.Score)
	}
	t.Log("BYPASS CONFIRMED (by design): recorded human replay passes. " +
		"Behavioral is advisory only — see ADR-0011.")
}

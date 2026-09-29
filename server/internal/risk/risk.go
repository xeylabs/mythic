// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package risk scores requests and decides what happens next.
//
// v0 is deterministic and auditable on purpose: every score bump has a named
// reason. Client-reported hints participate as advisory signals with hard
// weight caps (ADR-0004) — they can raise suspicion, never decide alone.
package risk

import (
	"fmt"
	"sort"

	"github.com/xeylabs/mythic/server/internal/challenge"
)

type Decision string

const (
	Allow     Decision = "allow"
	Challenge Decision = "challenge"
	Deny      Decision = "deny"
)

// Input is everything the engine knows at decision time.
type Input struct {
	IP            string
	SiteKey       string
	Attempts      int64          // challenges issued to this IP inside the pressure window
	SolveMillis   int64          // server-measured solve time for the challenge being redeemed; 0 = unknown
	Difficulty    int            // difficulty of that challenge
	ClientSignals map[string]any // advisory hints reported by the SDK
}

// Result is the engine verdict plus the PoW difficulty for the next challenge.
type Result struct {
	Score      int
	Decision   Decision
	Difficulty int
	Reasons    []string
}

// Config holds weights and thresholds. Exported for tuning and tests.
type Config struct {
	BaseDifficulty   int
	MaxDifficulty    int
	DenyAt           int // score >= DenyAt → deny
	HeavyAt          int // score >= HeavyAt → challenge at Base+8
	StepUpAt         int // score >= StepUpAt → challenge at Base+4
	FastSolvePenalty int
	PressurePerReq   int
	PressureMax      int
	AdvisoryPenalty  map[string]int
}

func DefaultConfig() Config {
	return Config{
		BaseDifficulty:   18,
		MaxDifficulty:    26,
		DenyAt:           85,
		HeavyAt:          65,
		StepUpAt:         30,
		FastSolvePenalty: 35,
		PressurePerReq:   2,
		PressureMax:      30,
		AdvisoryPenalty: map[string]int{
			"webdriver":    15, // navigator.webdriver === true: automation by definition
			"headless":     10, // browser claims Chrome but lacks chrome object, etc.
			"no_languages": 5,  // navigator.languages empty: common in headless default profiles
		},
	}
}

type Engine struct {
	cfg Config
}

func New(cfg Config) *Engine { return &Engine{cfg: cfg} }

func (e *Engine) Evaluate(in Input) Result {
	score := 0
	var reasons []string
	add := func(points int, reason string) {
		if points > 0 {
			score += points
			reasons = append(reasons, fmt.Sprintf("%s(+%d)", reason, points))
		}
	}

	// Server-observed: the round trip returned faster than a legitimate
	// browser worker could grind the required hashes.
	if in.SolveMillis > 0 && in.Difficulty > 0 {
		if floor := challenge.MinPlausibleSolveMillis(in.Difficulty); in.SolveMillis < floor {
			add(e.cfg.FastSolvePenalty, "solve_time_implausible")
		}
	}

	// Server-observed: per-IP challenge pressure inside the window.
	if in.Attempts > 1 {
		penalty := e.cfg.PressurePerReq * int(in.Attempts-1)
		if penalty > e.cfg.PressureMax {
			penalty = e.cfg.PressureMax
		}
		add(penalty, "challenge_pressure")
	}

	// Advisory client hints — weight-capped, sorted for deterministic output.
	names := make([]string, 0, len(e.cfg.AdvisoryPenalty))
	for name := range e.cfg.AdvisoryPenalty {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if v, ok := in.ClientSignals[name].(bool); ok && v {
			add(e.cfg.AdvisoryPenalty[name], "advisory_"+name)
		}
	}

	// The score is a 0-100 contract (token claim `risk`, dashboards, tuning
	// docs). Hostile tuning must clamp here, not leak 500 into tokens
	// (red-team H3).
	if score > 100 {
		score = 100
	}

	decision := Allow
	next := e.cfg.BaseDifficulty
	switch {
	case score >= e.cfg.DenyAt:
		decision = Deny
		next = e.cfg.MaxDifficulty
	case score >= e.cfg.HeavyAt:
		decision = Challenge
		next = min(e.cfg.BaseDifficulty+8, e.cfg.MaxDifficulty)
	case score >= e.cfg.StepUpAt:
		decision = Challenge
		next = min(e.cfg.BaseDifficulty+4, e.cfg.MaxDifficulty)
	}
	return Result{Score: score, Decision: decision, Difficulty: next, Reasons: reasons}
}

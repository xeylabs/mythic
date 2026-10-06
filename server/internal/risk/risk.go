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
	// ADR-0010: network-layer advisory signals. JA4Fingerprint comes from
	// the trusted proxy's X-Mythic-JA4 header (empty = unavailable, not an
	// error). ASN is the client IP's autonomous system number (0 = unknown).
	JA4Fingerprint string
	ASN            uint
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
	// ADR-0010: hard caps for network-layer advisory signals. Neither can
	// decide alone — they raise the cost of blending in.
	JA4AnomalyPenalty int // max points for unknown/suspicious JA4 (default 15)
	JA4KnownDiscount  int // max discount for known-good browser JA4 (default 5)
	ASNHostingPenalty int // max points for datacenter/hosting ASN (default 10)
	// KnownJA4Prefixes are JA4_a prefixes of mainstream browsers. Matching
	// earns the discount; anything else is scored as anomalous. This is a
	// heuristic, not an allowlist — see ADR-0010.
	KnownJA4Prefixes []string
	// HostingASNs are ASNs known to belong to datacenter/hosting providers.
	// Matching adds the hosting penalty. Heuristic, not a blocklist.
	HostingASNs map[uint]bool
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
		JA4AnomalyPenalty: 15,
		JA4KnownDiscount:  5,
		ASNHostingPenalty: 10,
		// JA4_a prefixes observed from mainstream browsers (2026).
		// These earn a small discount; everything else is anomalous.
		// Heuristic — attackers can parrot any fingerprint (ADR-0010).
		KnownJA4Prefixes: []string{
			"t13d1516h2_8daaf6152771", // Chrome/Chromium
			"t13d1516h2_5b0d8b67751f", // Firefox
		},
		HostingASNs: map[uint]bool{
			16509: true, // AWS
			14618: true, // AWS
			15169: true, // Google
			8075:  true, // Microsoft
			14061: true, // DigitalOcean
			20473: true, // Vultr
			63949: true, // Linode
			16276: true, // OVH
			12876: true, // Scaleway/Online
			9009:  true, // M247
		},
	}
}

type Engine struct {
	cfg Config
}

func New(cfg Config) *Engine { return &Engine{cfg: cfg} }

// isPlausibleJA4 checks minimal JA4 structure: three underscore-separated
// sections (a_b_c), each non-empty. This rejects prefix-only or otherwise
// truncated junk from earning the known-browser discount — a real proxy
// always emits the full fingerprint. Not a full JA4 validator; the signal
// is advisory, and strict parsing would just create a new evasion surface.
func isPlausibleJA4(fp string) bool {
	parts := 0
	start := 0
	for i := 0; i <= len(fp); i++ {
		if i == len(fp) || fp[i] == '_' {
			if i-start == 0 {
				return false // empty section
			}
			parts++
			start = i + 1
		}
	}
	return parts >= 3
}

// isKnownJA4 reports whether fp starts with a known browser JA4_a prefix
// and is structurally plausible. Prefix-only input is rejected by the
// plausibility check first.
func isKnownJA4(fp string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if len(fp) >= len(prefix) && fp[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

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

	// ADR-0010: JA4 TLS fingerprint — advisory, hard-capped. Empty means
	// the signal is unavailable (no proxy header), which scores nothing.
	// A known-good browser fingerprint earns a small discount; anything
	// else is anomalous. Attackers can parrot any fingerprint, so this
	// raises blending cost, never proves humanity.
	if in.JA4Fingerprint != "" {
		if !isPlausibleJA4(in.JA4Fingerprint) {
			// Malformed: not even shaped like a JA4. Anomalous, no discount.
			add(e.cfg.JA4AnomalyPenalty, "ja4_malformed")
		} else if isKnownJA4(in.JA4Fingerprint, e.cfg.KnownJA4Prefixes) {
			// Discount, not a negative add — applied as score reduction.
			if score >= e.cfg.JA4KnownDiscount {
				score -= e.cfg.JA4KnownDiscount
			} else {
				score = 0
			}
			reasons = append(reasons, fmt.Sprintf("ja4_known(-%d)", e.cfg.JA4KnownDiscount))
		} else {
			add(e.cfg.JA4AnomalyPenalty, "ja4_anomaly")
		}
	}

	// ADR-0010: ASN — advisory, hard-capped. 0 means unknown (no DB or no
	// match), which scores nothing. Datacenter/hosting ASNs add risk;
	// residential/ISP ASNs are neutral. Heuristic, not a blocklist.
	if in.ASN != 0 && e.cfg.HostingASNs[in.ASN] {
		add(e.cfg.ASNHostingPenalty, "asn_hosting")
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

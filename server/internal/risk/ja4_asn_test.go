// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package risk_test

import (
	"testing"

	"github.com/xeylabs/mythic/server/internal/risk"
)

// ADR-0010 bypass tests: JA4 and ASN are advisory signals with hard caps.
// These tests prove the bypass properties the ADR claims.

// TestJA4EmptyScoresNothing: no header = no signal, not an error, not a penalty.
func TestJA4EmptyScoresNothing(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s"})
	if r.Score != 0 {
		t.Fatalf("empty JA4 must score 0, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestJA4KnownEarnsDiscount: a known browser fingerprint reduces the score.
func TestJA4KnownEarnsDiscount(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	// First build some score via pressure, then check the discount applies.
	base := eng.Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s", Attempts: 5})
	withJA4 := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s", Attempts: 5,
		JA4Fingerprint: "t13d1516h2_8daaf6152771_e8f1bf7b9c16",
	})
	if withJA4.Score >= base.Score {
		t.Fatalf("known JA4 must discount: base=%d withJA4=%d", base.Score, withJA4.Score)
	}
	if diff := base.Score - withJA4.Score; diff != 5 {
		t.Fatalf("discount must be exactly 5, got %d", diff)
	}
}

// TestJA4AnomalyCapped: unknown fingerprints add risk, but never more than the cap.
func TestJA4AnomalyCapped(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		JA4Fingerprint: "t13d1516h2_000000000000_000000000000", // curl-like
	})
	if r.Score != 15 {
		t.Fatalf("anomalous JA4 must add exactly 15, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestJA4MalformedNoDiscount: prefix-only or truncated JA4 must NOT earn
// the known-browser discount — it scores as malformed (anomaly penalty).
func TestJA4MalformedNoDiscount(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	for _, fp := range []string{
		"t13d1516h2_8daaf6152771",       // prefix only, no _b_c
		"t13d1516h2_8daaf6152771_",      // trailing empty section
		"t13d1516h2__e8f1bf7b9c16",      // empty middle section
		"_8daaf6152771_e8f1bf7b9c16",    // empty first section
	} {
		r := eng.Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s", JA4Fingerprint: fp})
		if r.Score != 15 {
			t.Fatalf("malformed JA4 %q must score anomaly 15, got %d (%v)", fp, r.Score, r.Reasons)
		}
		found := false
		for _, reason := range r.Reasons {
			if reason == "ja4_malformed(+15)" {
				found = true
			}
		}
		if !found {
			t.Fatalf("malformed JA4 %q must report ja4_malformed, got %v", fp, r.Reasons)
		}
	}
}
// TestJA4ParrotBypass: an attacker parroting a known Chrome fingerprint
// gets the discount. This is the documented bypass — JA4 raises the cost
// of blending in, it does not prove humanity (ADR-0010).
func TestJA4ParrotBypass(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	// Attacker with uTLS parroting Chrome's JA4:
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s", Attempts: 3, // some pressure
		JA4Fingerprint: "t13d1516h2_8daaf6152771_e8f1bf7b9c16",
	})
	// Pressure (3-1)*2=4, minus JA4 discount 5 → clamped at 0.
	// The bypass works: parroted JA4 erases the pressure signal's contribution.
	if r.Score != 0 {
		t.Fatalf("parroted JA4 should neutralize low pressure: got %d (%v)", r.Score, r.Reasons)
	}
	t.Logf("BYPASS CONFIRMED (by design): parroted JA4 + low pressure = score 0. " +
		"JA4 is advisory only — see ADR-0010.")
}

// TestASNHostingAddsRisk: datacenter ASN adds the capped penalty.
func TestASNHostingAddsRisk(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s", ASN: 16509}) // AWS
	if r.Score != 10 {
		t.Fatalf("hosting ASN must add exactly 10, got %d (%v)", r.Score, r.Reasons)
	}
}

// TestASNUnknownScoresNothing: ASN 0 (no DB / no match) scores nothing.
func TestASNUnknownScoresNothing(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s", ASN: 0})
	if r.Score != 0 {
		t.Fatalf("unknown ASN must score 0, got %d", r.Score)
	}
}

// TestASNResidentialNeutral: non-hosting ASN adds nothing.
func TestASNResidentialNeutral(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{IP: "1.2.3.4", SiteKey: "s", ASN: 17995}) // Telkomsel (example)
	if r.Score != 0 {
		t.Fatalf("residential ASN must score 0, got %d", r.Score)
	}
}

// TestJA4ASNCapsHold: combined signals respect their individual caps.
func TestJA4ASNCapsHold(t *testing.T) {
	eng := risk.New(risk.DefaultConfig())
	r := eng.Evaluate(risk.Input{
		IP: "1.2.3.4", SiteKey: "s",
		JA4Fingerprint: "t00_anomalous",
		ASN:            16509,
	})
	if r.Score != 25 { // 15 (JA4) + 10 (ASN)
		t.Fatalf("combined capped signals must total 25, got %d (%v)", r.Score, r.Reasons)
	}
}

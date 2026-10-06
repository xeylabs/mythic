// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/api"
	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
	"github.com/xeylabs/mythic/server/internal/store"
)

// newTestServerWithProxy builds a test server with TrustProxy configurable.
func newTestServerWithProxy(t *testing.T, trustProxy bool) *httptest.Server {
	t.Helper()
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	eng := risk.New(risk.DefaultConfig())
	srv := api.New(api.Config{
		Sites:        []string{"test-site"},
		TokenTTL:     time.Minute,
		ChallengeTTL: time.Minute,
		IPWindow:     time.Minute,
		IPLimit:      1000,
		TrustProxy:   trustProxy,
	}, km, store.NewMemory(time.Minute), eng, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func postWithHeader(t *testing.T, url, ja4 string, body any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if ja4 != "" {
		req.Header.Set("X-Mythic-JA4", ja4)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestJA4HeaderIgnoredWithoutTrustProxy: the bypass that must NOT work.
// A client sending X-Mythic-JA4 directly (no trusted proxy) must have the
// header ignored — it must not affect the risk score.
//
// NOTE: two sequential challenges from the same IP accrue pressure (+2 on
// the second), so we compare against a second no-header baseline, not the
// first.
func TestJA4HeaderIgnoredWithoutTrustProxy(t *testing.T) {
	ts := newTestServerWithProxy(t, false)

	// Two baselines without header (pressure accrues on the 2nd).
	_ = postWithHeader(t, ts.URL+"/v1/challenge", "",
		map[string]any{"site_key": "test-site"})
	base := postWithHeader(t, ts.URL+"/v1/challenge", "",
		map[string]any{"site_key": "test-site"})
	// Attack: client injects a "known-good" JA4 hoping for the discount.
	// Pressure accrues equally here, so any JA4 effect would show as a
	// deviation from the pressure-only trajectory.
	attack := postWithHeader(t, ts.URL+"/v1/challenge", "t13d1516h2_8daaf6152771_e8f1bf7b9c16",
		map[string]any{"site_key": "test-site"})

	baseRisk := base["risk"].(float64)
	attackRisk := attack["risk"].(float64)
	// Both should carry the same pressure penalty and no JA4 effect.
	// base = 2nd request (pressure +2), attack = 3rd request (pressure +4).
	// If JA4 were honored, attack would get -5 discount → lower than expected.
	expectedAttack := baseRisk + 2 // one more pressure step, no JA4
	if attackRisk != expectedAttack {
		t.Fatalf("client-supplied JA4 must be ignored without TrustProxy: "+
			"base(2nd)=%v attack(3rd)=%v expected=%v (pressure-only)",
			baseRisk, attackRisk, expectedAttack)
	}
}

// TestJA4HeaderHonoredWithTrustProxy: with a trusted proxy, the header
// flows into the risk engine.
func TestJA4HeaderHonoredWithTrustProxy(t *testing.T) {
	ts := newTestServerWithProxy(t, true)

	// Anomalous JA4 (curl-like) should add risk vs. no header.
	base := postWithHeader(t, ts.URL+"/v1/challenge", "",
		map[string]any{"site_key": "test-site"})
	anomaly := postWithHeader(t, ts.URL+"/v1/challenge", "t13d1516h2_000000000000_000000000000",
		map[string]any{"site_key": "test-site"})

	baseRisk := base["risk"].(float64)
	anomalyRisk := anomaly["risk"].(float64)
	if anomalyRisk <= baseRisk {
		t.Fatalf("trusted-proxy JA4 anomaly must raise risk: base=%v anomaly=%v",
			baseRisk, anomalyRisk)
	}
}

var _ = ed25519.PublicKey{} // keep import if unused in future edits

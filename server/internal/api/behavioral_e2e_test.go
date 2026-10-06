// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/api"
	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
	"github.com/xeylabs/mythic/server/internal/store"
)

// TestEndToEndWithBehavioral exercises the full challenge → verify flow
// with behavioral hints, verifying the behavioral signal flows from
// client hints through to the risk score in the response.
func TestEndToEndWithBehavioral(t *testing.T) {
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
	}, km, store.NewMemory(time.Minute), eng, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Bot-like behavioral features: straight line, no variance.
	botHints := map[string]any{
		"behavioral": map[string]any{
			"v":                 1,
			"mouse_points":      50,
			"mouse_mean_v":      1.0,
			"mouse_var_v":       0.0, // zero variance = scripted
			"mouse_dir_changes": 0,
			"mouse_curvature":   1.01, // straight line
		},
	}

	// Challenge with bot-like behavior should score higher than without.
	resp1, out1 := post(t, ts.URL+"/v1/challenge", map[string]any{"site_key": "test-site"})
	resp2, out2 := post(t, ts.URL+"/v1/challenge", map[string]any{
		"site_key": "test-site",
		"hints":    botHints,
	})
	if resp1.StatusCode != 200 || resp2.StatusCode != 200 {
		t.Fatalf("challenges failed: %d %d", resp1.StatusCode, resp2.StatusCode)
	}
	risk1 := out1["risk"].(float64)
	risk2 := out2["risk"].(float64)
	t.Logf("risk without behavior=%.0f, with bot behavior=%.0f", risk1, risk2)
	if risk2 <= risk1 {
		t.Fatalf("bot-like behavior must increase risk: without=%.0f with=%.0f", risk1, risk2)
	}

	// Human-like behavioral features should not increase risk.
	// Use a fresh server to avoid pressure contamination.
	km2, _ := crypto.LoadOrCreate("")
	eng2 := risk.New(risk.DefaultConfig())
	srv2 := api.New(api.Config{
		Sites:        []string{"test-site"},
		TokenTTL:     time.Minute,
		ChallengeTTL: time.Minute,
		IPWindow:     time.Minute,
		IPLimit:      1000,
	}, km2, store.NewMemory(time.Minute), eng2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()

	humanHints := map[string]any{
		"behavioral": map[string]any{
			"v":                 1,
			"mouse_points":      50,
			"mouse_mean_v":      0.5,
			"mouse_var_v":       0.1,
			"mouse_dir_changes": 8,
			"mouse_curvature":   1.8,
			"key_dwells":        10,
			"key_mean_dwell":    120.0,
		},
	}
	_, out3 := post(t, ts2.URL+"/v1/challenge", map[string]any{"site_key": "test-site"})
	_, out4 := post(t, ts2.URL+"/v1/challenge", map[string]any{
		"site_key": "test-site",
		"hints":    humanHints,
	})
	// Second request has pressure (+2), so human behavior should roughly
	// offset it (human scores 0 behavioral, pressure adds 2).
	risk3 := out3["risk"].(float64)
	risk4 := out4["risk"].(float64)
	t.Logf("fresh: without=%.0f, with human=%.0f", risk3, risk4)
	if risk4 > risk3+2 {
		t.Fatalf("human-like behavior must not spike risk: without=%.0f with=%.0f", risk3, risk4)
	}
}

// TestEndToEndMalformedBehavioral verifies malformed behavioral data
// is handled gracefully (no crash, no bypass).
func TestEndToEndMalformedBehavioral(t *testing.T) {
	ts, _ := newTestServer(t)

	malformed := []map[string]any{
		{"behavioral": "not an object"},
		{"behavioral": map[string]any{"mouse_points": "fifty"}},
		{"behavioral": map[string]any{"v": 999}},
		{"behavioral": nil},
	}
	for i, hints := range malformed {
		resp, out := post(t, ts.URL+"/v1/challenge", map[string]any{
			"site_key": "test-site",
			"hints":    hints,
		})
		if resp.StatusCode != 200 {
			t.Fatalf("malformed case %d: expected 200, got %d", i, resp.StatusCode)
		}
		if _, ok := out["risk"]; !ok {
			t.Fatalf("malformed case %d: missing risk in response", i)
		}
	}
}

var _ = json.Marshal // keep import if needed

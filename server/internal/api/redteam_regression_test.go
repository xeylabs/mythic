// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api_test

// Regression test for red-team finding F4 (2026-09-29): a decision token
// could outlive its challenge — a 1-hour token was issued from a 5-second
// challenge. The ADR-0002 contract ("never longer than the challenge TTL")
// is now enforced by a clamp in api.New; this test pins the behavior.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/api"
	"github.com/xeylabs/mythic/server/internal/challenge"
	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
	"github.com/xeylabs/mythic/server/internal/store"
	"github.com/xeylabs/mythic/server/xtoken"
)

func TestTokenTTLCannotExceedChallengeTTL(t *testing.T) {
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(km.Close)

	eng := risk.New(risk.Config{
		BaseDifficulty:   8,
		MaxDifficulty:    12,
		DenyAt:           85,
		HeavyAt:          65,
		StepUpAt:         30,
		FastSolvePenalty: 35,
		PressurePerReq:   2,
		PressureMax:      30,
		AdvisoryPenalty:  map[string]int{},
	})
	// Token TTL 1 hour, challenge TTL 30 seconds — the exact red-team shape.
	srv := api.New(api.Config{
		Sites:        []string{"test-site"},
		TokenTTL:     time.Hour,
		ChallengeTTL: 30 * time.Second,
		IPWindow:     time.Minute,
		IPLimit:      1000,
	}, km, store.NewMemory(time.Minute), eng, silentLogger())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ch := issueChallenge(t, ts.URL)
	nonce, ok := challenge.Solve(&ch, 1<<20)
	if !ok {
		t.Fatal("solver gave up")
	}
	resp, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	if resp.StatusCode != 200 {
		t.Fatalf("verify: %d: %v", resp.StatusCode, out)
	}
	token, _ := out["token"].(string)
	payloadPart, _, _ := strings.Cut(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		t.Fatal(err)
	}
	var claims xtoken.TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if ttl := claims.Exp - claims.IssuedAt; ttl > 30 {
		t.Fatalf("token TTL %ds exceeds the 30s challenge TTL — the ADR-0002 clamp failed", ttl)
	}
}

// Red-team G1: the 4xx paths (invalid JSON, unknown site key) used to bypass
// the limiter entirely — 600 hostile rounds at 225 req/s, zero 429s. Budget
// is now consumed before validation: garbage drains the caller's own budget.
func TestGarbageConsumesRateLimitBudget(t *testing.T) {
	ts := newLimitTestServer(t, 10)
	for i := 0; i < 10; i++ {
		if code := postRaw(t, ts.URL+"/v1/challenge", `{garbage`); code != 400 {
			t.Fatalf("invalid JSON must be 400, got %d", code)
		}
	}
	if code := postRaw(t, ts.URL+"/v1/challenge", `{"site_key":"test-site"}`); code != 429 {
		t.Fatalf("after 10 garbage rounds the budget must be spent: got %d, want 429", code)
	}
}

// Red-team G5: trailing bytes after a JSON value used to be silently ignored.
func TestTrailingJSONDataRejected(t *testing.T) {
	ts := newLimitTestServer(t, 1000)
	if code := postRaw(t, ts.URL+"/v1/challenge", `{"site_key":"nope"}{"injected":true}`); code != 400 {
		t.Fatalf("trailing data must be rejected, got %d", code)
	}
}

func newLimitTestServer(t *testing.T, ipLimit int64) *httptest.Server {
	t.Helper()
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(km.Close)
	eng := risk.New(risk.Config{
		BaseDifficulty:  8,
		MaxDifficulty:   12,
		DenyAt:          85,
		HeavyAt:         65,
		StepUpAt:        30,
		AdvisoryPenalty: map[string]int{},
	})
	srv := api.New(api.Config{
		Sites:    []string{"test-site"},
		TokenTTL: time.Minute, ChallengeTTL: time.Minute,
		IPWindow: time.Minute, IPLimit: ipLimit,
	}, km, store.NewMemory(time.Minute), eng, silentLogger())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func postRaw(t *testing.T, url, body string) int {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

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

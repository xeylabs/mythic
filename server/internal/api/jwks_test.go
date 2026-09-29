// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api_test

// Tests for the multi-key JWKS surface (ADR-0006): after a rotation the
// endpoint advertises both keys, a pre-rotation token verifies against the
// retired key selected by kid, and the round trip still works end to end.

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/api"
	"github.com/xeylabs/mythic/server/internal/challenge"
	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
	"github.com/xeylabs/mythic/server/internal/store"
	"github.com/xeylabs/mythic/server/xtoken"
)

func newTestServerWithKM(t *testing.T, km *crypto.KeyManager) *httptest.Server {
	t.Helper()
	eng := risk.New(risk.Config{
		BaseDifficulty:   12,
		MaxDifficulty:    20,
		DenyAt:           85,
		HeavyAt:          65,
		StepUpAt:         30,
		FastSolvePenalty: 35,
		PressurePerReq:   2,
		PressureMax:      30,
		AdvisoryPenalty:  map[string]int{"webdriver": 15},
	})
	srv := api.New(api.Config{
		Sites:        []string{"test-site"},
		TokenTTL:     time.Minute,
		ChallengeTTL: time.Minute,
		IPWindow:     time.Minute,
		IPLimit:      1000,
	}, km, store.NewMemory(time.Minute), eng, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func fetchJWKS(t *testing.T, url string) []map[string]any {
	t.Helper()
	resp, err := http.Get(url + "/v1/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.Keys
}

func keyByKid(t *testing.T, keys []map[string]any, kid string) (ed25519.PublicKey, bool) {
	t.Helper()
	for _, k := range keys {
		if k["kid"] == kid {
			pub, err := xtoken.ParsePublicKey(k["x"].(string))
			if err != nil {
				t.Fatalf("jwks x invalid: %v", err)
			}
			return pub, true
		}
	}
	return nil, false
}

func TestJWKSAfterRotationAdvertisesBothKeys(t *testing.T) {
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	// Token signed by the key that is active NOW, before rotation.
	preToken, err := crypto.SignToken(km, xtoken.TokenClaims{SiteKey: "test-site", Decision: xtoken.DecisionAllow}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	preKid := km.KeyID()
	prePub := km.PublicKey()

	if err := km.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	ts := newTestServerWithKM(t, km)
	keys := fetchJWKS(t, ts.URL)
	if len(keys) != 2 {
		t.Fatalf("JWKS must list active + retired after rotation, got %d", len(keys))
	}
	if keys[0]["kid"] != km.KeyID() {
		t.Fatalf("first JWKS entry must be the active key: %v != %v", keys[0]["kid"], km.KeyID())
	}

	// The token signed before rotation verifies against its own key...
	if _, err := xtoken.VerifyToken(prePub, preToken); err != nil {
		t.Fatalf("pre-rotation token must verify: %v", err)
	}
	// ...and the origin's contract — pick the key by kid from the JWKS —
	// resolves the retired key and still verifies.
	retired, ok := keyByKid(t, keys, preKid)
	if !ok {
		t.Fatalf("retired key %s must be advertised in JWKS", preKid)
	}
	if _, err := xtoken.VerifyToken(retired, preToken); err != nil {
		t.Fatalf("pre-rotation token must verify against the JWKS-advertised retired key: %v", err)
	}
	// A token from before must not verify against the NEW active key.
	if _, err := xtoken.VerifyToken(km.PublicKey(), preToken); err == nil {
		t.Fatal("pre-rotation token must not verify against the new active key")
	}
}

func TestRoundTripAfterRotationUsesActiveKey(t *testing.T) {
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()
	if err := km.Rotate(); err != nil {
		t.Fatal(err)
	}

	ts := newTestServerWithKM(t, km)
	ch := issueChallenge(t, ts.URL)
	nonce, ok := challenge.Solve(&ch, 1<<24)
	if !ok {
		t.Fatal("solver gave up")
	}
	resp, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify after rotation: status %d: %v", resp.StatusCode, out)
	}
	token, _ := out["token"].(string)
	claims, err := xtoken.VerifyToken(km.PublicKey(), token)
	if err != nil {
		t.Fatalf("token must verify against the active key: %v", err)
	}
	if claims.KeyID != km.KeyID() {
		t.Fatalf("token kid = %q, want active %q", claims.KeyID, km.KeyID())
	}
}

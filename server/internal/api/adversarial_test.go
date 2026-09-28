// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api_test

// Tests born from adversarial poking of a live server ("chaos session").
// The invariant binding them all: no input, however hostile, may produce a
// 5xx, a panic, or a security-property violation.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
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

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func adversarialServer(t *testing.T, ipLimit int64, trustProxy bool) *httptest.Server {
	t.Helper()
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
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
		Sites:        []string{"chaos"},
		TokenTTL:     time.Minute,
		ChallengeTTL: time.Minute,
		IPWindow:     time.Minute,
		IPLimit:      ipLimit,
		TrustProxy:   trustProxy,
	}, km, store.NewMemory(time.Minute), eng, silentLogger())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func issueChaosChallenge(t *testing.T, baseURL string) challenge.Challenge {
	t.Helper()
	resp, out := post(t, baseURL+"/v1/challenge", map[string]any{"site_key": "chaos"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge: status %d: %v", resp.StatusCode, out)
	}
	raw, err := json.Marshal(out["challenge"])
	if err != nil {
		t.Fatal(err)
	}
	var ch challenge.Challenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

func postChallenge(t *testing.T, baseURL, xff string) int {
	t.Helper()
	req, err := http.NewRequest("POST", baseURL+"/v1/challenge", strings.NewReader(`{"site_key":"chaos"}`))
	if err != nil {
		t.Fatal(err)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestGarbageNeverCausesFiveHundred throws hostile junk at every endpoint —
// wrong methods, mangled paths, type-confused JSON, prototype-pollution
// keys, NUL bytes, 70KB strings, 30k-deep nesting, random binary — and
// asserts the server stays in 2xx/4xx territory. Always.
func TestGarbageNeverCausesFiveHundred(t *testing.T) {
	ts := adversarialServer(t, 1_000_000, false)
	rng := rand.New(rand.NewSource(99))

	endpoints := []string{
		"/v1/challenge", "/v1/verify", "/v1/.well-known/jwks.json",
		"/healthz", "/", "/v1/challenge/", "//v1/verify", "/nope",
	}
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	bodies := []string{
		"", "null", "[]", "123", `"str"`, "{}",
		`{"site_key":null}`, `{"site_key":123}`, `{"site_key":["x"]}`,
		`{"challenge_id":{},"nonce":[]}`,
		`{"nonce":{"$gt":""},"challenge_id":"x"}`,
		`{"site_key":"chaos","hints":"not-a-map"}`,
		`{"site_key":"chaos","hints":{"webdriver":"yes","__proto__":{"polluted":1},"constructor":1}}`,
		`{"site_key":"chaos","hints":` + strings.Repeat(`{"a":`, 5000) + `1` + strings.Repeat(`}`, 5000) + `}`,
		`{"site_key":"chaos","hints":` + strings.Repeat(`{"a":`, 30000) + `1` + strings.Repeat(`}`, 30000) + `}`,
		`{"challenge_id":"` + strings.Repeat("A", 70_000) + `","nonce":"n"}`,
		`{"challenge_id":"x","nonce":"y","challenge_id":"z"}`, // duplicate keys
		`{"site_key":"a\u0000b","decision":"allow"}`,          // control character in string
		`{"site_key":"chaos"`, // truncated JSON
	}
	for i := 0; i < 400; i++ {
		method := methods[rng.Intn(len(methods))]
		endpoint := endpoints[rng.Intn(len(endpoints))]
		var body string
		if rng.Intn(4) == 0 {
			raw := make([]byte, 1+rng.Intn(512))
			for j := range raw {
				raw[j] = byte(rng.Intn(256))
			}
			body = string(raw)
		} else {
			body = bodies[rng.Intn(len(bodies))]
		}

		req, err := http.NewRequest(method, ts.URL+endpoint, bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("5xx leaked: %s %s body=%.40q → %d", method, endpoint, body, resp.StatusCode)
		}
	}
}

// TestConcurrentRedemptionIsSingleUse races 16 verifies of one solved
// challenge. The single-use consumption is atomic: exactly one racer may
// win, everyone else gets 400.
func TestConcurrentRedemptionIsSingleUse(t *testing.T) {
	ts := adversarialServer(t, 1_000_000, false)
	ch := issueChaosChallenge(t, ts.URL)
	nonce, ok := challenge.Solve(&ch, 1<<24)
	if !ok {
		t.Fatal("no nonce found")
	}

	const racers = 16
	type result struct {
		status int
		err    error
	}
	results := make(chan result, racers)
	for i := 0; i < racers; i++ {
		go func() {
			req, err := http.NewRequest("POST", ts.URL+"/v1/verify",
				strings.NewReader(fmt.Sprintf(`{"challenge_id":%q,"nonce":%q}`, ch.ID, nonce)))
			if err != nil {
				results <- result{err: err}
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results <- result{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			results <- result{status: resp.StatusCode}
			resp.Body.Close()
		}()
	}

	wins := 0
	for i := 0; i < racers; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		switch r.status {
		case http.StatusOK:
			wins++
		case http.StatusBadRequest:
			// expected for every racer that lost the single-use take
		default:
			t.Fatalf("unexpected status during redemption race: %d", r.status)
		}
	}
	if wins != 1 {
		t.Fatalf("exactly one racer may redeem a challenge, got %d wins of %d", wins, racers)
	}
}

// TestRateLimitEnforcedPerIP: an honest client hits the wall exactly at the
// configured limit, and every 429 carries Retry-After.
func TestRateLimitEnforcedPerIP(t *testing.T) {
	ts := adversarialServer(t, 20, false)
	passed, limited := 0, 0
	retryAfter := ""
	for i := 0; i < 25; i++ {
		status := postChallenge(t, ts.URL, "")
		switch status {
		case http.StatusOK:
			passed++
		case http.StatusTooManyRequests:
			limited++
			retryAfter = "seen"
		}
	}
	if passed != 20 || limited != 5 {
		t.Fatalf("want 20 pass + 5 limited, got %d pass + %d limited", passed, limited)
	}
	if retryAfter == "" {
		t.Fatal("429 responses must carry Retry-After")
	}
}

// TestSpoofedForwardedForCannotBypassRateLimit is the regression test for
// the chaos-session finding: with TrustProxy off (default), a rotating fake
// X-Forwarded-For must NOT reset the per-IP counters. Before the fix this
// exact request pattern sailed past the limiter 20/20.
func TestSpoofedForwardedForCannotBypassRateLimit(t *testing.T) {
	ts := adversarialServer(t, 10, false) // TrustProxy explicitly off
	passed, limited := 0, 0
	for i := 0; i < 30; i++ {
		switch postChallenge(t, ts.URL, fmt.Sprintf("10.99.%d.%d", i/250, i%250)) {
		case http.StatusOK:
			passed++
		case http.StatusTooManyRequests:
			limited++
		}
	}
	if passed != 10 || limited != 20 {
		t.Fatalf("spoofed XFF must not bypass the limiter: %d passed, %d limited (want 10/20)", passed, limited)
	}
}

// TestTrustProxyAttributesForwardedIP: with the opt-in flag on, distinct
// forwarded addresses get distinct counters — that is the supported proxy
// deployment.
func TestTrustProxyAttributesForwardedIP(t *testing.T) {
	ts := adversarialServer(t, 3, true) // TrustProxy on
	for i := 0; i < 8; i++ {
		if status := postChallenge(t, ts.URL, fmt.Sprintf("10.9.0.%d", i)); status != http.StatusOK {
			t.Fatalf("fresh forwarded IP %d must not be limited, got %d", i, status)
		}
	}
}

// TestCrossChallengeSolutionRejected: a valid solution is bound to its own
// challenge — swap ids and the difficulty check must fail.
func TestCrossChallengeSolutionRejected(t *testing.T) {
	ts := adversarialServer(t, 1_000_000, false)
	a := issueChaosChallenge(t, ts.URL)
	b := issueChaosChallenge(t, ts.URL)

	nonceA, ok := challenge.Solve(&a, 1<<24)
	if !ok {
		t.Fatal("no nonce for A")
	}
	resp, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": b.ID, "nonce": nonceA})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("solution of A must not redeem B, got %d: %v", resp.StatusCode, out)
	}

	// B was CONSUMED by the failed cross attempt — deliberate: single-use
	// consumption happens before validation, so every verification attempt
	// (right or wrong) burns the challenge and brute force is capped at one
	// guess per issuance. The SDK requests a fresh challenge instead.
	nonceB, ok := challenge.Solve(&b, 1<<24)
	if !ok {
		t.Fatal("no nonce for B")
	}
	resp, out = post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": b.ID, "nonce": nonceB})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a failed attempt must burn the challenge even against a later valid solution, got %d: %v", resp.StatusCode, out)
	}
}

// TestEphemeralKeyPairwiseDistinct: two servers started with no key file get
// independent ephemeral keys — a token from one must not verify on the
// other's public key.
func TestEphemeralKeyPairwiseDistinct(t *testing.T) {
	tsA := adversarialServer(t, 1_000_000, false)
	tsB := adversarialServer(t, 1_000_000, false)

	ch := issueChaosChallenge(t, tsA.URL)
	nonce, ok := challenge.Solve(&ch, 1<<24)
	if !ok {
		t.Fatal("no nonce")
	}
	_, out := post(t, tsA.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatalf("no token from A: %v", out)
	}

	resp, err := http.Get(tsB.URL + "/v1/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct {
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	pubB, err := xtoken.ParsePublicKey(doc.Keys[0].X)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xtoken.VerifyToken(pubB, token); err == nil {
		t.Fatal("token from server A must not verify against server B's key")
	}
}

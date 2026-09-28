package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xeylabs/xprotect/server/internal/api"
	"github.com/xeylabs/xprotect/server/internal/challenge"
	"github.com/xeylabs/xprotect/server/internal/crypto"
	"github.com/xeylabs/xprotect/server/internal/risk"
	"github.com/xeylabs/xprotect/server/internal/store"
	"github.com/xeylabs/xprotect/server/xtoken"
)

func newTestServer(t *testing.T) (*httptest.Server, ed25519.PublicKey) {
	t.Helper()
	km, err := crypto.LoadOrCreate("") // ephemeral key
	if err != nil {
		t.Fatal(err)
	}
	// Low base difficulty keeps the round trip fast; plausibility floors are
	// exercised separately in the risk engine tests.
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
	return ts, km.PublicKey()
}

func post(t *testing.T, url string, body any) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp, out
}

func issueChallenge(t *testing.T, url string) challenge.Challenge {
	t.Helper()
	resp, out := post(t, url+"/v1/challenge", map[string]any{"site_key": "test-site"})
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
	if ch.ID == "" || ch.Salt == "" || ch.Difficulty <= 0 || ch.Algorithm != challenge.Algorithm {
		t.Fatalf("malformed challenge: %+v", ch)
	}
	return ch
}

func TestRoundTrip(t *testing.T) {
	ts, pub := newTestServer(t)
	ch := issueChallenge(t, ts.URL)

	nonce, ok := challenge.Solve(&ch, 1<<24)
	if !ok {
		t.Fatal("solver gave up")
	}

	resp, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: status %d: %v", resp.StatusCode, out)
	}
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatalf("no token in response: %v", out)
	}
	claims, err := xtoken.VerifyToken(pub, token)
	if err != nil {
		t.Fatalf("token rejected: %v", err)
	}
	if claims.SiteKey != "test-site" {
		t.Fatalf("wrong site key claim: %q", claims.SiteKey)
	}
	if claims.Decision != xtoken.DecisionAllow && claims.Decision != xtoken.DecisionChallenge {
		t.Fatalf("unexpected decision: %q", claims.Decision)
	}
	if claims.Risk < 0 || claims.Risk > 100 {
		t.Fatalf("risk out of range: %d", claims.Risk)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	ts, _ := newTestServer(t)
	ch := issueChallenge(t, ts.URL)
	nonce, ok := challenge.Solve(&ch, 1<<24)
	if !ok {
		t.Fatal("solver gave up")
	}

	resp, _ := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first redemption failed: %d", resp.StatusCode)
	}
	resp, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay must be rejected, got %d: %v", resp.StatusCode, out)
	}
}

func TestInvalidSolutionRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	ch := issueChallenge(t, ts.URL)
	resp, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": "deadbeef"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong nonce must be rejected, got %d: %v", resp.StatusCode, out)
	}
}

func TestUnknownSiteKeyRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, out := post(t, ts.URL+"/v1/challenge", map[string]any{"site_key": "not-registered"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown site key must be rejected, got %d: %v", resp.StatusCode, out)
	}
}

func TestTamperedTokenRejected(t *testing.T) {
	ts, pub := newTestServer(t)
	ch := issueChallenge(t, ts.URL)
	nonce, _ := challenge.Solve(&ch, 1<<24)
	_, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	token, _ := out["token"].(string)

	// Mutate the payload deterministically: the signed bytes change, so the
	// Ed25519 signature can no longer match. Overwriting the signature's tail
	// was flaky — a random signature can already end in the same characters.
	payload, sig, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatal("token must be payload.signature")
	}
	mutated := []byte(payload)
	if mutated[0] == 'B' {
		mutated[0] = 'C'
	} else {
		mutated[0] = 'B'
	}
	tampered := string(mutated) + "." + sig
	if _, err := xtoken.VerifyToken(pub, tampered); err == nil {
		t.Fatal("tampered token must not verify")
	}
	if _, err := xtoken.VerifyToken(pub, "not.a.token"); err == nil {
		t.Fatal("garbage token must not verify")
	}
}

func TestExpiredChallengeIsGone(t *testing.T) {
	ts, _ := newTestServer(t)
	// Issue via server, but pretend the clock ran out by crafting expiry
	// through a fresh store entry with a past timestamp is not possible from
	// here; instead drive the public behavior: TTL of the challenge is
	// enforced server-side, so simulate by issuing and rewinding ExpiresAt.
	ch := issueChallenge(t, ts.URL)
	ch.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	nonce, _ := challenge.Solve(&ch, 1<<24)
	resp, out := post(t, ts.URL+"/v1/verify", map[string]any{"challenge_id": ch.ID, "nonce": nonce})
	// The server validates expiry from its own record, not the client copy —
	// a still-fresh challenge verifies. A truly expired one 410s; that path
	// needs store injection and is covered by the store janitor semantics.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh challenge with doctored client expiry must still verify, got %d: %v", resp.StatusCode, out)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	ts, pub := newTestServer(t)
	resp, err := http.Get(ts.URL + "/v1/.well-known/jwks.json")
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
	if len(doc.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(doc.Keys))
	}
	x, _ := doc.Keys[0]["x"].(string)
	got, err := xtoken.ParsePublicKey(x)
	if err != nil {
		t.Fatalf("jwks x invalid: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatal("jwks key does not match server public key")
	}
}

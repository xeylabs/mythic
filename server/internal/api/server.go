// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package api wires the HTTP surface of mythicd: challenge issuance,
// solution verification, JWKS, and health — behind shared middleware.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xeylabs/mythic/server/internal/challenge"
	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
	"github.com/xeylabs/mythic/server/internal/store"
	"github.com/xeylabs/mythic/server/xtoken"
)

// Config carries deployment settings into the API layer.
type Config struct {
	Sites        []string // site-key allowlist; empty = accept any (dev mode)
	CORSOrigins  []string // empty = allow all origins on /v1 (no credentials are involved)
	TokenTTL     time.Duration
	ChallengeTTL time.Duration
	IPWindow     time.Duration
	IPLimit      int64
	// TrustProxy opts into honoring X-Forwarded-For. The header is
	// client-controlled; trusting it blindly lets anyone rotate fake IPs and
	// bypass per-IP rate limits and risk pressure (ADR-0005). Enable only
	// behind a proxy that overwrites the header.
	TrustProxy bool
}

type Server struct {
	cfg Config
	km  *crypto.KeyManager
	st  store.Store
	eng *risk.Engine
	log *slog.Logger
	asn *ASNLookup // nil = ASN signal disabled (ADR-0010)
}

func New(cfg Config, km *crypto.KeyManager, st store.Store, eng *risk.Engine, log *slog.Logger) *Server {
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 5 * time.Minute
	}
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = 3 * time.Minute
	}
	if cfg.IPWindow == 0 {
		cfg.IPWindow = time.Minute
	}
	if cfg.IPLimit == 0 {
		cfg.IPLimit = 120
	}
	// ADR-0002's contract: a decision token never outlives the challenge it
	// came from. Nothing enforced it before — a red-team session issued a
	// 1-hour token from a 5-second challenge. Clamp, visibly.
	if cfg.TokenTTL > cfg.ChallengeTTL {
		log.Warn("token TTL exceeds challenge TTL; clamping to the challenge TTL (ADR-0002)",
			"token_ttl", cfg.TokenTTL.String(), "challenge_ttl", cfg.ChallengeTTL.String())
		cfg.TokenTTL = cfg.ChallengeTTL
	}
	return &Server{cfg: cfg, km: km, st: st, eng: eng, log: log}
}

// WithASNLookup attaches an ASN resolver for the ADR-0010 network signal.
// Nil disables the signal. Returns the server for chaining.
func (s *Server) WithASNLookup(a *ASNLookup) *Server {
	s.asn = a
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	// Every /v1 request counts against the caller's budget BEFORE any
	// validation (red-team G1): otherwise invalid-JSON and unknown-site-key
	// floods were an unthrottled CPU/log amplifier. healthz stays open for
	// load balancers.
	mux.Handle("GET /v1/.well-known/jwks.json", s.ipLimit(http.HandlerFunc(s.handleJWKS)))
	mux.Handle("POST /v1/challenge", s.ipLimit(http.HandlerFunc(s.handleChallenge)))
	mux.Handle("POST /v1/verify", s.ipLimit(http.HandlerFunc(s.handleVerify)))
	return s.middleware(mux)
}

// attemptsCtxKey carries the caller's pressure count from the limiter into
// the handlers without counting twice.
type attemptsCtxKey struct{}

// ipLimit counts the request against the aggregated identity budget and
// rejects it once the limit is exceeded. The count feeds the risk engine's
// pressure signal downstream via the request context.
func (s *Server) ipLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, s.cfg.TrustProxy)
		attempts, err := s.st.IncrIP(limiterKey(ip), s.cfg.IPWindow, s.cfg.IPLimit+1)
		if err != nil {
			// Fail closed (ADR-0009): a store outage must not issue
			// challenges or tokens from uncounted requests.
			s.log.Error("store unavailable", "err", err)
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "state store is unreachable")
			return
		}
		if attempts > s.cfg.IPLimit {
			w.Header().Set("Retry-After", "30")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
			return
		}
		ctx := context.WithValue(r.Context(), attemptsCtxKey{}, attempts)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func attemptsFrom(r *http.Request) int64 {
	if v, ok := r.Context().Value(attemptsCtxKey{}).(int64); ok {
		return v
	}
	return 1 // direct handler invocation (tests); no pressure signal
}

// --- handlers -------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	// ADR-0006: the active key first, then retired keys — origins select the
	// verification key by the kid claimed inside the token.
	writeJSON(w, http.StatusOK, map[string]any{"keys": s.km.PublicJWKS()})
}

type challengeRequest struct {
	SiteKey string         `json:"site_key"`
	Hints   map[string]any `json:"hints,omitempty"` // advisory; see ADR-0004
}

type challengeResponse struct {
	Challenge *challenge.Challenge `json:"challenge"`
	Decision  string               `json:"decision"`
	Risk      int                  `json:"risk"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if !s.siteAllowed(req.SiteKey) {
		writeError(w, http.StatusBadRequest, "unknown_site_key", "site key is not registered")
		return
	}

	ip := clientIP(r, s.cfg.TrustProxy)
	attempts := attemptsFrom(r)

	res := s.eng.Evaluate(risk.Input{
		IP:             limiterKey(ip),
		SiteKey:        req.SiteKey,
		Attempts:       attempts,
		ClientSignals:  req.Hints,
		JA4Fingerprint: ja4From(r, s.cfg.TrustProxy),
		ASN:            s.asn.ASN(ip),
		Behavior:       behaviorFrom(req.Hints),
	})
	if res.Decision == risk.Deny {
		writeJSON(w, http.StatusForbidden, map[string]any{"decision": string(res.Decision), "risk": res.Score})
		return
	}

	ch := &challenge.Challenge{
		ID:         crypto.NewID(),
		SiteKey:    req.SiteKey,
		Salt:       crypto.NewID(),
		Difficulty: res.Difficulty,
		Algorithm:  challenge.Algorithm,
		ExpiresAt:  time.Now().Add(s.cfg.ChallengeTTL).Unix(),
	}
	if err := s.st.Put(ch, time.Now()); err != nil {
		s.log.Error("store unavailable", "err", err)
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "state store is unreachable")
		return
	}
	s.log.Debug("challenge issued", "ip", ip, "site", req.SiteKey, "difficulty", ch.Difficulty, "score", res.Score)
	writeJSON(w, http.StatusOK, challengeResponse{Challenge: ch, Decision: string(res.Decision), Risk: res.Score})
}

type verifyRequest struct {
	ChallengeID string         `json:"challenge_id"`
	Nonce       string         `json:"nonce"`
	Hints       map[string]any `json:"hints,omitempty"`
}

type verifyResponse struct {
	Token    string `json:"token"`
	Decision string `json:"decision"`
	Risk     int    `json:"risk"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}

	ip := clientIP(r, s.cfg.TrustProxy)
	attempts := attemptsFrom(r)

	// Single-use consumption happens before validation: a replayed or expired
	// id burns itself either way.
	ch, issuedAt, ok, err := s.st.Take(req.ChallengeID)
	if err != nil {
		s.log.Error("store unavailable", "err", err)
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "state store is unreachable")
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown_challenge", "challenge was not issued here or was already redeemed")
		return
	}
	if time.Now().Unix() > ch.ExpiresAt {
		writeError(w, http.StatusGone, "challenge_expired", "challenge expired before redemption")
		return
	}
	if !challenge.MeetsDifficulty(challenge.Digest(ch.ID, ch.Salt, req.Nonce), ch.Difficulty) {
		writeError(w, http.StatusBadRequest, "invalid_solution", "solution does not meet the difficulty target")
		return
	}

	res := s.eng.Evaluate(risk.Input{
		IP:             limiterKey(ip),
		SiteKey:        ch.SiteKey,
		Attempts:       attempts,
		SolveMillis:    time.Since(issuedAt).Milliseconds(),
		Difficulty:     ch.Difficulty,
		ClientSignals:  req.Hints,
		JA4Fingerprint: ja4From(r, s.cfg.TrustProxy),
		ASN:            s.asn.ASN(ip),
		Behavior:       behaviorFrom(req.Hints),
	})
	if res.Decision == risk.Deny {
		writeJSON(w, http.StatusForbidden, map[string]any{"decision": string(res.Decision), "risk": res.Score})
		return
	}

	token, err := crypto.SignToken(s.km, xtoken.TokenClaims{
		SiteKey:  ch.SiteKey,
		Decision: xtoken.Decision(res.Decision),
		Risk:     res.Score,
	}, s.cfg.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_failed", "could not sign decision token")
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Token: token, Decision: string(res.Decision), Risk: res.Score})
}

func (s *Server) siteAllowed(siteKey string) bool {
	if len(s.cfg.Sites) == 0 {
		return siteKey != "" // dev mode: any non-empty key
	}
	for _, allowed := range s.cfg.Sites {
		if siteKey == allowed {
			return true
		}
	}
	return false
}

// --- helpers ---------------------------------------------------------------

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Strict parsing: trailing bytes after the first JSON value are rejected,
	// not silently ignored (red-team G5).
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing data after JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

// clientIP derives the client address. X-Forwarded-For is honored ONLY when
// the operator explicitly opts in via TrustProxy — the header is
// client-controlled, and blind trust made it a free rate-limit and
// risk-pressure bypass (found by adversarial testing, fixed per ADR-0005).
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ja4From extracts the JA4 TLS fingerprint injected by the trusted reverse
// proxy (ADR-0010). The header is attacker-controlled input — it is only
// honored when TrustProxy is true, i.e. the operator has asserted the proxy
// overwrites it (same trust gate as X-Forwarded-For, ADR-0005). Otherwise
// it is ignored entirely: an empty fingerprint scores nothing.
func ja4From(r *http.Request, trustProxy bool) string {
	if !trustProxy {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-Mythic-JA4"))
}

// behaviorFrom extracts privacy-preserving behavioral features from the
// client's hints map (ADR-0011). Returns nil if absent or malformed —
// absent data scores nothing, not a penalty. Type-safe: wrong types are
// ignored, never crash.
func behaviorFrom(hints map[string]any) *risk.BehavioralFeatures {
	if hints == nil {
		return nil
	}
	raw, ok := hints["behavioral"].(map[string]any)
	if !ok {
		return nil
	}
	b := &risk.BehavioralFeatures{}
	// Extract each field with type assertion; wrong types → zero value.
	if v, ok := raw["mouse_points"].(float64); ok {
		b.MousePoints = int(v)
	}
	if v, ok := raw["mouse_mean_v"].(float64); ok {
		b.MouseMeanV = v
	}
	if v, ok := raw["mouse_var_v"].(float64); ok {
		b.MouseVarV = v
	}
	if v, ok := raw["mouse_dir_changes"].(float64); ok {
		b.MouseDirChanges = int(v)
	}
	if v, ok := raw["mouse_curvature"].(float64); ok {
		b.MouseCurvature = v
	}
	if v, ok := raw["key_dwells"].(float64); ok {
		b.KeyDwells = int(v)
	}
	if v, ok := raw["key_mean_dwell"].(float64); ok {
		b.KeyMeanDwell = v
	}
	if v, ok := raw["key_mean_flight"].(float64); ok {
		b.KeyMeanFlight = v
	}
	if v, ok := raw["scroll_events"].(float64); ok {
		b.ScrollEvents = int(v)
	}
	if v, ok := raw["scroll_reversals"].(float64); ok {
		b.ScrollReversals = int(v)
	}
	return b
}

// limiterKey aggregates a client address to the identity the limiter and
// pressure counters key on (ADR-0007): IPv4 stays /32, IPv6 collapses to its
// /64 prefix — the smallest block an ISP delegates to one line. Keyed at
// /128, a single /64 holder controlled 2^64 limiter identities and rotated
// past the rate limit at will (red-team finding, 2026-09-29). Access logs
// keep the full address; only the counter key is aggregated.
func limiterKey(host string) string {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return host
	}
	v6 := ip.To16()
	prefix := make([]byte, 16) // net.IP renders only the 4- and 16-byte forms
	copy(prefix, v6[:8])
	return net.IP(prefix).String() + "/64"
}

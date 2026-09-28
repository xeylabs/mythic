// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package api wires the HTTP surface of mythicd: challenge issuance,
// solution verification, JWKS, and health — behind shared middleware.
package api

import (
	"encoding/json"
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
	return &Server{cfg: cfg, km: km, st: st, eng: eng, log: log}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("POST /v1/challenge", s.handleChallenge)
	mux.HandleFunc("POST /v1/verify", s.handleVerify)
	return s.middleware(mux)
}

// --- handlers -------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{s.km.PublicKeyJWK()}})
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
	attempts := s.st.IncrIP(ip, s.cfg.IPWindow)
	if attempts > s.cfg.IPLimit {
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}

	res := s.eng.Evaluate(risk.Input{
		IP:            ip,
		SiteKey:       req.SiteKey,
		Attempts:      attempts,
		ClientSignals: req.Hints,
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
	s.st.Put(ch, time.Now())
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
	attempts := s.st.IncrIP(ip, s.cfg.IPWindow)

	// Single-use consumption happens before validation: a replayed or expired
	// id burns itself either way.
	ch, issuedAt, ok := s.st.Take(req.ChallengeID)
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
		IP:            ip,
		SiteKey:       ch.SiteKey,
		Attempts:      attempts,
		SolveMillis:   time.Since(issuedAt).Milliseconds(),
		Difficulty:    ch.Difficulty,
		ClientSignals: req.Hints,
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

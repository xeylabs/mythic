// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/xeylabs/mythic/server/internal/crypto"
)

// statusRecorder captures the response status for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

type middleware func(http.Handler) http.Handler

// middleware applies, outermost first: request id, recovery, access logging,
// CORS.
func (s *Server) middleware(next http.Handler) http.Handler {
	h := cors(s.cfg.CORSOrigins)(next)
	h = s.logRequests()(h)
	h = recoverPanics(s.log)(h)
	return requestID(h)
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", crypto.NewID())
		next.ServeHTTP(w, r)
	})
}

func recoverPanics(log *slog.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if p := recover(); p != nil {
					log.Error("panic recovered", "path", r.URL.Path, "panic", p)
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) logRequests() middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			s.log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"dur_ms", time.Since(start).Milliseconds(),
				"ip", clientIP(r, s.cfg.TrustProxy),
			)
		})
	}
}

// cors sets CORS headers. With no configured origins it allows any origin on
// the public /v1 surface — the API never uses cookies or credentials, so the
// ambient-authority CSRF class does not apply. Restrict origins in production
// via MYTHIC_CORS_ORIGINS (see SECURITY.md).
func cors(allowed []string) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && originAllowed(origin, allowed) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if origin == a {
			return true
		}
	}
	return false
}

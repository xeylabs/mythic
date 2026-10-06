// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api

import (
	"log/slog"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// ASNLookup resolves client IPs to autonomous system numbers via a
// MaxMind GeoLite2-ASN database (ADR-0010). Nil-safe: a nil lookup
// (no database configured) returns 0 for every IP — signal disabled,
// not an error.
type ASNLookup struct {
	db  *geoip2.Reader
	log *slog.Logger
}

// NewASNLookup opens the MaxMind database at path. Empty path returns
// (nil, nil) — the ASN signal is disabled, which is valid. A non-empty
// path that fails to open returns an error: an operator who configured
// a database expects it to work (fail-closed on misconfiguration, not
// silent degradation).
func NewASNLookup(path string, log *slog.Logger) (*ASNLookup, error) {
	if path == "" {
		return nil, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	log.Info("asn database loaded", "path", path)
	return &ASNLookup{db: db, log: log}, nil
}

// ASN returns the autonomous system number for ip, or 0 if unknown.
// Never panics, never errors — unknown is a valid signal state.
func (a *ASNLookup) ASN(ip string) uint {
	if a == nil || a.db == nil {
		return 0
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	record, err := a.db.ASN(parsed)
	if err != nil {
		return 0
	}
	return uint(record.AutonomousSystemNumber)
}

// Close releases the database handle. Safe on nil receiver.
func (a *ASNLookup) Close() error {
	if a == nil || a.db == nil {
		return nil
	}
	return a.db.Close()
}

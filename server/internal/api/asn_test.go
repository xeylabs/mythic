// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/xeylabs/mythic/server/internal/api"
)

// TestASNLookupNilSafe: nil lookup returns 0, never panics.
func TestASNLookupNilSafe(t *testing.T) {
	var a *api.ASNLookup
	if got := a.ASN("1.2.3.4"); got != 0 {
		t.Fatalf("nil lookup must return 0, got %d", got)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("nil close must not error: %v", err)
	}
}

// TestASNLookupEmptyPath: empty path = disabled, not an error.
func TestASNLookupEmptyPath(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := api.NewASNLookup("", log)
	if err != nil {
		t.Fatalf("empty path must not error: %v", err)
	}
	if a != nil {
		t.Fatal("empty path must return nil lookup")
	}
}

// TestASNLookupBadPath: non-empty bad path = error (fail-closed).
func TestASNLookupBadPath(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := api.NewASNLookup("/nonexistent/path.mmdb", log)
	if err == nil {
		t.Fatal("bad path must return error (fail-closed on misconfiguration)")
	}
}

// TestASNLookupInvalidIP: invalid IP returns 0, never panics.
func TestASNLookupInvalidIP(t *testing.T) {
	var a *api.ASNLookup
	for _, ip := range []string{"", "not-an-ip", "999.999.999.999"} {
		if got := a.ASN(ip); got != 0 {
			t.Fatalf("invalid IP %q must return 0, got %d", ip, got)
		}
	}
}

// TestASNLookupPositive: real database lookups return the mapped ASNs.
// Fixture testdata/test-asn.mmdb is synthetic and generated in-repo
// (see testdata/README.md) — never a licensed MaxMind database.
func TestASNLookupPositive(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := api.NewASNLookup("testdata/test-asn.mmdb", log)
	if err != nil {
		t.Fatalf("open fixture database: %v", err)
	}
	defer a.Close()

	cases := []struct {
		ip   string
		want uint
	}{
		{"8.8.8.8", 15169},      // mapped /24
		{"8.8.8.200", 15169},    // same /24, different host
		{"1.1.1.1", 13335},      // mapped /24
		{"2001:4860::1", 15169}, // mapped IPv6 /32
		{"9.9.9.9", 0},          // not in fixture -> unknown
		{"192.0.2.1", 0},        // not in fixture -> unknown
	}
	for _, tc := range cases {
		if got := a.ASN(tc.ip); got != tc.want {
			t.Errorf("ASN(%q) = %d, want %d", tc.ip, got, tc.want)
		}
	}
}

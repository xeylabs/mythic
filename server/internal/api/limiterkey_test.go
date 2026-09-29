// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api

// Regression tests for red-team finding F3 (2026-09-29): the per-IP limiter
// keyed at /128 let one IPv6 /64 mint 2^64 identities. limiterKey aggregates
// to /64 (ADR-0007); these tests pin the aggregation.

import (
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/store"
)

func TestLimiterKeyAggregatesIPv6ToSlash64(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		// Two addresses in one /64 are ONE limiter identity.
		{"2001:db8:aaaa:bbbb::1", "2001:db8:aaaa:bbbb::/64"},
		{"2001:db8:aaaa:bbbb:dead:beef:cafe:0", "2001:db8:aaaa:bbbb::/64"},
		{"::1", "::/64"},
		// Different /64s stay distinct.
		{"2001:db8:aaaa:cccc::1", "2001:db8:aaaa:cccc::/64"},
		// IPv4 — including IPv4-mapped forms — stays /32.
		{"1.2.3.4", "1.2.3.4"},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4"},
		// Unparseable garbage passes through untouched (upstream rejects it anyway).
		{"not-an-ip", "not-an-ip"},
	}
	for _, c := range cases {
		if got := limiterKey(c.host); got != c.want {
			t.Errorf("limiterKey(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestLimiterKeySlash64CannotRotateIdentities(t *testing.T) {
	// The red-team PoC, now as a regression test: 5,000 requests from one
	// /64 must all land on ONE counter.
	st := store.NewMemory(time.Minute)
	t.Cleanup(st.Close)

	host := func(i int) string { return "2001:db8:aaaa:bbbb::" + hexByte(byte(i%251)) + hexByte(byte(i/251)) }
	for i := 0; i < 5_000; i++ {
		if _, err := st.IncrIP(limiterKey(host(i)), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := st.IncrIP(limiterKey(host(9999)), time.Minute); n != 5_001 {
		t.Fatalf("the whole /64 must share a single counter; got count %d", n)
	}
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}

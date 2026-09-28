// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package challenge_test

import (
	"testing"

	"github.com/xeylabs/xprotect/server/internal/challenge"
)

func TestLeadingZeroBits(t *testing.T) {
	// Digests are always 32 bytes; pad cases so trailing bytes are explicit.
	pad := func(first ...byte) [32]byte {
		var sum [32]byte
		for i, b := range first {
			sum[i] = b
		}
		for i := len(first); i < 32; i++ {
			sum[i] = 0xff
		}
		return sum
	}

	if got := challenge.LeadingZeroBits([32]byte{}); got != 256 {
		t.Fatalf("all-zero digest = %d, want 256", got)
	}
	cases := []struct {
		in   [32]byte
		want int
	}{
		{pad(0xff), 0},
		{pad(0b1000_0000), 0},
		{pad(0b0100_0000), 1},
		{pad(0b0010_0000), 2},
		{pad(0b0000_0100), 5},
		{pad(0x00, 0x01), 15},
		{pad(0x00, 0x00, 0x01), 23},
	}
	for _, c := range cases {
		if got := challenge.LeadingZeroBits(c.in); got != c.want {
			t.Fatalf("LeadingZeroBits(% x…) = %d, want %d", c.in[:3], got, c.want)
		}
	}
}

func TestMeetsDifficultyBoundary(t *testing.T) {
	var sum [32]byte
	sum[0] = 0b1111_1111
	if challenge.MeetsDifficulty(sum, 1) {
		t.Fatal("0xff… must not meet difficulty 1")
	}
	sum[0] = 0
	if !challenge.MeetsDifficulty(sum, 8) {
		t.Fatal("0x00… must meet difficulty 8")
	}
	if !challenge.MeetsDifficulty(sum, 0) {
		t.Fatal("everything meets difficulty 0")
	}
}

func TestSolveProducesValidNonce(t *testing.T) {
	ch := &challenge.Challenge{ID: "id", Salt: "salt", Difficulty: 10}
	nonce, ok := challenge.Solve(ch, 1<<20)
	if !ok {
		t.Fatal("no nonce found for difficulty 10 within 2^20 tries")
	}
	if !challenge.MeetsDifficulty(challenge.Digest(ch.ID, ch.Salt, nonce), ch.Difficulty) {
		t.Fatalf("solver returned a nonce that does not verify: %q", nonce)
	}
}

func TestMinPlausibleSolveMillis(t *testing.T) {
	cases := map[int]int64{
		0:  0,
		12: 81,   // 4096 * 1000 / 50000
		18: 5242, // 262144 * 1000 / 50000
	}
	for d, want := range cases {
		if got := challenge.MinPlausibleSolveMillis(d); got != want {
			t.Fatalf("MinPlausibleSolveMillis(%d) = %d, want %d", d, got, want)
		}
	}
}

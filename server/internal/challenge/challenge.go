// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package challenge

import (
	"crypto/sha256"
	"strconv"
)

// Algorithm is the only PoW algorithm v0 speaks.
const Algorithm = "sha256"

// OptimisticHashRate models the fastest plausible honest browser worker
// (hashes/second). Red-team measurement (2026-09-29): real crypto.subtle
// workers run ~400k–1.5M H/s, so the original 50k model flagged honest
// clients as implausible. We model the top of the honest range, then divide.
const OptimisticHashRate = 2_000_000

// FloorSafetyDivisor moves the plausibility floor to a low quantile of
// honest solve time (ADR-0008). Solve time is geometrically distributed, so
// ANY floor catches some honest solves: at ÷32, even a client 2× faster than
// the modeled worker is flagged ≤ ~6% of the time, while GPU-class clients
// (~100× a worker — the case the floor exists for) trip it ~96% of the time.
// What no floor can do: catch a client that solves instantly and DELAYS the
// verify. That is M2's job (behavioral signals), never wall-clock time.
const FloorSafetyDivisor = 32

// Challenge is issued to a client and must be solved exactly once.
type Challenge struct {
	ID         string `json:"id"`
	SiteKey    string `json:"site_key"`
	Salt       string `json:"salt"`
	Difficulty int    `json:"difficulty"` // required leading zero bits
	Algorithm  string `json:"algorithm"`
	ExpiresAt  int64  `json:"expires_at"` // unix seconds
}

// Solution is a client's answer to a challenge.
type Solution struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
}

// Digest is the value a client must grind: SHA-256("id:salt:nonce").
func Digest(id, salt, nonce string) [sha256.Size]byte {
	return sha256.Sum256([]byte(id + ":" + salt + ":" + nonce))
}

// LeadingZeroBits counts the leading zero bits of a digest.
func LeadingZeroBits(sum [sha256.Size]byte) int {
	n := 0
	for _, b := range sum {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) != 0 {
				return n
			}
			n++
		}
	}
	return n
}

// MeetsDifficulty reports whether sum starts with at least n zero bits.
func MeetsDifficulty(sum [sha256.Size]byte, n int) bool {
	return LeadingZeroBits(sum) >= n
}

// MinPlausibleSolveMillis estimates the fastest solve time an honest browser
// worker could realistically achieve at the given difficulty — a low
// quantile of the honest distribution, not its mean (ADR-0008).
// Server-measured solve times below this floor are scored as implausible by
// the risk engine. At low difficulties the floor truncates to zero by integer
// division: where PoW is not real work, the floor has nothing to say.
func MinPlausibleSolveMillis(difficulty int) int64 {
	if difficulty <= 0 {
		return 0
	}
	if difficulty > 30 {
		difficulty = 30
	}
	hashes := uint64(1) << difficulty
	return int64(hashes * 1_000 / (OptimisticHashRate * FloorSafetyDivisor))
}

// Solve grinds a nonce for the challenge. It is exported for tests and
// tooling; production clients use the JS SDK. Returns ok=false after maxIter.
func Solve(ch *Challenge, maxIter uint64) (nonce string, ok bool) {
	for i := uint64(0); i < maxIter; i++ {
		n := strconv.FormatUint(i, 16)
		if MeetsDifficulty(Digest(ch.ID, ch.Salt, n), ch.Difficulty) {
			return n, true
		}
	}
	return "", false
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package challenge

import (
	"crypto/sha256"
	"strconv"
)

// Algorithm is the only PoW algorithm v0 speaks.
const Algorithm = "sha256"

// OptimisticHashRate is the client hash rate (hashes/second) used to derive
// the plausible minimum solve time for a difficulty. It intentionally models
// a fast browser Web Worker, not a GPU.
const OptimisticHashRate = 50_000

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

// MinPlausibleSolveMillis estimates the fastest solve time a legitimate
// browser worker could achieve at the given difficulty. Server-measured solve
// times below this floor are scored as implausible by the risk engine.
func MinPlausibleSolveMillis(difficulty int) int64 {
	if difficulty <= 0 {
		return 0
	}
	if difficulty > 30 {
		difficulty = 30
	}
	hashes := uint64(1) << difficulty
	return int64(hashes * 1_000 / OptimisticHashRate)
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

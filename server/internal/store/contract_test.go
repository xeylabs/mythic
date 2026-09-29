// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package store_test

// The shared contract suite (ADR-0009): every backend must pass the same
// tests, so memory and Redis cannot drift apart. Redis semantics are pinned
// against miniredis — a real wire-compatible server, in-process.

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/xeylabs/mythic/server/internal/challenge"
	"github.com/xeylabs/mythic/server/internal/store"
)

func newBackends(t *testing.T) map[string]store.Store {
	t.Helper()
	mr := miniredis.RunT(t)
	rs, err := store.NewRedis(mr.Addr(), "", 0, time.Minute)
	if err != nil {
		t.Fatalf("redis backend must start against miniredis: %v", err)
	}
	t.Cleanup(rs.Close)
	return map[string]store.Store{
		"memory": store.NewMemory(time.Minute),
		"redis":  rs,
	}
}

func TestContractChallengeRoundTripAndSingleUse(t *testing.T) {
	for name, st := range newBackends(t) {
		t.Run(name, func(t *testing.T) {
			ch := &challenge.Challenge{ID: "id-" + name, SiteKey: "s", Salt: "salt", Difficulty: 18, Algorithm: "sha256"}
			issued := time.Now()

			if _, _, ok, _ := st.Take(ch.ID); ok {
				t.Fatal("unknown id must not take")
			}
			if err := st.Put(ch, issued); err != nil {
				t.Fatalf("put: %v", err)
			}
			got, at, ok, err := st.Get(ch.ID)
			if err != nil || !ok {
				t.Fatalf("get after put: ok=%v err=%v", ok, err)
			}
			if got.ID != ch.ID || got.Salt != ch.Salt || got.Difficulty != ch.Difficulty {
				t.Fatalf("round trip changed the challenge: %+v", got)
			}
			if !at.Equal(issued) {
				t.Fatalf("issuedAt not preserved: %v != %v", at, issued)
			}
			// Single-use: exactly one Take wins, the second finds nothing.
			taken, _, ok, err := st.Take(ch.ID)
			if err != nil || !ok || taken.ID != ch.ID {
				t.Fatalf("first take must win: ok=%v err=%v", ok, err)
			}
			if _, _, ok, _ := st.Take(ch.ID); ok {
				t.Fatal("replay must find nothing — single-use is the anti-replay property")
			}
			if _, _, ok, _ := st.Get(ch.ID); ok {
				t.Fatal("consumed challenge must be gone for reads too")
			}
		})
	}
}

func TestContractChallengeExpiry(t *testing.T) {
	// miniredis runs on its own clock — real sleeps do not advance its
	// expiries, FastForward does. Each backend advances time its own way;
	// the contract being pinned is identical: an expired challenge is
	// unredeemable everywhere.
	mr := miniredis.RunT(t)
	rs, err := store.NewRedis(mr.Addr(), "", 0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rs.Close)
	mem := store.NewMemory(time.Second)
	t.Cleanup(mem.Close)

	t.Run("memory", func(t *testing.T) {
		ch := &challenge.Challenge{ID: "exp-memory", SiteKey: "s", Salt: "salt", Difficulty: 8}
		if err := mem.Put(ch, time.Now()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1300 * time.Millisecond)
		if _, _, ok, _ := mem.Take(ch.ID); ok {
			t.Fatal("expired challenge must not redeem on memory")
		}
	})

	t.Run("redis", func(t *testing.T) {
		ch := &challenge.Challenge{ID: "exp-redis", SiteKey: "s", Salt: "salt", Difficulty: 8}
		if err := rs.Put(ch, time.Now()); err != nil {
			t.Fatal(err)
		}
		mr.FastForward(2 * time.Second)
		if _, _, ok, _ := rs.Take(ch.ID); ok {
			t.Fatal("expired challenge must not redeem on redis")
		}
	})
}

func TestContractSlidingWindowCounter(t *testing.T) {
	for name, st := range newBackends(t) {
		t.Run(name, func(t *testing.T) {
			const window = 200 * time.Millisecond
			// 5 hits land immediately.
			for i := 0; i < 5; i++ {
				n, err := st.IncrIP("a:"+name, window, 1<<20)
				if err != nil {
					t.Fatalf("incr: %v", err)
				}
				if n != int64(i+1) {
					t.Fatalf("hit %d counted as %d", i+1, n)
				}
			}
			// Sliding semantics: after the window passes, the count resets —
			// a client timed to a window boundary cannot double its burst
			// (the fixed-window flaw this replaces).
			time.Sleep(window + 50*time.Millisecond)
			if n, _ := st.IncrIP("a:"+name, window, 1<<20); n != 1 {
				t.Fatalf("count after window must reset to 1, got %d", n)
			}
			// Different identities count independently.
			if n, _ := st.IncrIP("b:"+name, window, 1<<20); n != 1 {
				t.Fatalf("independent identity must start at 1, got %d", n)
			}
		})
	}
}

// Red-team H1: a saturated identity must report "still over" without
// growing its stored history — the flood pays nothing in memory or CPU.
func TestContractCounterSaturatesInsteadOfGrowing(t *testing.T) {
	for name, st := range newBackends(t) {
		t.Run(name, func(t *testing.T) {
			const window = time.Minute
			const cap0 = int64(10)
			for i := int64(1); i <= cap0; i++ {
				n, err := st.IncrIP("sat:"+name, window, cap0)
				if err != nil {
					t.Fatalf("incr: %v", err)
				}
				if n != i {
					t.Fatalf("hit %d counted as %d", i, n)
				}
			}
			// Hammer past the cap: the count must never drop back to
			// "under the limit" while hits keep landing inside the window.
			// The stored history caps at maxHits, and as old members age out
			// the count may dip to exactly maxHits — still over the limit,
			// still a 429 — but never below. (miniredis interprets Lua per
			// call, so the redis subtest hammers a handful; the property —
			// and the Lua-side cap itself — is identical.)
			extra := 100_000
			if name == "redis" {
				extra = 20
			}
			for i := 0; i < extra; i++ {
				n, err := st.IncrIP("sat:"+name, window, cap0)
				if err != nil {
					t.Fatalf("incr: %v", err)
				}
				if n < cap0 {
					t.Fatalf("saturated identity must never count below %d inside the window, got %d at extra hit %d", cap0, n, i)
				}
			}
			// Once the window slides past the stored hits, counting resumes.
			time.Sleep(50 * time.Millisecond)
			if n, _ := st.IncrIP("sat-fresh:"+name, 10*time.Millisecond, cap0); n != 1 {
				t.Fatalf("fresh window must count from 1 again, got %d", n)
			}
		})
	}
}

func TestContractRedisFailsClosedWhenServerDies(t *testing.T) {
	mr := miniredis.RunT(t)
	rs, err := store.NewRedis(mr.Addr(), "", 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rs.Close)

	mr.Close() // the "outage"

	if _, err := rs.IncrIP("x", time.Minute, 1<<20); err == nil {
		t.Fatal("counter must report the outage, not swallow it (fail closed)")
	}
	if err := rs.Put(&challenge.Challenge{ID: "x"}, time.Now()); err == nil {
		t.Fatal("put must report the outage, not swallow it")
	}
	if _, _, _, err := rs.Take("x"); err == nil {
		t.Fatal("take must report the outage, not swallow it")
	}
}

func TestNewRedisRefusesUnreachableServer(t *testing.T) {
	if _, err := store.NewRedis("127.0.0.1:1", "", 0, time.Minute); err == nil {
		t.Fatal("unreachable Redis must refuse startup (fail closed, ADR-0009)")
	}
}

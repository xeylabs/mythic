// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Redis backend of the store contract (ADR-0009): single-use challenges via
// GETDEL, sliding-window pressure counters via a sorted set pruned by one
// Lua script. Multi-node mythicd points every node at the same Redis.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/xeylabs/mythic/server/internal/challenge"
)

// storedChallenge is the JSON payload of one challenge record: the challenge
// plus the issue time the solve-time plausibility check needs.
type storedChallenge struct {
	Ch       challenge.Challenge `json:"ch"`
	IssuedAt int64               `json:"issued_at"` // unix nanos
}

const (
	chKeyPrefix = "mythic:ch:"
	ipKeyPrefix = "mythic:ip:"

	// slidingIncr prunes the window, counts what remains, records this hit
	// and refreshes the key TTL — atomically. ARGV[4] caps the stored
	// history: a saturated identity (red-team H1) returns maxHits+1 without
	// ZADDing, so a flood cannot grow the ZSET (shared Redis memory) or the
	// per-call prune cost.
	// KEYS[1] = counter key; ARGV[1] = now ms, ARGV[2] = window ms,
	// ARGV[3] = unique member, ARGV[4] = maxHits.
	slidingIncr = `
local n = redis.call('ZCARD', KEYS[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[2]))
n = redis.call('ZCARD', KEYS[1])
if n >= tonumber(ARGV[4]) then
  return n + 1
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return n + 1`
)

// Redis is the multi-node Store implementation.
type Redis struct {
	rdb    *redis.Client
	ttl    time.Duration
	hitSeq atomic.Uint64
}

// NewRedis builds a Redis-backed store. It pings the server: an unreachable
// Redis refuses startup — fail closed, per ADR-0009.
func NewRedis(addr, password string, db int, ttl time.Duration) (*Redis, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("store: redis at %s is unreachable: %w", addr, err)
	}
	return &Redis{rdb: rdb, ttl: ttl}, nil
}

func (s *Redis) Close() { _ = s.rdb.Close() }

// Put stores a challenge with the challenge TTL. A store error propagates:
// an unrecorded challenge can never be redeemed, so the caller must fail
// the request instead of pretending it was issued.
func (s *Redis) Put(ch *challenge.Challenge, issuedAt time.Time) error {
	blob, err := json.Marshal(storedChallenge{Ch: *ch, IssuedAt: issuedAt.UnixNano()})
	if err != nil {
		return fmt.Errorf("store: encode challenge: %w", err)
	}
	return s.rdb.Set(context.Background(), chKeyPrefix+ch.ID, blob, s.ttl).Err()
}

func (s *Redis) Get(id string) (*challenge.Challenge, time.Time, bool, error) {
	blob, err := s.rdb.Get(context.Background(), chKeyPrefix+id).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, time.Time{}, false, nil
		}
		return nil, time.Time{}, false, fmt.Errorf("store: get challenge: %w", err)
	}
	return decodeStored(blob)
}

// Take is GETDEL: atomic single-use. A replayed id finds nothing — which is
// what makes replay useless.
func (s *Redis) Take(id string) (*challenge.Challenge, time.Time, bool, error) {
	blob, err := s.rdb.GetDel(context.Background(), chKeyPrefix+id).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, time.Time{}, false, nil
		}
		return nil, time.Time{}, false, fmt.Errorf("store: take challenge: %w", err)
	}
	return decodeStored(blob)
}

func decodeStored(blob []byte) (*challenge.Challenge, time.Time, bool, error) {
	var sc storedChallenge
	if err := json.Unmarshal(blob, &sc); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("store: decode challenge: %w", err)
	}
	ch := sc.Ch
	return &ch, time.Unix(0, sc.IssuedAt), true, nil
}

// IncrIP records a hit in the identity's sliding window and returns the
// count including it — the same semantics the memory store implements.
// A Redis error propagates: uncounted pressure must not silently pass.
func (s *Redis) IncrIP(ip string, window time.Duration, maxHits int64) (int64, error) {
	now := time.Now()
	res := s.rdb.Eval(context.Background(), slidingIncr, []string{ipKeyPrefix + ip},
		now.UnixMilli(), window.Milliseconds(),
		fmt.Sprintf("%d:%d", now.UnixNano(), s.hitSeq.Add(1)), maxHits)
	n, err := res.Int64()
	if err != nil {
		return 0, fmt.Errorf("store: sliding-window increment: %w", err)
	}
	return n, nil
}

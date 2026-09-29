// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package store persists issued challenges (single-use) and per-identity
// request counters. Two backends implement the same contract: Memory (the
// zero-deploy single-node default) and Redis (multi-node, ADR-0009). A
// shared contract suite pins the semantics so the backends cannot drift.
//
// Backends report errors instead of swallowing them: mythicd fails CLOSED —
// a verifier that cannot reach its store must not issue tokens.
package store

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/xeylabs/mythic/server/internal/challenge"
)

type record struct {
	ch       *challenge.Challenge
	issuedAt time.Time
}

// Store is the persistence surface of mythicd. Counters are sliding-window
// on every backend (ADR-0009): a hit is counted inside any window of the
// given length ending now. Errors mean the backend is unavailable — callers
// fail the request, they never degrade silently.
type Store interface {
	Put(ch *challenge.Challenge, issuedAt time.Time) error
	Get(id string) (*challenge.Challenge, time.Time, bool, error)
	Take(id string) (*challenge.Challenge, time.Time, bool, error) // atomic single-use fetch+delete
	// IncrIP records a hit and returns the sliding-window count including
	// it. maxHits caps the stored history per identity: beyond it the count
	// saturates (returned as maxHits+1) instead of growing memory and CPU
	// with the flood — a caller over the limit only needs to learn it is
	// still over (red-team H1: uncapped, 429'd floods grew O(n) memory and
	// O(n²) CPU per identity).
	IncrIP(ip string, window time.Duration, maxHits int64) (int64, error)
	Close()
}

// Memory is the in-process Store implementation. Challenges expire after
// ttl; a janitor evicts expired challenges and stale counter entries.
type Memory struct {
	mu     sync.Mutex
	items  map[string]record
	hits   map[string][]time.Time // sliding window: timestamps of recent hits per identity
	hitSeq atomic.Uint64          // members must be unique even within one nanosecond
	ttl    time.Duration
	stop   chan struct{}
	done   chan struct{}
}

func NewMemory(ttl time.Duration) *Memory {
	m := &Memory{
		items: make(map[string]record),
		hits:  make(map[string][]time.Time),
		ttl:   ttl,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go m.janitor()
	return m
}

func (m *Memory) janitor() {
	defer close(m.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.evict()
		}
	}
}

func (m *Memory) evict() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, r := range m.items {
		if now.Sub(r.issuedAt) > m.ttl {
			delete(m.items, id)
		}
	}
	for ip, hits := range m.hits {
		if len(hits) == 0 || now.Sub(hits[len(hits)-1]) > time.Hour {
			delete(m.hits, ip)
		}
	}
}

// Put stores a challenge for ttl. The in-memory backend cannot fail; the
// error exists for the shared contract.
func (m *Memory) Put(ch *challenge.Challenge, issuedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[ch.ID] = record{ch: ch, issuedAt: issuedAt}
	return nil
}

func (m *Memory) Get(id string) (*challenge.Challenge, time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.items[id]
	if !ok {
		return nil, time.Time{}, false, nil
	}
	// Read-time expiry, matching the Redis backend's SET EX semantics: an
	// expired challenge is unredeemable, janitor or not.
	if time.Since(r.issuedAt) > m.ttl {
		delete(m.items, id)
		return nil, time.Time{}, false, nil
	}
	return r.ch, r.issuedAt, true, nil
}

// Take atomically consumes a challenge: a redeemed id can never be redeemed
// again, which is what makes replay useless.
func (m *Memory) Take(id string) (*challenge.Challenge, time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.items[id]
	if !ok {
		return nil, time.Time{}, false, nil
	}
	if time.Since(r.issuedAt) > m.ttl {
		delete(m.items, id)
		return nil, time.Time{}, false, nil
	}
	delete(m.items, id)
	return r.ch, r.issuedAt, true, nil
}

// IncrIP records a hit and returns the sliding-window count including it
// (ADR-0009): hits older than window no longer count, so a client timed to
// a boundary cannot double its burst.
func (m *Memory) IncrIP(ip string, window time.Duration, maxHits int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	old := m.hits[ip]
	kept := old[:0]
	for _, t := range old {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if int64(len(kept)) >= maxHits {
		// Saturated: the identity is far over the limit. Report "still over"
		// without storing — the window keeps sliding via the entries we hold.
		m.hits[ip] = kept
		return maxHits + 1, nil
	}
	kept = append(kept, now)
	m.hits[ip] = kept
	return int64(len(kept)), nil
}

func (m *Memory) Close() {
	close(m.stop)
	<-m.done
}

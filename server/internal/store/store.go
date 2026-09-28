// Package store persists issued challenges (single-use) and per-IP request
// counters. The v0 implementation is in-process memory; the interface exists
// so a Redis backend can replace it without touching the API layer.
package store

import (
	"sync"
	"time"

	"github.com/xeylabs/xprotect/server/internal/challenge"
)

type record struct {
	ch       *challenge.Challenge
	issuedAt time.Time
}

type counter struct {
	n     int64
	start time.Time
}

// Store is the persistence surface of xprotectd.
type Store interface {
	Put(ch *challenge.Challenge, issuedAt time.Time)
	Get(id string) (*challenge.Challenge, time.Time, bool)
	Take(id string) (*challenge.Challenge, time.Time, bool) // atomic single-use fetch+delete
	IncrIP(ip string, window time.Duration) int64
	Close()
}

// Memory is the in-process Store implementation. Challenges expire after ttl;
// a janitor evicts both expired challenges and stale IP counters.
type Memory struct {
	mu       sync.Mutex
	items    map[string]record
	counters map[string]*counter
	ttl      time.Duration
	stop     chan struct{}
	done     chan struct{}
}

func NewMemory(ttl time.Duration) *Memory {
	m := &Memory{
		items:    make(map[string]record),
		counters: make(map[string]*counter),
		ttl:      ttl,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
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
	for ip, c := range m.counters {
		if now.Sub(c.start) > time.Hour {
			delete(m.counters, ip)
		}
	}
}

func (m *Memory) Put(ch *challenge.Challenge, issuedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[ch.ID] = record{ch: ch, issuedAt: issuedAt}
}

func (m *Memory) Get(id string) (*challenge.Challenge, time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.items[id]
	return r.ch, r.issuedAt, ok
}

// Take atomically consumes a challenge: a redeemed id can never be redeemed
// again, which is what makes replay useless.
func (m *Memory) Take(id string) (*challenge.Challenge, time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.items[id]
	if ok {
		delete(m.items, id)
	}
	return r.ch, r.issuedAt, ok
}

// IncrIP counts a request inside a fixed window starting at the first hit.
func (m *Memory) IncrIP(ip string, window time.Duration) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	c, ok := m.counters[ip]
	if !ok || now.Sub(c.start) > window {
		m.counters[ip] = &counter{n: 1, start: now}
		return 1
	}
	c.n++
	return c.n
}

func (m *Memory) Close() {
	close(m.stop)
	<-m.done
}

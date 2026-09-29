// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package api_test

// Red-team round 4: a store outage must surface as 503 at the HTTP edge —
// never as a silently-processed request (fail closed, ADR-0009).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/api"
	"github.com/xeylabs/mythic/server/internal/challenge"
	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/internal/risk"
)

// brokenStore fails at the layer each test asks about.
type brokenStore struct {
	failIncr bool
	failTake bool
	failPut  bool
}

func (b *brokenStore) Put(*challenge.Challenge, time.Time) error {
	if b.failPut {
		return errors.New("down")
	}
	return nil
}
func (b *brokenStore) Get(string) (*challenge.Challenge, time.Time, bool, error) {
	return nil, time.Time{}, false, errors.New("down")
}
func (b *brokenStore) Take(string) (*challenge.Challenge, time.Time, bool, error) {
	if b.failTake {
		return nil, time.Time{}, false, errors.New("down")
	}
	return nil, time.Time{}, false, nil
}
func (b *brokenStore) IncrIP(string, time.Duration) (int64, error) {
	if b.failIncr {
		return 0, errors.New("down")
	}
	return 1, nil
}
func (b *brokenStore) Close() {}

func newBrokenServer(t *testing.T, bs *brokenStore) *httptest.Server {
	t.Helper()
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(km.Close)
	eng := risk.New(risk.Config{BaseDifficulty: 8, MaxDifficulty: 12, DenyAt: 85, HeavyAt: 65, StepUpAt: 30, AdvisoryPenalty: map[string]int{}})
	srv := api.New(api.Config{Sites: []string{"test-site"}, TokenTTL: time.Minute, ChallengeTTL: time.Minute, IPWindow: time.Minute, IPLimit: 1000},
		km, bs, eng, silentLogger())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestStoreOutageFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		bs   *brokenStore
		path string
		body string
	}{
		{"incr outage blocks jwks", &brokenStore{failIncr: true}, "/v1/.well-known/jwks.json", ""},
		{"incr outage blocks challenge", &brokenStore{failIncr: true}, "/v1/challenge", `{"site_key":"test-site"}`},
		{"incr outage blocks verify", &brokenStore{failIncr: true}, "/v1/verify", `{"challenge_id":"x","nonce":"n"}`},
		{"take outage blocks verify", &brokenStore{failTake: true}, "/v1/verify", `{"challenge_id":"x","nonce":"n"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := newBrokenServer(t, c.bs)
			var resp *http.Response
			var err error
			if c.path == "/v1/.well-known/jwks.json" {
				resp, err = http.Get(ts.URL + c.path)
			} else {
				resp, err = http.Post(ts.URL+c.path, "application/json", strings.NewReader(c.body))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("store outage must surface as 503, got %d on %s", resp.StatusCode, c.path)
			}
		})
	}
}

func TestHealthzStaysAliveDuringStoreOutage(t *testing.T) {
	ts := newBrokenServer(t, &brokenStore{failIncr: true})
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz must stay open for load balancers, got %d", resp.StatusCode)
	}
}

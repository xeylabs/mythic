// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package crypto holds the Ed25519 key manager and token signing used by
// xprotectd. Verification lives in the public xtoken package so origins can
// verify without importing server internals.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/xeylabs/xprotect/server/xtoken"
)

// KeyManager owns the Ed25519 signing key. Seeds are 32 bytes on disk (0600);
// the key id is the first 8 bytes of SHA-256 over the public key.
type KeyManager struct {
	mu    sync.RWMutex
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// LoadOrCreate loads the seed at path, or generates and persists one on first
// run. An empty path yields an ephemeral key (dev/testing).
func LoadOrCreate(path string) (*KeyManager, error) {
	if path != "" {
		if seed, err := os.ReadFile(path); err == nil {
			if len(seed) != ed25519.SeedSize {
				return nil, fmt.Errorf("crypto: seed file %s must be %d bytes, got %d", path, ed25519.SeedSize, len(seed))
			}
			return newKeyManager(ed25519.NewKeyFromSeed(seed)), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate ed25519 key: %w", err)
	}
	if path != "" {
		if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
			return nil, fmt.Errorf("crypto: persist signing seed: %w", err)
		}
	}
	return newKeyManager(priv), nil
}

func newKeyManager(priv ed25519.PrivateKey) *KeyManager {
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &KeyManager{
		priv:  priv,
		pub:   pub,
		keyID: base64.RawURLEncoding.EncodeToString(sum[:8]),
	}
}

func (k *KeyManager) KeyID() string { return k.keyID }

func (k *KeyManager) PublicKey() ed25519.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.pub
}

func (k *KeyManager) Sign(payload []byte) []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return ed25519.Sign(k.priv, payload)
}

// PublicKeyJWK renders the public key as a JWKS OKP entry (RFC 8037).
func (k *KeyManager) PublicKeyJWK() map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"alg": "Ed25519",
		"use": "sig",
		"kid": k.keyID,
		"x":   base64.RawURLEncoding.EncodeToString(k.PublicKey()),
	}
}

// SignToken fills the managed claims (version, kid, timestamps, jti), signs
// the payload and returns the wire token.
func SignToken(km *KeyManager, claims xtoken.TokenClaims, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.Version = 1
	claims.KeyID = km.KeyID()
	claims.IssuedAt = now.Unix()
	claims.Exp = now.Add(ttl).Unix()
	if claims.JTI == "" {
		claims.JTI = NewID()
	}
	if claims.Decision == "" {
		claims.Decision = xtoken.DecisionAllow
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("crypto: marshal token claims: %w", err)
	}
	sig := km.Sign(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// NewID returns a 128-bit random identifier, URL-safe.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read is documented not to fail; this is a hard stop.
		panic("crypto: entropy source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

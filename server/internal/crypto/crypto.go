// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Package crypto holds the Ed25519 key ring and token signing used by
// mythicd. Verification lives in the public xtoken package so origins can
// verify without importing server internals.
//
// The KeyManager is a small key ring (ADR-0006): exactly one active key signs
// every token, retired keys stay verifiable until retention expires, and
// rotation is a time-based in-process operation — not a deploy event.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/xeylabs/mythic/server/xtoken"
)

// managedKey is one ring entry. retiredAt == zero means the key is active.
type managedKey struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	keyID     string
	createdAt time.Time
	retiredAt time.Time
}

// KeyManager owns the Ed25519 key ring. With a path configured, the ring is
// persisted as a JSON keystore (0600); a legacy file holding a bare 32-byte
// seed still loads as the active key and migrates on the next save.
type KeyManager struct {
	mu        sync.RWMutex
	keys      []*managedKey // keys[0] is the active signer; the rest are retired, newest first
	path      string        // "" = ephemeral (nothing persists)
	maxAge    time.Duration // rotate when the active key is older; 0 = no auto-rotation
	retention time.Duration // how long a retired key remains in the JWKS
	log       *slog.Logger  // nil-safe: rotation failures surface in the server log
	loadMtime time.Time     // keystore mtime at load — a changed mtime means another process wrote it
	stop      chan struct{}
	done      chan struct{}
}

// DefaultKeyRetention is how long a retired key stays advertised after a
// rotation — far beyond the token TTL plus realistic JWKS cache ages.
const DefaultKeyRetention = 24 * time.Hour

// LoadOrCreate loads the keystore at path, or generates a single active key
// on first run. No auto-rotation: use LoadOrCreateWithPolicy for that.
// An empty path yields an ephemeral ring (dev/testing).
func LoadOrCreate(path string) (*KeyManager, error) {
	return LoadOrCreateWithPolicy(path, 0, DefaultKeyRetention, nil)
}

// LoadOrCreateWithPolicy is LoadOrCreate plus rotation policy: maxAge is the
// lifetime of an active key (0 disables auto-rotation), retention is how long
// retired keys stay in the JWKS. The logger is optional (nil-safe).
func LoadOrCreateWithPolicy(path string, maxAge, retention time.Duration, log *slog.Logger) (*KeyManager, error) {
	km := &KeyManager{
		path:      path,
		maxAge:    maxAge,
		retention: retention,
		log:       log,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	if path == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("crypto: generate ed25519 key: %w", err)
		}
		km.keys = []*managedKey{newManagedKey(priv, time.Now())}
	} else {
		keys, err := loadKeystore(path)
		if err != nil {
			return nil, err
		}
		km.keys = keys
	}
	// Remember the on-disk state we loaded: a rotation must never silently
	// clobber a keystore another process has written since (red-team G3 —
	// two nodes on one file split-brained their signing keys).
	if path != "" {
		if info, err := os.Stat(path); err == nil {
			km.loadMtime = info.ModTime()
		}
	}

	// An over-age ring rotates before serving, so the advertised active key
	// never starts out past its lifetime.
	if km.maxAge > 0 {
		km.RotateIfDue(time.Now())
	}
	go km.ticker()
	return km, nil
}

func newManagedKey(priv ed25519.PrivateKey, createdAt time.Time) *managedKey {
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &managedKey{
		priv:      priv,
		pub:       pub,
		keyID:     base64.RawURLEncoding.EncodeToString(sum[:8]),
		createdAt: createdAt,
	}
}

// ticker drives auto-rotation. One-minute granularity is plenty: key
// lifetimes are measured in days.
func (k *KeyManager) ticker() {
	defer close(k.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-ticker.C:
			k.RotateIfDue(time.Now())
		}
	}
}

// Close stops the rotation ticker.
func (k *KeyManager) Close() {
	close(k.stop)
	<-k.done
}

// Rotate unconditionally makes a fresh key active and retires the current
// one. It is the operational entry point (and what auto-rotation calls).
func (k *KeyManager) Rotate() error {
	return k.rotateAt(time.Now())
}

// RotateIfDue rotates when auto-rotation is enabled and the active key has
// reached maxAge. It reports whether a rotation happened.
func (k *KeyManager) RotateIfDue(now time.Time) bool {
	if k.maxAge <= 0 {
		return false
	}
	k.mu.RLock()
	due := now.Sub(k.keys[0].createdAt) >= k.maxAge
	k.mu.RUnlock()
	if !due {
		return false
	}
	if err := k.rotateAt(now); err != nil {
		// A failed persistence must not kill a serving process; the old key
		// keeps signing and the next tick retries.
		if k.log != nil {
			k.log.Error("key rotation failed; active key keeps signing", "err", err)
		}
		return false
	}
	if k.log != nil {
		k.log.Info("signing key rotated", "kid", k.KeyID())
	}
	return true
}

func (k *KeyManager) rotateAt(now time.Time) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("crypto: generate ed25519 key: %w", err)
	}
	k.keys[0].retiredAt = now
	fresh := newManagedKey(priv, now)
	k.keys = append([]*managedKey{fresh}, k.keys...)
	k.pruneLocked(now)
	return k.saveLocked()
}

// pruneLocked drops retired keys past retention. The active key (index 0) is
// never a prune candidate.
func (k *KeyManager) pruneLocked(now time.Time) {
	kept := k.keys[:1]
	for _, key := range k.keys[1:] {
		if now.Sub(key.retiredAt) <= k.retention {
			kept = append(kept, key)
		}
	}
	k.keys = kept
}

// --- ring reads -------------------------------------------------------------

// KeyID returns the active key id.
func (k *KeyManager) KeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys[0].keyID
}

// PublicKey returns the active public key.
func (k *KeyManager) PublicKey() ed25519.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys[0].pub
}

// Sign signs with the active key.
func (k *KeyManager) Sign(payload []byte) []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return ed25519.Sign(k.keys[0].priv, payload)
}

// PublicKeyJWK renders the active public key as a JWKS OKP entry (RFC 8037).
func (k *KeyManager) PublicKeyJWK() map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return jwk(k.keys[0])
}

// PublicJWKS renders every ring entry: the active key first, then retired
// keys, newest first. Origins select by the kid claimed inside the token.
func (k *KeyManager) PublicJWKS() []map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]map[string]any, 0, len(k.keys))
	for _, key := range k.keys {
		out = append(out, jwk(key))
	}
	return out
}

func jwk(key *managedKey) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"alg": "Ed25519",
		"use": "sig",
		"kid": key.keyID,
		"x":   base64.RawURLEncoding.EncodeToString(key.pub),
	}
}

// --- persistence -------------------------------------------------------------

// keystoreFile is the on-disk ring: version 1, active key first.
type keystoreFile struct {
	Version int           `json:"version"`
	Keys    []keystoreKey `json:"keys"`
}

type keystoreKey struct {
	Seed      string `json:"seed"`
	CreatedAt int64  `json:"created_at"`
	RetiredAt int64  `json:"retired_at,omitempty"`
}

// loadKeystore reads a keystore file. A legacy file containing a bare 32-byte
// seed loads as the single active key, with the file mtime as its creation
// time; it migrates to JSON on the next save.
func loadKeystore(path string) ([]*managedKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("crypto: read keystore %s: %w", path, err)
		}
		// First run: generate and persist.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("crypto: generate ed25519 key: %w", err)
		}
		key := newManagedKey(priv, time.Now())
		if err := saveKeystore(path, []*managedKey{key}); err != nil {
			return nil, err
		}
		return []*managedKey{key}, nil
	}

	if len(raw) == ed25519.SeedSize {
		key := newManagedKey(ed25519.NewKeyFromSeed(raw), fileTime(path))
		return []*managedKey{key}, nil
	}

	var doc keystoreFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("crypto: keystore %s is neither a 32-byte seed nor valid JSON: %w", path, err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("crypto: keystore %s has unsupported version %d", path, doc.Version)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("crypto: keystore %s contains no keys", path)
	}
	keys := make([]*managedKey, 0, len(doc.Keys))
	for i, entry := range doc.Keys {
		seed, err := base64.RawURLEncoding.DecodeString(entry.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("crypto: keystore %s key %d has a bad seed", path, i)
		}
		key := newManagedKey(ed25519.NewKeyFromSeed(seed), time.Unix(entry.CreatedAt, 0))
		if entry.RetiredAt > 0 {
			key.retiredAt = time.Unix(entry.RetiredAt, 0)
		}
		keys = append(keys, key)
	}
	if keys[0].retiredAt != (time.Time{}) {
		return nil, fmt.Errorf("crypto: keystore %s: the first key must be the active signer", path)
	}
	return keys, nil
}

// saveLocked persists the ring via temp-file + rename so a crash mid-write
// cannot corrupt the keystore. The write is refused when the file changed on
// disk since we loaded it: MYTHIC_KEY_FILE is per-node, and two processes
// sharing it otherwise overwrite each other's rings — whoever saves last
// silently erases the other's keys (red-team G3).
func (k *KeyManager) saveLocked() error {
	if k.path == "" {
		return nil
	}
	if info, err := os.Stat(k.path); err == nil && !k.loadMtime.IsZero() && !info.ModTime().Equal(k.loadMtime) {
		return fmt.Errorf("crypto: keystore %s changed on disk since load; refusing to overwrite (is another process sharing this file?)", k.path)
	}
	if err := saveKeystore(k.path, k.keys); err != nil {
		return err
	}
	if info, err := os.Stat(k.path); err == nil {
		k.loadMtime = info.ModTime()
	}
	return nil
}

func saveKeystore(path string, keys []*managedKey) error {
	doc := keystoreFile{Version: 1, Keys: make([]keystoreKey, 0, len(keys))}
	for _, key := range keys {
		entry := keystoreKey{
			Seed:      base64.RawURLEncoding.EncodeToString(key.priv.Seed()),
			CreatedAt: key.createdAt.Unix(),
		}
		if !key.retiredAt.IsZero() {
			entry.RetiredAt = key.retiredAt.Unix()
		}
		doc.Keys = append(doc.Keys, entry)
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("crypto: marshal keystore: %w", err)
	}
	// The temp name is process-unique: two processes saving the same keystore
	// must not collide on one .tmp file (red-team G3 startup failure).
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("crypto: persist keystore: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("crypto: persist keystore: %w", err)
	}
	return nil
}

func fileTime(path string) time.Time {
	if info, err := os.Stat(path); err == nil {
		return info.ModTime()
	}
	return time.Now()
}

// SignToken fills the managed claims (version, kid, timestamps, jti), signs
// the payload with the active key and returns the wire token.
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

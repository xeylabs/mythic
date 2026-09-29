// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package crypto_test

// Tests for the key ring (ADR-0006): rotation must never invalidate a token
// that is still unexpired, the JWKS must advertise retired keys, the keystore
// must survive a restart, and legacy bare-seed files must keep loading.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/internal/crypto"
	"github.com/xeylabs/mythic/server/xtoken"
)

func signProbe(t *testing.T, km *crypto.KeyManager) (string, ed25519.PublicKey, string) {
	t.Helper()
	token, err := crypto.SignToken(km, xtoken.TokenClaims{SiteKey: "s", Decision: xtoken.DecisionAllow}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kid := km.KeyID()
	return token, km.PublicKey(), kid
}

func jwksKids(t *testing.T, km *crypto.KeyManager) []string {
	t.Helper()
	var kids []string
	for _, entry := range km.PublicJWKS() {
		kids = append(kids, entry["kid"].(string))
	}
	return kids
}

func TestLegacySeedFileStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mythic.key")
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	km, err := crypto.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("legacy seed file must load: %v", err)
	}
	defer km.Close()

	// The loaded key must be the one the seed defines.
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(km.PublicKey(), pub) {
		t.Fatal("legacy seed must define the active public key")
	}
	if len(jwksKids(t, km)) != 1 {
		t.Fatalf("legacy load must yield exactly one key, got %d", len(jwksKids(t, km)))
	}
}

func TestRotationKeepsOldTokensVerifiable(t *testing.T) {
	km, err := crypto.LoadOrCreate("")
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	oldToken, oldPub, oldKid := signProbe(t, km)
	if err := km.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	newToken, newPub, newKid := signProbe(t, km)
	if oldKid == newKid {
		t.Fatal("rotation must change the active key id")
	}
	if bytes.Equal(oldPub, newPub) {
		t.Fatal("rotation must change the active public key")
	}

	// Tokens signed before the rotation verify against the retired key.
	claims, err := xtoken.VerifyToken(oldPub, oldToken)
	if err != nil {
		t.Fatalf("pre-rotation token must verify against the retired key: %v", err)
	}
	if claims.KeyID != oldKid {
		t.Fatalf("pre-rotation token kid = %q, want %q", claims.KeyID, oldKid)
	}
	// Post-rotation tokens verify against the new active key.
	if _, err := xtoken.VerifyToken(newPub, newToken); err != nil {
		t.Fatalf("post-rotation token must verify: %v", err)
	}
	// And the old token does NOT verify against the new key.
	if _, err := xtoken.VerifyToken(newPub, oldToken); err == nil {
		t.Fatal("pre-rotation token must not verify against the new active key")
	}

	kids := jwksKids(t, km)
	if len(kids) != 2 {
		t.Fatalf("JWKS must list active + retired key, got %d", len(kids))
	}
	if kids[0] != newKid || kids[1] != oldKid {
		t.Fatalf("JWKS order must be [new active, retired], got %v", kids)
	}
}

func TestKeystoreSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mythic.keys")

	km, err := crypto.LoadOrCreateWithPolicy(path, 0, crypto.DefaultKeyRetention, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, oldPub, oldKid := signProbe(t, km)
	if err := km.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	_, _, activeKid := signProbe(t, km)
	km.Close()

	km2, err := crypto.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer km2.Close()

	if got := km2.KeyID(); got != activeKid {
		t.Fatalf("reloaded active kid = %q, want %q", got, activeKid)
	}
	kids := jwksKids(t, km2)
	if len(kids) != 2 || kids[0] != activeKid || kids[1] != oldKid {
		t.Fatalf("reloaded ring = %v, want [%s %s]", kids, activeKid, oldKid)
	}
	// A token signed before the restart still verifies after it.
	if _, err := xtoken.VerifyToken(oldPub, oldToken); err != nil {
		t.Fatalf("pre-restart token must verify against reloaded retired key: %v", err)
	}
}

func TestLegacyFileMigratesToKeystoreOnRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mythic.key")
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0xA0 + i)
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	km, err := crypto.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	legacyPub := km.PublicKey()
	if err := km.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	km.Close()

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("rotation must migrate the legacy seed to a JSON keystore: %v", err)
	}
	if doc.Version != 1 {
		t.Fatalf("keystore version = %d, want 1", doc.Version)
	}

	// The legacy seed lives on as the retired key.
	km2, err := crypto.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer km2.Close()
	if _, err := xtoken.VerifyToken(legacyPub, mustLegacyToken(t, seed)); err != nil {
		t.Fatalf("legacy seed key must remain verifiable after migration: %v", err)
	}
}

// mustLegacyToken signs with the legacy seed directly, independent of the
// keystore machinery.
func mustLegacyToken(t *testing.T, seed []byte) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	payload, err := json.Marshal(xtoken.TokenClaims{
		Version: 1, SiteKey: "s", Decision: xtoken.DecisionAllow,
		IssuedAt: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestRetiredKeysExpire(t *testing.T) {
	// Retention 100ms + a real sleep between rotations: deterministic even
	// when parallel tests slow the clock down (retention 0 relied on two
	// rotations landing on different timestamps — flaky under -race).
	km, err := crypto.LoadOrCreateWithPolicy("", 0, 100*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	_, _, first := signProbe(t, km)
	if err := km.Rotate(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := km.Rotate(); err != nil {
		t.Fatal(err)
	}

	kids := jwksKids(t, km)
	if len(kids) != 2 {
		t.Fatalf("expired retention must prune older retired keys, got %v", kids)
	}
	if kids[0] != km.KeyID() {
		t.Fatalf("first JWKS entry must be the active key, got %v", kids)
	}
	for _, kid := range kids {
		if kid == first {
			t.Fatalf("pruned key %s must no longer be advertised", first)
		}
	}
}

func TestRotateIfDueHonorsMaxAge(t *testing.T) {
	km, err := crypto.LoadOrCreateWithPolicy("", time.Hour, crypto.DefaultKeyRetention, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	before := km.KeyID()
	if km.RotateIfDue(time.Now().Add(30 * time.Minute)) {
		t.Fatal("key younger than max age must not rotate")
	}
	if km.KeyID() != before {
		t.Fatal("early RotateIfDue must not change the active key")
	}
	if !km.RotateIfDue(time.Now().Add(2 * time.Hour)) {
		t.Fatal("key past max age must rotate")
	}
	if km.KeyID() == before {
		t.Fatal("due rotation must change the active key")
	}
}

func TestStartRotatesOverAgeKeystore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mythic.keys")

	km, err := crypto.LoadOrCreateWithPolicy(path, 0, crypto.DefaultKeyRetention, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, oldKid := signProbe(t, km)
	km.Close()

	// Rewrite created_at to two days ago, then start with maxAge 24h: the
	// over-age key must rotate before serving.
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}
	keys := doc["keys"].([]any)
	keys[0].(map[string]any)["created_at"] = time.Now().Add(-48 * time.Hour).Unix()
	blob, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	km2, err := crypto.LoadOrCreateWithPolicy(path, 24*time.Hour, crypto.DefaultKeyRetention, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer km2.Close()
	if km2.KeyID() == oldKid {
		t.Fatal("an over-age keystore must rotate on startup")
	}
	kids := jwksKids(t, km2)
	if len(kids) != 2 || kids[1] != oldKid {
		t.Fatalf("over-age startup rotation must retain the old key, got %v", kids)
	}
}

func TestLoadRejectsCorruptKeystore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mythic.keys")

	if err := os.WriteFile(path, []byte(`{"version":2,"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadOrCreate(path); err == nil {
		t.Fatal("unsupported keystore version must be rejected")
	}

	if err := os.WriteFile(path, []byte(`{"version":1,"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadOrCreate(path); err == nil {
		t.Fatal("empty keystore must be rejected")
	}

	// A retired key first must be rejected: the active signer is always
	// keys[0] by construction.
	doc := `{"version":1,"keys":[{"seed":"` +
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SeedSize)) +
		`","created_at":1,"retired_at":2}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadOrCreate(path); err == nil {
		t.Fatal("keystore whose first key is retired must be rejected")
	}
}

// Red-team G3: a rotation must refuse to overwrite a keystore that another
// process has written since we loaded it — silent clobbering is what let two
// nodes split-brain their signing keys.
func TestSaveRefusedWhenKeystoreChangedOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mythic.keys")

	km, err := crypto.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(km.Close)

	// Another process writes its own ring behind our back.
	other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // all-zero seed, deterministic
	doc := map[string]any{
		"version": 1,
		"keys": []map[string]any{{
			"seed":       base64.RawURLEncoding.EncodeToString(other.Seed()),
			"created_at": time.Now().Unix(),
		}},
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := km.Rotate(); err == nil {
		t.Fatal("rotation must refuse to clobber a keystore changed since load")
	}

	// The foreign ring survives untouched on disk, and the in-memory ring
	// keeps signing (degraded, loud — not silently divergent).
	again, err := crypto.LoadOrCreate(path)
	if err != nil {
		t.Fatalf("foreign ring must remain loadable: %v", err)
	}
	t.Cleanup(again.Close)
	foreign := other.Public().(ed25519.PublicKey)
	if !bytes.Equal(again.PublicKey(), foreign) {
		t.Fatal("the other process's ring must not be erased from disk")
	}
	token, _, _ := signProbe(t, km)
	if _, err := xtoken.VerifyToken(km.PublicKey(), token); err != nil {
		t.Fatalf("refused rotation must leave in-memory signing intact: %v", err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package xtoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/xtoken"
)

func sign(t *testing.T, claims xtoken.TokenClaims, ttl time.Duration, signer ed25519.PrivateKey) string {
	t.Helper()
	now := time.Now()
	claims.Version = 1
	claims.IssuedAt = now.Unix()
	claims.Exp = now.Add(ttl).Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signer, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := sign(t, xtoken.TokenClaims{SiteKey: "s", Decision: xtoken.DecisionAllow, Risk: 7}, time.Minute, priv)

	claims, err := xtoken.VerifyToken(pub, token)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.SiteKey != "s" || claims.Decision != xtoken.DecisionAllow || claims.Risk != 7 {
		t.Fatalf("wrong claims: %+v", claims)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	token := sign(t, xtoken.TokenClaims{SiteKey: "s"}, -time.Minute, priv)
	if _, err := xtoken.VerifyToken(pub, token); err == nil {
		t.Fatal("expired token must not verify")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	token := sign(t, xtoken.TokenClaims{SiteKey: "s"}, time.Minute, priv)
	if _, err := xtoken.VerifyToken(otherPub, token); err == nil {
		t.Fatal("token from a different key must not verify")
	}
}

func TestParsePublicKeyRejectsBadInput(t *testing.T) {
	if _, err := xtoken.ParsePublicKey("!!!not base64"); err == nil {
		t.Fatal("garbage x must fail")
	}
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	if _, err := xtoken.ParsePublicKey(short); err == nil {
		t.Fatal("short x must fail")
	}
	good := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if _, err := xtoken.ParsePublicKey(good); err != nil {
		t.Fatalf("valid 32-byte x must parse: %v", err)
	}
}

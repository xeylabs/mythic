// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

package xtoken_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/xeylabs/mythic/server/xtoken"
)

// This file is the empirical answer to one question: can ANY byte-level
// tampering make a token verify? Ed25519 says no — these tests prove it at
// scale, deterministically, on every run.

// b64url is the token alphabet; character mutations must stay inside it.
const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func keyFromRNG(rng *rand.Rand) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(rng.Intn(256))
	}
	return ed25519.NewKeyFromSeed(seed)
}

func mustSign(signer ed25519.PrivateKey, claims xtoken.TokenClaims, ttl time.Duration) string {
	now := time.Now()
	claims.Version = 1
	claims.IssuedAt = now.Unix()
	claims.Exp = now.Add(ttl).Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(signer, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// replaceRandomChar swaps one character for a different one — never a no-op.
func replaceRandomChar(rng *rand.Rand, s string) string {
	b := []byte(s)
	i := rng.Intn(len(b))
	orig := b[i]
	for {
		c := b64url[rng.Intn(len(b64url))]
		if c != orig {
			b[i] = c
			break
		}
	}
	return string(b)
}

// mutate applies one random corruption to a token. Every branch produces a
// string that differs from the input by at least one byte — the no-op
// mutation class that made the original tamper test flaky cannot occur.
func mutate(rng *rand.Rand, token string) string {
	payload, sig, _ := strings.Cut(token, ".")
	switch rng.Intn(7) {
	case 0: // flip one bit anywhere in the wire token
		s := []byte(token)
		s[rng.Intn(len(s))] ^= 1 << rng.Intn(8)
		return string(s)
	case 1: // swap one alphabet character for a different one
		return replaceRandomChar(rng, token)
	case 2: // realistic attacker edit: change a signed claim byte, keep signature
		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil || len(raw) == 0 {
			return replaceRandomChar(rng, token)
		}
		raw[rng.Intn(len(raw))] ^= 1 << rng.Intn(8)
		return base64.RawURLEncoding.EncodeToString(raw) + "." + sig
	case 3: // truncate the tail
		n := 1 + rng.Intn(8)
		if n >= len(token) {
			return token[:len(token)-1]
		}
		return token[:len(token)-n]
	case 4: // strip the signature entirely
		return payload
	case 5: // drop the separator
		return payload + sig
	default: // append garbage
		return token + string(b64url[rng.Intn(len(b64url))])
	}
}

// TestTamperResistanceMutationStorm signs 500 tokens with 20 independent keys
// and hammers each with 20 guaranteed byte-changing corruptions: 10,000
// tamper attempts per run. Every one must be rejected; every untouched token
// must verify. The RNG is seeded, so failures reproduce exactly.
func TestTamperResistanceMutationStorm(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EED))
	const (
		keys         = 20
		tokensPerKey = 25
		mutations    = 20 // keys * tokensPerKey * mutations = 10,000
	)

	attempts := 0
	for k := 0; k < keys; k++ {
		signer := keyFromRNG(rng)
		verifier := signer.Public().(ed25519.PublicKey)

		for i := 0; i < tokensPerKey; i++ {
			claims := xtoken.TokenClaims{
				SiteKey:  "site",
				Decision: xtoken.DecisionAllow,
				Risk:     rng.Intn(101),
			}
			token := mustSign(signer, claims, 5*time.Minute)

			if _, err := xtoken.VerifyToken(verifier, token); err != nil {
				t.Fatalf("untouched token must always verify: %v", err)
			}

			for m := 0; m < mutations; m++ {
				tampered := mutate(rng, token)
				if tampered == token {
					t.Fatalf("mutation produced a no-op — storm integrity broken (key %d token %d mutation %d)", k, i, m)
				}
				if _, err := xtoken.VerifyToken(verifier, tampered); err == nil {
					t.Fatalf("TAMPERED TOKEN ACCEPTED (key %d token %d mutation %d)\noriginal: %s\ntampered: %s", k, i, m, token, tampered)
				}
				attempts++
			}
		}
	}
	t.Logf("mutation storm: %d tamper attempts, 0 accepted, %d untouched tokens verified", attempts, keys*tokensPerKey)
}

// TestForgedClaimsRejected simulates the attack that actually matters: an
// attacker holds a legitimately signed token, decodes it, edits the claims
// that matter, and re-attaches the original signature. Every field edit must
// be caught.
func TestForgedClaimsRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	signer := keyFromRNG(rng)
	verifier := signer.Public().(ed25519.PublicKey)

	base := mustSign(signer, xtoken.TokenClaims{
		SiteKey:  "site-a",
		Decision: xtoken.DecisionDeny,
		Risk:     95,
	}, time.Minute)

	payload, sig, ok := strings.Cut(base, ".")
	if !ok {
		t.Fatal("fixture token must be payload.signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var claims xtoken.TokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}

	// Sanity: re-marshaling without edits must reproduce the signed bytes and
	// still verify — so any rejection below is caused by the edit itself.
	reencoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	untouched := base64.RawURLEncoding.EncodeToString(reencoded) + "." + sig
	if untouched != base {
		t.Fatal("re-marshaled claims must reproduce the original payload")
	}
	if _, err := xtoken.VerifyToken(verifier, untouched); err != nil {
		t.Fatalf("unedited re-encoding must verify: %v", err)
	}

	edits := []struct {
		name string
		edit func(*xtoken.TokenClaims)
	}{
		{"deny becomes allow", func(c *xtoken.TokenClaims) { c.Decision = xtoken.DecisionAllow }},
		{"risk wiped to zero", func(c *xtoken.TokenClaims) { c.Risk = 0 }},
		{"site key swapped", func(c *xtoken.TokenClaims) { c.SiteKey = "site-b" }},
		{"expiry extended", func(c *xtoken.TokenClaims) { c.Exp = time.Now().Add(time.Hour).Unix() }},
		{"version bumped", func(c *xtoken.TokenClaims) { c.Version = 2 }},
		{"jti replaced", func(c *xtoken.TokenClaims) { c.JTI = "forged-jti" }},
	}
	for _, e := range edits {
		forged := claims
		e.edit(&forged)
		reencoded, err := json.Marshal(forged)
		if err != nil {
			t.Fatal(err)
		}
		token := base64.RawURLEncoding.EncodeToString(reencoded) + "." + sig
		if _, err := xtoken.VerifyToken(verifier, token); err == nil {
			t.Fatalf("forged claim (%s) was ACCEPTED with the original signature", e.name)
		}
	}
}

// TestCrossKeyRejected: 10 keys, 90 foreign pairs — a token signed by one
// key must never verify against another.
func TestCrossKeyRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	const n = 10
	signers := make([]ed25519.PrivateKey, n)
	tokens := make([]string, n)
	for i := range signers {
		signers[i] = keyFromRNG(rng)
		tokens[i] = mustSign(signers[i], xtoken.TokenClaims{SiteKey: "s", Decision: xtoken.DecisionAllow, Risk: 1}, time.Minute)
		if _, err := xtoken.VerifyToken(signers[i].Public().(ed25519.PublicKey), tokens[i]); err != nil {
			t.Fatalf("token %d must verify against its own key: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			if _, err := xtoken.VerifyToken(signers[j].Public().(ed25519.PublicKey), tokens[i]); err == nil {
				t.Fatalf("token %d verified against FOREIGN key %d", i, j)
			}
		}
	}
}

// nonCanonicalVariant replaces the trailing character of part (0=payload,
// 1=signature) with the alphabet character one value-step away — same top
// data bits, different string. ok=false when the part length leaves no
// ignored bits (decoded length %3 == 0).
func nonCanonicalVariant(token string, part int) (string, bool) {
	p, s, _ := strings.Cut(token, ".")
	parts := [2]*string{&p, &s}
	b := []byte(*parts[part])
	val := strings.IndexByte(b64url, b[len(b)-1])
	if val < 0 {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(b))
	if err != nil || len(decoded)%3 == 0 {
		return "", false
	}
	b[len(b)-1] = b64url[val^1]
	*parts[part] = string(b)
	return p + "." + s, true
}

// TestNonCanonicalEncodingRejected is the regression test for the finding the
// mutation storm caught on day one: Go's base64 decoder silently discards the
// unused low bits of a trailing character, so a DIFFERENT string can decode
// to the identical token. Canonical enforcement must reject it — string
// identity and cryptographic identity must coincide.
func TestNonCanonicalEncodingRejected(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	signer := keyFromRNG(rng)
	pub := signer.Public().(ed25519.PublicKey)
	token := mustSign(signer, xtoken.TokenClaims{SiteKey: "s", Decision: xtoken.DecisionAllow, Risk: 3}, time.Minute)
	if _, err := xtoken.VerifyToken(pub, token); err != nil {
		t.Fatalf("baseline token must verify: %v", err)
	}

	dec := func(x string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	origPayload, origSig, _ := strings.Cut(token, ".")

	for part := 0; part <= 1; part++ {
		variant, ok := nonCanonicalVariant(token, part)
		if !ok {
			continue // no ignored bits in this part (the 64-byte signature always qualifies)
		}
		if variant == token {
			t.Fatalf("non-canonical variant (part %d) must differ as a string", part)
		}
		varPayload, varSig, _ := strings.Cut(variant, ".")
		if part == 0 && !bytes.Equal(dec(origPayload), dec(varPayload)) {
			t.Fatal("payload variant must decode to identical bytes — that is what makes it non-canonical")
		}
		if part == 1 && !bytes.Equal(dec(origSig), dec(varSig)) {
			t.Fatal("signature variant must decode to identical bytes — that is what makes it non-canonical")
		}
		if _, err := xtoken.VerifyToken(pub, variant); err == nil {
			t.Fatalf("non-canonical token (part %d) was ACCEPTED — string identity must equal crypto identity", part)
		}
	}
}

// FuzzVerifyToken keeps exploring token-shaped input forever. The invariant:
// verification never panics, and exactly one input verifies — the untouched,
// correctly signed token. Every push runs the seed corpus for free; run a
// deep pass locally with:
//
//	go test ./xtoken -run '^$' -fuzz FuzzVerifyToken -fuzztime 60s
func FuzzVerifyToken(f *testing.F) {
	rng := rand.New(rand.NewSource(3))
	signer := keyFromRNG(rng)
	pub := signer.Public().(ed25519.PublicKey)
	valid := mustSign(signer, xtoken.TokenClaims{SiteKey: "s", Decision: xtoken.DecisionAllow, Risk: 5}, time.Hour)

	f.Add(valid)
	f.Add(valid + "x")
	f.Add("")
	f.Add("garbage")
	f.Add("a.b")
	f.Add(strings.Repeat("A", 256))

	f.Fuzz(func(t *testing.T, input string) {
		_, err := xtoken.VerifyToken(pub, input)
		if input == valid {
			if err != nil {
				t.Fatalf("the one valid token must verify: %v", err)
			}
			return
		}
		if err == nil {
			t.Fatalf("non-identical input ACCEPTED as a valid token: %q", input)
		}
	})
}

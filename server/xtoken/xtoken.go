// Package xtoken verifies XProtect decision tokens on origin backends.
//
// It is a public package (importable as
// github.com/xeylabs/xprotect/server/xtoken) so protected services can verify
// tokens locally, without any dependency on the xprotectd runtime:
//
//	pub, err := xtoken.ParsePublicKey(jwkX)
//	claims, err := xtoken.VerifyToken(pub, token)
package xtoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidToken covers every rejected token. Use errors.Is to test for it;
// the wrapped cause says which check failed.
var ErrInvalidToken = errors.New("xtoken: invalid token")

// Decision is the verdict carried by a token.
type Decision string

const (
	DecisionAllow     Decision = "allow"
	DecisionChallenge Decision = "challenge"
	DecisionDeny      Decision = "deny"
)

// TokenClaims is the signed payload of a decision token.
type TokenClaims struct {
	Version  int      `json:"v"`    // token format version
	SiteKey  string   `json:"sid"`  // site key the challenge was issued for
	Decision Decision `json:"dec"`  // allow | challenge
	Risk     int      `json:"risk"` // 0-100 risk score at decision time
	KeyID    string   `json:"kid"`  // signing key id
	JTI      string   `json:"jti"`  // unique token id (revocation-ready)
	IssuedAt int64    `json:"iat"`  // unix seconds
	Exp      int64    `json:"exp"`  // unix seconds
}

// ParsePublicKey decodes a JWKS "x" value (base64url raw Ed25519 public key).
func ParsePublicKey(x string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("%w: bad public key encoding", ErrInvalidToken)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key must be %d bytes, got %d", ErrInvalidToken, ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyToken checks the signature and expiry of a decision token and returns
// its claims. Callers must still enforce site key and decision per their own
// policy — verification only proves xprotectd signed these claims.
func VerifyToken(pub ed25519.PublicKey, token string) (*TokenClaims, error) {
	payloadPart, sigPart, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("%w: malformed", ErrInvalidToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrInvalidToken)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrInvalidToken)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}
	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: bad claims", ErrInvalidToken)
	}
	if claims.Version != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidToken, claims.Version)
	}
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	return &claims, nil
}

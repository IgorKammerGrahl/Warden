package aat

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ThumbprintURIPrefix is the RFC 9278 JWK Thumbprint URI prefix for SHA-256.
// Draft §3.2 requires a derived token's iss to have this form, which is what
// makes I1 checkable offline: the enforcement point compares the thumbprint in
// derived.iss against parent.cnf.jwk without an external lookup.
const ThumbprintURIPrefix = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"

// b64 is base64url without padding, strict about non-canonical trailing bits.
var b64 = base64.RawURLEncoding.Strict()

// JWK is an Ed25519 public key in JWK form (RFC 8037 §2).
//
// D exists only so that a private key smuggled into cnf.jwk is detected rather
// than silently ignored: draft §3.2 requires that private key material MUST NOT
// appear there, and a field we do not decode is a field we cannot reject.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"`
}

// NewJWK builds the public JWK for an Ed25519 key.
func NewJWK(pub ed25519.PublicKey) *JWK {
	return &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   b64.EncodeToString(pub),
	}
}

// PublicKey decodes the key material.
func (j *JWK) PublicKey() (ed25519.PublicKey, error) {
	if err := j.check(); err != nil {
		return nil, err
	}
	raw, _ := b64.DecodeString(j.X) // check() already decoded it successfully
	return ed25519.PublicKey(raw), nil
}

// Thumbprint returns the RFC 7638 JWK Thumbprint using SHA-256.
func (j *JWK) Thumbprint() (string, error) {
	if err := j.check(); err != nil {
		return "", err
	}
	// RFC 7638 §3: hash the required members only, with no whitespace and the
	// member names in lexicographic order. RFC 8037 §2 fixes that set for OKP
	// as crv, kty, x — which is why this is a separate struct rather than a
	// marshal of JWK, whose field order differs and which carries d.
	ordered := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}{j.Crv, j.Kty, j.X}

	raw, err := json.Marshal(ordered)
	if err != nil {
		return "", fmt.Errorf("aat: marshal thumbprint input: %w", err)
	}
	sum := sha256.Sum256(raw)
	return b64.EncodeToString(sum[:]), nil
}

// ThumbprintURI returns the RFC 9278 URI form required of a derived token's iss.
func (j *JWK) ThumbprintURI() (string, error) {
	tp, err := j.Thumbprint()
	if err != nil {
		return "", err
	}
	return ThumbprintURIPrefix + tp, nil
}

// check enforces the shape of an Ed25519 public JWK.
func (j *JWK) check() error {
	if j == nil {
		return errors.New("aat: cnf.jwk is absent")
	}
	if j.Kty != "OKP" {
		return fmt.Errorf("aat: jwk kty is %q, want OKP", j.Kty)
	}
	if j.Crv != "Ed25519" {
		return fmt.Errorf("aat: jwk crv is %q, want Ed25519", j.Crv)
	}
	if j.D != "" {
		return errors.New("aat: jwk carries private key material (§3.2: MUST NOT appear in cnf)")
	}
	raw, err := b64.DecodeString(j.X)
	if err != nil {
		return fmt.Errorf("aat: jwk x is not base64url: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("aat: jwk x is %d bytes, want %d",
			len(raw), ed25519.PublicKeySize)
	}
	return nil
}

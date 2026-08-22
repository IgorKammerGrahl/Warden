package aat

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/igorkg/warden/internal/aat/jws"
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

// algKeyTypes binds each permitted JWS algorithm to the key type it requires.
// Draft §7 steps 3a, 4a and 7a make this a check separate from the §8.13
// allowlist: the allowlist says the algorithm is one we accept, this says the
// algorithm matches the key we are about to verify against.
var algKeyTypes = map[jws.Algorithm]struct{ Kty, Crv string }{
	jws.EdDSA: {Kty: "OKP", Crv: "Ed25519"},
}

// checkAlgorithm rejects a declared alg that is inconsistent with this key's
// kty and crv.
//
// §7's post-algorithm note requires denial "regardless of whether the signature
// bytes would verify under an alternate interpretation", which is why callers
// run this BEFORE signature verification rather than as a fallback after it: an
// attacker who can choose the key type must not be able to reach the signature
// check at all.
func (j *JWK) checkAlgorithm(alg jws.Algorithm) error {
	if j == nil {
		return errors.New("aat: no verifying key")
	}
	want, ok := algKeyTypes[alg]
	if !ok {
		return fmt.Errorf("aat: algorithm %q has no key type binding", alg)
	}
	if j.Kty != want.Kty || j.Crv != want.Crv {
		return fmt.Errorf(
			"aat: alg %q requires kty %q crv %q, verifying key is kty %q crv %q (§7 steps 3a/4a/7a)",
			alg, want.Kty, want.Crv, j.Kty, j.Crv)
	}
	return nil
}

// privateJWKMembers are every member that carries private key material across
// the key types of RFC 7517/7518/8037: the RSA private exponent, primes and CRT
// values, the EC and OKP private scalar, and the symmetric key. Draft §3.2 says
// private key material MUST NOT appear in cnf, and §7 steps 3l and 4b2 make
// rejecting it part of verification.
//
// This is checked against the raw JSON rather than the decoded JWK because a
// member we do not decode is a member we cannot reject: an RSA key smuggled in
// as cnf.jwk would otherwise be turned away for its kty, reporting the wrong
// reason and only by luck.
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// checkNoPrivateKeyMaterial rejects a cnf object whose jwk carries any private
// member.
func checkNoPrivateKeyMaterial(rawCnf json.RawMessage) error {
	var cnf struct {
		JWK map[string]json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(rawCnf, &cnf); err != nil {
		return fmt.Errorf("aat: cnf is not an object: %w", err)
	}
	for _, member := range privateJWKMembers {
		if _, ok := cnf.JWK[member]; ok {
			return fmt.Errorf(
				"aat: cnf.jwk carries private key member %q (§3.2; §7 steps 3l, 4b2)",
				member)
		}
	}
	return nil
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

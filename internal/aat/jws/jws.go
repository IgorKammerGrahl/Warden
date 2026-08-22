// Package jws implements the JWS compact serialization (RFC 7515) restricted
// to Ed25519 (EdDSA, RFC 8037), which AAT draft-01 §3.2 requires every
// implementation to support.
//
// The restriction is deliberate. Draft §8.13 requires an explicit algorithm
// allowlist, requires alg:"none" to be rejected unconditionally, and requires
// that the absence of alg never be treated as any permitted algorithm. A
// package that only knows one algorithm cannot be confused into accepting
// another, so the allowlist here is a one-entry map rather than a policy knob.
//
// Parse does NOT verify. Draft §7 step 2c requires extracting jti from an
// unverified payload before signature verification, so this decode path runs on
// attacker-controlled bytes by design — hence FuzzParse.
package jws

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/igorkg/warden/internal/aat/jcs"
)

// Algorithm is a JWS "alg" header parameter value.
type Algorithm string

// EdDSA is the only algorithm this implementation permits.
const EdDSA Algorithm = "EdDSA"

// permitted is the §8.13 allowlist. Adding an entry means auditing Sign and
// Verify, which are written against Ed25519's key and signature sizes.
var permitted = map[Algorithm]bool{EdDSA: true}

// ErrSignature reports a cryptographically invalid signature, as distinct from
// a malformed token. Callers must not leak the difference to a remote peer.
var ErrSignature = errors.New("jws: signature verification failed")

// Header is the JWS protected header. Unrecognized members are ignored per
// RFC 7515 §4, except that any "crit" member is rejected: we understand no
// extensions, and §4.1.11 requires rejection of what we do not understand.
type Header struct {
	Alg  Algorithm `json:"alg"`
	Typ  string    `json:"typ,omitempty"`
	Kid  string    `json:"kid,omitempty"`
	Crit []string  `json:"crit,omitempty"`
}

// Message is a parsed but UNVERIFIED JWS. Nothing in it may be trusted until
// Verify returns nil.
type Message struct {
	Header    Header
	Payload   []byte
	Signature []byte

	// SigningInput is the RFC 7515 §5.1 input, BASE64URL(header) || '.' ||
	// BASE64URL(payload). It is retained rather than recomputed because
	// re-encoding could differ from the bytes the signer actually signed, and
	// because draft §4.6 (I5) hashes exactly these bytes to form par_hash.
	SigningInput []byte
}

// b64 is base64url without padding (RFC 7515 Appendix C). Strict rejects
// non-canonical trailing bits, which would otherwise give a token two distinct
// encodings and a verifier two distinct signing inputs.
var b64 = base64.RawURLEncoding.Strict()

// Sign produces the compact serialization of payload under key.
func Sign(hdr Header, payload []byte, key ed25519.PrivateKey) (string, error) {
	if err := hdr.check(); err != nil {
		return "", err
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("jws: Ed25519 private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(key))
	}
	// Every payload this system signs is a JSON object; an empty one is a bug
	// upstream, not a token worth minting.
	if len(payload) == 0 {
		return "", errors.New("jws: empty payload")
	}

	raw, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("jws: marshal header: %w", err)
	}

	signingInput := b64.EncodeToString(raw) + "." + b64.EncodeToString(payload)
	sig := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// Parse decodes a compact serialization and enforces the header allowlist. It
// performs no cryptography: the result is unverified.
func Parse(compact string) (*Message, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jws: compact serialization has %d parts, want 3", len(parts))
	}
	// An empty signature part is the unsecured-JWS attack; an empty header or
	// payload is not a token we ever mint.
	for i, name := range []string{"header", "payload", "signature"} {
		if parts[i] == "" {
			return nil, fmt.Errorf("jws: empty %s", name)
		}
	}

	rawHeader, err := decodePart("header", parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := decodePart("payload", parts[1])
	if err != nil {
		return nil, err
	}
	sig, err := decodePart("signature", parts[2])
	if err != nil {
		return nil, err
	}

	// RFC 7515 §4: header parameter names MUST be unique. Go's encoding/json
	// keeps the last duplicate silently, so {"alg":"none","alg":"EdDSA"} would
	// read as EdDSA here and as none in an implementation that keeps the first.
	// Canonicalizing rejects duplicates (and invalid UTF-8) and is already
	// tested against RFC 8785's vectors; the output is discarded.
	// ponytail: reuses jcs rather than a bespoke uniqueness scan. If a header
	// ever needs a value jcs rejects — a non-double number, say — replace this
	// with a token-level scan.
	if _, err := jcs.Canonicalize(rawHeader); err != nil {
		return nil, fmt.Errorf("jws: invalid header: %w", err)
	}

	var hdr Header
	if err := json.Unmarshal(rawHeader, &hdr); err != nil {
		return nil, fmt.Errorf("jws: parse header: %w", err)
	}
	if err := hdr.check(); err != nil {
		return nil, err
	}

	return &Message{
		Header:       hdr,
		Payload:      payload,
		Signature:    sig,
		SigningInput: []byte(parts[0] + "." + parts[1]),
	}, nil
}

// decodePart decodes one base64url segment and requires the encoding to be the
// canonical one. Two things make that check necessary: Strict() rejects
// non-zero trailing bits but Go's decoder still silently skips \r and \n, and
// RawURLEncoding still accepts input that re-encodes differently. Either would
// give a single token many textual encodings — one signature, many par_hash
// inputs, and many keys for a jti replay cache that keys on the wire string.
func decodePart(name, s string) ([]byte, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("jws: decode %s: %w", name, err)
	}
	if b64.EncodeToString(raw) != s {
		return nil, fmt.Errorf("jws: %s is not canonical base64url", name)
	}
	return raw, nil
}

// Verify checks the signature over the signing input. It re-checks the
// algorithm because a Message can be constructed without going through Parse.
func (m *Message) Verify(key ed25519.PublicKey) error {
	if err := m.Header.check(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("jws: Ed25519 public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(key))
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("jws: Ed25519 signature must be %d bytes, got %d",
			ed25519.SignatureSize, len(m.Signature))
	}
	if !ed25519.Verify(key, m.SigningInput, m.Signature) {
		return ErrSignature
	}
	return nil
}

// check applies the §8.13 allowlist. The empty algorithm is rejected by the
// same lookup that rejects "none", so a header with no alg member cannot be
// treated as any permitted algorithm.
func (h Header) check() error {
	if !permitted[h.Alg] {
		return fmt.Errorf("jws: algorithm %q is not permitted", h.Alg)
	}
	if len(h.Crit) > 0 {
		return fmt.Errorf("jws: unrecognized critical header parameters %v", h.Crit)
	}
	return nil
}

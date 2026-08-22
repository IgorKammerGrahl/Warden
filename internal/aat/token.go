// Package aat implements the AAT token format from
// draft-niyikiza-oauth-attenuating-agent-tokens-01: the claim set of §3.2,
// the PoP JWT of §5.2, and the cryptographic linkage of §4.6.
//
// Scope boundary. Everything here is SINGLE-TOKEN: a token's own claims, its
// own signature, its own shape. The chain invariants I1-I5 (§4.2-§4.6), the
// eight-step verification algorithm (§7), constraint evaluation (§3.4) and
// subsumption (§4.5) are deliberately absent — they belong to M0b and to
// internal/core. Verify here means "this token was signed by this key and is
// structurally well formed", never "this chain is authorized".
package aat

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/igorkg/warden/internal/aat/jcs"
	"github.com/igorkg/warden/internal/aat/jws"
)

// DefaultMaxTokenSize is the value draft §4.3.1 RECOMMENDS.
const DefaultMaxTokenSize = 65536

// MaxTokenSize bounds the encoded size of a single token. §4.3.1 requires
// implementations to enforce a finite limit; 64 KiB is only a RECOMMENDATION,
// so this is operator configuration.
//
// Set it once at startup, before any token is parsed. It is a plain package
// variable rather than a field on a parser: nothing in this milestone needs two
// limits in one process, and a mutable global read concurrently is only safe
// because it is written once. Give it a home on a config struct when the daemon
// grows one.
//
// A non-positive value is a misconfiguration, not "unlimited": §4.3.1 requires
// the limit to be finite, so Parse fails closed rather than disabling the check.
var MaxTokenSize = DefaultMaxTokenSize

// Confirmation is the RFC 7800 cnf claim. Draft §3.2 requires it to carry the
// holder's public key as jwk.
type Confirmation struct {
	JWK *JWK `json:"jwk"`
}

// Claims is the AAT claim set of draft §3.2 Table 1.
//
// Unrecognized claims are ignored rather than rejected: the draft's extension
// model puts future members here, including this project's proposed
// invocation_constraints. They are not preserved across decode, so a Token is
// never re-serialized — Payload and SigningInput return the bytes that were
// actually signed.
//
// sub is intentionally absent, per the text following Table 1: holder identity
// is fully determined by cnf.jwk.
type Claims struct {
	JTI                  string            `json:"jti"`
	Issuer               string            `json:"iss"`
	IssuedAt             int64             `json:"iat"`
	Expires              int64             `json:"exp"`
	Confirmation         Confirmation      `json:"cnf"`
	DelegationDepth      int               `json:"del_depth"`
	MaxDelegationDepth   int               `json:"del_max_depth"`
	ParentHash           string            `json:"par_hash,omitempty"`
	AuthorizationDetails []json.RawMessage `json:"authorization_details"`
}

// requiredClaims are the members marked REQUIRED in Table 1. par_hash is
// excluded: its requirement is conditional on del_depth and is checked in
// validate. Presence must be tested against the raw payload because a decoded
// zero value cannot distinguish an absent claim from a present zero.
var requiredClaims = []string{
	"jti", "iss", "iat", "exp", "cnf", "del_depth", "del_max_depth",
	"authorization_details",
}

// Token is a parsed AAT. A Token from Parse is UNVERIFIED until Verify returns
// nil; its claims are structurally valid but cryptographically unattested.
type Token struct {
	Claims Claims

	msg     *jws.Message
	compact string
}

// Mint signs a new token. key is the issuer's signing key: the root issuer's
// key for a root token, or the parent's holder key for a derived one.
func Mint(c Claims, key ed25519.PrivateKey) (*Token, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}

	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("aat: marshal claims: %w", err)
	}
	// The draft requires JCS only for the PoP payload (§5.2), not for AATs.
	// Canonicalizing anyway costs one call and makes minting deterministic,
	// which is what lets a test compare two independently minted tokens.
	payload, err := jcs.Canonicalize(raw)
	if err != nil {
		return nil, fmt.Errorf("aat: canonicalize claims: %w", err)
	}

	compact, err := jws.Sign(jws.Header{Alg: jws.EdDSA, Typ: "JWT"}, payload, key)
	if err != nil {
		return nil, err
	}
	// Parse rather than construct: whatever Mint emits must be something Parse
	// accepts, and routing through it makes the two definitions impossible to
	// drift apart.
	return Parse(compact)
}

// Parse decodes and structurally validates a token. It does NOT verify the
// signature — draft §7 step 2c requires reading jti from an unverified payload
// before signature verification, so this path runs on attacker-controlled bytes.
func Parse(compact string) (*Token, error) {
	if err := checkSize("token", len(compact)); err != nil {
		return nil, err
	}

	msg, err := jws.Parse(compact)
	if err != nil {
		return nil, err
	}

	// Duplicate claim names would let us read del_depth:0 where an
	// implementation that keeps the first duplicate reads del_depth:9 — same
	// signature, two different tokens. Canonicalizing rejects that (and invalid
	// UTF-8); the output is discarded.
	if _, err := jcs.Canonicalize(msg.Payload); err != nil {
		return nil, fmt.Errorf("aat: invalid payload: %w", err)
	}

	var present map[string]json.RawMessage
	if err := json.Unmarshal(msg.Payload, &present); err != nil {
		return nil, fmt.Errorf("aat: payload is not a JSON object: %w", err)
	}
	for _, name := range requiredClaims {
		if _, ok := present[name]; !ok {
			return nil, fmt.Errorf("aat: required claim %q is absent (§3.2 Table 1)", name)
		}
	}

	if err := checkNoPrivateKeyMaterial(present["cnf"]); err != nil {
		return nil, err
	}

	var c Claims
	if err := json.Unmarshal(msg.Payload, &c); err != nil {
		return nil, fmt.Errorf("aat: decode claims: %w", err)
	}
	// A present-but-empty par_hash is not an absent par_hash; validate sees
	// only the decoded string, so the distinction is drawn here.
	if _, ok := present["par_hash"]; ok && c.ParentHash == "" {
		return nil, errors.New("aat: par_hash is present but empty")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}

	return &Token{Claims: c, msg: msg, compact: compact}, nil
}

// Verify checks this token's signature against key. Single token only: it does
// not walk a chain, does not check I1-I5, and does not evaluate constraints.
// The caller selects key — a trust anchor for a root token, the parent's
// cnf.jwk for a derived one — and that selection is chain verification's job.
//
// key is a JWK rather than a raw public key so that the §7 algorithm/key
// consistency check is possible at all: an ed25519.PublicKey cannot express the
// mismatch the check exists to catch.
func (t *Token) Verify(key *JWK) error {
	if err := key.checkAlgorithm(t.msg.Header.Alg); err != nil {
		return err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return err
	}
	return t.msg.Verify(pub)
}

// checkSize enforces the §4.3.1 MAX_TOKEN_SIZE limit.
func checkSize(kind string, n int) error {
	if MaxTokenSize <= 0 {
		return fmt.Errorf("aat: MaxTokenSize is %d; §4.3.1 requires a finite positive limit",
			MaxTokenSize)
	}
	if n > MaxTokenSize {
		return fmt.Errorf("aat: %s is %d bytes, exceeds MaxTokenSize %d",
			kind, n, MaxTokenSize)
	}
	return nil
}

// Compact returns the wire form.
func (t *Token) Compact() string { return t.compact }

// Payload returns the claim bytes exactly as signed.
func (t *Token) Payload() []byte { return t.msg.Payload }

// SigningInput returns the RFC 7515 §5.1 signing input, which is what a child
// token's par_hash commits to (§4.6).
func (t *Token) SigningInput() []byte { return t.msg.SigningInput }

// ParentHash computes the par_hash a token derived from parent must carry:
// base64url-nopad(SHA-256(parent token signing input)), per draft §4.6 (I5).
func ParentHash(parent *Token) string {
	sum := sha256.Sum256(parent.SigningInput())
	return b64.EncodeToString(sum[:])
}

// validate applies the single-token rules of Table 1 and the one line of I2
// that is quantified over a single token (derived.del_depth <=
// derived.del_max_depth, §4.3). Rules relating a token to its parent are not
// checked here and cannot be: they need the parent.
func (c Claims) validate() error {
	if c.JTI == "" {
		return errors.New("aat: jti is empty")
	}
	if err := checkUUIDCase("jti", c.JTI); err != nil {
		return err
	}
	if c.Issuer == "" {
		return errors.New("aat: iss is empty")
	}
	if c.IssuedAt <= 0 {
		return fmt.Errorf("aat: iat is %d, want a positive NumericDate", c.IssuedAt)
	}
	if c.Expires <= c.IssuedAt {
		return fmt.Errorf("aat: exp (%d) must be greater than iat (%d) (§3.2 Table 1)",
			c.Expires, c.IssuedAt)
	}
	if err := c.Confirmation.JWK.check(); err != nil {
		return err
	}
	if c.DelegationDepth < 0 {
		return fmt.Errorf("aat: del_depth is %d, want non-negative", c.DelegationDepth)
	}
	if c.MaxDelegationDepth < 0 {
		return fmt.Errorf("aat: del_max_depth is %d, want non-negative (§3.2 Table 1)",
			c.MaxDelegationDepth)
	}
	if c.DelegationDepth > c.MaxDelegationDepth {
		return fmt.Errorf("aat: del_depth (%d) exceeds del_max_depth (%d) (§4.3 I2)",
			c.DelegationDepth, c.MaxDelegationDepth)
	}
	if c.AuthorizationDetails == nil {
		return errors.New("aat: authorization_details is absent or null (§3.2 Table 1)")
	}

	// par_hash: MUST be absent in root tokens, MUST be present in all derived
	// tokens (§3.2 Table 1). del_depth == 0 is what makes a token a root.
	root := c.DelegationDepth == 0
	switch {
	case root && c.ParentHash != "":
		return errors.New("aat: par_hash MUST be absent in root tokens (§3.2 Table 1)")
	case !root && c.ParentHash == "":
		return errors.New("aat: par_hash MUST be present in derived tokens (§3.2 Table 1)")
	}
	if !root {
		raw, err := b64.DecodeString(c.ParentHash)
		if err != nil {
			return fmt.Errorf("aat: par_hash is not base64url-nopad: %w", err)
		}
		if len(raw) != sha256.Size {
			return fmt.Errorf("aat: par_hash decodes to %d bytes, want %d",
				len(raw), sha256.Size)
		}
		// Table 1: a derived token's iss MUST be a JWK Thumbprint URI over its
		// signing key. Only the form is checkable here; matching it against
		// parent.cnf.jwk is I1.
		if !strings.HasPrefix(c.Issuer, ThumbprintURIPrefix) {
			return fmt.Errorf("aat: derived token iss %q is not a JWK Thumbprint URI (§3.2)",
				c.Issuer)
		}
	}
	return nil
}

// checkUUIDCase enforces the Table 1 rule that a jti which IS a UUID must be
// lowercase hyphenated per RFC 9562. A jti that is not a UUID is permitted:
// UUIDv7 is a SHOULD, not a MUST.
func checkUUIDCase(name, s string) error {
	if !looksLikeUUID(s) {
		return nil
	}
	if s != strings.ToLower(s) {
		return fmt.Errorf("aat: %s is a UUID but not lowercase hyphenated (§3.2, RFC 9562): %q",
			name, s)
	}
	return nil
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexDigit(r) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}

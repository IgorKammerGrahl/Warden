package aat

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/igorkg/warden/internal/aat/jcs"
	"github.com/igorkg/warden/internal/aat/jws"
)

// PoPClaims is the proof-of-possession JWT claim set of draft §5.2 Table 4.
// The holder of the leaf token produces one per tool invocation, signed with
// the private key matching the leaf token's cnf.jwk.
type PoPClaims struct {
	JTI      string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	TokenID  string `json:"aat_id"`
	Tool     string `json:"aat_tool"`
	// Audience is OPTIONAL. Deployments that require audience binding MUST
	// require it and enforce the match at verification time (§5.2) — that
	// enforcement is policy, not encoding, and lives outside this package.
	Audience string `json:"aat_aud,omitempty"`
	// Args is the hta member: argument names to argument values.
	Args map[string]any `json:"hta"`
}

var requiredPoPClaims = []string{"jti", "iat", "aat_id", "aat_tool", "hta"}

// PoP is a parsed PoP JWT. Unverified until Verify returns nil.
type PoP struct {
	Claims PoPClaims

	msg     *jws.Message
	compact string
}

// SignPoP produces a PoP JWT. key is the leaf token holder's private key.
func SignPoP(c PoPClaims, key ed25519.PrivateKey) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}

	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("aat: marshal PoP claims: %w", err)
	}
	// §5.2: the payload MUST be JCS-canonical before JWS signing. This is a
	// whole-payload requirement, not specific to hta — it is what gives hta
	// stable equality across implementations, so argument comparison at the
	// enforcement point is unambiguous.
	payload, err := jcs.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("aat: canonicalize PoP claims: %w", err)
	}

	return jws.Sign(jws.Header{Alg: jws.EdDSA, Typ: "JWT"}, payload, key)
}

// ParsePoP decodes and structurally validates a PoP JWT without verifying it.
func ParsePoP(compact string) (*PoP, error) {
	if len(compact) > MaxTokenSize {
		return nil, fmt.Errorf("aat: PoP is %d bytes, exceeds MaxTokenSize %d",
			len(compact), MaxTokenSize)
	}

	msg, err := jws.Parse(compact)
	if err != nil {
		return nil, err
	}

	// §5.2 makes canonical serialization a MUST on the producer, so a payload
	// that is not already canonical is malformed. Enforcing it here also
	// rejects duplicate claim names and invalid UTF-8, as in Parse.
	canonical, err := jcs.Canonicalize(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("aat: invalid PoP payload: %w", err)
	}
	if !bytes.Equal(msg.Payload, canonical) {
		return nil, errors.New("aat: PoP payload is not JCS-canonical (§5.2)")
	}

	var present map[string]json.RawMessage
	if err := json.Unmarshal(msg.Payload, &present); err != nil {
		return nil, fmt.Errorf("aat: PoP payload is not a JSON object: %w", err)
	}
	for _, name := range requiredPoPClaims {
		if _, ok := present[name]; !ok {
			return nil, fmt.Errorf("aat: required PoP claim %q is absent (§5.2 Table 4)", name)
		}
	}

	var c PoPClaims
	if err := json.Unmarshal(msg.Payload, &c); err != nil {
		return nil, fmt.Errorf("aat: decode PoP claims: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}

	return &PoP{Claims: c, msg: msg, compact: compact}, nil
}

// Verify checks the PoP signature against key, which the caller takes from the
// leaf token's cnf.jwk. It does not check freshness (§5.3), audience, or that
// aat_tool names a tool the leaf token authorizes — those are M0b.
func (p *PoP) Verify(key ed25519.PublicKey) error {
	return p.msg.Verify(key)
}

// Compact returns the wire form.
func (p *PoP) Compact() string { return p.compact }

// Payload returns the claim bytes exactly as signed.
func (p *PoP) Payload() []byte { return p.msg.Payload }

// SigningInput returns the RFC 7515 §5.1 signing input.
func (p *PoP) SigningInput() []byte { return p.msg.SigningInput }

func (c PoPClaims) validate() error {
	if c.JTI == "" {
		return errors.New("aat: PoP jti is empty (§5.2 Table 4)")
	}
	if err := checkUUIDCase("PoP jti", c.JTI); err != nil {
		return err
	}
	if c.IssuedAt <= 0 {
		return fmt.Errorf("aat: PoP iat is %d, want a positive NumericDate", c.IssuedAt)
	}
	if c.TokenID == "" {
		return errors.New("aat: PoP aat_id is empty (§5.2 Table 4)")
	}
	if c.Tool == "" {
		return errors.New("aat: PoP aat_tool is empty (§5.2 Table 4)")
	}
	if c.Args == nil {
		return errors.New("aat: PoP hta is absent or null (§5.2 Table 4)")
	}
	return nil
}

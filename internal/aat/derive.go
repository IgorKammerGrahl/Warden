package aat

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/igorkg/warden/internal/aat/jcs"
	"github.com/igorkg/warden/internal/core"
)

// Derivation is the child a holder wants to mint: the fields §6 leaves to the
// deriving party, and only those.
//
// del_depth, par_hash and iss are absent on purpose. §6 computes all three from
// the parent and the signing key, so Derive computes them too — a field a
// caller cannot set is an invariant a caller cannot violate, and those three
// are exactly I2's increment, I5, and I1.
type Derivation struct {
	// JTI is §6 step 1: a fresh unique identifier, RECOMMENDED UUIDv7. If it
	// is a UUID at all, Mint requires the lowercase hyphenated form (§3.2).
	JTI string

	// IssuedAt and Expires are §6 step 2 (I3): iat MUST NOT precede the
	// parent's, exp MUST NOT exceed it, and §4.4's MAX_IAT_SKEW and
	// MAX_TOKEN_LIFETIME bound both.
	IssuedAt, Expires int64

	// HolderKey is §6 step 8: the intended holder's PUBLIC key, which becomes
	// cnf.jwk. Public, because this is what makes cross-process delegation
	// work — the deriving party never needs the child holder's private key,
	// and a JWK carrying one is refused (§8.2).
	HolderKey *JWK

	// MaxDelegationDepth is §6 step 6 (I2), capped at the parent's. Setting it
	// equal to the child's own del_depth mints a terminal token: §4.3's
	// del_depth == del_max_depth, a holder that can invoke but not delegate.
	MaxDelegationDepth int

	// Tools is §6 steps 3 and 4: the tool identifiers the child may invoke,
	// each mapped to its §3.4 constraint map as a JSON object. It becomes the
	// tools member of the single §3.3 attenuating_agent_token entry.
	//
	// nil means the empty map — a token authorizing no tool. That is not an
	// error: it is the most attenuated child expressible, and refusing it
	// would make the safest derivation the one you cannot write.
	Tools map[string]json.RawMessage
}

// Deriver mints child tokens per §6.
//
// Its fields are the deployment policy Verifier takes, because derivation is
// verification run forwards: a Deriver whose Limits are looser than the
// enforcement point's will happily mint tokens that are denied on arrival.
type Deriver struct {
	// Limits are the §4.3/§4.4 bounds. The zero value is a misconfiguration
	// and is refused, same as on the verifying side.
	Limits core.Limits
	// Now overrides the clock, for tests. nil means time.Now.
	Now func() int64
}

func (dv *Deriver) now() int64 {
	if dv.Now != nil {
		return dv.Now()
	}
	return time.Now().Unix()
}

// Derive mints a child of parent, signed by signKey, per draft §6.
//
// signKey MUST be the private half of the parent's cnf.jwk. §6 step 9 requires
// it and I1 is the check: the child's iss is computed from signKey, so a caller
// signing with any other key is refused at step 4c — before a signature exists.
//
// The refusal mechanism is core.CheckLink, the same function §7 step 4 runs at
// the enforcement point, applied to the child about to be minted. That is the
// point of this API. A derivation that would be denied is never signed, and
// there is no second implementation of I1-I4 here to drift from the first.
//
// What this does NOT check is whether the parent chain above it is valid.
// Derive extends a chain; it does not vouch for one. A holder deriving from a
// token it did not verify mints a child of an unverified parent, and the
// enforcement point is where that is caught (§7 steps 1-3).
func (dv *Deriver) Derive(parent *Token, signKey ed25519.PrivateKey, d Derivation) (*Token, error) {
	if parent == nil {
		return nil, errors.New("aat: derive: no parent token")
	}
	if len(signKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("aat: derive: signing key is %d bytes, want %d",
			len(signKey), ed25519.PrivateKeySize)
	}

	// §4.3: del_depth == del_max_depth is terminal. CheckLink step 4e catches
	// this too, but as "child del_depth exceeds parent del_max_depth" — the
	// enforcement point's view of a malformed chain, not the deriving holder's
	// answer to "may I delegate at all". The holder deserves the direct one.
	if parent.Claims.DelegationDepth >= parent.Claims.MaxDelegationDepth {
		return nil, core.Deny("§6, §4.3, I2",
			"aat: derive: parent is terminal (del_depth %d, del_max_depth %d); a holder may "+
				"derive only while del_depth is strictly less than del_max_depth",
			parent.Claims.DelegationDepth, parent.Claims.MaxDelegationDepth)
	}

	// §6 step 8, checked before it is copied into cnf rather than after the
	// token exists: this is where private key material in a holder JWK gets
	// caught while it is still a caller error and not a minted secret leak.
	if d.HolderKey == nil {
		return nil, core.Deny("§6 step 8, I6", "aat: derive: no holder key for cnf.jwk")
	}
	if err := d.HolderKey.check(); err != nil {
		return nil, fmt.Errorf("aat: derive: cnf.jwk: %w", err)
	}

	// §6 step 9. Deriving iss from signKey instead of accepting it from the
	// caller is what turns I1 into a mint-time fact rather than a promise.
	iss, err := NewJWK(signKey.Public().(ed25519.PublicKey)).ThumbprintURI()
	if err != nil {
		return nil, fmt.Errorf("aat: derive: signing key: %w", err)
	}

	details, err := d.details()
	if err != nil {
		return nil, err
	}

	c := Claims{
		JTI:                  d.JTI,                             // §6 step 1
		Issuer:               iss,                               // §6 step 9 (I1)
		IssuedAt:             d.IssuedAt,                        // §6 step 2 (I3)
		Expires:              d.Expires,                         // §6 step 2 (I3)
		Confirmation:         Confirmation{JWK: d.HolderKey},    // §6 step 8 (I6)
		DelegationDepth:      parent.Claims.DelegationDepth + 1, // §6 step 5 (I2)
		MaxDelegationDepth:   d.MaxDelegationDepth,              // §6 step 6 (I2)
		ParentHash:           ParentHash(parent),                // §6 step 7 (I5)
		AuthorizationDetails: details,                           // §6 steps 3, 4 (I4)
	}

	// Projection first, because it is also §3.3 shape and MAX_CONSTRAINT_DEPTH
	// parsing: a constraint map this cannot parse is one no verifier will
	// accept either, and finding that out here beats finding it out on arrival.
	parentDom, err := project(parent)
	if err != nil {
		return nil, fmt.Errorf("aat: derive: parent: %w", err)
	}
	childDom, err := projectClaims(c)
	if err != nil {
		return nil, fmt.Errorf("aat: derive: child: %w", err)
	}
	// I1-I4, by the enforcement point's own code. §6 step 4's two rules — a
	// non-empty parent map requires the child to carry exactly the same
	// argument keys, an empty one lets the child introduce them — live inside
	// CheckI4 and are unreachable from here, which is the intent.
	if err := core.CheckLink(parentDom, childDom, dv.now(), dv.Limits); err != nil {
		return nil, fmt.Errorf("aat: derive: %w", err)
	}
	return Mint(c, signKey)
}

// details wraps Tools in the single §3.3 attenuating_agent_token entry.
func (d Derivation) details() ([]json.RawMessage, error) {
	tools := d.Tools
	if tools == nil {
		tools = map[string]json.RawMessage{}
	}
	entry, err := json.Marshal(struct {
		Type  string                     `json:"type"`
		Tools map[string]json.RawMessage `json:"tools"`
	}{core.CapabilityType, tools})
	if err != nil {
		return nil, fmt.Errorf("aat: derive: capability entry: %w", err)
	}
	// NOTES.md #7, applied to constraint literals rather than to invocation
	// arguments. RFC 8785 serializes every number through binary64, and an AAT
	// payload is canonicalized before it is signed — so a bound above 2^53
	// gets signed as a different number than the issuer wrote. Refused here
	// because warden is the issuer: minting it would produce a token that does
	// not constrain what its own issuer asked for, and the holder would have
	// no way to tell.
	if err := jcs.CheckNumbers(entry); err != nil {
		return nil, core.Deny("§3.4, RFC 8785 §3.2.2.3", "aat: derive: constraint literal: %w", err)
	}
	return []json.RawMessage{entry}, nil
}

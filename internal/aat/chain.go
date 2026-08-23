package aat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/igorkg/warden/internal/aat/jcs"
	"github.com/igorkg/warden/internal/aat/jws"
	"github.com/igorkg/warden/internal/core"
)

// DefaultMaxStackSize is the value draft §4.3.1 RECOMMENDS for MAX_STACK_SIZE.
const DefaultMaxStackSize = 262144

// MaxStackSize bounds the total encoded size of a chain (§4.3.1, §7 step 2b).
// Operator configuration, on the same terms as MaxTokenSize: set once at
// startup, and a non-positive value is a misconfiguration rather than
// "unlimited".
var MaxStackSize = DefaultMaxStackSize

// DefaultPoPSkew is the ±30 seconds §5.3 RECOMMENDS as the PoP clock tolerance.
const DefaultPoPSkew = 30

// Verifier runs the §7 chain verification algorithm. Its fields are the
// deployment policy the algorithm takes as given: who is trusted, what the
// finite limits are, and whether PoP audience binding is required.
type Verifier struct {
	// TrustAnchors are the public keys trusted as root issuers. A root token
	// verifying under any one of them satisfies step 3b.
	TrustAnchors []*JWK

	// Limits are the §4.3/§4.4 bounds. The zero value is a misconfiguration;
	// use core.DefaultLimits as a starting point.
	Limits core.Limits

	// PoPSkew is the §5.3 clock tolerance window in seconds, applied
	// symmetrically around now.
	PoPSkew int64

	// Audience, when non-empty, means this deployment requires PoP audience
	// binding (§5.3 rule 3, §7 step 7d): the PoP JWT MUST carry a matching
	// aat_aud. Empty means the deployment does not require it, which is the
	// draft's default since aat_aud is OPTIONAL.
	Audience string

	// Now overrides the clock, for tests. nil means time.Now.
	Now func() int64
}

func (v *Verifier) now() int64 {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().Unix()
}

// Verify executes draft §7 steps 1 through 8 in order and returns nil only on
// step 8, PERMIT. Any error is a DENY; the caller must not distinguish between
// them to a remote peer.
//
// The ordering is normative, not incidental. §5.3: an enforcement point MUST
// complete chain verification (steps 1-6) before evaluating the PoP JWT, and a
// valid PoP against an invalid chain MUST NOT authorize. So the PoP is not
// touched until step 7, after the chain has been accepted whole.
func (v *Verifier) Verify(chain []string, tool string, args map[string]any, popJWT string) error {
	// Step 1.
	if len(chain) == 0 {
		return core.Deny("§7 step 1", "aat: empty chain")
	}
	now := v.now()

	// Step 2a, 2b.
	total := 0
	for i, compact := range chain {
		if err := checkSize(fmt.Sprintf("chain[%d]", i), len(compact)); err != nil {
			return core.Deny("§7 step 2a, §4.3.1", "aat: %w", err)
		}
		total += len(compact)
	}
	if MaxStackSize <= 0 {
		return core.Deny("§4.3.1", "aat: MaxStackSize is %d; a finite positive limit is required",
			MaxStackSize)
	}
	if total > MaxStackSize {
		return core.Deny("§7 step 2b", "aat: chain is %d bytes, exceeds MaxStackSize %d",
			total, MaxStackSize)
	}

	// Step 2c. The sole parse permitted before signature verification, and only
	// for the jti string. What comes out is untrusted and is used for nothing
	// but cycle detection: every later comparison against a jti reads it from a
	// token whose signature has verified.
	seen := make(map[string]struct{}, len(chain))
	for i, compact := range chain {
		jti, err := extractJTI(compact)
		if err != nil {
			return core.Deny("§7 step 2c", "aat: chain[%d]: %w", i, err)
		}
		if _, dup := seen[jti]; dup {
			return core.Deny("§7 step 2c, cycle detection",
				"aat: jti %q appears more than once in the presented chain",
				jti)
		}
		seen[jti] = struct{}{}
	}

	// Step 3.
	rootTok, err := v.verifyRoot(chain[0])
	if err != nil {
		return err
	}
	rootDom, err := project(rootTok)
	if err != nil {
		return fmt.Errorf("aat: root: %w", err) // project cites its own clause
	}
	if err := core.CheckRoot(rootDom, now, v.Limits); err != nil {
		return err
	}

	// Step 4. Steps 3d (par_hash absent from the root), 4b1-4b5 and the
	// public-key shape of 3l/4b2 are enforced inside Parse, which every token
	// here goes through after its signature verifies.
	parentTok, parentDom := rootTok, rootDom
	for i := 1; i < len(chain); i++ {
		// 4a, 4b: the child is signed by the parent's holder key, so choosing
		// that key is what step 4 does and why the loop cannot be reordered.
		childTok, err := verifyThenParse(chain[i], parentTok.Claims.Confirmation.JWK)
		if err != nil {
			return core.Deny("§7 steps 4a-4b, I1", "aat: chain[%d]: %w", i, err)
		}
		// 4n, 4o.
		childDom, err := project(childTok)
		if err != nil {
			return fmt.Errorf("aat: chain[%d]: %w", i, err)
		}
		// 4c-4p.
		if err := core.CheckLink(parentDom, childDom, now, v.Limits); err != nil {
			return fmt.Errorf("aat: chain[%d]: %w", i, err)
		}
		// 4q (I5). par_hash commits the child to one parent token instance,
		// which the signature and I1 together do not do when a holder key holds
		// several compatible parents.
		if want := ParentHash(parentTok); childTok.Claims.ParentHash != want {
			return core.Deny("§7 step 4q, I5",
				"aat: chain[%d] par_hash %q does not match SHA-256 of the parent signing input %q",
				i, childTok.Claims.ParentHash, want)
		}
		parentTok, parentDom = childTok, childDom
	}

	// Step 5.
	leafTok, leafDom := parentTok, parentDom
	if len(chain) != leafDom.Depth+1 {
		return core.Deny("§7 step 5", "aat: chain has %d tokens, leaf del_depth is %d",
			len(chain), leafDom.Depth)
	}

	// Step 6a.
	if leafDom.Caps == nil {
		return core.Deny("§7 step 6a",
			"aat: leaf carries no %q entry; §3.3 requires exactly one in a leaf token",
			core.CapabilityType)
	}
	// Step 6b.
	if err := leafDom.Caps.CheckInvocation(tool, args); err != nil {
		return err
	}

	// Step 7. Chain verification is complete; only now is the PoP looked at.
	if err := v.verifyPoP(popJWT, leafTok, tool, args, now); err != nil {
		return err
	}

	return nil // Step 8. PERMIT.
}

// verifyRoot is §7 steps 3a and 3b: the root verifies under some trust anchor,
// with the algorithm/key consistency check applied per candidate key.
func (v *Verifier) verifyRoot(compact string) (*Token, error) {
	if len(v.TrustAnchors) == 0 {
		return nil, core.Deny("§7 step 3b", "aat: no trust anchors configured")
	}
	var last error
	for _, anchor := range v.TrustAnchors {
		tok, err := verifyThenParse(compact, anchor)
		if err == nil {
			return tok, nil
		}
		last = err
	}
	return nil, core.Deny("§7 steps 3a-3b, I1", "aat: root verifies under no trust anchor: %w", last)
}

// verifyThenParse enforces §7's ordering for one token: signature first, claims
// after.
//
// jws.Parse splits the compact serialization and decodes the protected header.
// That is not the "application-layer claim deserialization" the step-8 note
// defers — the payload comes back as bytes, and nothing reads a claim out of it
// until Parse runs, which is after ed25519.Verify has succeeded over exactly
// those bytes.
func verifyThenParse(compact string, key *JWK) (*Token, error) {
	msg, err := jws.Parse(compact)
	if err != nil {
		return nil, err
	}
	// Before the signature check, not after: §7 requires denial on an
	// alg/key-type mismatch regardless of whether the bytes would verify under
	// an alternate interpretation.
	if err := key.checkAlgorithm(msg.Header.Alg); err != nil {
		return nil, err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := msg.Verify(pub); err != nil {
		return nil, err
	}
	return Parse(compact)
}

// project maps a verified token onto the domain. The thumbprint URI is computed
// here rather than in core because only this layer knows what a JWK is; §3.3
// parsing and MAX_CONSTRAINT_DEPTH (steps 3n, 4o) come from core.
func project(t *Token) (*core.Token, error) {
	uri, err := t.Claims.Confirmation.JWK.ThumbprintURI()
	if err != nil {
		return nil, core.Deny("§7 steps 3l, 4b2", "aat: cnf.jwk: %w", err)
	}
	caps, err := core.ParseCapabilities(t.Claims.AuthorizationDetails)
	if err != nil {
		return nil, err
	}
	return &core.Token{
		JTI:          t.Claims.JTI,
		Issuer:       t.Claims.Issuer,
		IssuedAt:     t.Claims.IssuedAt,
		Expires:      t.Claims.Expires,
		Depth:        t.Claims.DelegationDepth,
		MaxDepth:     t.Claims.MaxDelegationDepth,
		HolderKeyURI: uri,
		Caps:         caps,
	}, nil
}

// verifyPoP is §7 step 7 and the §5.3 rejection list (I6).
func (v *Verifier) verifyPoP(compact string, leaf *Token, tool string, args map[string]any, now int64) error {
	// 7a, 7b.
	pop, err := verifyThenParsePoP(compact, leaf.Claims.Confirmation.JWK)
	if err != nil {
		return core.Deny("§7 steps 7a-7b, I6", "aat: PoP: %w", err)
	}
	// 7c. leaf.Claims.JTI comes from a verified token, not from step 2c.
	if pop.Claims.TokenID != leaf.Claims.JTI {
		return core.Deny("§7 step 7c", "aat: PoP aat_id %q is not the leaf jti %q",
			pop.Claims.TokenID, leaf.Claims.JTI)
	}
	// 7d. Audience binding is deployment policy; when required it is a MUST.
	if v.Audience != "" && pop.Claims.Audience != v.Audience {
		return core.Deny("§7 step 7d", "aat: PoP aat_aud %q does not identify this enforcement point %q",
			pop.Claims.Audience, v.Audience)
	}
	// 7e. Exact string comparison, per §3.3.1: no normalization of any kind.
	if pop.Claims.Tool != tool {
		return core.Deny("§7 step 7e, §3.3.1", "aat: PoP aat_tool %q is not the invoked tool %q",
			pop.Claims.Tool, tool)
	}
	// 7f.
	if err := sameCanonicalArgs(pop, args); err != nil {
		return err
	}
	// 7g.
	if v.PoPSkew <= 0 {
		return core.Deny("§5.3", "aat: PoPSkew is %d; a finite positive tolerance window is required",
			v.PoPSkew)
	}
	if delta := pop.Claims.IssuedAt - now; delta > v.PoPSkew || delta < -v.PoPSkew {
		return core.Deny("§7 step 7g, §5.3",
			"aat: PoP iat %d is %ds from now %d, outside the ±%ds tolerance",
			pop.Claims.IssuedAt, delta, now, v.PoPSkew)
	}
	return nil
}

func verifyThenParsePoP(compact string, key *JWK) (*PoP, error) {
	msg, err := jws.Parse(compact)
	if err != nil {
		return nil, err
	}
	if err := key.checkAlgorithm(msg.Header.Alg); err != nil {
		return nil, err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	if err := msg.Verify(pub); err != nil {
		return nil, err
	}
	return ParsePoP(compact)
}

// sameCanonicalArgs is §7 step 7f: pop_jwt.hta and the invocation args must
// agree as JCS byte sequences.
//
// Both sides are canonicalized independently and the BYTES are compared. Not
// the raw JSON, which two conformant producers spell differently for the same
// value; not the decoded maps, because reflect.DeepEqual over any would give
// this security check its own private notion of equality, distinct from the one
// the signature covers. hta is read back out of the payload rather than
// re-marshalled from PoPClaims.Args so that what is compared is what was signed.
func sameCanonicalArgs(pop *PoP, args map[string]any) error {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(pop.Payload(), &payload); err != nil {
		return core.Deny("§7 step 7f", "aat: PoP payload: %w", err)
	}
	hta, ok := payload["hta"]
	if !ok {
		return core.Deny("§5.2 Table 4", "aat: PoP has no hta member")
	}
	htaCanonical, err := jcs.Canonicalize(hta)
	if err != nil {
		return core.Deny("§7 step 7f", "aat: canonicalize PoP hta: %w", err)
	}

	if args == nil {
		args = map[string]any{}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return core.Deny("§7 step 7f", "aat: marshal invocation args: %w", err)
	}
	argsCanonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return core.Deny("§7 step 7f", "aat: canonicalize invocation args: %w", err)
	}

	if !bytes.Equal(htaCanonical, argsCanonical) {
		return core.Deny("§7 step 7f", "aat: PoP hta does not match the invocation arguments: "+
			"hta canonicalizes to %s, args to %s", htaCanonical, argsCanonical)
	}
	return nil
}

// extractJTI is §7 step 2c: decode the base64url payload segment and read only
// the jti string, before any signature has been verified.
//
// Nothing else is read out. The draft permits this single extraction for cycle
// detection and requires the result be treated as untrusted until that token's
// signature verifies — which is why the returned value never leaves the
// duplicate-detection set in Verify.
func extractJTI(compact string) (string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", errors.New("not a JWS compact serialization")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload is not base64url: %w", err)
	}
	var probe struct {
		JTI *string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return "", fmt.Errorf("payload is not valid JSON: %w", err)
	}
	if probe.JTI == nil {
		return "", errors.New("payload has no string-valued jti")
	}
	if *probe.JTI == "" {
		return "", errors.New("payload jti is empty")
	}
	return *probe.JTI, nil
}

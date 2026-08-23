package core

import (
	"fmt"
	"net/url"
)

// Token is the domain projection of an AAT whose signature has already been
// verified: the claims that the §4 attenuation invariants are stated over, with
// the JOSE encoding gone.
//
// HolderKeyURI is the one field that is not a claim. It is
// jwk_thumbprint_uri(this token's cnf.jwk), computed by the wire layer because
// only the wire layer knows what a JWK is; I1 is then a string comparison
// against the child's iss, which is what makes I1 checkable offline.
type Token struct {
	JTI          string
	Issuer       string
	IssuedAt     int64
	Expires      int64
	Depth        int
	MaxDepth     int
	HolderKeyURI string
	Caps         *Capabilities // nil = no attenuating_agent_token entry (§7 step 4n)
}

// Limits are the implementation-defined bounds §4.3 and §4.4 require an
// enforcement point to enforce. All three MUST be finite; a non-positive value
// is a misconfiguration, not "unlimited".
type Limits struct {
	MaxDelegationDepth int   // §4.3, no draft-recommended value: deployment topology decides
	MaxIATSkew         int64 // §4.4, seconds, RECOMMENDED 30
	MaxTokenLifetime   int64 // §4.4, seconds, RECOMMENDED upper bound 90 days
}

// DefaultLimits are the §4.4 recommended values plus a delegation ceiling.
//
// Appendix B.4 declines to recommend a MAX_DELEGATION_DEPTH: it says the
// ceiling "should reflect the maximum depth the deployment actually needs, not
// an arbitrary conservative default". 8 is a starting point for a linear
// orchestration topology and is meant to be overridden, not inherited.
var DefaultLimits = Limits{
	MaxDelegationDepth: 8,
	MaxIATSkew:         30,
	MaxTokenLifetime:   90 * 24 * 60 * 60,
}

func (l Limits) check() error {
	switch {
	case l.MaxDelegationDepth < 0:
		return fmt.Errorf("core: MaxDelegationDepth is %d, want non-negative (§4.3)", l.MaxDelegationDepth)
	case l.MaxIATSkew < 0:
		return fmt.Errorf("core: MaxIATSkew is %d, want a finite non-negative bound (§4.4)", l.MaxIATSkew)
	case l.MaxTokenLifetime <= 0:
		return fmt.Errorf("core: MaxTokenLifetime is %d, want a finite positive bound (§4.4)", l.MaxTokenLifetime)
	}
	return nil
}

// CheckRoot is the domain half of §7 step 3: the checks that do not need the
// wire form. Steps 3a/3b (algorithm, signature), 3d (par_hash absent) and 3l
// (cnf carries a public key) belong to the caller.
//
// Step 3m — exactly one attenuating_agent_token entry — is the nil check here:
// ParseCapabilities has already rejected more than one.
func CheckRoot(root *Token, now int64, lim Limits) error {
	if err := lim.check(); err != nil {
		return err
	}
	if root.Depth != 0 { // 3c
		return fmt.Errorf("core: root del_depth is %d, want 0 (§7 step 3c)", root.Depth)
	}
	if root.Expires <= now { // 3e
		return fmt.Errorf("core: root exp %d is not after now %d (§7 step 3e, I3)", root.Expires, now)
	}
	if root.IssuedAt > now+lim.MaxIATSkew { // 3f
		return fmt.Errorf("core: root iat %d exceeds now %d plus MaxIATSkew %d (§7 step 3f, I3)",
			root.IssuedAt, now, lim.MaxIATSkew)
	}
	if root.Expires <= root.IssuedAt { // 3g
		return fmt.Errorf("core: root exp %d is not after iat %d (§7 step 3g, I3)",
			root.Expires, root.IssuedAt)
	}
	if root.Expires > root.IssuedAt+lim.MaxTokenLifetime { // 3h
		return fmt.Errorf("core: root lifetime %ds exceeds MaxTokenLifetime %ds (§7 step 3h, I3)",
			root.Expires-root.IssuedAt, lim.MaxTokenLifetime)
	}
	if root.MaxDepth < 0 || root.MaxDepth > lim.MaxDelegationDepth { // 3i
		return fmt.Errorf("core: root del_max_depth %d is outside [0, MaxDelegationDepth %d] (§7 step 3i, I2)",
			root.MaxDepth, lim.MaxDelegationDepth)
	}
	if root.JTI == "" { // 3j
		return fmt.Errorf("core: root jti is empty (§7 step 3j)")
	}
	if err := checkURI(root.Issuer); err != nil { // 3k
		return fmt.Errorf("core: root iss (§7 step 3k): %w", err)
	}
	if root.Caps == nil { // 3m
		return fmt.Errorf(
			"core: root carries no %q entry; §3.3 requires exactly one in a root token (§7 step 3m)",
			CapabilityType)
	}
	return nil
}

// CheckLink is the domain half of §7 step 4, one adjacent (parent, child) pair:
// steps 4c through 4p, which is I1, I2, I3 and I4. Steps 4a/4b (algorithm,
// signature), the 4b1-4b5 structural claim checks, and 4q (par_hash, I5) are
// the wire layer's, because each of them needs a key, a segment or a signature.
//
// Step 4n — at most one attenuating_agent_token entry — has already been
// enforced by ParseCapabilities; zero is legal here and reaches CheckI4 as a
// nil Caps meaning the empty capability set.
func CheckLink(parent, child *Token, now int64, lim Limits) error {
	if err := lim.check(); err != nil {
		return err
	}
	if child.Issuer != parent.HolderKeyURI { // 4c (I1)
		return fmt.Errorf(
			"core: child iss %q is not the thumbprint URI of the parent holder key %q (§7 step 4c, I1)",
			child.Issuer, parent.HolderKeyURI)
	}
	if child.Depth != parent.Depth+1 { // 4d (I2)
		return fmt.Errorf("core: child del_depth %d, want parent %d + 1 (§7 step 4d, I2)",
			child.Depth, parent.Depth)
	}
	if child.Depth > parent.MaxDepth { // 4e (I2)
		return fmt.Errorf("core: child del_depth %d exceeds parent del_max_depth %d (§7 step 4e, I2)",
			child.Depth, parent.MaxDepth)
	}
	if child.Depth > lim.MaxDelegationDepth { // 4f (I2)
		return fmt.Errorf("core: child del_depth %d exceeds MaxDelegationDepth %d (§7 step 4f, I2)",
			child.Depth, lim.MaxDelegationDepth)
	}
	if child.MaxDepth > parent.MaxDepth { // 4g (I2)
		return fmt.Errorf("core: child del_max_depth %d exceeds parent's %d (§7 step 4g, I2)",
			child.MaxDepth, parent.MaxDepth)
	}
	if child.Expires > parent.Expires { // 4h (I3)
		return fmt.Errorf("core: child exp %d outlives parent exp %d (§7 step 4h, I3)",
			child.Expires, parent.Expires)
	}
	if child.Expires <= now { // 4i (I3)
		return fmt.Errorf("core: child exp %d is not after now %d (§7 step 4i, I3)", child.Expires, now)
	}
	if child.IssuedAt < parent.IssuedAt { // 4j (I3)
		return fmt.Errorf("core: child iat %d precedes parent iat %d (§7 step 4j, I3)",
			child.IssuedAt, parent.IssuedAt)
	}
	if child.IssuedAt > now+lim.MaxIATSkew { // 4k (I3)
		return fmt.Errorf("core: child iat %d exceeds now %d plus MaxIATSkew %d (§7 step 4k, I3)",
			child.IssuedAt, now, lim.MaxIATSkew)
	}
	if child.Expires <= child.IssuedAt { // 4l (I3)
		return fmt.Errorf("core: child exp %d is not after its iat %d (§7 step 4l, I3)",
			child.Expires, child.IssuedAt)
	}
	if child.Depth > child.MaxDepth { // 4m (I2)
		return fmt.Errorf("core: child del_depth %d exceeds its own del_max_depth %d (§7 step 4m, I2)",
			child.Depth, child.MaxDepth)
	}
	return CheckI4(child.Caps, parent.Caps) // 4p (I4)
}

// checkURI accepts what §7 step 3k calls "a URI": absolute, with a scheme.
func checkURI(s string) error {
	if s == "" {
		return fmt.Errorf("is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%q is not a URI: %w", s, err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("%q is not an absolute URI", s)
	}
	return nil
}

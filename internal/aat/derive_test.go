package aat

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/igorkg/warden/internal/core"
)

// A chain built the way §6 says one is built: a minted root plus derivations
// produced by Deriver, rather than the hand-assembled hops chain_test.go uses.
//
// The distinction is the point of this file. chain_test.go asks whether the
// verifier rejects a forged chain; this file asks whether it still does when
// the forgery is the last link of an otherwise genuine one — a real holder,
// with a real parent it was really delegated, extending it into something
// Derive would not have signed.
type dchain struct {
	dv    *Deriver
	privs []ed25519.PrivateKey
	pubs  []ed25519.PublicKey
	toks  []*Token
}

// newDChain mints a root and derives depth-1 children under it, narrowing at
// every link: rootTools, then midTools, then leafTools for anything deeper.
func newDChain(t *testing.T, depth int) *dchain {
	t.Helper()
	d := &dchain{dv: &Deriver{Limits: core.DefaultLimits, Now: func() int64 { return chainNow }}}
	for i := 0; i < depth; i++ {
		priv, pub := keypair(t)
		d.privs, d.pubs = append(d.privs, priv), append(d.pubs, pub)
	}

	root, err := Mint(Claims{
		JTI:                  fmt.Sprintf("01957a41-0081-7c20-bf3a-00a0c91e%04d", 1),
		Issuer:               rootIssuer,
		IssuedAt:             chainNow - 100,
		Expires:              chainNow + 3600,
		Confirmation:         Confirmation{JWK: NewJWK(d.pubs[0])},
		DelegationDepth:      0,
		MaxDelegationDepth:   depth - 1,
		AuthorizationDetails: details(caps(rootTools)),
	}, d.privs[0])
	if err != nil {
		t.Fatalf("Mint root: %v", err)
	}
	d.toks = append(d.toks, root)

	for i := 1; i < depth; i++ {
		tools := leafTools
		if i == 1 {
			tools = midTools
		}
		child, err := d.derive(i, d.privs[i-1], func(dv *Derivation) { dv.Tools = toolMap(t, tools) })
		if err != nil {
			t.Fatalf("Derive %d: %v", i, err)
		}
		d.toks = append(d.toks, child)
	}
	return d
}

// derive extends the chain by one, signed by signer. The Derivation handed to
// tweak is the valid one; a test breaks exactly the field it is about.
func (d *dchain) derive(i int, signer ed25519.PrivateKey, tweak func(*Derivation)) (*Token, error) {
	parent := d.toks[i-1]
	dv := Derivation{
		JTI:                fmt.Sprintf("01957a41-0081-7c20-bf3a-00a0c91e%04d", i+1),
		IssuedAt:           parent.Claims.IssuedAt + 10,
		Expires:            parent.Claims.Expires - 10,
		HolderKey:          NewJWK(d.pubs[i]),
		MaxDelegationDepth: parent.Claims.MaxDelegationDepth,
		Tools:              toolMap(nil, leafTools),
	}
	tweak(&dv)
	return d.dv.Derive(parent, signer, dv)
}

func (d *dchain) compact() []string {
	out := make([]string, len(d.toks))
	for i, tok := range d.toks {
		out[i] = tok.Compact()
	}
	return out
}

func (d *dchain) verifier() *Verifier {
	return &Verifier{
		TrustAnchors: []*JWK{NewJWK(d.pubs[0])},
		Limits:       core.DefaultLimits,
		PoPSkew:      DefaultPoPSkew,
		Now:          func() int64 { return chainNow },
	}
}

// pop signs a proof of possession under the leaf holder key, or under holder if
// one is given: I6 is the only invariant a claims mutation cannot express.
func (d *dchain) pop(t *testing.T, tool string, args map[string]any, holder ed25519.PrivateKey) string {
	t.Helper()
	if holder == nil {
		holder = d.privs[len(d.toks)-1]
	}
	compact, err := SignPoP(PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c0001",
		IssuedAt: chainNow,
		TokenID:  d.toks[len(d.toks)-1].Claims.JTI,
		Tool:     tool,
		Args:     args,
	}, holder)
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	return compact
}

// forgeLeaf replaces the leaf with a token minted straight from claims, past
// Derive entirely. This is what a holder who does not use the API produces, and
// the only thing standing between it and an authorized call is §7.
func (d *dchain) forgeLeaf(t *testing.T, signer ed25519.PrivateKey, mutate func(*Claims)) []string {
	t.Helper()
	c := d.toks[len(d.toks)-1].Claims
	mutate(&c)
	if signer == nil {
		signer = d.privs[len(d.toks)-2] // the legitimate parent holder
	}
	tok, err := Mint(c, signer)
	if err != nil {
		t.Fatalf("forgeLeaf: Mint: %v (the forgery must be well-formed to test the chain check)", err)
	}
	out := d.compact()
	out[len(out)-1] = tok.Compact()
	return out
}

func toolMap(t *testing.T, tools string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(tools), &m); err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatalf("toolMap: %v", err)
	}
	return m
}

func deniesChain(t *testing.T, d *dchain, chain []string, pop, want string) {
	t.Helper()
	err := d.verifier().Verify(chain, "read_file", goodArgs, pop)
	if err == nil {
		t.Fatalf("Verify permitted a forged chain; want DENY mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("Verify error = %v, want one mentioning %q", err, want)
	}
	if ref := core.RefOf(err); ref == "" {
		t.Errorf("Verify error = %v carries no core.Denial; the trace would have no ref", err)
	}
}

// The milestone: a chain warden minted, verifying under warden's own verifier.
// Asserted rather than assumed, because Derive is the first thing here that
// produces tokens instead of consuming them, and nothing else in the suite
// would notice if it emitted something only it could read.
func TestDerivedChainVerifies(t *testing.T) {
	d := newDChain(t, 3)
	rep, err := d.verifier().VerifyReport(d.compact(), "read_file", goodArgs, d.pop(t, "read_file", goodArgs, nil))
	if err != nil {
		t.Fatalf("Verify denied a chain Derive produced: %v", err)
	}
	if len(rep.SameScope) != 0 {
		t.Errorf("SameScope = %v; every link in this chain narrows", rep.SameScope)
	}
	if got := d.toks[2].Claims.DelegationDepth; got != 2 {
		t.Errorf("leaf del_depth = %d, want 2", got)
	}
	// §6 step 7 and step 9, computed by Derive rather than supplied: I5 and I1
	// are not fields a caller can get wrong.
	if got, want := d.toks[2].Claims.ParentHash, ParentHash(d.toks[1]); got != want {
		t.Errorf("leaf par_hash = %q, want %q", got, want)
	}
	if got, want := d.toks[2].Claims.Issuer, thumbURI(t, d.pubs[1]); got != want {
		t.Errorf("leaf iss = %q, want the parent holder thumbprint URI %q", got, want)
	}
}

// Mint-time refusals. These are thin on purpose: core.CheckLink is the gate, and
// chain_test.go already proves CheckLink's semantics against a hand-built chain.
// What is worth asserting here is only that Derive routes through it at all, and
// that the fields §6 computes are unreachable from a Derivation.
func TestDeriveRefusesAttenuationViolations(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tweak func(*Derivation)
		want  string
	}{
		{"I2 raised ceiling", func(dv *Derivation) { dv.MaxDelegationDepth = 7 }, "step 4g, I2"},
		{"I3 outlives parent", func(dv *Derivation) { dv.Expires = chainNow + 7200 }, "step 4h, I3"},
		{"I3 predates parent", func(dv *Derivation) { dv.IssuedAt = chainNow - 500 }, "step 4j, I3"},
		{"I3 already expired", func(dv *Derivation) { dv.Expires = chainNow - 1 }, "step 4i, I3"},
		// midTools plus one tool the parent does not grant, and nothing else
		// changed. Handing it rootTools would ALSO widen read_file.path, and
		// CheckI4 walks a map: which of the two violations it reports first is
		// then whichever the runtime iterates first.
		{"I4 adds a tool", func(dv *Derivation) {
			dv.Tools = toolMap(t, `{"read_file":{"path":{"constraint_type":"one_of",`+
				`"values":["/data/q3.pdf","/data/q4.pdf"]},`+
				`"mode":{"constraint_type":"exact","value":"r"}},"list_dir":{}}`)
		}, "step 4p1, I4"},
		{"I4 widens a constraint", func(dv *Derivation) {
			dv.Tools = toolMap(t, `{"read_file":{"path":{"constraint_type":"one_of","values":`+
				`["/data/q3.pdf","/etc/shadow"]},"mode":{"constraint_type":"exact","value":"r"}}}`)
		}, "step 4p4, I4"},
		{"I4 drops a constrained key", func(dv *Derivation) {
			dv.Tools = toolMap(t, `{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"}}}`)
		}, "step 4p2, I4"},
		{"I4 adds a constrained key", func(dv *Derivation) {
			dv.Tools = toolMap(t, `{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"},`+
				`"mode":{"constraint_type":"exact","value":"r"},"depth":{"constraint_type":"exact","value":1}}}`)
		}, "step 4p2, I4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Derived from the mid token, not the root: rootTools is broad
			// enough that "adds a tool" and "widens a constraint" would be
			// legal narrowings of it and the case would assert nothing.
			d := newDChain(t, 3)
			_, err := d.derive(2, d.privs[1], tc.tweak)
			if err == nil {
				t.Fatalf("Derive minted a token that violates %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Derive error = %v, want one mentioning %q", err, tc.want)
			}
			if ref := core.RefOf(err); ref == "" {
				t.Errorf("Derive error = %v carries no core.Denial", err)
			}
		})
	}
}

// I1 at mint time: iss is computed from the signing key, so the only way to get
// it wrong is to hold the wrong key — and then step 4c fires before a signature
// is produced.
func TestDeriveRefusesSigningByStranger(t *testing.T) {
	d := newDChain(t, 2)
	stranger, _ := keypair(t)
	_, err := d.derive(1, stranger, func(*Derivation) {})
	if err == nil || !strings.Contains(err.Error(), "step 4c, I1") {
		t.Fatalf("Derive error = %v, want a step 4c, I1 denial", err)
	}
}

// §4.3: del_depth == del_max_depth is terminal. The holder is told so directly
// rather than through step 4e's "child exceeds parent del_max_depth", which
// describes a chain it was not trying to build.
func TestDeriveRefusesTerminalParent(t *testing.T) {
	d := newDChain(t, 3) // leaf is depth 2 of max 2
	_, err := d.dv.Derive(d.toks[2], d.privs[2], Derivation{
		JTI:                "01957a41-0081-7c20-bf3a-00a0c91e0004",
		IssuedAt:           chainNow,
		Expires:            chainNow + 60,
		HolderKey:          NewJWK(d.pubs[0]),
		MaxDelegationDepth: 2,
		Tools:              toolMap(t, leafTools),
	})
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("Derive error = %v, want a terminal-parent refusal", err)
	}
}

// I6 at mint time: cnf.jwk is required, and it is the HOLDER's public key. A
// private member in it would mint the child's secret into a token the whole
// chain carries (§8.2).
func TestDeriveRefusesUnusableHolderKey(t *testing.T) {
	d := newDChain(t, 2)
	for _, tc := range []struct {
		name string
		key  *JWK
	}{
		{"absent", nil},
		{"carrying private key material", &JWK{Kty: "OKP", Crv: "Ed25519", X: NewJWK(d.pubs[1]).X, D: "c2VjcmV0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.derive(1, d.privs[0], func(dv *Derivation) { dv.HolderKey = tc.key })
			if err == nil {
				t.Fatalf("Derive accepted a %s holder key", tc.name)
			}
		})
	}
}

// §6 step 4, open-world half: an empty parent constraint map means unconstrained,
// so the child MAY introduce keys. This is the rule most easily lost when the
// closed-world half is implemented first, and losing it silently forbids every
// legitimate first narrowing of an unconstrained tool.
func TestDerivePermitsNewKeysUnderAnEmptyParentMap(t *testing.T) {
	d := newDChain(t, 2)
	child, err := d.derive(1, d.privs[0], func(dv *Derivation) {
		dv.Tools = toolMap(t, `{"list_dir":{"path":{"constraint_type":"exact","value":"/data"}}}`)
	})
	if err != nil {
		t.Fatalf("Derive refused a narrowing of the root's empty list_dir map: %v", err)
	}
	d.toks[1] = child
	if err := d.verifier().Verify(d.compact(), "list_dir",
		map[string]any{"path": "/data"}, d.pop(t, "list_dir", map[string]any{"path": "/data"}, nil)); err != nil {
		t.Fatalf("Verify denied it: %v", err)
	}
}

// NOTES.md #7, at the issuing end. RFC 8785 puts every number through binary64
// before the payload is signed, so a bound above 2^53 is signed as a number the
// issuer did not write — and unlike an invocation argument, nobody downstream
// can tell it was ever different.
func TestDeriveRefusesAmbiguousConstraintNumbers(t *testing.T) {
	d := newDChain(t, 2)
	_, err := d.derive(1, d.privs[0], func(dv *Derivation) {
		dv.Tools = toolMap(t, `{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"},`+
			`"mode":{"constraint_type":"exact","value":"r"},`+
			`"size":{"constraint_type":"range","max":9007199254740993}}}`)
	})
	if err == nil {
		t.Fatal("Derive signed a constraint bound that RFC 8785 canonicalization changes")
	}
	if ref := core.RefOf(err); !strings.Contains(ref, "8785") {
		t.Errorf("ref = %q, want the RFC 8785 citation", ref)
	}
}

// §6, final paragraph: a derivation that narrows nothing is valid. It must
// PERMIT, and it must be visible.
func TestSameScopeDerivationIsPermittedAndFlagged(t *testing.T) {
	d := newDChain(t, 3)
	parent := d.toks[1]
	child, err := d.derive(2, d.privs[1], func(dv *Derivation) {
		dv.IssuedAt, dv.Expires = parent.Claims.IssuedAt, parent.Claims.Expires
		dv.MaxDelegationDepth = parent.Claims.MaxDelegationDepth
		dv.Tools = toolMap(t, midTools)
	})
	if err != nil {
		t.Fatalf("Derive refused a same-scope derivation; §6 declares it valid: %v", err)
	}
	d.toks[2] = child

	rep, err := d.verifier().VerifyReport(d.compact(), "read_file", goodArgs,
		d.pop(t, "read_file", goodArgs, nil))
	if err != nil {
		t.Fatalf("Verify denied a same-scope chain; §6 declares it valid: %v", err)
	}
	if want := []int{2}; len(rep.SameScope) != 1 || rep.SameScope[0] != want[0] {
		t.Errorf("SameScope = %v, want %v", rep.SameScope, want)
	}
}

// The other half, and the half that matters: Derive refusing to sign something
// proves nothing about a holder who does not use Derive. Each of these is a
// genuine two-token chain extended by a leaf minted straight from claims.
func TestForgedLeafIsDeniedAtVerify(t *testing.T) {
	d0 := newDChain(t, 3)
	stranger, strangerPub := keypair(t)

	for _, tc := range []struct {
		name   string
		signer ed25519.PrivateKey
		mutate func(*Claims)
		want   string
	}{
		{"I1 iss rewritten", nil, func(c *Claims) {
			c.Issuer = thumbURI(t, strangerPub)
		}, "step 4c, I1"},
		{"I1 signed by a stranger", stranger, func(*Claims) {}, "steps 4a-4b, I1"},
		{"I2 depth skipped", nil, func(c *Claims) {
			c.DelegationDepth, c.MaxDelegationDepth = 3, 3
		}, "step 4d, I2"},
		{"I2 ceiling raised", nil, func(c *Claims) { c.MaxDelegationDepth = 7 }, "step 4g, I2"},
		{"I3 outlives its parent", nil, func(c *Claims) { c.Expires = chainNow + 7200 }, "step 4h, I3"},
		{"I3 predates its parent", nil, func(c *Claims) { c.IssuedAt = chainNow - 500 }, "step 4j, I3"},
		// leafTools plus the tool its parent dropped, and nothing else: handing
		// it rootTools would ALSO widen read_file.path, and CheckI4 walks a map,
		// so which violation surfaces first is whichever the runtime iterates.
		{"I4 regains a dropped tool", nil, func(c *Claims) {
			c.AuthorizationDetails = details(caps(
				`{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"},` +
					`"mode":{"constraint_type":"exact","value":"r"}},"list_dir":{}}`))
		}, "step 4p1, I4"},
		{"I4 widens a constraint", nil, func(c *Claims) {
			// Reaching past the mid token's one_of, not merely back up to it:
			// re-stating the parent's own constraints is a same-scope
			// derivation, which is valid and would assert nothing here.
			c.AuthorizationDetails = details(caps(`{"read_file":{"path":{"constraint_type":"one_of",` +
				`"values":["/data/q3.pdf","/etc/shadow"]},` +
				`"mode":{"constraint_type":"exact","value":"r"}}}`))
		}, "step 4p4, I4"},
		{"I5 par_hash of a different parent", nil, func(c *Claims) {
			c.ParentHash = ParentHash(d0.toks[0])
		}, "step 4q, I5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDChain(t, 3)
			// The PoP is built before the forgery and stays valid: the denial
			// has to come from the chain, not from a proof that stopped
			// matching. §5.3 puts the chain first for exactly this reason.
			pop := d.pop(t, "read_file", goodArgs, nil)
			deniesChain(t, d, d.forgeLeaf(t, tc.signer, tc.mutate), pop, tc.want)
		})
	}
}

// I6 is the one invariant no claims mutation reaches: the chain is intact and
// every attenuation invariant holds. What is missing is possession.
func TestForgedPoPIsDeniedAtVerify(t *testing.T) {
	d := newDChain(t, 3)
	stranger, _ := keypair(t)
	deniesChain(t, d, d.compact(), d.pop(t, "read_file", goodArgs, stranger), "PoP")
}

// A derived chain must not be re-parentable: §6 step 7 hashes the parent's JWS
// Signing Input, so a token derived under one parent cannot be presented under
// a sibling even when both parents are legitimate and both hold the same
// authority. This is I5 doing the work I2 alone could not.
func TestDerivedTokenCannotBeReparented(t *testing.T) {
	d := newDChain(t, 3)
	sibling, err := d.derive(1, d.privs[0], func(dv *Derivation) {
		dv.JTI = "01957a41-0081-7c20-bf3a-00a0c91e0009"
		dv.HolderKey = NewJWK(d.pubs[1]) // same holder, so only par_hash differs
		dv.Tools = toolMap(t, midTools)
	})
	if err != nil {
		t.Fatalf("Derive sibling: %v", err)
	}
	chain := d.compact()
	chain[1] = sibling.Compact()
	deniesChain(t, d, chain, d.pop(t, "read_file", goodArgs, nil), "step 4q, I5")
}

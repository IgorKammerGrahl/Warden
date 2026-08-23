package aat

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/igorkg/warden/internal/core"
)

// The clock every chain test runs against. Fixed so that iat/exp are literals
// in the fixtures and a failure never depends on wall time.
const chainNow int64 = 1741600100

// hop is one token in a test chain: the claims, the key that signs it (the
// parent holder's, per I1), and the key it names as its own holder in cnf.jwk.
type hop struct {
	claims Claims
	signer ed25519.PrivateKey
	holder ed25519.PrivateKey
}

// chainFixture is a three-token chain plus everything a test needs to bend one
// link of it: root issuer -> orchestrator -> worker.
type chainFixture struct {
	rootPriv, workerPriv ed25519.PrivateKey
	anchor               *JWK
	hops                 []hop
}

func thumbURI(t testing.TB, pub ed25519.PublicKey) string {
	t.Helper()
	uri, err := NewJWK(pub).ThumbprintURI()
	if err != nil {
		t.Fatalf("ThumbprintURI: %v", err)
	}
	return uri
}

func details(entries ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(entries))
	for i, e := range entries {
		out[i] = json.RawMessage(e)
	}
	return out
}

// caps builds one §3.3 attenuating_agent_token entry from a tools-map literal.
func caps(tools string) string {
	return `{"type":"attenuating_agent_token","tools":` + tools + `}`
}

const (
	// The root authorizes two tools. read_file is constrained (closed-world:
	// path and mode are the required invocation shape), list_dir is
	// unconstrained (open-world).
	rootTools = `{"read_file":{"path":{"constraint_type":"one_of",` +
		`"values":["/data/q3.pdf","/data/q4.pdf","/etc/shadow"]},` +
		`"mode":{"constraint_type":"exact","value":"r"}},` +
		`"list_dir":{}}`
	// The orchestrator drops list_dir and narrows path to two of the three.
	midTools = `{"read_file":{"path":{"constraint_type":"one_of",` +
		`"values":["/data/q3.pdf","/data/q4.pdf"]},` +
		`"mode":{"constraint_type":"exact","value":"r"}}}`
	// The worker narrows path to exactly one file.
	leafTools = `{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"},` +
		`"mode":{"constraint_type":"exact","value":"r"}}}`
)

// newChainFixture builds the happy-path three-token chain.
func newChainFixture(t testing.TB) *chainFixture {
	t.Helper()
	rootPriv, rootPub := keypair(t)
	midPriv, midPub := keypair(t)
	workerPriv, workerPub := keypair(t)

	f := &chainFixture{rootPriv: rootPriv, workerPriv: workerPriv, anchor: NewJWK(rootPub)}
	f.hops = []hop{
		{
			claims: Claims{
				JTI:                  "01957a41-0081-7c20-bf3a-00a0c91e0001",
				Issuer:               rootIssuer,
				IssuedAt:             chainNow - 100,
				Expires:              chainNow + 3600,
				Confirmation:         Confirmation{JWK: NewJWK(rootPub)},
				DelegationDepth:      0,
				MaxDelegationDepth:   3,
				AuthorizationDetails: details(caps(rootTools)),
			},
			signer: rootPriv,
			holder: rootPriv,
		},
		{
			claims: Claims{
				JTI:                  "01957a41-0081-7c20-bf3a-00a0c91e0002",
				Issuer:               thumbURI(t, rootPub),
				IssuedAt:             chainNow - 50,
				Expires:              chainNow + 1800,
				Confirmation:         Confirmation{JWK: NewJWK(midPub)},
				DelegationDepth:      1,
				MaxDelegationDepth:   3,
				AuthorizationDetails: details(caps(midTools)),
			},
			signer: rootPriv, // the parent HOLDER signs the child (I1)
			holder: midPriv,
		},
		{
			claims: Claims{
				JTI:                  "01957a41-0081-7c20-bf3a-00a0c91e0003",
				Issuer:               thumbURI(t, midPub),
				IssuedAt:             chainNow - 10,
				Expires:              chainNow + 900,
				Confirmation:         Confirmation{JWK: NewJWK(workerPub)},
				DelegationDepth:      2,
				MaxDelegationDepth:   2,
				AuthorizationDetails: details(caps(leafTools)),
			},
			signer: midPriv,
			holder: workerPriv,
		},
	}
	return f
}

// mint signs the fixture's hops in order, filling in each par_hash from the
// token actually minted for the parent. A test that wants a broken par_hash
// overrides it after this returns.
func (f *chainFixture) mint(t testing.TB) []string {
	t.Helper()
	compact := make([]string, len(f.hops))
	var parent *Token
	for i, h := range f.hops {
		c := h.claims
		if i > 0 && c.ParentHash == "" {
			c.ParentHash = ParentHash(parent)
		}
		tok, err := Mint(c, h.signer)
		if err != nil {
			t.Fatalf("Mint hop %d: %v", i, err)
		}
		compact[i] = tok.Compact()
		parent = tok
	}
	return compact
}

func (f *chainFixture) verifier() *Verifier {
	return &Verifier{
		TrustAnchors: []*JWK{f.anchor},
		Limits:       core.DefaultLimits,
		PoPSkew:      DefaultPoPSkew,
		Now:          func() int64 { return chainNow },
	}
}

// pop signs a PoP JWT under the worker's key for the leaf of the given chain.
func (f *chainFixture) pop(t testing.TB, chain []string, tool string, args map[string]any) string {
	t.Helper()
	leaf, err := Parse(chain[len(chain)-1])
	if err != nil {
		t.Fatalf("Parse leaf: %v", err)
	}
	compact, err := SignPoP(PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c0001",
		IssuedAt: chainNow,
		TokenID:  leaf.Claims.JTI,
		Tool:     tool,
		Args:     args,
	}, f.hops[len(chain)-1].holder)
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	return compact
}

var goodArgs = map[string]any{"path": "/data/q3.pdf", "mode": "r"}

// TestChainVerifies is the milestone's exit criterion: a three-token chain
// mints and verifies end to end, PoP included.
func TestChainVerifies(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)
	if err := f.verifier().Verify(chain, "read_file", goodArgs, f.pop(t, chain, "read_file", goodArgs)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// denies runs a mutated fixture and requires a DENY mentioning want.
func denies(t *testing.T, f *chainFixture, tool string, args map[string]any, want string) {
	t.Helper()
	chain := f.mint(t)
	err := f.verifier().Verify(chain, tool, args, f.pop(t, chain, tool, args))
	if err == nil {
		t.Fatalf("Verify permitted; want DENY mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("Verify error = %v, want one mentioning %q", err, want)
	}
	// Every DENY must be attributable. ARCHITECTURE §6 makes the citation the
	// substance of the audit trace, so a denial that cannot name the clause it
	// fired on is a bug in the check, not a gap in the log format — and this
	// helper runs on every I1-I6 denial in the file, which is what keeps a
	// newly added check from arriving uncited.
	if ref := core.RefOf(err); ref == "" {
		t.Errorf("Verify error = %v carries no core.Denial; the trace would have no ref", err)
	}
}

// I1: delegation authority. Two ways to break it, and both must DENY: the
// child's iss naming a key that is not the parent holder's, and the child
// signed by a key that is not the parent holder's.
func TestDenyI1IssuerMismatch(t *testing.T) {
	f := newChainFixture(t)
	_, strangerPub := keypair(t)
	f.hops[2].claims.Issuer = thumbURI(t, strangerPub)
	denies(t, f, "read_file", goodArgs, "step 4c, I1")
}

func TestDenyI1SignedByStranger(t *testing.T) {
	f := newChainFixture(t)
	strangerPriv, _ := keypair(t)
	f.hops[2].signer = strangerPriv
	denies(t, f, "read_file", goodArgs, "steps 4a-4b, I1")
}

// I2: depth monotonicity. A child that skips a depth, and a child that raises
// the ceiling its parent set.
func TestDenyI2DepthSkip(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.DelegationDepth = 3
	f.hops[2].claims.MaxDelegationDepth = 3 // else Mint rejects it single-token
	denies(t, f, "read_file", goodArgs, "step 4d, I2")
}

func TestDenyI2RaisedCeiling(t *testing.T) {
	f := newChainFixture(t)
	f.hops[1].claims.MaxDelegationDepth = 9
	denies(t, f, "read_file", goodArgs, "step 4g, I2")
}

// I3: TTL monotonicity. A child outliving its parent.
func TestDenyI3ChildOutlivesParent(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.Expires = f.hops[1].claims.Expires + 1
	denies(t, f, "read_file", goodArgs, "step 4h, I3")
}

func TestDenyI3ChildPredatesParent(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.IssuedAt = f.hops[1].claims.IssuedAt - 1
	denies(t, f, "read_file", goodArgs, "step 4j, I3")
}

// I4: capability monotonicity. Three distinct ways to widen authority.
func TestDenyI4AddsTool(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.AuthorizationDetails = details(caps(
		`{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"},` +
			`"mode":{"constraint_type":"exact","value":"r"}},` +
			`"write_file":{}}`))
	denies(t, f, "read_file", goodArgs, "step 4p1, I4")
}

func TestDenyI4WidensConstraint(t *testing.T) {
	f := newChainFixture(t)
	// The orchestrator had dropped /etc/shadow; the worker puts it back.
	f.hops[2].claims.AuthorizationDetails = details(caps(
		`{"read_file":{"path":{"constraint_type":"one_of",` +
			`"values":["/data/q3.pdf","/etc/shadow"]},` +
			`"mode":{"constraint_type":"exact","value":"r"}}}`))
	denies(t, f, "read_file", goodArgs, "step 4p4, I4")
}

// 4p2: the parent's constraint map is non-empty, so the key set must match
// exactly. Dropping mode would let the worker invoke read_file without the
// argument the orchestrator required be validated.
func TestDenyI4DropsConstrainedKey(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.AuthorizationDetails = details(caps(
		`{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"}}}`))
	denies(t, f, "read_file", goodArgs, "step 4p2, I4")
}

func TestDenyI4AddsConstrainedKey(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.AuthorizationDetails = details(caps(
		`{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"},` +
			`"mode":{"constraint_type":"exact","value":"r"},` +
			`"encoding":{"constraint_type":"wildcard"}}}`))
	denies(t, f, "read_file", goodArgs, "step 4p2, I4")
}

// 4p3 is the other rule, and it must NOT be collapsed into 4p2: the root's
// list_dir map is empty, so a child MAY introduce keys there.
func TestPermitI4OpenWorldParentGainsKeys(t *testing.T) {
	f := newChainFixture(t)
	f.hops[1].claims.AuthorizationDetails = details(caps(
		`{"list_dir":{"path":{"constraint_type":"wildcard"}}}`))
	f.hops[2].claims.AuthorizationDetails = details(caps(
		`{"list_dir":{"path":{"constraint_type":"exact","value":"/data"}}}`))

	chain := f.mint(t)
	args := map[string]any{"path": "/data"}
	if err := f.verifier().Verify(chain, "list_dir", args, f.pop(t, chain, "list_dir", args)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// I5: cryptographic linkage. A par_hash committing to the wrong parent
// instance, with everything else — signature, issuer, depth — still valid.
func TestDenyI5WrongParentHash(t *testing.T) {
	f := newChainFixture(t)
	sibling := f.hops[1].claims
	sibling.JTI = "01957a41-0081-7c20-bf3a-00a0c91e0009"
	sibling.ParentHash = ParentHash(mustMint(t, f.hops[0].claims, f.rootPriv))
	f.hops[2].claims.ParentHash = ParentHash(mustMint(t, sibling, f.rootPriv))
	denies(t, f, "read_file", goodArgs, "step 4q, I5")
}

func mustMint(t testing.TB, c Claims, key ed25519.PrivateKey) *Token {
	t.Helper()
	tok, err := Mint(c, key)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return tok
}

// I6: proof of possession. A PoP signed by a key that is not the leaf holder's.
func TestDenyI6PoPSignedByStranger(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)
	leaf, err := Parse(chain[2])
	if err != nil {
		t.Fatalf("Parse leaf: %v", err)
	}
	strangerPriv, _ := keypair(t)
	popJWT, err := SignPoP(PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c0002",
		IssuedAt: chainNow,
		TokenID:  leaf.Claims.JTI,
		Tool:     "read_file",
		Args:     goodArgs,
	}, strangerPriv)
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	err = f.verifier().Verify(chain, "read_file", goodArgs, popJWT)
	if err == nil {
		t.Fatal("Verify permitted a PoP signed by a stranger")
	}
	if !strings.Contains(err.Error(), "I6") {
		t.Errorf("Verify error = %v, want one mentioning I6", err)
	}
}

// §5.3: chain verification completes BEFORE the PoP is evaluated, and a valid
// PoP over an invalid chain MUST NOT authorize. The PoP here is impeccable —
// right key, right jti, right tool, right args, right clock — and the chain is
// broken at I4. The failure must name the chain, not the PoP.
func TestPoPDoesNotRescueAnInvalidChain(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.AuthorizationDetails = details(caps(
		`{"read_file":{"path":{"constraint_type":"one_of",` +
			`"values":["/data/q3.pdf","/etc/shadow"]},` +
			`"mode":{"constraint_type":"exact","value":"r"}}}`))
	chain := f.mint(t)
	popJWT := f.pop(t, chain, "read_file", goodArgs)

	err := f.verifier().Verify(chain, "read_file", goodArgs, popJWT)
	if err == nil {
		t.Fatal("Verify permitted an invalid chain carrying a valid PoP")
	}
	if !strings.Contains(err.Error(), "I4") {
		t.Errorf("Verify error = %v, want the I4 chain failure, not a PoP failure", err)
	}
}

// §7 step 2c: token-instance cycle detection, on jti extracted before any
// signature is verified.
func TestDenyRepeatedJTI(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.JTI = f.hops[1].claims.JTI
	denies(t, f, "read_file", goodArgs, "step 2c")
}

// §7 step 5 is labelled "(Defense in depth)" by the draft, and it is: step 3c
// pins the root at del_depth 0 and step 4d increments by exactly one at every
// link, so len(chain) == leaf.del_depth + 1 holds for every chain that reaches
// it. There is no chain that fails step 5 and passes steps 3 and 4, which is
// why this test asserts the truncation is ACCEPTED rather than denied — a
// prefix of a valid chain is a valid chain, and step 5 agrees.
func TestChainPrefixIsItselfAValidChain(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)[:2]
	args := map[string]any{"path": "/data/q3.pdf", "mode": "r"}
	if err := f.verifier().Verify(chain, "read_file", args, f.pop(t, chain, "read_file", args)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// §7 step 3b: a root that verifies under no trust anchor.
func TestDenyUntrustedRoot(t *testing.T) {
	f := newChainFixture(t)
	_, strangerPub := keypair(t)
	f.anchor = NewJWK(strangerPub)
	denies(t, f, "read_file", goodArgs, "no trust anchor")
}

// §7 step 6a: a leaf carrying zero attenuating_agent_token entries. Legal for a
// non-leaf (the empty capability set), never for a leaf.
func TestDenyLeafWithoutCapabilityEntry(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.AuthorizationDetails = details()
	denies(t, f, "read_file", goodArgs, "step 6a")
}

// The other half of the same rule: a non-leaf MAY carry zero entries, and then
// authorizes nothing, so its descendants authorize nothing either.
func TestDenyEmptyCapabilityParentCannotRegrant(t *testing.T) {
	f := newChainFixture(t)
	f.hops[1].claims.AuthorizationDetails = details()
	denies(t, f, "read_file", goodArgs, "step 4p1, I4")
}

func TestEmptyCapabilityMidChainIsAcceptedUntilTheLeafNeedsIt(t *testing.T) {
	f := newChainFixture(t)
	f.hops[1].claims.AuthorizationDetails = details()
	f.hops[2].claims.AuthorizationDetails = details()
	// The link is valid (empty derives empty); the DENY comes from step 6a.
	denies(t, f, "read_file", goodArgs, "step 6a")
}

// §3.3: more than one attenuating_agent_token entry is invalid.
func TestDenyTwoCapabilityEntries(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.AuthorizationDetails = details(caps(leafTools), caps(leafTools))
	denies(t, f, "read_file", goodArgs, "more than one")
}

// §3.3: entries of other types are ignored, not rejected.
func TestOtherAuthorizationDetailsTypesAreIgnored(t *testing.T) {
	f := newChainFixture(t)
	f.hops[2].claims.AuthorizationDetails = details(
		`{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"123.50"}}`,
		caps(leafTools),
	)
	chain := f.mint(t)
	if err := f.verifier().Verify(chain, "read_file", goodArgs, f.pop(t, chain, "read_file", goodArgs)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// §7 step 6b, closed-world: an argument the constraint map does not name, and a
// constrained argument the invocation omits.
func TestDenyClosedWorldViolations(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"unknown argument", map[string]any{"path": "/data/q3.pdf", "mode": "r", "follow": true},
			"not named in the constraint map"},
		{"omitted constrained argument", map[string]any{"path": "/data/q3.pdf"},
			"absent from the invocation"},
		{"value violates constraint", map[string]any{"path": "/data/q4.pdf", "mode": "r"},
			"does not satisfy its constraint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newChainFixture(t)
			denies(t, f, "read_file", tc.args, tc.want)
		})
	}
}

// §7 step 7f: hta and args are compared as JCS bytes, never as raw JSON. Two
// spellings of the same map must agree; a different map must not.
func TestPoPArgumentComparisonIsCanonical(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)
	// SignPoP canonicalizes, so hta reaches the wire in sorted-key form. The
	// invocation passes its args in the other order: the bytes differ before
	// canonicalization and must match after.
	popJWT := f.pop(t, chain, "read_file", map[string]any{"mode": "r", "path": "/data/q3.pdf"})
	if err := f.verifier().Verify(chain, "read_file",
		map[string]any{"path": "/data/q3.pdf", "mode": "r"}, popJWT); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestDenyPoPArgumentMismatch(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)
	// The PoP commits to q3; the invocation presents q4. Both satisfy nothing
	// the leaf forbids on their own terms, so only step 7f catches this.
	popJWT := f.pop(t, chain, "read_file", map[string]any{"path": "/data/q3.pdf", "mode": "r"})
	err := f.verifier().Verify(chain, "read_file",
		map[string]any{"path": "/data/q3.pdf", "mode": "rw"}, popJWT)
	if err == nil {
		t.Fatal("Verify permitted an invocation the PoP did not commit to")
	}
	if !strings.Contains(err.Error(), "does not satisfy its constraint") &&
		!strings.Contains(err.Error(), "step 7f") {
		t.Errorf("Verify error = %v, want a step 6b or 7f failure", err)
	}
}

// The one that step 7f exists for: args the leaf permits, but not the args the
// holder signed.
func TestDenyPoPCommitsToDifferentPermittedArgs(t *testing.T) {
	f := newChainFixture(t)
	// Widen the leaf so both spellings pass step 6b; only 7f separates them.
	f.hops[2].claims.AuthorizationDetails = details(caps(
		`{"read_file":{"path":{"constraint_type":"one_of",` +
			`"values":["/data/q3.pdf","/data/q4.pdf"]},` +
			`"mode":{"constraint_type":"exact","value":"r"}}}`))
	chain := f.mint(t)
	popJWT := f.pop(t, chain, "read_file", map[string]any{"path": "/data/q3.pdf", "mode": "r"})
	err := f.verifier().Verify(chain, "read_file",
		map[string]any{"path": "/data/q4.pdf", "mode": "r"}, popJWT)
	if err == nil {
		t.Fatal("Verify permitted args the PoP did not commit to")
	}
	if !strings.Contains(err.Error(), "step 7f") {
		t.Errorf("Verify error = %v, want a step 7f failure", err)
	}
}

// §7 steps 7c-7g.
func TestDenyPoPClaimFailures(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)
	leaf, err := Parse(chain[2])
	if err != nil {
		t.Fatalf("Parse leaf: %v", err)
	}

	base := PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c0003",
		IssuedAt: chainNow,
		TokenID:  leaf.Claims.JTI,
		Tool:     "read_file",
		Args:     goodArgs,
	}

	for _, tc := range []struct {
		name     string
		mutate   func(*PoPClaims)
		audience string
		want     string
	}{
		{"aat_id names another token", func(c *PoPClaims) {
			c.TokenID = "01957a41-0081-7c20-bf3a-00a0c91e0002"
		}, "", "step 7c"},
		{"aat_tool names another tool", func(c *PoPClaims) {
			c.Tool = "list_dir"
		}, "", "step 7e"},
		{"iat outside the tolerance window", func(c *PoPClaims) {
			c.IssuedAt = chainNow + DefaultPoPSkew + 1
		}, "", "step 7g"},
		{"audience required and absent", func(*PoPClaims) {}, "https://tools.example.com", "step 7d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			popJWT, err := SignPoP(c, f.workerPriv)
			if err != nil {
				t.Fatalf("SignPoP: %v", err)
			}
			v := f.verifier()
			v.Audience = tc.audience
			err = v.Verify(chain, "read_file", goodArgs, popJWT)
			if err == nil {
				t.Fatalf("Verify permitted; want DENY mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Verify error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

func TestPoPAudienceBindingWhenRequired(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)
	leaf, err := Parse(chain[2])
	if err != nil {
		t.Fatalf("Parse leaf: %v", err)
	}
	const aud = "https://tools.example.com"
	popJWT, err := SignPoP(PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c0004",
		IssuedAt: chainNow,
		TokenID:  leaf.Claims.JTI,
		Tool:     "read_file",
		Audience: aud,
		Args:     goodArgs,
	}, f.workerPriv)
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	v := f.verifier()
	v.Audience = aud
	if err := v.Verify(chain, "read_file", goodArgs, popJWT); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// §7 steps 1, 2a, 2b: the structural gates before anything is parsed.
func TestDenySizeAndEmptyChain(t *testing.T) {
	f := newChainFixture(t)
	chain := f.mint(t)
	popJWT := f.pop(t, chain, "read_file", goodArgs)
	v := f.verifier()

	if err := v.Verify(nil, "read_file", goodArgs, popJWT); err == nil ||
		!strings.Contains(err.Error(), "step 1") {
		t.Errorf("empty chain: err = %v, want a step 1 denial", err)
	}

	t.Run("stack size", func(t *testing.T) {
		saved := MaxStackSize
		t.Cleanup(func() { MaxStackSize = saved })
		MaxStackSize = 100
		if err := v.Verify(chain, "read_file", goodArgs, popJWT); err == nil ||
			!strings.Contains(err.Error(), "MaxStackSize") {
			t.Errorf("err = %v, want a MaxStackSize denial", err)
		}
	})

	t.Run("token size", func(t *testing.T) {
		saved := MaxTokenSize
		t.Cleanup(func() { MaxTokenSize = saved })
		MaxTokenSize = 100
		if err := v.Verify(chain, "read_file", goodArgs, popJWT); err == nil ||
			!strings.Contains(err.Error(), "MaxTokenSize") {
			t.Errorf("err = %v, want a MaxTokenSize denial", err)
		}
	})
}

// A single-token chain: root and leaf are the same token, step 4 never runs,
// and §7's note says steps 3, 5, 6 and 7 must still carry the validation.
func TestSingleTokenChain(t *testing.T) {
	f := newChainFixture(t)
	f.hops = f.hops[:1]
	chain := f.mint(t)
	args := map[string]any{"path": "/data/q3.pdf", "mode": "r"}
	if err := f.verifier().Verify(chain, "read_file", args, f.pop(t, chain, "read_file", args)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// list_dir is open-world in the root, so any args go.
	if err := f.verifier().Verify(chain, "list_dir", map[string]any{"anything": 1.0},
		f.pop(t, chain, "list_dir", map[string]any{"anything": 1.0})); err != nil {
		t.Fatalf("Verify list_dir: %v", err)
	}
}

// §7 step 2c is a decode, not a claim parse: it must reject a payload it cannot
// read a jti out of, without ever touching a key.
func TestExtractJTI(t *testing.T) {
	for _, tc := range []struct {
		name, compact, want string
	}{
		{"not compact", "a.b", "compact serialization"},
		{"payload not base64url", "aGRy.!!!.c2ln", "base64url"},
		{"payload not JSON", "aGRy." + b64.EncodeToString([]byte("nope")) + ".c2ln", "valid JSON"},
		{"jti absent", "aGRy." + b64.EncodeToString([]byte(`{"iss":"x"}`)) + ".c2ln", "no string-valued jti"},
		{"jti not a string", "aGRy." + b64.EncodeToString([]byte(`{"jti":7}`)) + ".c2ln", "valid JSON"},
		{"jti empty", "aGRy." + b64.EncodeToString([]byte(`{"jti":""}`)) + ".c2ln", "jti is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := extractJTI(tc.compact); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Errorf("extractJTI err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

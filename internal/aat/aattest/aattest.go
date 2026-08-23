// Package aattest builds signed AAT chains for tests.
//
// It exists so that the proxy's tests and wardend's end-to-end tests present
// the same material. A fixture duplicated across two suites is a fixture that
// drifts, and the two places that need one here are exactly the two places
// where a divergence would be invisible: a unit test that denies for the right
// reason and an e2e test that permits for the wrong one.
//
// Nothing outside a test imports this, so it is not linked into any binary.
package aattest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/core"
)

// Now is the clock every fixture runs against. Fixed so iat and exp are
// literals and no test ever depends on wall time.
const Now int64 = 1741600100

// RootIssuer is the https issuer URI the root token names (§7 step 3k).
const RootIssuer = "https://issuer.example.com"

// SpecVersion is the pinned draft identifier the §3.1 binding carries.
//
// Spelled out rather than taken from proxy.SpecVersion, because the proxy's own
// tests import this package and the dependency would be a cycle. The two are
// asserted equal by TestFixtureSpecVersionMatches in the proxy package, so the
// duplication cannot drift silently.
const SpecVersion = "draft-niyikiza-oauth-attenuating-agent-tokens-01"

// Tools the fixtures authorize.
const (
	// Read is authorized at every depth, with path narrowing as the chain
	// descends: the root allows three files, every delegate allows one.
	Read = "read_file"
	// List is authorized by the root only, so a chain of depth 2 or more
	// denies it at §7 step 6b. It is the "tool not in the leaf" case.
	List = "list_dir"
)

// Allowed is an invocation every fixture permits at every depth.
var Allowed = map[string]any{"path": "/data/q3.pdf", "mode": "r"}

// OutOfAuthority is the file only the root may read. Presented against a chain
// of depth 2 or more it is denied by the leaf's one_of constraint (§3.4).
var OutOfAuthority = map[string]any{"path": "/etc/shadow", "mode": "r"}

const (
	rootTools = `{"read_file":{"path":{"constraint_type":"one_of",` +
		`"values":["/data/q3.pdf","/data/q4.pdf","/etc/shadow"]},` +
		`"mode":{"constraint_type":"exact","value":"r"}},` +
		`"list_dir":{}}`
	delegateTools = `{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"},` +
		`"mode":{"constraint_type":"exact","value":"r"}}}`
)

// Fixture is a signed chain and the key that holds its leaf.
type Fixture struct {
	// Anchor is the root issuer's public key, the one trust anchor a
	// Verifier built by this fixture accepts.
	Anchor *aat.JWK
	// Chain is root-to-leaf compact JWTs, ready for the §3.1 binding.
	Chain []string

	leafHolder ed25519.PrivateKey
	leafJTI    string
	popSeq     int
}

// New builds a chain of depth tokens: one root plus depth-1 delegations, each
// signed by the previous holder as I1 requires.
func New(t testing.TB, depth int) *Fixture {
	t.Helper()
	if depth < 1 {
		t.Fatalf("aattest.New(%d): a chain has at least a root", depth)
	}

	privs := make([]ed25519.PrivateKey, depth)
	pubs := make([]ed25519.PublicKey, depth)
	for i := range privs {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		privs[i], pubs[i] = priv, pub
	}

	f := &Fixture{
		Anchor:     aat.NewJWK(pubs[0]),
		leafHolder: privs[depth-1],
		Chain:      make([]string, depth),
	}

	var parent *aat.Token
	for i := 0; i < depth; i++ {
		c := aat.Claims{
			JTI: fmt.Sprintf("01957a41-0081-7c20-bf3a-00a0c91e%04d", i+1),
			// exp and iat only narrow as the chain descends (I3).
			IssuedAt:             Now - 100 + int64(i)*10,
			Expires:              Now + 3600 - int64(i)*10,
			Confirmation:         aat.Confirmation{JWK: aat.NewJWK(pubs[i])},
			DelegationDepth:      i,
			MaxDelegationDepth:   depth - 1,
			AuthorizationDetails: details(rootTools),
		}
		signer := privs[0]
		if i == 0 {
			c.Issuer = RootIssuer
		} else {
			c.Issuer = thumbURI(t, pubs[i-1])
			c.ParentHash = aat.ParentHash(parent)
			c.AuthorizationDetails = details(delegateTools)
			signer = privs[i-1] // the parent HOLDER signs the child (I1)
		}
		tok, err := aat.Mint(c, signer)
		if err != nil {
			t.Fatalf("Mint token %d of %d: %v", i, depth, err)
		}
		f.Chain[i] = tok.Compact()
		f.leafJTI = c.JTI
		parent = tok
	}
	return f
}

// Verifier accepts this fixture's anchor and runs at the fixed clock.
func (f *Fixture) Verifier() *aat.Verifier {
	return &aat.Verifier{
		TrustAnchors: []*aat.JWK{f.Anchor},
		Limits:       core.DefaultLimits,
		PoPSkew:      aat.DefaultPoPSkew,
		Now:          func() int64 { return Now },
	}
}

// PoP signs a proof of possession under the leaf holder key. Each call uses a
// fresh jti so a caller replaying one is doing it deliberately.
func (f *Fixture) PoP(t testing.TB, tool string, args map[string]any) string {
	t.Helper()
	f.popSeq++
	compact, err := aat.SignPoP(aat.PoPClaims{
		JTI:      fmt.Sprintf("c980f2a1-4a37-4e88-bb3c-9defd37c%04d", f.popSeq),
		IssuedAt: Now,
		TokenID:  f.leafJTI,
		Tool:     tool,
		Args:     args,
	}, f.leafHolder)
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	return compact
}

// Meta is the ARCHITECTURE §3.1 params._meta binding for one invocation.
func (f *Fixture) Meta(t testing.TB, tool string, args map[string]any) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		"dev.warden/chain": mustJSON(t, f.Chain),
		"dev.warden/pop":   mustJSON(t, f.PoP(t, tool, args)),
		"dev.warden/spec":  mustJSON(t, SpecVersion),
	}
}

func details(entries ...string) []json.RawMessage {
	out := make([]json.RawMessage, len(entries))
	for i, e := range entries {
		out[i] = json.RawMessage(`{"type":"attenuating_agent_token","tools":` + e + `}`)
	}
	return out
}

func thumbURI(t testing.TB, pub ed25519.PublicKey) string {
	t.Helper()
	uri, err := aat.NewJWK(pub).ThumbprintURI()
	if err != nil {
		t.Fatalf("ThumbprintURI: %v", err)
	}
	return uri
}

func mustJSON(t testing.TB, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

package aat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/igorkg/warden/internal/aat/jcs"
	"github.com/igorkg/warden/internal/aat/jws"
)

const (
	// RFC 8037 Appendix A.1/A.3: the Ed25519 key and the JWK Thumbprint the
	// RFC publishes for it.
	rfc8037Seed       = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037X          = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	rootIssuer = "https://issuer.example.com"
	// A representative §3.3 capability entry. M0a treats it as opaque JSON:
	// constraint semantics are M0b.
	capability = `{"type":"attenuating_agent_token",` +
		`"tools":{"read_file":{"path":{"constraint_type":"one_of",` +
		`"values":["/data/q3.pdf"]}}}}`
)

func keypair(t testing.TB) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, pub
}

// rootClaims returns a structurally valid root token's claims.
func rootClaims(t testing.TB, pub ed25519.PublicKey) Claims {
	t.Helper()
	return Claims{
		JTI:                  "01957a41-0081-7c20-bf3a-00a0c91e1234",
		Issuer:               rootIssuer,
		IssuedAt:             1741600000,
		Expires:              1741603600,
		Confirmation:         Confirmation{JWK: NewJWK(pub)},
		DelegationDepth:      0,
		MaxDelegationDepth:   3,
		AuthorizationDetails: []json.RawMessage{json.RawMessage(capability)},
	}
}

func TestRFC8037Thumbprint(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037Seed)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	jwk := NewJWK(pub)
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		t.Errorf("NewJWK = %+v, want kty OKP crv Ed25519", jwk)
	}
	if jwk.X != rfc8037X {
		t.Errorf("NewJWK x = %q, want %q", jwk.X, rfc8037X)
	}

	got, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != rfc8037Thumbprint {
		t.Errorf("Thumbprint = %q, want %q (RFC 8037 A.3)", got, rfc8037Thumbprint)
	}

	// RFC 9278 URI form, which draft §3.2 requires as a derived token's iss.
	wantURI := "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + rfc8037Thumbprint
	uri, err := jwk.ThumbprintURI()
	if err != nil {
		t.Fatalf("ThumbprintURI: %v", err)
	}
	if uri != wantURI {
		t.Errorf("ThumbprintURI = %q, want %q", uri, wantURI)
	}
}

// TestRFC7638RSAThumbprint checks the thumbprint *construction* against the
// RSA vector RFC 7638 §3.1 publishes. Our JWK type is OKP-only, so this cannot
// go through Thumbprint; what it validates is the rule Thumbprint depends on —
// required members only, lexicographic order, no whitespace, SHA-256,
// base64url-nopad — against a vector produced by someone else.
func TestRFC7638RSAThumbprint(t *testing.T) {
	const (
		n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z" +
			"wu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5Js" +
			"GY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMic" +
			"AtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-" +
			"bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csF" +
			"Cur-kEgU8awapJzKnqDKgw"
		want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	)
	// RFC 7638 §3.1: the RSA required members are e, kty, n. alg and kid are
	// present in the source JWK and MUST be excluded.
	ordered := struct {
		E   string `json:"e"`
		Kty string `json:"kty"`
		N   string `json:"n"`
	}{"AQAB", "RSA", n}

	raw, err := json.Marshal(ordered)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(raw)
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("RSA thumbprint = %q, want %q (RFC 7638 §3.1)", got, want)
	}
}

// TestParseRejectsPrivateKeyMaterial covers §3.2 ("private key material MUST
// NOT appear in this field") and §7 steps 3l and 4b2, for every private member
// of every JWK key type — not only OKP's d, which is the only one our own JWK
// struct decodes.
func TestParseRejectsPrivateKeyMaterial(t *testing.T) {
	priv, pub := keypair(t)
	jwk := NewJWK(pub)

	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		t.Run(member, func(t *testing.T) {
			base, err := json.Marshal(rootClaims(t, pub))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(base, &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			m["cnf"] = map[string]any{"jwk": map[string]any{
				"kty": jwk.Kty, "crv": jwk.Crv, "x": jwk.X, member: "c2VjcmV0",
			}}
			payload, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal mutated: %v", err)
			}
			compact, err := jws.Sign(jws.Header{Alg: jws.EdDSA}, payload, priv)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if _, err := Parse(compact); err == nil {
				t.Errorf("Parse accepted cnf.jwk carrying %q", member)
			}
		})
	}
}

func TestJWKPublicKeyRoundTrip(t *testing.T) {
	_, pub := keypair(t)
	got, err := NewJWK(pub).PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Errorf("round-trip key = %x, want %x", got, pub)
	}
}

// TestRootRoundTrip is the first half of the M0a round-trip exit criterion.
func TestRootRoundTrip(t *testing.T) {
	priv, pub := keypair(t)

	tok, err := Mint(rootClaims(t, pub), priv)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	compact := tok.Compact()
	if strings.Count(compact, ".") != 2 {
		t.Fatalf("Compact() = %q, not a compact serialization", compact)
	}

	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := parsed.Verify(NewJWK(pub)); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	want := rootClaims(t, pub)
	if parsed.Claims.JTI != want.JTI ||
		parsed.Claims.Issuer != want.Issuer ||
		parsed.Claims.IssuedAt != want.IssuedAt ||
		parsed.Claims.Expires != want.Expires ||
		parsed.Claims.DelegationDepth != want.DelegationDepth ||
		parsed.Claims.MaxDelegationDepth != want.MaxDelegationDepth {
		t.Errorf("round-trip claims =\n%+v\nwant\n%+v", parsed.Claims, want)
	}
	if parsed.Claims.ParentHash != "" {
		t.Errorf("root par_hash = %q, want absent", parsed.Claims.ParentHash)
	}
	if parsed.Claims.Confirmation.JWK == nil ||
		parsed.Claims.Confirmation.JWK.X != NewJWK(pub).X {
		t.Errorf("round-trip cnf.jwk = %+v", parsed.Claims.Confirmation.JWK)
	}
	if len(parsed.Claims.AuthorizationDetails) != 1 {
		t.Fatalf("authorization_details has %d entries, want 1",
			len(parsed.Claims.AuthorizationDetails))
	}
	if !json.Valid(parsed.Claims.AuthorizationDetails[0]) {
		t.Error("authorization_details entry did not survive as valid JSON")
	}
}

// TestDerivedChainRoundTrip is the second half: mint a root, derive from it,
// serialize both, parse both back, verify both signatures, and check that the
// derived token's par_hash commits to the parent's signing input (draft §4.6).
func TestDerivedChainRoundTrip(t *testing.T) {
	rootPriv, rootPub := keypair(t)
	agentPriv, agentPub := keypair(t)

	root, err := Mint(rootClaims(t, rootPub), rootPriv)
	if err != nil {
		t.Fatalf("Mint root: %v", err)
	}

	// The parent holder signs the child, so the child's iss is the thumbprint
	// URI of the parent's holder key: draft §3.2, verifiable offline against
	// parent.cnf.jwk.
	iss, err := NewJWK(rootPub).ThumbprintURI()
	if err != nil {
		t.Fatalf("ThumbprintURI: %v", err)
	}
	derivedClaims := Claims{
		JTI:                  "01957a41-0081-7c20-bf3a-00a0c91e5678",
		Issuer:               iss,
		IssuedAt:             root.Claims.IssuedAt + 10,
		Expires:              root.Claims.Expires,
		Confirmation:         Confirmation{JWK: NewJWK(agentPub)},
		DelegationDepth:      1,
		MaxDelegationDepth:   root.Claims.MaxDelegationDepth,
		ParentHash:           ParentHash(root),
		AuthorizationDetails: []json.RawMessage{json.RawMessage(capability)},
	}
	derived, err := Mint(derivedClaims, rootPriv)
	if err != nil {
		t.Fatalf("Mint derived: %v", err)
	}

	parsedRoot, err := Parse(root.Compact())
	if err != nil {
		t.Fatalf("Parse root: %v", err)
	}
	parsedDerived, err := Parse(derived.Compact())
	if err != nil {
		t.Fatalf("Parse derived: %v", err)
	}
	if err := parsedRoot.Verify(NewJWK(rootPub)); err != nil {
		t.Fatalf("Verify root: %v", err)
	}
	// The derived token is signed by the parent's holder key, per draft §7.
	if err := parsedDerived.Verify(NewJWK(rootPub)); err != nil {
		t.Fatalf("Verify derived: %v", err)
	}

	// I5, computed independently of ParentHash.
	sum := sha256.Sum256(parsedRoot.SigningInput())
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if parsedDerived.Claims.ParentHash != want {
		t.Errorf("par_hash = %q, want %q", parsedDerived.Claims.ParentHash, want)
	}
	if parsedDerived.Claims.DelegationDepth != 1 {
		t.Errorf("del_depth = %d, want 1", parsedDerived.Claims.DelegationDepth)
	}

	// The holder key really is the agent's, so the agent can sign PoPs.
	got, err := parsedDerived.Claims.Confirmation.JWK.PublicKey()
	if err != nil {
		t.Fatalf("cnf.jwk PublicKey: %v", err)
	}
	if !bytes.Equal(got, agentPub) {
		t.Errorf("cnf.jwk = %x, want the agent key %x", got, agentPub)
	}
	_ = agentPriv
}

func TestVerifyRejectsTamperedClaims(t *testing.T) {
	priv, pub := keypair(t)
	tok, err := Mint(rootClaims(t, pub), priv)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	parts := strings.Split(tok.Compact(), ".")
	forged := strings.Replace(string(tok.Payload()), `"del_max_depth":3`, `"del_max_depth":9`, 1)
	if forged == string(tok.Payload()) {
		t.Fatal("test setup: del_max_depth not found in payload")
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(forged)) +
		"." + parts[2]

	parsed, err := Parse(tampered)
	if err != nil {
		return // parse-time rejection is also a rejection
	}
	if err := parsed.Verify(NewJWK(pub)); err == nil {
		t.Error("Verify accepted a token with a raised del_max_depth")
	}
}

// TestStructuralRules covers the presence/absence rules of draft §3.2 Table 1
// and the single-token shape rules. Chain invariants (I1-I5) are M0b.
func TestStructuralRules(t *testing.T) {
	priv, pub := keypair(t)
	jwk := NewJWK(pub)

	// Each case mutates the payload JSON of an otherwise valid root token and
	// re-signs it, so Parse sees a correctly signed but malformed token.
	tests := []struct {
		name    string
		mutate  func(m map[string]any)
		wantErr bool
	}{
		{"valid root", func(m map[string]any) {}, false},
		{"jti absent", func(m map[string]any) { delete(m, "jti") }, true},
		{"jti empty", func(m map[string]any) { m["jti"] = "" }, true},
		{"jti uppercase UUID", func(m map[string]any) {
			m["jti"] = "01957A41-0081-7C20-BF3A-00A0C91E1234"
		}, true},
		{"jti non-UUID string is allowed", func(m map[string]any) {
			m["jti"] = "opaque-Token-ID"
		}, false},
		{"iss absent", func(m map[string]any) { delete(m, "iss") }, true},
		{"iss empty", func(m map[string]any) { m["iss"] = "" }, true},
		{"iat absent", func(m map[string]any) { delete(m, "iat") }, true},
		{"exp absent", func(m map[string]any) { delete(m, "exp") }, true},
		{"exp equals iat", func(m map[string]any) { m["exp"] = m["iat"] }, true},
		{"exp before iat", func(m map[string]any) { m["exp"] = 1741599999 }, true},
		{"cnf absent", func(m map[string]any) { delete(m, "cnf") }, true},
		{"cnf without jwk", func(m map[string]any) { m["cnf"] = map[string]any{} }, true},
		{"cnf jwk carries private key", func(m map[string]any) {
			m["cnf"] = map[string]any{"jwk": map[string]any{
				"kty": "OKP", "crv": "Ed25519", "x": jwk.X, "d": rfc8037Seed,
			}}
		}, true},
		{"cnf jwk wrong kty", func(m map[string]any) {
			m["cnf"] = map[string]any{"jwk": map[string]any{
				"kty": "EC", "crv": "Ed25519", "x": jwk.X,
			}}
		}, true},
		{"cnf jwk wrong crv", func(m map[string]any) {
			m["cnf"] = map[string]any{"jwk": map[string]any{
				"kty": "OKP", "crv": "X25519", "x": jwk.X,
			}}
		}, true},
		{"cnf jwk short x", func(m map[string]any) {
			m["cnf"] = map[string]any{"jwk": map[string]any{
				"kty": "OKP", "crv": "Ed25519", "x": "AAAA",
			}}
		}, true},
		{"del_depth absent", func(m map[string]any) { delete(m, "del_depth") }, true},
		{"del_depth negative", func(m map[string]any) { m["del_depth"] = -1 }, true},
		{"del_max_depth absent", func(m map[string]any) { delete(m, "del_max_depth") }, true},
		{"del_max_depth negative", func(m map[string]any) { m["del_max_depth"] = -1 }, true},
		// par_hash presence and del_depth <= del_max_depth are NOT here: both
		// are position-in-chain rules, and Parse holds one token. They are
		// asserted with their §7 citations in chain_test.go —
		// TestDenyRootCarriesParHash (3d), TestDenyRootNonZeroDepth (3c),
		// TestDenyDerivedOmitsParHash (4b5), TestDenyTerminalParentDelegates
		// (4e). A Parse that guessed the position named the wrong defect.
		{"par_hash present in derived", func(m map[string]any) {
			m["del_depth"] = 1
			m["iss"] = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + rfc8037Thumbprint
			m["par_hash"] = strings.Repeat("A", 43)
		}, false},
		{"par_hash wrong length", func(m map[string]any) {
			m["del_depth"] = 1
			m["iss"] = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + rfc8037Thumbprint
			m["par_hash"] = "AAAA"
		}, true},
		{"par_hash not base64url", func(m map[string]any) {
			m["del_depth"] = 1
			m["iss"] = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + rfc8037Thumbprint
			m["par_hash"] = strings.Repeat("+", 43)
		}, true},
		// "derived iss is not a thumbprint URI" is not here either: §7 step 4c
		// compares it to the parent holder key's actual thumbprint, which is
		// stronger than a prefix test. TestDenyI1IssuerMismatch covers it.
		{"authorization_details absent", func(m map[string]any) {
			delete(m, "authorization_details")
		}, true},
		{"authorization_details not an array", func(m map[string]any) {
			m["authorization_details"] = map[string]any{}
		}, true},
		{"unknown claim is ignored", func(m map[string]any) {
			m["invocation_constraints"] = map[string]any{"budget": 1}
		}, false},
	}

	base, err := json.Marshal(rootClaims(t, pub))
	if err != nil {
		t.Fatalf("marshal base claims: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(base, &m); err != nil {
				t.Fatalf("unmarshal base: %v", err)
			}
			tt.mutate(m)
			payload, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal mutated: %v", err)
			}
			compact, err := jws.Sign(jws.Header{Alg: jws.EdDSA}, payload, priv)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			_, err = Parse(compact)
			if tt.wantErr && err == nil {
				t.Errorf("Parse accepted %s\npayload: %s", tt.name, payload)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Parse rejected %s: %v\npayload: %s", tt.name, err, payload)
			}
		})
	}
}

func TestParseRejectsDuplicateClaims(t *testing.T) {
	priv, pub := keypair(t)
	base, err := json.Marshal(rootClaims(t, pub))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A second del_depth: encoding/json keeps the last, an implementation that
	// keeps the first sees a root token where we see a derived one.
	dup := `{"del_depth":9,` + string(base[1:])
	compact, err := jws.Sign(jws.Header{Alg: jws.EdDSA}, []byte(dup), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Parse(compact); err == nil {
		t.Error("Parse accepted a payload with a duplicate claim")
	}
}

func TestMintRejectsInvalidClaims(t *testing.T) {
	priv, pub := keypair(t)

	bad := rootClaims(t, pub)
	bad.ParentHash = strings.Repeat("A", 43) // root MUST NOT carry par_hash
	if _, err := Mint(bad, priv); err == nil {
		t.Error("Mint accepted a root token with par_hash")
	}

	bad = rootClaims(t, pub)
	bad.Confirmation.JWK = nil
	if _, err := Mint(bad, priv); err == nil {
		t.Error("Mint accepted a token without cnf.jwk")
	}

	bad = rootClaims(t, pub)
	bad.AuthorizationDetails = nil
	if _, err := Mint(bad, priv); err == nil {
		t.Error("Mint accepted a token without authorization_details")
	}
}

// TestPoPRoundTrip covers draft §5.2, including the whole-payload JCS
// requirement: the bytes that were signed must already be JCS-canonical.
func TestPoPRoundTrip(t *testing.T) {
	priv, pub := keypair(t)

	claims := PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c1a45",
		IssuedAt: 1741600300,
		TokenID:  "01957a41-0081-7c20-bf3a-00a0c91e1234",
		Tool:     "read_file",
		Audience: "https://tools.example.com",
		Args: map[string]any{
			"path":  "/data/q3.pdf",
			"limit": 100,
			"深":     "unicode key",
		},
	}

	compact, err := SignPoP(claims, priv)
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	pop, err := ParsePoP(compact)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}
	if err := pop.Verify(NewJWK(pub)); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	payload := pop.Payload()
	canonical, err := jcs.Canonicalize(payload)
	if err != nil {
		t.Fatalf("Canonicalize signed payload: %v", err)
	}
	if !bytes.Equal(payload, canonical) {
		t.Errorf("signed PoP payload is not JCS-canonical:\n got %s\nwant %s",
			payload, canonical)
	}

	if pop.Claims.TokenID != claims.TokenID || pop.Claims.Tool != claims.Tool ||
		pop.Claims.Audience != claims.Audience || pop.Claims.JTI != claims.JTI {
		t.Errorf("round-trip claims = %+v, want %+v", pop.Claims, claims)
	}
	if pop.Claims.Args["path"] != "/data/q3.pdf" {
		t.Errorf("hta.path = %v, want /data/q3.pdf", pop.Claims.Args["path"])
	}
}

func TestPoPStructuralRules(t *testing.T) {
	priv, _ := keypair(t)
	valid := PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c1a45",
		IssuedAt: 1741600300,
		TokenID:  "01957a41-0081-7c20-bf3a-00a0c91e1234",
		Tool:     "read_file",
		Args:     map[string]any{},
	}
	if _, err := SignPoP(valid, priv); err != nil {
		t.Fatalf("SignPoP rejected a valid PoP (aat_aud is OPTIONAL): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(c *PoPClaims)
	}{
		{"jti empty", func(c *PoPClaims) { c.JTI = "" }},
		{"jti uppercase UUID", func(c *PoPClaims) {
			c.JTI = "C980F2A1-4A37-4E88-BB3C-9DEFD37C1A45"
		}},
		{"iat absent", func(c *PoPClaims) { c.IssuedAt = 0 }},
		{"aat_id empty", func(c *PoPClaims) { c.TokenID = "" }},
		{"aat_tool empty", func(c *PoPClaims) { c.Tool = "" }},
		{"hta absent", func(c *PoPClaims) { c.Args = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid
			c.Args = map[string]any{}
			tt.mutate(&c)
			if _, err := SignPoP(c, priv); err == nil {
				t.Errorf("SignPoP accepted %s", tt.name)
			}
		})
	}
}

// TestVerifyRejectsAlgKeyMismatch covers draft §7 steps 3a/4a/7a and the
// post-algorithm note. The key here carries the CORRECT Ed25519 public bytes in
// x, so the signature would verify under an alternate interpretation of the
// key's type — the draft requires denial anyway, on kty/crv alone.
func TestVerifyRejectsAlgKeyMismatch(t *testing.T) {
	priv, pub := keypair(t)
	tok, err := Mint(rootClaims(t, pub), priv)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	parsed, err := Parse(tok.Compact())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	good := NewJWK(pub)

	tests := []struct {
		name string
		key  *JWK
	}{
		{"nil key", nil},
		{"EC kty with correct key bytes", &JWK{Kty: "EC", Crv: "P-256", X: good.X}},
		{"RSA kty with correct key bytes", &JWK{Kty: "RSA", Crv: "Ed25519", X: good.X}},
		{"OKP but X25519 curve", &JWK{Kty: "OKP", Crv: "X25519", X: good.X}},
		{"OKP but Ed448 curve", &JWK{Kty: "OKP", Crv: "Ed448", X: good.X}},
		{"kty absent", &JWK{Crv: "Ed25519", X: good.X}},
		{"crv absent", &JWK{Kty: "OKP", X: good.X}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parsed.Verify(tt.key)
			if err == nil {
				t.Fatal("Verify accepted a key inconsistent with the declared alg")
			}
			// The denial must come from the algorithm/key binding, not from the
			// signature check: reaching ErrSignature would mean the bytes were
			// interpreted before the type was rejected.
			if errors.Is(err, jws.ErrSignature) {
				t.Errorf("Verify reached signature verification: %v", err)
			}
		})
	}

	// The same token still verifies under a consistent key.
	if err := parsed.Verify(good); err != nil {
		t.Errorf("Verify rejected a consistent key: %v", err)
	}
}

func TestPoPVerifyRejectsAlgKeyMismatch(t *testing.T) {
	priv, pub := keypair(t)
	compact, err := SignPoP(PoPClaims{
		JTI:      "c980f2a1-4a37-4e88-bb3c-9defd37c1a45",
		IssuedAt: 1741600300,
		TokenID:  "01957a41-0081-7c20-bf3a-00a0c91e1234",
		Tool:     "read_file",
		Args:     map[string]any{},
	}, priv)
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	pop, err := ParsePoP(compact)
	if err != nil {
		t.Fatalf("ParsePoP: %v", err)
	}

	mismatched := &JWK{Kty: "EC", Crv: "P-256", X: NewJWK(pub).X}
	if err := pop.Verify(mismatched); err == nil {
		t.Error("PoP Verify accepted a key inconsistent with the declared alg")
	} else if errors.Is(err, jws.ErrSignature) {
		t.Errorf("PoP Verify reached signature verification: %v", err)
	}
	if err := pop.Verify(NewJWK(pub)); err != nil {
		t.Errorf("PoP Verify rejected a consistent key: %v", err)
	}
}

func TestMaxTokenSizeIsConfigurable(t *testing.T) {
	priv, pub := keypair(t)
	tok, err := Mint(rootClaims(t, pub), priv)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	compact := tok.Compact()

	defer func(n int) { MaxTokenSize = n }(MaxTokenSize)

	MaxTokenSize = len(compact) - 1
	if _, err := Parse(compact); err == nil {
		t.Error("Parse accepted a token larger than MaxTokenSize")
	}

	MaxTokenSize = len(compact)
	if _, err := Parse(compact); err != nil {
		t.Errorf("Parse rejected a token exactly at MaxTokenSize: %v", err)
	}

	// §4.3.1 requires a finite limit, so a non-positive value fails closed
	// rather than meaning "unlimited".
	MaxTokenSize = 0
	if _, err := Parse(compact); err == nil {
		t.Error("Parse treated MaxTokenSize 0 as unlimited")
	}
}

// FuzzParse exercises the token decode path. Draft §7 step 2c extracts jti from
// an unverified payload before signature verification, so this runs on
// attacker-controlled bytes and must never panic.
func FuzzParse(f *testing.F) {
	priv, pub := keypair(f)
	tok, err := Mint(rootClaims(f, pub), priv)
	if err != nil {
		f.Fatalf("Mint: %v", err)
	}
	f.Add(tok.Compact())
	f.Add("")
	f.Add("..")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add(strings.Split(tok.Compact(), ".")[0] + ".e30.AAAA")

	f.Fuzz(func(t *testing.T, s string) {
		parsed, err := Parse(s)
		if err != nil {
			return
		}
		// Anything Parse accepted must satisfy the structural rules, and
		// verifying it must be safe.
		if parsed.Claims.DelegationDepth == 0 && parsed.Claims.ParentHash != "" {
			t.Fatalf("Parse accepted a root token with par_hash: %q", s)
		}
		if parsed.Claims.DelegationDepth > 0 && parsed.Claims.ParentHash == "" {
			t.Fatalf("Parse accepted a derived token without par_hash: %q", s)
		}
		if parsed.Claims.Confirmation.JWK == nil {
			t.Fatalf("Parse accepted a token without cnf.jwk: %q", s)
		}
		_ = parsed.Verify(NewJWK(pub))
		_ = ParentHash(parsed)
	})
}

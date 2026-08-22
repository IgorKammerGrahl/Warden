package jws

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// RFC 8037 Appendix A: the published Ed25519 JWS example. This is the only
// cross-implementation evidence in this package that our signing input and
// base64url encoding agree with everyone else's.
const (
	rfc8037PrivateD = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037PublicX  = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	rfc8037Payload  = "Example of Ed25519 signing"
	rfc8037Compact  = "eyJhbGciOiJFZERTQSJ9." +
		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5B" +
		"hVsPt9g7sVvpAr_MuM0KAg"
)

func rfc8037Keys(t testing.TB) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037PrivateD)
	if err != nil {
		t.Fatalf("decode d: %v", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(rfc8037PublicX)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatalf("RFC 8037 d and x disagree: derived %x, want %x",
			priv.Public().(ed25519.PublicKey), pub)
	}
	return priv, ed25519.PublicKey(pub)
}

func testKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, pub
}

func TestRFC8037Vector(t *testing.T) {
	priv, pub := rfc8037Keys(t)

	// Ed25519 is deterministic, so our output must equal the RFC's byte for byte.
	got, err := Sign(Header{Alg: EdDSA}, []byte(rfc8037Payload), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != rfc8037Compact {
		t.Errorf("Sign =\n%q\nwant\n%q", got, rfc8037Compact)
	}

	msg, err := Parse(rfc8037Compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Header.Alg != EdDSA {
		t.Errorf("Header.Alg = %q, want %q", msg.Header.Alg, EdDSA)
	}
	if string(msg.Payload) != rfc8037Payload {
		t.Errorf("Payload = %q, want %q", msg.Payload, rfc8037Payload)
	}
	if err := msg.Verify(pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSigningInput(t *testing.T) {
	// RFC 7515 §5.1: BASE64URL(protected header) || '.' || BASE64URL(payload).
	msg, err := Parse(rfc8037Compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := rfc8037Compact[:strings.LastIndex(rfc8037Compact, ".")]
	if string(msg.SigningInput) != want {
		t.Errorf("SigningInput = %q, want %q", msg.SigningInput, want)
	}
}

func TestRoundTrip(t *testing.T) {
	priv, pub := testKeys(t)
	payloads := [][]byte{
		[]byte(`{}`),
		[]byte(`{"jti":"01900000-0000-7000-8000-000000000000"}`),
		bytes.Repeat([]byte("a"), 4096),
		{0x00, 0xff, 0x80}, // the payload is opaque octets to this layer
	}
	for _, p := range payloads {
		compact, err := Sign(Header{Alg: EdDSA, Typ: "aat+jwt"}, p, priv)
		if err != nil {
			t.Fatalf("Sign(%q): %v", p, err)
		}
		if strings.Contains(compact, "=") {
			t.Errorf("Sign(%q) = %q, contains base64 padding", p, compact)
		}
		msg, err := Parse(compact)
		if err != nil {
			t.Fatalf("Parse(%q): %v", compact, err)
		}
		if !bytes.Equal(msg.Payload, p) {
			t.Errorf("round-trip payload = %q, want %q", msg.Payload, p)
		}
		if msg.Header.Typ != "aat+jwt" {
			t.Errorf("Header.Typ = %q, want %q", msg.Header.Typ, "aat+jwt")
		}
		if err := msg.Verify(pub); err != nil {
			t.Errorf("Verify(%q): %v", p, err)
		}
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	priv, _ := testKeys(t)
	_, otherPub := testKeys(t)

	compact, err := Sign(Header{Alg: EdDSA}, []byte(`{"a":1}`), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	msg, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := msg.Verify(otherPub); err == nil {
		t.Error("Verify with the wrong key succeeded")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	priv, pub := testKeys(t)
	compact, err := Sign(Header{Alg: EdDSA, Kid: "k1"}, []byte(`{"amount":1}`), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parts := strings.Split(compact, ".")

	tests := []struct {
		name    string
		mutate  func(p []string) string
		wantErr bool
	}{
		{
			name: "payload swapped",
			mutate: func(p []string) string {
				return p[0] + "." +
					base64.RawURLEncoding.EncodeToString([]byte(`{"amount":9}`)) + "." + p[2]
			},
		},
		{
			name: "header kid changed",
			mutate: func(p []string) string {
				h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k2"}`))
				return h + "." + p[1] + "." + p[2]
			},
		},
		{
			name: "signature bit flipped",
			mutate: func(p []string) string {
				sig, _ := base64.RawURLEncoding.DecodeString(p[2])
				sig[0] ^= 0x01
				return p[0] + "." + p[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
			},
		},
		{
			name: "signature truncated",
			mutate: func(p []string) string {
				sig, _ := base64.RawURLEncoding.DecodeString(p[2])
				return p[0] + "." + p[1] + "." +
					base64.RawURLEncoding.EncodeToString(sig[:len(sig)-1])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := Parse(tt.mutate(parts))
			if err != nil {
				return // rejecting at parse time is also a rejection
			}
			if err := msg.Verify(pub); err == nil {
				t.Error("Verify accepted a tampered token")
			}
		})
	}
}

// TestParseRejectsAlg covers draft §8.13: an explicit allowlist, alg:"none"
// rejected unconditionally, and a missing alg never treated as permitted.
func TestParseRejectsAlg(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"none lowercase", `{"alg":"none"}`},
		{"none uppercase", `{"alg":"NONE"}`},
		{"none mixed case", `{"alg":"None"}`},
		{"alg absent", `{}`},
		{"alg absent but typ present", `{"typ":"JWT"}`},
		{"alg empty", `{"alg":""}`},
		{"alg null", `{"alg":null}`},
		{"HS256", `{"alg":"HS256"}`},
		{"RS256", `{"alg":"RS256"}`},
		{"ES256", `{"alg":"ES256"}`},
		{"PS256", `{"alg":"PS256"}`},
		{"EdDSA wrong case", `{"alg":"EDDSA"}`},
		{"EdDSA lower case", `{"alg":"eddsa"}`},
		{"alg not a string", `{"alg":1}`},
		{"crit unrecognized", `{"alg":"EdDSA","crit":["exp"]}`},
		{"duplicate alg, none first", `{"alg":"none","alg":"EdDSA"}`},
		{"duplicate alg, EdDSA first", `{"alg":"EdDSA","alg":"none"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compact := base64.RawURLEncoding.EncodeToString([]byte(tt.header)) +
				"." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`)) +
				"." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 64))
			if _, err := Parse(compact); err == nil {
				t.Errorf("Parse accepted header %s", tt.header)
			}
		})
	}
}

// TestParseRejectsNoneWithEmptySignature is the classic unsecured-JWS attack:
// header alg:"none" with the signature part empty.
func TestParseRejectsNoneWithEmptySignature(t *testing.T) {
	compact := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(`{"del_depth":0}`)) + "."
	if _, err := Parse(compact); err == nil {
		t.Error("Parse accepted an unsecured JWS")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good := rfc8037Compact
	parts := strings.Split(good, ".")

	tests := []struct{ name, compact string }{
		{"empty", ""},
		{"no separators", "abc"},
		{"one separator", parts[0] + "." + parts[1]},
		{"four parts", good + "." + parts[2]},
		{"empty header", "." + parts[1] + "." + parts[2]},
		{"empty payload part", parts[0] + ".." + parts[2]},
		{"empty signature part", parts[0] + "." + parts[1] + "."},
		{"padded base64", parts[0] + "=." + parts[1] + "." + parts[2]},
		{"standard base64 alphabet", "eyJhbGciOiJFZERTQSJ9+" + "." + parts[1] + "." + parts[2]},
		{"header not base64", "!!!." + parts[1] + "." + parts[2]},
		{"signature not base64", parts[0] + "." + parts[1] + ".!!!"},
		{"header not JSON", base64.RawURLEncoding.EncodeToString([]byte("notjson")) +
			"." + parts[1] + "." + parts[2]},
		{"header is an array", base64.RawURLEncoding.EncodeToString([]byte(`["EdDSA"]`)) +
			"." + parts[1] + "." + parts[2]},
		{"leading whitespace", " " + good},
		{"trailing newline", good + "\n"},
		{"JWE five parts", parts[0] + "." + parts[1] + "." + parts[2] + ".." + parts[2]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.compact); err == nil {
				t.Errorf("Parse(%q) succeeded, want error", tt.compact)
			}
		})
	}
}

func TestSignRejectsBadAlgorithm(t *testing.T) {
	priv, _ := testKeys(t)
	for _, alg := range []Algorithm{"none", "HS256", "", "EDDSA"} {
		if _, err := Sign(Header{Alg: alg}, []byte(`{}`), priv); err == nil {
			t.Errorf("Sign accepted alg %q", alg)
		}
	}
}

func TestSignRejectsBadKey(t *testing.T) {
	if _, err := Sign(Header{Alg: EdDSA}, []byte(`{}`), nil); err == nil {
		t.Error("Sign accepted a nil key")
	}
	if _, err := Sign(Header{Alg: EdDSA}, []byte(`{}`), make(ed25519.PrivateKey, 5)); err == nil {
		t.Error("Sign accepted a short key")
	}
}

func TestSignRejectsEmptyPayload(t *testing.T) {
	priv, _ := testKeys(t)
	if _, err := Sign(Header{Alg: EdDSA}, nil, priv); err == nil {
		t.Error("Sign accepted an empty payload")
	}
}

func TestVerifyRejectsBadKey(t *testing.T) {
	msg, err := Parse(rfc8037Compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := msg.Verify(nil); err == nil {
		t.Error("Verify accepted a nil key")
	}
	if err := msg.Verify(make(ed25519.PublicKey, 5)); err == nil {
		t.Error("Verify accepted a short key")
	}
}

// FuzzParse exercises the decode path on attacker-controlled bytes. Draft §7
// requires extracting jti before signature verification, so Parse necessarily
// runs before the token is trusted: it must never panic.
func FuzzParse(f *testing.F) {
	f.Add(rfc8037Compact)
	f.Add("")
	f.Add("..")
	f.Add("eyJhbGciOiJub25lIn0..")
	f.Add(strings.Repeat(".", 64))

	_, pub := rfc8037Keys(f)
	f.Fuzz(func(t *testing.T, s string) {
		msg, err := Parse(s)
		if err != nil {
			return
		}
		if msg.Header.Alg != EdDSA {
			t.Fatalf("Parse accepted alg %q", msg.Header.Alg)
		}
		// Verifying must be safe on anything Parse accepted.
		_ = msg.Verify(pub)
	})
}

package jcs

import (
	"encoding/json"
	"testing"
)

// TestCanonicalizeIsUnchangedByAGoValueRoundTrip is the regression guard for a
// trap that turned out not to be one, which is why it is worth pinning.
//
// encoding/json decodes every JSON number into float64, so canonicalizing a
// re-marshalled map[string]any could in principle disagree with canonicalizing
// the original bytes — and §7 step 7f compares exactly those two things, the
// PoP's hta (canonicalized from raw payload bytes) against the invocation's
// arguments (which reach the verifier as Go values). They agree because
// RFC 8785 §3.2.2.3 puts numbers through IEEE 754 doubles as well, so both
// paths lose the same information in the same place, and Go's shortest
// round-trip float formatting recovers the identical double.
//
// The consequence is that the float64 decode causes neither a false denial nor
// a false permit. What it does not fix is the collapse itself — see
// TestCheckNumbers.
func TestCanonicalizeIsUnchangedByAGoValueRoundTrip(t *testing.T) {
	for _, raw := range []string{
		`{"n":9007199254740993}`, // 2^53+1: the first integer a double cannot hold
		`{"n":9007199254740992}`, // 2^53
		`{"n":12345678901234567890}`,
		`{"n":123456789012345678901234567890}`,
		`{"n":-9007199254740993}`,
		`{"n":-0}`,
		`{"n":1.0}`,
		`{"n":0.1}`,
		`{"n":1e21}`,
		`{"n":5e-324}`, // smallest subnormal
	} {
		direct, err := Canonicalize([]byte(raw))
		if err != nil {
			t.Fatalf("Canonicalize(%s) = %v", raw, err)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatalf("Unmarshal(%s) = %v", raw, err)
		}
		remarshalled, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("Marshal(%s) = %v", raw, err)
		}
		viaGo, err := Canonicalize(remarshalled)
		if err != nil {
			t.Fatalf("Canonicalize(remarshal(%s)) = %v", raw, err)
		}
		if string(direct) != string(viaGo) {
			t.Errorf("%s: canonicalizing raw bytes gives %s, canonicalizing the "+
				"float64 round trip gives %s; §7 step 7f compares these two",
				raw, direct, viaGo)
		}
	}
}

func TestCheckNumbers(t *testing.T) {
	ok := []string{
		`{"n":9007199254740992}`, // 2^53 is exactly representable
		`{"n":0}`,
		`{"n":-0}`,   // canonicalizes to 0; same number
		`{"n":1.0}`,  // canonicalizes to 1; same number
		`{"n":1e21}`, // canonicalizes to 1e+21; same number
		`{"n":0.1}`,  // the double is not exactly 0.1, but "0.1" still names it
		`{"n":5e-324}`,
		`{"a":[1,2,{"b":3}],"c":"9007199254740993"}`, // the big value is a string
		`{}`,
		`"no numbers here"`,
	}
	for _, raw := range ok {
		if err := CheckNumbers([]byte(raw)); err != nil {
			t.Errorf("CheckNumbers(%s) = %v, want nil", raw, err)
		}
	}

	bad := []string{
		`{"n":9007199254740993}`,  // 2^53+1
		`{"n":-9007199254740993}`, // and its negation
		`{"n":12345678901234567890}`,
		`{"n":123456789012345678901234567890}`,
		`{"n":0.1000000000000000000000001}`,
		`[1,2,9007199254740993]`, // nested inside an array
		`{"a":{"b":9007199254740993}}`,
	}
	for _, raw := range bad {
		if err := CheckNumbers([]byte(raw)); err == nil {
			t.Errorf("CheckNumbers(%s) = nil, want a rejection", raw)
		}
	}
}

// TestCheckNumbersAcceptsCanonicalOutput is the property that makes the check
// safe to apply at a trust boundary: it can never reject a document some
// conformant peer produced by canonicalizing, because canonical output always
// names its own value.
func TestCheckNumbersAcceptsCanonicalOutput(t *testing.T) {
	for _, raw := range []string{
		`{"n":9007199254740993}`,
		`{"n":123456789012345678901234567890}`,
		`{"n":0.1000000000000000000000001}`,
		`{"n":1e21}`,
		`{"n":5e-324}`,
	} {
		canonical, err := Canonicalize([]byte(raw))
		if err != nil {
			t.Fatalf("Canonicalize(%s) = %v", raw, err)
		}
		if err := CheckNumbers(canonical); err != nil {
			t.Errorf("CheckNumbers(Canonicalize(%s)) = CheckNumbers(%s) = %v, want nil",
				raw, canonical, err)
		}
	}
}

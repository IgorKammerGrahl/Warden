package jcs

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// unhex turns the RFC's spaced hex dumps into bytes, so expected values can be
// transcribed from the document without reformatting them by hand.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	if err != nil {
		t.Fatalf("test data: %v", err)
	}
	return b
}

// TestRFC8785NumberVectors is Appendix B, Table 1 of RFC 8785, verbatim.
// Vectors are keyed by IEEE 754 bit pattern because that is how the RFC states
// them: the input is a double, not a JSON literal.
func TestRFC8785NumberVectors(t *testing.T) {
	tests := []struct {
		bits    uint64
		want    string
		comment string
	}{
		{0x0000000000000000, "0", "Zero"},
		{0x8000000000000000, "0", "Minus zero"},
		{0x0000000000000001, "5e-324", "Min pos number"},
		{0x8000000000000001, "-5e-324", "Min neg number"},
		{0x7fefffffffffffff, "1.7976931348623157e+308", "Max pos number"},
		{0xffefffffffffffff, "-1.7976931348623157e+308", "Max neg number"},
		{0x4340000000000000, "9007199254740992", "Max pos int"},
		{0xc340000000000000, "-9007199254740992", "Max neg int"},
		{0x4430000000000000, "295147905179352830000", "~2**68"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22", ""},
		{0x44b52d02c7e14af6, "1e+23", ""},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23", ""},
		{0x444b1ae4d6e2ef4e, "999999999999999700000", ""},
		{0x444b1ae4d6e2ef4f, "999999999999999900000", ""},
		{0x444b1ae4d6e2ef50, "1e+21", ""},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7", ""},
		{0x3eb0c6f7a0b5ed8d, "0.000001", ""},
		{0x41b3de4355555553, "333333333.3333332", ""},
		{0x41b3de4355555554, "333333333.33333325", ""},
		{0x41b3de4355555555, "333333333.3333333", ""},
		{0x41b3de4355555556, "333333333.3333334", ""},
		{0x41b3de4355555557, "333333333.33333343", ""},
		{0xbecbf647612f3696, "-0.0000033333333333333333", ""},
		{0x43143ff3c1cb0959, "1424953923781206.2", "Round to even"},
	}

	for _, tt := range tests {
		f := math.Float64frombits(tt.bits)
		got, err := formatNumber(f)
		if err != nil {
			t.Errorf("formatNumber(%016x) [%s]: unexpected error: %v", tt.bits, tt.comment, err)
			continue
		}
		if got != tt.want {
			t.Errorf("formatNumber(%016x) [%s] = %q, want %q", tt.bits, tt.comment, got, tt.want)
		}
	}
}

// RFC 8785 Appendix B note (3) and §3.2.2.3: NaN and Infinity are not permitted
// in JSON and MUST terminate canonicalization with an error.
func TestRFC8785NumberVectorsOutOfRange(t *testing.T) {
	tests := []struct {
		bits    uint64
		comment string
	}{
		{0x7fffffffffffffff, "NaN"},
		{0x7ff0000000000000, "Infinity"},
		{0xfff0000000000000, "-Infinity"},
	}
	for _, tt := range tests {
		f := math.Float64frombits(tt.bits)
		if got, err := formatNumber(f); err == nil {
			t.Errorf("formatNumber(%016x) [%s] = %q, want error", tt.bits, tt.comment, got)
		}
	}
}

// TestRFC8785WorkedExample is the example carried through §3.2.2, §3.2.3 and
// §3.2.4. Input is the §3.2.2 sample verbatim; expected output is the §3.2.4
// hex dump verbatim.
func TestRFC8785WorkedExample(t *testing.T) {
	input := []byte(`{
       "numbers": [333333333.33333329, 1E30, 4.50,
                   2e-3, 0.000000000000000000000000001],
       "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
       "literals": [null, true, false]
     }`)

	want := unhex(t, `
		7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
		75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
		5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
		65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
		5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
		30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d
	`)

	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Canonicalize mismatch\n got: %s\nwant: %s\n got hex: % x\nwant hex: % x",
			got, want, got, want)
	}
}

// TestRFC8785PropertySorting is the §3.2.3 sorting vector. The emoji key is the
// case that separates UTF-16 code-unit order from code-point order: U+1F600
// encodes to the surrogate 0xD83D, which sorts BEFORE U+FB33 even though the
// code point is larger. Sorting raw UTF-8 bytes gets this backwards.
func TestRFC8785PropertySorting(t *testing.T) {
	input := []byte(`{
       "€": "Euro Sign",
       "\r": "Carriage Return",
       "דּ": "Hebrew Letter Dalet With Dagesh",
       "1": "One",
       "😀": "Emoji: Grinning Face",
       "\u0080": "Control",
       "ö": "Latin Small Letter O With Diaeresis"
     }`)

	// §3.2.3 "Expected argument order after sorting property strings".
	wantOrder := []string{
		"Carriage Return",
		"One",
		"Control",
		"Latin Small Letter O With Diaeresis",
		"Euro Sign",
		"Emoji: Grinning Face",
		"Hebrew Letter Dalet With Dagesh",
	}

	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}

	prev := -1
	for _, w := range wantOrder {
		idx := bytes.Index(got, []byte(`"`+w+`"`))
		if idx < 0 {
			t.Fatalf("value %q missing from output: %s", w, got)
		}
		if idx <= prev {
			t.Errorf("property order wrong at %q (index %d, previous %d)\noutput: %s", w, idx, prev, got)
		}
		prev = idx
	}
}

func TestCanonicalizeStrings(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// §3.2.2.2: the five predefined JSON control escapes.
		{"predefined controls", `["\b\t\n\f\r"]`, `["\b\t\n\f\r"]`},
		// §3.2.2.2: other C0 controls use lowercase \uhhhh.
		{"other controls", `["\u0000\u001f\u000b"]`, `["\u0000\u001f\u000b"]`},
		// Uppercase hex in the input is normalized to lowercase on output.
		{"hex case normalized", `["\u000F"]`, `["\u000f"]`},
		// §3.2.2.2: only \ and " are escaped outside the control range.
		{"quote and backslash", `["\"\\"]`, `["\"\\"]`},
		// Solidus is NOT escaped.
		{"solidus", `["\/"]`, `["/"]`},
		// Non-ASCII passes through as UTF-8, not \u-escaped.
		{"non-ascii passthrough", `["€ö"]`, "[\"€ö\"]"},
		{"astral passthrough", `["😀"]`, "[\"\U0001F600\"]"},
		{"del is not a control", `["\u007f"]`, "[\"\u007f\"]"},
		{"empty string", `[""]`, `[""]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Canonicalize(%q): %v", tt.input, err)
			}
			if string(got) != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeStructure(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"whitespace stripped", "{ \"a\" : 1 ,\n\"b\":\t2 }", `{"a":1,"b":2}`},
		{"nested objects sorted recursively", `{"b":{"z":1,"a":2},"a":3}`, `{"a":3,"b":{"a":2,"z":1}}`},
		{"array order preserved", `[3,1,2]`, `[3,1,2]`},
		{"objects inside arrays sorted", `[{"b":1,"a":2}]`, `[{"a":2,"b":1}]`},
		{"literals", `[null,true,false]`, `[null,true,false]`},
		{"empty object", `{}`, `{}`},
		{"empty array", `[]`, `[]`},
		{"top-level scalar", `4.50`, `4.5`},
		{"top-level string", `"x"`, `"x"`},
		{"top-level null", `null`, `null`},
		{"empty key sorts first", `{"a":1,"":2}`, `{"":2,"a":1}`},
		{"prefix shorter first", `{"ab":1,"aa":2,"a":3}`, `{"a":3,"aa":2,"ab":1}`},
		{"deep nesting", `{"a":[[[{"b":[1]}]]]}`, `{"a":[[[{"b":[1]}]]]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Canonicalize(%q): %v", tt.input, err)
			}
			if string(got) != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		// §3.2.2.2 note: lone surrogates MUST terminate with an error.
		{"lone high surrogate", `["\ud83d"]`},
		{"lone low surrogate", `["\ude00"]`},
		{"high surrogate then plain", `["\ud83dA"]`},
		{"high surrogate then escape", `["\ud83d\u0041"]`},
		{"reversed pair", `["\ude00\ud83d"]`},
		{"lone surrogate in key", `{"\ud83d":1}`},
		// §3.1 / I-JSON: duplicate property names MUST NOT appear. Silently
		// keeping the last one is a signature-confusion vector.
		{"duplicate keys", `{"a":1,"a":2}`},
		{"duplicate keys nested", `{"x":{"a":1,"a":2}}`},
		{"duplicate keys in array element", `[{"a":1,"a":2}]`},
		// §3.2.2.3: NaN/Infinity cannot appear as JSON literals, but an
		// overflowing decimal literal parses to +Inf.
		{"overflow to infinity", `[1e400]`},
		// Not JSON at all.
		{"trailing garbage", `{} {}`},
		{"truncated", `{"a":`},
		{"empty input", ``},
		{"bare word", `undefined`},
		{"invalid utf8 in string", "[\"\xff\xfe\"]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := Canonicalize([]byte(tt.input)); err == nil {
				t.Errorf("Canonicalize(%q) = %q, want error", tt.input, got)
			}
		})
	}
}

// Canonicalizing canonical output must be a no-op. Any drift here means the
// serializer and the parser disagree, which would break signatures.
func TestCanonicalizeIdempotent(t *testing.T) {
	inputs := []string{
		`{"b":{"z":[1,2,{"y":null}],"a":""},"a":333333333.33333329}`,
		`[1e30,4.50,2e-3,0.000000000000000000000000001]`,
		`{"€":"x","😀":"y","דּ":"z"}`,
		`["\b\t\n\f\r\u0000\u001f"]`,
	}
	for _, in := range inputs {
		once, err := Canonicalize([]byte(in))
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", in, err)
		}
		twice, err := Canonicalize(once)
		if err != nil {
			t.Fatalf("Canonicalize(canonical %q): %v", once, err)
		}
		if !bytes.Equal(once, twice) {
			t.Errorf("not idempotent\nonce:  %s\ntwice: %s", once, twice)
		}
	}
}

// FuzzCanonicalize: JCS runs on attacker-controlled bytes (a presented PoP JWT
// payload). It may return an error, but it must never panic — and anything it
// accepts must be a fixed point, or signatures do not reproduce.
func FuzzCanonicalize(f *testing.F) {
	seeds := []string{
		`{"a":1}`, `[1,2,3]`, `"x"`, `null`, `1e30`, `{}`, `[]`,
		`{"€":"x","😀":"y"}`,
		`["\b\t\n\f\r\u0000"]`,
		`{"b":{"z":1,"a":2},"a":3}`,
		`333333333.33333329`,
		`["\ud83d"]`,
		`{"a":1,"a":2}`,
		`[1e400]`,
		`{"a":[[[{"b":[1]}]]]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Canonicalize(data)
		if err != nil {
			return
		}
		again, err := Canonicalize(out)
		if err != nil {
			t.Fatalf("canonical output rejected on re-canonicalization: %v\ninput: %q\noutput: %q", err, data, out)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("not idempotent\ninput: %q\nonce:  %q\ntwice: %q", data, out, again)
		}
	})
}

// Package jcs implements RFC 8785, the JSON Canonicalization Scheme.
//
// AAT draft-01 §5.2 requires the PoP JWT payload to be serialized as
// JCS-canonical JSON before JWS signing — a whole-payload requirement, not
// specific to the hta member. Canonicalization is therefore on the signature
// path: any divergence from RFC 8785 shows up as a PoP verification failure
// against a conformant peer, which is indistinguishable from a semantics bug.
// That is why this package is verified against the RFC's own test vectors
// rather than against our expectations of them.
//
// Go's encoding/json does NOT produce JCS output. The differences that matter:
// number formatting (JCS requires the ECMAScript Number::toString shortest
// round-trip form), property sorting (UTF-16 code units, not UTF-8 bytes),
// string escaping (only the minimal ES set), and rejection of lone surrogates.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// maxDepth bounds nesting. Canonicalize runs on attacker-controlled bytes (a
// presented PoP JWT payload), and decodeValue is recursive.
// ponytail: a fixed cap, not a configurable one — AAT payloads are shallow and
// nothing in the draft needs more. Make it a parameter only if a caller appears
// that legitimately nests deeper.
const maxDepth = 1000

const hexDigits = "0123456789abcdef"

// Canonicalize returns the RFC 8785 canonical form of the JSON value in data.
//
// It is a fixed point: canonicalizing canonical output reproduces it byte for
// byte. Input that RFC 8785 forbids is rejected rather than coerced — lone
// surrogates (§3.2.2.2), duplicate property names (§3.1, I-JSON), and numbers
// that are not finite doubles (§3.2.2.3).
func Canonicalize(data []byte) ([]byte, error) {
	// Both of these have to run on the raw bytes. Go's encoding/json silently
	// substitutes U+FFFD for invalid UTF-8 and for unpaired surrogate escapes,
	// so by the time a string reaches the serializer the evidence is gone — and
	// a conformant peer that errors instead would produce a different signature.
	if !utf8.Valid(data) {
		return nil, errors.New("jcs: input is not valid UTF-8 (RFC 8259 §8.1)")
	}
	if err := checkSurrogatePairs(data); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	v, err := decodeValue(dec, tok, 0)
	if err != nil {
		return nil, err
	}
	// A canonical document holds exactly one value. "{} {}" is two.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("jcs: trailing data after top-level JSON value")
	}

	return appendValue(make([]byte, 0, len(data)), v)
}

// decodeValue builds the value tree from the token stream. It uses Token()
// rather than Unmarshal for two reasons: UseNumber preserves the literal so the
// float conversion happens here, and duplicate property names are visible —
// Unmarshal silently keeps the last one, which is a signature-confusion vector.
func decodeValue(dec *json.Decoder, tok json.Token, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("jcs: nesting deeper than %d", maxDepth)
	}

	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}

	switch delim {
	case '{':
		obj := make(map[string]any)
		for {
			kt, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("jcs: %w", err)
			}
			if d, ok := kt.(json.Delim); ok && d == '}' {
				return obj, nil
			}
			key, ok := kt.(string)
			if !ok {
				return nil, fmt.Errorf("jcs: object key is not a string: %v", kt)
			}
			if _, dup := obj[key]; dup {
				return nil, fmt.Errorf("jcs: duplicate property name %q (RFC 8785 §3.1, I-JSON)", key)
			}
			vt, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("jcs: %w", err)
			}
			val, err := decodeValue(dec, vt, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}

	case '[':
		arr := []any{}
		for {
			et, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("jcs: %w", err)
			}
			if d, ok := et.(json.Delim); ok && d == ']' {
				return arr, nil
			}
			val, err := decodeValue(dec, et, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
	}

	return nil, fmt.Errorf("jcs: unexpected delimiter %q", delim)
}

func appendValue(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil

	case bool:
		if x {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil

	case string:
		return appendString(dst, x)

	case json.Number:
		f, err := parseDouble(string(x))
		if err != nil {
			return nil, err
		}
		s, err := formatNumber(f)
		if err != nil {
			return nil, err
		}
		return append(dst, s...), nil

	case []any:
		dst = append(dst, '[')
		for i, e := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendValue(dst, e); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil

	case map[string]any:
		// §3.2.3: sort property names as arrays of UTF-16 code units. Encoding
		// once up front rather than inside the comparator keeps this O(n log n)
		// comparisons rather than O(n log n) re-encodings.
		type prop struct {
			name  string
			units []uint16
		}
		props := make([]prop, 0, len(x))
		for k := range x {
			props = append(props, prop{name: k, units: utf16.Encode([]rune(k))})
		}
		slices.SortFunc(props, func(a, b prop) int {
			return slices.Compare(a.units, b.units)
		})

		dst = append(dst, '{')
		for i, p := range props {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendString(dst, p.name); err != nil {
				return nil, err
			}
			dst = append(dst, ':')
			if dst, err = appendValue(dst, x[p.name]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	}

	return nil, fmt.Errorf("jcs: unsupported value type %T", v)
}

// appendString serializes a JSON string per RFC 8785 §3.2.2.2: the five
// predefined escapes for U+0008/09/0A/0C/0D, lowercase \u00hh for the rest of
// the C0 range, \\ and \" for U+005C and U+0022, and everything else verbatim
// as UTF-8. Notably the solidus is NOT escaped and non-ASCII is NOT escaped.
func appendString(dst []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, errors.New("jcs: string is not valid UTF-8")
	}

	dst = append(dst, '"')
	// Byte-wise is safe: every byte of a multi-byte UTF-8 sequence is >= 0x80
	// and falls through to the verbatim branch.
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\r':
			dst = append(dst, '\\', 'r')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"'), nil
}

// parseDouble converts a JSON number literal to the IEEE 754 double that
// RFC 8785 §3.1 says it must be expressible as. Overflow yields ±Inf, which
// formatNumber then rejects; underflow yields ±0, which is what ECMAScript
// does and is a legitimate value.
func parseDouble(lit string) (float64, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		var ne *strconv.NumError
		if !errors.As(err, &ne) || !errors.Is(ne.Err, strconv.ErrRange) {
			return 0, fmt.Errorf("jcs: %w", err)
		}
	}
	return f, nil
}

// formatNumber implements ECMAScript Number::toString (ECMA-262 §7.1.12.1)
// with the "Note 2" enhancement, as required by RFC 8785 §3.2.2.3.
//
// The shortest round-trip digit string and the decimal exponent come from
// strconv.AppendFloat(_, 'e', -1, 64); ECMAScript's own output rules are then
// applied to them. Go's own 'g'/'e'/'f' formatting does not match ECMAScript:
// the thresholds at which it switches to exponential notation differ, and it
// pads exponents to two digits ("1e+05" where ECMAScript gives "100000").
func formatNumber(f float64) (string, error) {
	if math.IsNaN(f) {
		return "", errors.New("jcs: NaN is not permitted in JSON (RFC 8785 §3.2.2.3)")
	}
	if math.IsInf(f, 0) {
		return "", errors.New("jcs: Infinity is not permitted in JSON (RFC 8785 §3.2.2.3)")
	}
	// Covers -0, which ECMAScript serializes as "0".
	if f == 0 {
		return "0", nil
	}

	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}

	// "d[.ddd]e±dd"
	buf := strconv.AppendFloat(nil, f, 'e', -1, 64)
	epos := bytes.IndexByte(buf, 'e')
	if epos < 0 {
		return "", fmt.Errorf("jcs: unexpected float formatting %q", buf)
	}
	e, err := strconv.Atoi(string(buf[epos+1:]))
	if err != nil {
		return "", fmt.Errorf("jcs: unexpected float exponent %q: %w", buf, err)
	}
	digits := string(bytes.Replace(buf[:epos], []byte("."), nil, 1))

	// ECMA-262 names these k and n: the value is digits x 10^(n-k), with k the
	// digit count. Go's 'e' exponent is the power of ten of the leading digit,
	// so n = e + 1.
	k := len(digits)
	n := e + 1

	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	case k == 1:
		return sign + digits + "e" + exponent(n-1), nil
	default:
		return sign + digits[:1] + "." + digits[1:] + "e" + exponent(n-1), nil
	}
}

// exponent renders the ECMAScript exponent suffix: an explicit sign and no
// leading zeros.
func exponent(e int) string {
	if e < 0 {
		return "-" + strconv.Itoa(-e)
	}
	return "+" + strconv.Itoa(e)
}

// checkSurrogatePairs rejects lone surrogates, which RFC 8785 §3.2.2.2 requires
// to terminate canonicalization with an error.
//
// ponytail: scans the whole document rather than tracking string boundaries.
// A "\u" sequence outside a string is invalid JSON anyway, so the only effect
// of the imprecision is which error message an already-invalid document gets.
func checkSurrogatePairs(data []byte) error {
	for i := 0; i+1 < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		if data[i+1] != 'u' {
			// A backslash escaping a backslash is not the start of an escape.
			if data[i+1] == '\\' {
				i++
			}
			continue
		}
		hi, ok := hex4(data, i+2)
		if !ok {
			continue // malformed escape; the decoder reports it
		}
		switch {
		case hi >= 0xDC00 && hi <= 0xDFFF:
			return fmt.Errorf("jcs: lone low surrogate \\u%04x (RFC 8785 §3.2.2.2)", hi)
		case hi >= 0xD800 && hi <= 0xDBFF:
			lo, ok := hex4(data, i+8)
			if !ok || i+8 > len(data) || data[i+6] != '\\' || data[i+7] != 'u' ||
				lo < 0xDC00 || lo > 0xDFFF {
				return fmt.Errorf("jcs: lone high surrogate \\u%04x (RFC 8785 §3.2.2.2)", hi)
			}
			i += 11 // consume the whole pair
		}
	}
	return nil
}

// hex4 reads the four hex digits of a \uXXXX escape starting at off.
func hex4(data []byte, off int) (rune, bool) {
	if off+4 > len(data) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(data[off:off+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(v), true
}

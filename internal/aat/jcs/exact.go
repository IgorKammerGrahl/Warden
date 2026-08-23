package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// CheckNumbers reports whether every JSON number in data survives RFC 8785
// canonicalization without changing value.
//
// This is deliberately NOT part of Canonicalize. RFC 8785 §3.2.2.3 defines
// number serialization over IEEE 754 doubles, so collapsing 9007199254740993 to
// 9007199254740992 is conformant behaviour, and a Canonicalize that refused it
// would diverge from the RFC's own test vectors — which is the one property
// M0a exists to protect, because it is what makes a future interop failure
// attributable. The collapse is correct for canonicalization and unacceptable
// for authorization, so the check is a separate, opt-in obligation of the
// caller that is about to make a decision.
//
// Why a decision cannot tolerate it: two distinct argument values that
// canonicalize identically are indistinguishable to §7 step 7f, so a PoP
// committing to 9007199254740992 matches an invocation carrying
// 9007199254740993 — and warden relays the client's original bytes upstream, so
// the server would act on a value neither the PoP nor the constraint check ever
// saw. The lost precision is not a rounding inconvenience; it is a gap between
// the value authorized and the value executed.
//
// The criterion is that the canonical form denotes the same number as the
// literal, compared as exact rationals. That accepts every canonical document
// (canonicalizing is idempotent, so its own output always passes), accepts
// harmless rewrites like 1.0 to 1, -0 to 0 and 1e21 to 1e+21, and rejects
// exactly the literals whose value the canonical form no longer names.
func CheckNumbers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// Malformed input is not this function's to report: the caller
			// canonicalizes too, and that path produces the better message.
			return nil
		}
		num, ok := tok.(json.Number)
		if !ok {
			continue
		}
		if err := checkNumber(num.String()); err != nil {
			return err
		}
	}
}

func checkNumber(lit string) error {
	f, err := parseDouble(lit)
	if err != nil {
		return nil // Canonicalize will reject it with a better message.
	}
	canonical, err := formatNumber(f)
	if err != nil {
		return nil // likewise: ±Inf and NaN are Canonicalize's to refuse.
	}
	want, ok := new(big.Rat).SetString(lit)
	if !ok {
		return nil
	}
	got, ok := new(big.Rat).SetString(canonical)
	if !ok {
		return nil
	}
	if want.Cmp(got) != 0 {
		return fmt.Errorf("jcs: the number %s does not survive RFC 8785 canonicalization: "+
			"it canonicalizes to %s, so the canonical form no longer names the value given", lit, canonical)
	}
	return nil
}

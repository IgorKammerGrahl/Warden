package core

import (
	"errors"
	"fmt"
)

// Denial is a check failure that carries its own normative citation.
//
// Ref is set by the code that performed the check and is never recovered by
// reading an error message back. That distinction is the whole point of the
// type. Every denial message embeds attacker-supplied values — a tool name, an
// argument name, a constraint_type — so a citation parsed out of the rendered
// text is a citation the token's author can choose. The audit trace exists to
// name which clause of a public specification refused a call (ARCHITECTURE §6),
// and a forgeable ref does not produce a badly formatted explanation, it
// produces a false one.
//
// Every check that can deny states a Ref. A denial the trace cannot attribute
// is a bug in the check, not a gap in the log format.
type Denial struct {
	// Ref is the citation for the clause that fired, written the way the
	// audit trace records it: "§7 step 4p2, I4", "§3.4 exact", "§3.5.2".
	Ref string

	err error
}

func (d *Denial) Error() string { return d.err.Error() + " (" + d.Ref + ")" }

func (d *Denial) Unwrap() error { return d.err }

// Deny builds a Denial. format MUST NOT repeat the citation: Error appends Ref,
// and writing it in both places is how the two drift apart.
func Deny(ref, format string, a ...any) error {
	return &Denial{Ref: ref, err: fmt.Errorf(format, a...)}
}

// RefOf returns the citation of the innermost Denial in err's chain, or "" if
// the chain holds none.
//
// Innermost, because wrapping runs coarse to fine: the §7 orchestrator labels
// the step it was executing and the check inside it names the exact clause, so
// the deepest Denial is the most specific true statement available. A plain
// fmt.Errorf wrapper in between is transparent to this walk, which is why a
// wrapper that only adds a chain index does not need to be a Denial itself.
func RefOf(err error) string {
	ref := ""
	// Type assertion at each level rather than errors.As over the whole
	// chain: As would keep finding the outermost Denial and the walk would
	// never reach the finer one underneath it.
	for e := err; e != nil; e = errors.Unwrap(e) {
		if d, ok := e.(*Denial); ok {
			ref = d.Ref
		}
	}
	return ref
}

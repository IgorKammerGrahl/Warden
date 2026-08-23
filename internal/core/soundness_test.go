package core

import (
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The §3.5.1 property-2 soundness property, quantified over generated
// constraint trees and argument values:
//
//	for all (Cp, Cd) and all v:  Subsumes(Cd, Cp)  =>  ( Cd.Check(v) => Cp.Check(v) )
//
// The converse is deliberately not asserted. §3.5.1 permits the procedure to be
// conservative — to return false for semantically subsuming pairs it cannot
// verify — so a completeness property would fail on correct code. Unsoundness
// is the severity-1 direction: a true here that is not true semantically is an
// attenuation bypass, a derived token authorizing an invocation its parent
// never could.

// scalarPool is deliberately tiny. Soundness only says anything where Subsumes
// returns true, and independently drawn constraints over a wide value space
// essentially never subsume one another — the test would pass while asserting
// nothing. A ten-element universe makes collisions common; subsumingRate below
// is the guard that keeps this honest.
var scalarPool = []any{
	nil, false, true,
	float64(0), float64(1), float64(2), float64(3),
	"a", "b", "c",
}

// valueUniverse is checked exhaustively for every subsuming pair, on top of the
// values rapid draws. Fixed values cost nothing and cover the shapes the check
// predicates special-case: non-numbers against range, non-arrays against
// contains and subset, the empty array, an object.
var valueUniverse = []any{
	nil, false, true,
	float64(-1), float64(0), float64(0.5), float64(1), float64(2), float64(3), float64(4),
	"", "a", "b", "c",
	[]any{}, []any{"a"}, []any{"a", "b"}, []any{float64(1)}, []any{"a", "c"},
	map[string]any{"k": "v"},
}

func genScalar() *rapid.Generator[any] { return rapid.SampledFrom(scalarPool) }

func genValue() *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		if rapid.Bool().Draw(t, "isArray") {
			return rapid.SliceOfN(genScalar(), 0, 3).Draw(t, "elems")
		}
		return genScalar().Draw(t, "scalar")
	})
}

// genConstraint draws a well-formed constraint tree of at most maxDepth levels.
// It bypasses ParseConstraint on purpose: the property is about Check and
// Subsumes, and going through JSON would only test the parser twice while
// making shrinking report a string instead of a tree.
func genConstraint(maxDepth int) *rapid.Generator[Constraint] {
	return rapid.Custom(func(t *rapid.T) Constraint {
		kinds := []string{
			TypeExact, TypeRange, TypeOneOf, TypeNotOneOf,
			TypeContains, TypeSubset, TypeWildcard,
		}
		if maxDepth > 1 {
			kinds = append(kinds, TypeAll, TypeAny)
		}
		c := Constraint{Type: rapid.SampledFrom(kinds).Draw(t, "type")}
		switch c.Type {
		case TypeExact:
			c.Value = genScalar().Draw(t, "value")
		case TypeRange:
			c.MinInclusive = rapid.Bool().Draw(t, "min_inclusive")
			c.MaxInclusive = rapid.Bool().Draw(t, "max_inclusive")
			if rapid.Bool().Draw(t, "has_min") {
				n := float64(rapid.IntRange(-1, 4).Draw(t, "min"))
				c.Min = &n
			}
			if rapid.Bool().Draw(t, "has_max") {
				n := float64(rapid.IntRange(-1, 4).Draw(t, "max"))
				c.Max = &n
			}
		case TypeOneOf:
			c.Values = rapid.SliceOfN(genScalar(), 0, 4).Draw(t, "values")
		case TypeNotOneOf:
			c.Excluded = rapid.SliceOfN(genScalar(), 0, 4).Draw(t, "excluded")
		case TypeContains:
			c.Required = rapid.SliceOfN(genScalar(), 0, 3).Draw(t, "required")
		case TypeSubset:
			c.Allowed = rapid.SliceOfN(genScalar(), 0, 4).Draw(t, "allowed")
		case TypeWildcard:
		case TypeAll, TypeAny:
			c.Clauses = rapid.SliceOfN(genConstraint(maxDepth-1), 1, 3).Draw(t, "clauses")
		}
		return c
	})
}

// TestSubsumptionIsSound is the milestone's deliverable.
func TestSubsumptionIsSound(t *testing.T) {
	var drawn, subsuming int

	rapid.Check(t, func(t *rapid.T) {
		parent := genConstraint(3).Draw(t, "parent")
		derived := genConstraint(3).Draw(t, "derived")
		values := rapid.SliceOfN(genValue(), 1, 4).Draw(t, "values")
		drawn++

		if !Subsumes(&derived, &parent) {
			return
		}
		subsuming++

		for _, v := range append(values, valueUniverse...) {
			if derived.Check(v) && !parent.Check(v) {
				t.Fatalf("UNSOUND: Subsumes said the derived constraint is at least as "+
					"restrictive, but it accepts a value the parent rejects\n"+
					"  parent:  %s\n  derived: %s\n  value:   %#v",
					render(parent), render(derived), v)
			}
		}
	})

	if subsuming == 0 {
		t.Fatalf("vacuous: Subsumes never returned true over %d pairs — the property asserted nothing", drawn)
	}
	t.Logf("%d pairs drawn, %d subsuming (%.1f%%)", drawn, subsuming, 100*float64(subsuming)/float64(drawn))
}

// TestAttenuationIsSound raises the rate of interesting cases by drawing the
// derived constraint as a deliberate attenuation of the parent rather than
// independently. Same property; the independent version above is the one that
// finds cross-type mistakes, this one exercises the same-type rules and the
// clause matching far more densely.
func TestAttenuationIsSound(t *testing.T) {
	var drawn, subsuming int

	rapid.Check(t, func(t *rapid.T) {
		parent := genConstraint(3).Draw(t, "parent")
		derived := genAttenuation(parent).Draw(t, "derived")
		values := rapid.SliceOfN(genValue(), 1, 4).Draw(t, "values")
		drawn++

		if !Subsumes(&derived, &parent) {
			return
		}
		subsuming++

		for _, v := range append(values, valueUniverse...) {
			if derived.Check(v) && !parent.Check(v) {
				t.Fatalf("UNSOUND\n  parent:  %s\n  derived: %s\n  value:   %#v",
					render(parent), render(derived), v)
			}
		}
	})

	if subsuming == 0 {
		t.Fatalf("vacuous: no attenuation out of %d draws subsumed its parent", drawn)
	}
	t.Logf("%d pairs drawn, %d subsuming (%.1f%%)", drawn, subsuming, 100*float64(subsuming)/float64(drawn))
}

// genAttenuation produces a constraint shaped like a plausible attenuation of
// parent — usually a real one, sometimes not. It is a generator of candidates,
// never an oracle: whether it actually subsumes is Subsumes's answer to give,
// and the property only looks at cases where Subsumes says yes.
func genAttenuation(parent Constraint) *rapid.Generator[Constraint] {
	return rapid.Custom(func(t *rapid.T) Constraint {
		if rapid.IntRange(0, 9).Draw(t, "mutate") == 0 {
			// Occasionally ignore the parent entirely, so a bug that only shows
			// up on a wildly unrelated derived constraint is still reachable.
			return genConstraint(3).Draw(t, "unrelated")
		}
		c := Constraint{Type: parent.Type}
		switch parent.Type {
		case TypeExact:
			c.Value = parent.Value
			if rapid.Bool().Draw(t, "perturb") {
				c.Value = genScalar().Draw(t, "other_value")
			}
		case TypeRange:
			c.MinInclusive = rapid.Bool().Draw(t, "min_inclusive")
			c.MaxInclusive = rapid.Bool().Draw(t, "max_inclusive")
			if rapid.Bool().Draw(t, "has_min") {
				n := float64(rapid.IntRange(-2, 5).Draw(t, "min"))
				c.Min = &n
			}
			if rapid.Bool().Draw(t, "has_max") {
				n := float64(rapid.IntRange(-2, 5).Draw(t, "max"))
				c.Max = &n
			}
		case TypeOneOf:
			c.Values = subsample(t, parent.Values, "values")
		case TypeNotOneOf:
			c.Excluded = supersample(t, parent.Excluded, "excluded")
		case TypeContains:
			c.Required = supersample(t, parent.Required, "required")
		case TypeSubset:
			c.Allowed = subsample(t, parent.Allowed, "allowed")
		case TypeWildcard:
			// Anything at all is a candidate attenuation of a wildcard.
			return genConstraint(3).Draw(t, "under_wildcard")
		case TypeAll, TypeAny:
			for i, clause := range parent.Clauses {
				if rapid.Bool().Draw(t, fmt.Sprintf("keep%d", i)) {
					c.Clauses = append(c.Clauses, genAttenuation(clause).Draw(t, fmt.Sprintf("clause%d", i)))
				}
			}
			if rapid.Bool().Draw(t, "extra") {
				c.Clauses = append(c.Clauses, genConstraint(2).Draw(t, "extra_clause"))
			}
			if len(c.Clauses) == 0 {
				c.Clauses = append(c.Clauses, genConstraint(2).Draw(t, "fallback_clause"))
			}
		}
		return c
	})
}

// subsample keeps a random subset of set, and sometimes adds an element that
// was not there — the widening a sound Subsumes must catch.
func subsample(t *rapid.T, set []any, label string) []any {
	out := []any{}
	for i, e := range set {
		if rapid.Bool().Draw(t, fmt.Sprintf("%s_keep%d", label, i)) {
			out = append(out, e)
		}
	}
	if rapid.IntRange(0, 3).Draw(t, label+"_widen") == 0 {
		out = append(out, genScalar().Draw(t, label+"_extra"))
	}
	return out
}

// supersample keeps a random subset of set and usually adds to it — for
// not_one_of and contains, growing the set is the restriction.
func supersample(t *rapid.T, set []any, label string) []any {
	out := subsample(t, set, label)
	if rapid.Bool().Draw(t, label+"_grow") {
		out = append(out, genScalar().Draw(t, label+"_more"))
	}
	return out
}

// render prints a constraint the way the draft writes one, because a
// counterexample full of *float64 addresses is not a counterexample anyone can
// read.
func render(c Constraint) string {
	var b strings.Builder
	b.WriteString(c.Type)
	switch c.Type {
	case TypeExact:
		fmt.Fprintf(&b, "(%#v)", c.Value)
	case TypeRange:
		b.WriteString("(")
		if c.Min == nil {
			b.WriteString("-inf")
		} else {
			op := ">="
			if !c.MinInclusive {
				op = ">"
			}
			fmt.Fprintf(&b, "%s%g", op, *c.Min)
		}
		b.WriteString(", ")
		if c.Max == nil {
			b.WriteString("+inf")
		} else {
			op := "<="
			if !c.MaxInclusive {
				op = "<"
			}
			fmt.Fprintf(&b, "%s%g", op, *c.Max)
		}
		b.WriteString(")")
	case TypeOneOf:
		b.WriteString(renderSet(c.Values))
	case TypeNotOneOf:
		b.WriteString(renderSet(c.Excluded))
	case TypeContains:
		b.WriteString(renderSet(c.Required))
	case TypeSubset:
		b.WriteString(renderSet(c.Allowed))
	case TypeAll, TypeAny:
		parts := make([]string, 0, len(c.Clauses))
		for _, clause := range c.Clauses {
			parts = append(parts, render(clause))
		}
		fmt.Fprintf(&b, "[%s]", strings.Join(parts, ", "))
	}
	return b.String()
}

func renderSet(vs []any) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, fmt.Sprintf("%#v", v))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

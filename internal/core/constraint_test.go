package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) *Constraint {
	t.Helper()
	c, err := ParseConstraint([]byte(s))
	if err != nil {
		t.Fatalf("ParseConstraint(%s): %v", s, err)
	}
	return c
}

// TestPermittedTableMatchesDraft pins the table's key set against §4.5 read
// independently. Without it the 81-pair test below is a tautology: it would
// prove that pairs absent from the table reject, which is true by construction
// no matter which pairs are absent.
func TestPermittedTableMatchesDraft(t *testing.T) {
	want := map[pair]bool{}
	// §4.5 wildcard: "any other constraint type subsumes a parent wildcard",
	// and a derived wildcard is valid only against a parent wildcard.
	for _, d := range CoreTypes {
		want[pair{parent: TypeWildcard, derived: d}] = true
	}
	// §4.5 exact: parent exact with equal value, parent range containing the
	// value, parent one_of listing it.
	want[pair{parent: TypeExact, derived: TypeExact}] = true
	want[pair{parent: TypeRange, derived: TypeExact}] = true
	want[pair{parent: TypeOneOf, derived: TypeExact}] = true
	// §4.5 same-type rules.
	want[pair{parent: TypeRange, derived: TypeRange}] = true
	want[pair{parent: TypeOneOf, derived: TypeOneOf}] = true
	want[pair{parent: TypeNotOneOf, derived: TypeNotOneOf}] = true
	want[pair{parent: TypeContains, derived: TypeContains}] = true
	want[pair{parent: TypeSubset, derived: TypeSubset}] = true
	want[pair{parent: TypeAll, derived: TypeAll}] = true
	want[pair{parent: TypeAny, derived: TypeAny}] = true

	if len(want) != 19 {
		t.Fatalf("test's own list is %d pairs, expected 19", len(want))
	}
	for p := range want {
		if _, ok := permitted[p]; !ok {
			t.Errorf("§4.5 permits (parent %s, derived %s) but the table does not", p.parent, p.derived)
		}
	}
	for p := range permitted {
		if !want[p] {
			t.Errorf("table permits (parent %s, derived %s) but §4.5 does not", p.parent, p.derived)
		}
	}
}

// instances gives several representative constraints per type, so that a pair
// asserted to reject is not merely rejecting because of one unlucky instance.
func instances(t *testing.T) map[string][]*Constraint {
	t.Helper()
	byType := map[string][]string{
		TypeExact:    {`{"constraint_type":"exact","value":1}`, `{"constraint_type":"exact","value":"a"}`, `{"constraint_type":"exact","value":true}`},
		TypeRange:    {`{"constraint_type":"range","min":0,"max":10}`, `{"constraint_type":"range","min":0}`, `{"constraint_type":"range"}`},
		TypeOneOf:    {`{"constraint_type":"one_of","values":[1,2]}`, `{"constraint_type":"one_of","values":[]}`},
		TypeNotOneOf: {`{"constraint_type":"not_one_of","excluded":[1,2]}`, `{"constraint_type":"not_one_of","excluded":[]}`},
		TypeContains: {`{"constraint_type":"contains","required":[1]}`, `{"constraint_type":"contains","required":[]}`},
		TypeSubset:   {`{"constraint_type":"subset","allowed":[1,2]}`, `{"constraint_type":"subset","allowed":[]}`},
		TypeWildcard: {`{"constraint_type":"wildcard"}`},
		TypeAll:      {`{"constraint_type":"all","constraints":[{"constraint_type":"wildcard"}]}`, `{"constraint_type":"all","constraints":[{"constraint_type":"exact","value":1}]}`},
		TypeAny:      {`{"constraint_type":"any","constraints":[{"constraint_type":"wildcard"}]}`, `{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":1}]}`},
	}
	out := map[string][]*Constraint{}
	for typ, srcs := range byType {
		for _, s := range srcs {
			out[typ] = append(out[typ], mustParse(t, s))
		}
	}
	return out
}

// TestAllCorePairs is the default-deny assertion §4.5's closing sentence asks
// for: all 9x9 pairs of core types, every pair outside the permitted table
// rejecting for every instance combination, and every pair inside it reachable.
func TestAllCorePairs(t *testing.T) {
	inst := instances(t)
	reached := map[pair]bool{}
	seen := 0

	for _, pt := range CoreTypes {
		for _, dt := range CoreTypes {
			seen++
			p := pair{parent: pt, derived: dt}
			_, allowed := permitted[p]
			for _, pc := range inst[pt] {
				for _, dc := range inst[dt] {
					got := Subsumes(dc, pc)
					if !allowed && got {
						t.Errorf("(parent %s, derived %s) is not permitted by §4.5 but Subsumes returned true\n  parent:  %+v\n  derived: %+v", pt, dt, pc, dc)
					}
					if allowed && got {
						reached[p] = true
					}
				}
			}
		}
	}
	if seen != 81 {
		t.Fatalf("enumerated %d pairs, want 81", seen)
	}
	for p := range permitted {
		if !reached[p] {
			t.Errorf("(parent %s, derived %s) is permitted but no instance pair reached true — dead table entry", p.parent, p.derived)
		}
	}
}

// TestWildcardAsymmetry is the rule most likely to be implemented symmetrically
// by accident. A derived wildcard widens whatever it replaces.
func TestWildcardAsymmetry(t *testing.T) {
	wild := mustParse(t, `{"constraint_type":"wildcard"}`)
	for _, other := range []string{
		`{"constraint_type":"exact","value":1}`,
		`{"constraint_type":"range","min":0,"max":10}`,
		`{"constraint_type":"one_of","values":[1,2]}`,
		`{"constraint_type":"not_one_of","excluded":[1]}`,
		`{"constraint_type":"contains","required":[1]}`,
		`{"constraint_type":"subset","allowed":[1]}`,
		`{"constraint_type":"all","constraints":[{"constraint_type":"exact","value":1}]}`,
		`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":1}]}`,
	} {
		c := mustParse(t, other)
		if !Subsumes(c, wild) {
			t.Errorf("%s should subsume a parent wildcard", other)
		}
		if Subsumes(wild, c) {
			t.Errorf("a derived wildcard must not subsume parent %s", other)
		}
	}
	if !Subsumes(wild, wild) {
		t.Error("a derived wildcard must subsume a parent wildcard")
	}
}

// TestNotOneOfAgainstParentOneOf is the pair §4.5 rejects by name: a
// not_one_of accepts values outside the parent's permitted set, so it cannot be
// verified as subsuming, however small its excluded set looks.
func TestNotOneOfAgainstParentOneOf(t *testing.T) {
	parent := mustParse(t, `{"constraint_type":"one_of","values":[1,2]}`)
	for _, s := range []string{
		`{"constraint_type":"not_one_of","excluded":[3]}`,
		`{"constraint_type":"not_one_of","excluded":[1,2,3]}`,
		`{"constraint_type":"not_one_of","excluded":[]}`,
	} {
		if Subsumes(mustParse(t, s), parent) {
			t.Errorf("%s must not subsume parent one_of", s)
		}
	}
}

func TestRangeSubsumption(t *testing.T) {
	cases := []struct {
		name           string
		derived, paren string
		want           bool
	}{
		{"identical", `{"min":0,"max":10}`, `{"min":0,"max":10}`, true},
		{"narrower both ends", `{"min":2,"max":8}`, `{"min":0,"max":10}`, true},
		{"wider min", `{"min":-1,"max":10}`, `{"min":0,"max":10}`, false},
		{"wider max", `{"min":0,"max":11}`, `{"min":0,"max":10}`, false},

		// Inclusivity at an equal bound. Exclusive is the tighter side.
		{"derived min exclusive vs parent inclusive", `{"min":0,"max":10,"min_inclusive":false}`, `{"min":0,"max":10}`, true},
		{"derived min inclusive vs parent exclusive", `{"min":0,"max":10}`, `{"min":0,"max":10,"min_inclusive":false}`, false},
		{"both min exclusive", `{"min":0,"max":10,"min_inclusive":false}`, `{"min":0,"max":10,"min_inclusive":false}`, true},
		{"derived max exclusive vs parent inclusive", `{"min":0,"max":10,"max_inclusive":false}`, `{"min":0,"max":10}`, true},
		{"derived max inclusive vs parent exclusive", `{"min":0,"max":10}`, `{"min":0,"max":10,"max_inclusive":false}`, false},
		{"both max exclusive", `{"min":0,"max":10,"max_inclusive":false}`, `{"min":0,"max":10,"max_inclusive":false}`, true},
		// Inclusivity only matters at an equal bound: a strictly tighter bound
		// is tighter whatever the flags say.
		{"derived inclusive but strictly inside parent exclusive", `{"min":1,"max":9}`, `{"min":0,"max":10,"min_inclusive":false,"max_inclusive":false}`, true},

		// Missing bounds. A missing derived bound is unbounded on that side and
		// is valid only where the parent is also unbounded.
		{"both unbounded", `{}`, `{}`, true},
		{"derived unbounded below, parent bounded", `{"max":10}`, `{"min":0,"max":10}`, false},
		{"derived unbounded above, parent bounded", `{"min":0}`, `{"min":0,"max":10}`, false},
		{"derived bounded, parent unbounded", `{"min":0,"max":10}`, `{}`, true},
		{"derived fully unbounded, parent bounded", `{}`, `{"min":0}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			derived := mustParse(t, withType(tc.derived))
			parent := mustParse(t, withType(tc.paren))
			if got := Subsumes(derived, parent); got != tc.want {
				t.Errorf("Subsumes(%s, %s) = %v, want %v", tc.derived, tc.paren, got, tc.want)
			}
		})
	}
}

// withType splices constraint_type:"range" into a bare member object.
func withType(members string) string {
	inner := strings.TrimSpace(members)
	inner = strings.TrimPrefix(inner, "{")
	inner = strings.TrimSuffix(inner, "}")
	if strings.TrimSpace(inner) == "" {
		return `{"constraint_type":"range"}`
	}
	return `{"constraint_type":"range",` + inner + `}`
}

// TestAllRequiresBacktracking uses a pair where greedy left-to-right matching
// hits the dead end §4.5 warns about: the first parent clause has two
// candidates, and taking the obvious one strands the second parent clause.
func TestAllRequiresBacktracking(t *testing.T) {
	// parent clauses: one_of[1,2,3] then one_of[1].
	// derived clauses: exact 1 (subsumes both) then one_of[1,2] (subsumes only
	// the first). Greedy assigns exact 1 to the first parent clause and fails.
	parent := mustParse(t, `{"constraint_type":"all","constraints":[
		{"constraint_type":"one_of","values":[1,2,3]},
		{"constraint_type":"one_of","values":[1]}]}`)
	derived := mustParse(t, `{"constraint_type":"all","constraints":[
		{"constraint_type":"exact","value":1},
		{"constraint_type":"one_of","values":[1,2]}]}`)
	if !Subsumes(derived, parent) {
		t.Error("matching must backtrack out of the greedy dead end")
	}

	// One-to-one, not one-to-many: two parent clauses cannot both lean on the
	// same derived clause.
	parent2 := mustParse(t, `{"constraint_type":"all","constraints":[
		{"constraint_type":"one_of","values":[1,2]},
		{"constraint_type":"one_of","values":[1,3]}]}`)
	derived2 := mustParse(t, `{"constraint_type":"all","constraints":[
		{"constraint_type":"exact","value":1}]}`)
	if Subsumes(derived2, parent2) {
		t.Error("one derived clause must not be matched to two parent clauses")
	}

	// Extra derived clauses only add restrictions and are fine.
	derived3 := mustParse(t, `{"constraint_type":"all","constraints":[
		{"constraint_type":"one_of","values":[1,2]},
		{"constraint_type":"one_of","values":[1,3]},
		{"constraint_type":"not_one_of","excluded":[9]}]}`)
	if !Subsumes(derived3, parent2) {
		t.Error("unmatched extra derived clauses must be permitted")
	}
}

func TestAnySubsumption(t *testing.T) {
	parent := mustParse(t, `{"constraint_type":"any","constraints":[
		{"constraint_type":"one_of","values":[1,2]},
		{"constraint_type":"one_of","values":[3,4]}]}`)

	// Every derived clause covered by some parent clause.
	ok := mustParse(t, `{"constraint_type":"any","constraints":[
		{"constraint_type":"exact","value":1},
		{"constraint_type":"exact","value":3}]}`)
	if !Subsumes(ok, parent) {
		t.Error("every derived clause is subsumed by a parent clause")
	}

	// Two derived clauses may lean on the same parent clause: unlike all, this
	// is not a matching.
	shared := mustParse(t, `{"constraint_type":"any","constraints":[
		{"constraint_type":"exact","value":1},
		{"constraint_type":"exact","value":2}]}`)
	if !Subsumes(shared, parent) {
		t.Error("derived any clauses may share a parent clause")
	}

	// One uncovered derived clause widens the disjunction.
	bad := mustParse(t, `{"constraint_type":"any","constraints":[
		{"constraint_type":"exact","value":1},
		{"constraint_type":"exact","value":9}]}`)
	if Subsumes(bad, parent) {
		t.Error("a derived clause outside every parent clause must reject")
	}
}

func TestMaxConstraintDepth(t *testing.T) {
	nest := func(depth int) string {
		s := `{"constraint_type":"wildcard"}`
		for i := 1; i < depth; i++ {
			s = `{"constraint_type":"all","constraints":[` + s + `]}`
		}
		return s
	}

	if _, err := ParseConstraint([]byte(nest(MaxConstraintDepth))); err != nil {
		t.Errorf("depth %d must parse: %v", MaxConstraintDepth, err)
	}
	_, err := ParseConstraint([]byte(nest(MaxConstraintDepth + 1)))
	if err == nil {
		t.Fatalf("depth %d must be rejected", MaxConstraintDepth+1)
	}
	if !strings.Contains(err.Error(), "MAX_CONSTRAINT_DEPTH") {
		t.Errorf("error should name the limit, got %v", err)
	}

	// Subsumes carries its own bound, so a hand-built tree that never went
	// through ParseConstraint still cannot drive unbounded recursion.
	deep := func(depth int) *Constraint {
		c := &Constraint{Type: TypeWildcard}
		for i := 1; i < depth; i++ {
			c = &Constraint{Type: TypeAll, Clauses: []Constraint{*c}}
		}
		return c
	}
	if !Subsumes(deep(MaxConstraintDepth), deep(MaxConstraintDepth)) {
		t.Error("a tree at the limit must still be evaluated")
	}
	if Subsumes(deep(MaxConstraintDepth+1), deep(MaxConstraintDepth+1)) {
		t.Error("a tree past the limit must fail closed")
	}
	if deep(MaxConstraintDepth + 1).Check(nil) {
		t.Error("Check must fail closed past the limit")
	}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		src  string
		v    any
		want bool
	}{
		{`{"constraint_type":"exact","value":1}`, float64(1), true},
		{`{"constraint_type":"exact","value":1}`, float64(2), false},
		{`{"constraint_type":"exact","value":1}`, "1", false},
		{`{"constraint_type":"exact","value":null}`, nil, true},

		{`{"constraint_type":"range","min":0,"max":10}`, float64(0), true},
		{`{"constraint_type":"range","min":0,"max":10}`, float64(10), true},
		{`{"constraint_type":"range","min":0,"max":10,"min_inclusive":false}`, float64(0), false},
		{`{"constraint_type":"range","min":0,"max":10,"max_inclusive":false}`, float64(10), false},
		{`{"constraint_type":"range","min":0}`, float64(1e9), true},
		{`{"constraint_type":"range","min":0,"max":10}`, "5", false},
		{`{"constraint_type":"range"}`, float64(-5), true},

		{`{"constraint_type":"one_of","values":[1,"a"]}`, "a", true},
		{`{"constraint_type":"one_of","values":[1,"a"]}`, "b", false},
		{`{"constraint_type":"one_of","values":[]}`, float64(1), false},

		{`{"constraint_type":"not_one_of","excluded":[1]}`, float64(2), true},
		{`{"constraint_type":"not_one_of","excluded":[1]}`, float64(1), false},

		{`{"constraint_type":"contains","required":["a"]}`, []any{"a", "b"}, true},
		{`{"constraint_type":"contains","required":["a"]}`, []any{"b"}, false},
		{`{"constraint_type":"contains","required":["a"]}`, "a", false},
		{`{"constraint_type":"contains","required":[]}`, []any{}, true},

		{`{"constraint_type":"subset","allowed":["a","b"]}`, []any{"a"}, true},
		{`{"constraint_type":"subset","allowed":["a","b"]}`, []any{"a", "c"}, false},
		{`{"constraint_type":"subset","allowed":["a"]}`, "a", false},

		{`{"constraint_type":"wildcard"}`, map[string]any{"k": "v"}, true},

		{`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0},{"constraint_type":"range","max":10}]}`, float64(5), true},
		{`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0},{"constraint_type":"range","max":10}]}`, float64(11), false},
		{`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":1},{"constraint_type":"exact","value":2}]}`, float64(2), true},
		{`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":1},{"constraint_type":"exact","value":2}]}`, float64(3), false},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			if got := mustParse(t, tc.src).Check(tc.v); got != tc.want {
				t.Errorf("%s.Check(%#v) = %v, want %v", tc.src, tc.v, got, tc.want)
			}
		})
	}
}

// TestCheckUsesJSONNumberIdentity: 1 and 1.0 are the same argument value, the
// same identification RFC 8785 makes upstream.
func TestCheckUsesJSONNumberIdentity(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(`1.0`), &v); err != nil {
		t.Fatal(err)
	}
	if !mustParse(t, `{"constraint_type":"exact","value":1}`).Check(v) {
		t.Error("1.0 must equal 1")
	}
}

func TestParseFailsClosed(t *testing.T) {
	cases := []struct {
		name, src string
	}{
		{"unrecognized type", `{"constraint_type":"path_containment","root":"/a"}`},
		{"empty type", `{"constraint_type":""}`},
		{"missing type", `{"value":1}`},
		{"non-string type", `{"constraint_type":3}`},
		{"not an object", `[{"constraint_type":"wildcard"}]`},
		{"null", `null`},
		{"member the type does not define", `{"constraint_type":"wildcard","value":1}`},
		{"range member on exact", `{"constraint_type":"exact","value":1,"min":0}`},
		{"missing required member", `{"constraint_type":"one_of"}`},
		{"exact value is an object", `{"constraint_type":"exact","value":{"a":1}}`},
		{"exact value is an array", `{"constraint_type":"exact","value":[1]}`},
		{"values is not an array", `{"constraint_type":"one_of","values":1}`},
		{"values is null", `{"constraint_type":"one_of","values":null}`},
		{"min is not a number", `{"constraint_type":"range","min":"0"}`},
		{"min_inclusive is not a boolean", `{"constraint_type":"range","min":0,"min_inclusive":"no"}`},
		{"empty all", `{"constraint_type":"all","constraints":[]}`},
		{"empty any", `{"constraint_type":"any","constraints":[]}`},
		{"unrecognized nested type", `{"constraint_type":"all","constraints":[{"constraint_type":"nope"}]}`},
		{"trailing garbage", `{"constraint_type":"wildcard"} x`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if c, err := ParseConstraint([]byte(tc.src)); err == nil {
				t.Errorf("must reject %s, got %+v", tc.src, c)
			}
		})
	}
}

// TestSubsumesRejectsUnknownType: a hand-built constraint carrying a type the
// table has never heard of gets the §3.4 fail-closed answer in both positions.
func TestSubsumesRejectsUnknownType(t *testing.T) {
	unknown := &Constraint{Type: "path_containment"}
	wild := &Constraint{Type: TypeWildcard}
	if Subsumes(unknown, wild) {
		// Note: this one is a *parent wildcard*, which §4.5 says anything
		// subsumes — but "anything" means a core type. An extension type only
		// enters the matrix through its registration (§3.5.1).
		t.Error("an unregistered extension type must not subsume a parent wildcard")
	}
	if Subsumes(wild, unknown) {
		t.Error("nothing subsumes an unrecognized parent type")
	}
	if unknown.Check(1) {
		t.Error("an unrecognized type must not accept anything")
	}
}

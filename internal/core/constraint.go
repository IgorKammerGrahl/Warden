// Package core is warden's domain layer: constraints, capabilities, chains and
// decisions, expressed in terms that never mention JOSE or the wire format.
// It imports stdlib only (ARCHITECTURE §7).
//
// Scope boundary. This file is the §3.4 argument-constraint vocabulary and the
// §4.5 per-constraint subsumption rules, and nothing else. One constraint
// against one argument value (Check), one derived constraint against one parent
// constraint (Subsumes). The §7 verification algorithm, the I1-I5 invariants as
// a whole, and PoP verification are not here and must not creep in: a caller
// that wants to know whether a *chain* is authorized is asking a different
// question of a package that does not exist yet.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
)

// MaxConstraintDepth is MAX_CONSTRAINT_DEPTH (§3.4). The draft requires a
// finite limit to prevent resource exhaustion from pathologically deep trees
// and RECOMMENDS 32.
//
// A constant, not operator configuration: unlike MAX_TOKEN_SIZE, nothing in
// ARCHITECTURE asks for this to be tunable, and 32 is deep enough that no
// honest constraint tree reaches it. Give it a home on a config struct at the
// moment a deployment actually needs a different value.
const MaxConstraintDepth = 32

// The nine core constraint types of §3.4 Table 2. Extension types (§3.5) are
// out of scope here: this package implements the core set and rejects
// everything else, which is the fail-closed behaviour §3.4 requires.
const (
	TypeExact    = "exact"
	TypeRange    = "range"
	TypeOneOf    = "one_of"
	TypeNotOneOf = "not_one_of"
	TypeContains = "contains"
	TypeSubset   = "subset"
	TypeWildcard = "wildcard"
	TypeAll      = "all"
	TypeAny      = "any"
)

// CoreTypes is §3.4 Table 2 in table order. The subsumption matrix is built
// from it, so a type added here without a matching entry in permitted gets
// exactly one behaviour: it subsumes a parent wildcard and nothing else.
var CoreTypes = []string{
	TypeExact, TypeRange, TypeOneOf, TypeNotOneOf, TypeContains,
	TypeSubset, TypeWildcard, TypeAll, TypeAny,
}

// members lists the type-specific members §3.4 Table 2 defines for each type,
// excluding constraint_type itself. It doubles as the recognized-type set:
// absence from this map is an unrecognized constraint_type.
var members = map[string][]string{
	TypeExact:    {"value"},
	TypeRange:    {"min", "max", "min_inclusive", "max_inclusive"},
	TypeOneOf:    {"values"},
	TypeNotOneOf: {"excluded"},
	TypeContains: {"required"},
	TypeSubset:   {"allowed"},
	TypeWildcard: {},
	TypeAll:      {"constraints"},
	TypeAny:      {"constraints"},
}

// requiredMember names the one member each type cannot omit. range is absent
// because both of its bounds are optional, and so is wildcard, which has no
// members at all.
var requiredMember = map[string]string{
	TypeExact:    "value",
	TypeOneOf:    "values",
	TypeNotOneOf: "excluded",
	TypeContains: "required",
	TypeSubset:   "allowed",
	TypeAll:      "constraints",
	TypeAny:      "constraints",
}

// Constraint is one §3.4 argument constraint.
//
// It is a tagged union flattened into a struct: Type selects which of the
// remaining fields carry meaning, and the rest are zero. Nine small
// implementations behind an interface would buy dynamic dispatch that nothing
// here wants — the subsumption matrix is keyed by a *pair* of types, which a
// method set cannot express without double dispatch.
//
// Only ParseConstraint produces values that have been validated. A Constraint
// built as a literal is trusted to be well formed; Check and Subsumes fail
// closed on anything they do not understand rather than panicking.
type Constraint struct {
	Type string

	Value any // exact

	Min, Max                   *float64 // range; nil means unbounded on that side
	MinInclusive, MaxInclusive bool     // range; §3.4 default is true for both

	Values   []any // one_of
	Excluded []any // not_one_of
	Required []any // contains
	Allowed  []any // subset

	Clauses []Constraint // all, any
}

// ParseConstraint decodes one §3.4 constraint object.
//
// It fails closed in three ways §3.4 requires or implies: an unrecognized
// constraint_type is an error (never a constraint that quietly passes), a
// member the type does not define is an error (an issuer wrote something we
// would otherwise silently drop, and dropping a restriction is exactly the
// failure §3.5.2 warns about), and a tree deeper than MaxConstraintDepth is an
// error.
//
// ponytail: no duplicate-member detection. Constraints arrive inside an AAT
// payload, which internal/aat has already put through the JCS gate, and JCS
// rejects duplicate members. A caller feeding this raw bytes from somewhere
// else must run that gate itself — core does not import the wire layer.
func ParseConstraint(raw []byte) (*Constraint, error) {
	return parseConstraint(raw, MaxConstraintDepth)
}

func parseConstraint(raw []byte, depth int) (*Constraint, error) {
	if depth <= 0 {
		return nil, Deny("§3.4 MAX_CONSTRAINT_DEPTH", "constraint: tree deeper than MAX_CONSTRAINT_DEPTH (%d)", MaxConstraintDepth)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("constraint: %w", err)
	}
	if obj == nil {
		return nil, errors.New("constraint: not a JSON object")
	}

	rawType, ok := obj["constraint_type"]
	if !ok {
		return nil, errors.New("constraint: missing constraint_type")
	}
	var typ string
	if err := json.Unmarshal(rawType, &typ); err != nil {
		return nil, fmt.Errorf("constraint: constraint_type: %w", err)
	}
	allowed, known := members[typ]
	if !known {
		// §3.5.2: an enforcement point that meets a constraint type it has no
		// registered procedure for MUST reject the chain. Not skip the
		// constraint — the type is a restriction the issuer intended, and
		// omitting it silently is precisely what breaks attenuation.
		return nil, Deny("§3.5.2", "constraint: unrecognized constraint_type %q", typ)
	}
	for name := range obj {
		if name == "constraint_type" || slices.Contains(allowed, name) {
			continue
		}
		return nil, fmt.Errorf("constraint %s: unrecognized member %q", typ, name)
	}
	if req, need := requiredMember[typ]; need {
		if _, ok := obj[req]; !ok {
			return nil, fmt.Errorf("constraint %s: missing %s", typ, req)
		}
	}

	c := Constraint{Type: typ}
	var err error
	switch typ {
	case TypeExact:
		if c.Value, err = decodeScalar(obj["value"]); err != nil {
			return nil, fmt.Errorf("constraint exact: value: %w", err)
		}
	case TypeRange:
		if err = decodeRange(&c, obj); err != nil {
			return nil, fmt.Errorf("constraint range: %w", err)
		}
	case TypeOneOf:
		if c.Values, err = decodeArray(obj["values"]); err != nil {
			return nil, fmt.Errorf("constraint one_of: values: %w", err)
		}
	case TypeNotOneOf:
		if c.Excluded, err = decodeArray(obj["excluded"]); err != nil {
			return nil, fmt.Errorf("constraint not_one_of: excluded: %w", err)
		}
	case TypeContains:
		if c.Required, err = decodeArray(obj["required"]); err != nil {
			return nil, fmt.Errorf("constraint contains: required: %w", err)
		}
	case TypeSubset:
		if c.Allowed, err = decodeArray(obj["allowed"]); err != nil {
			return nil, fmt.Errorf("constraint subset: allowed: %w", err)
		}
	case TypeWildcard:
		// No members.
	case TypeAll, TypeAny:
		if c.Clauses, err = decodeClauses(obj["constraints"], depth); err != nil {
			return nil, fmt.Errorf("constraint %s: %w", typ, err)
		}
	}
	return &c, nil
}

// decodeScalar enforces §3.4's "value (any scalar)". An object or array here
// would make the derived-exact cross-type rules ask questions Table 2 does not
// answer, so it is rejected rather than guessed at.
func decodeScalar(raw []byte) (any, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	switch v.(type) {
	case nil, bool, float64, string:
		return v, nil
	}
	return nil, errors.New("not a scalar")
}

func decodeArray(raw []byte) ([]any, error) {
	var vs []any
	if err := json.Unmarshal(raw, &vs); err != nil {
		return nil, err
	}
	if vs == nil {
		return nil, errors.New("not an array")
	}
	return vs, nil
}

func decodeRange(c *Constraint, obj map[string]json.RawMessage) error {
	c.MinInclusive, c.MaxInclusive = true, true // §3.4: both default to true

	bounds := []struct {
		name string
		dst  **float64
	}{{"min", &c.Min}, {"max", &c.Max}}
	for _, b := range bounds {
		raw, ok := obj[b.name]
		if !ok {
			continue
		}
		var n float64
		if err := json.Unmarshal(raw, &n); err != nil {
			return fmt.Errorf("%s: %w", b.name, err)
		}
		*b.dst = &n
	}

	flags := []struct {
		name string
		dst  *bool
	}{{"min_inclusive", &c.MinInclusive}, {"max_inclusive", &c.MaxInclusive}}
	for _, f := range flags {
		raw, ok := obj[f.name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, f.dst); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	return nil
}

// decodeClauses rejects an empty constraints array. §4.5 says a derived any
// MUST contain at least one clause; the draft is silent on a parent any and on
// all in either position. An empty all accepts everything and an empty any
// accepts nothing, which are wildcard and a deny written obscurely — rejecting
// both is the fail-closed reading and costs an issuer nothing. Recorded in
// docs/ref/NOTES.md.
func decodeClauses(raw []byte, depth int) ([]Constraint, error) {
	var rawClauses []json.RawMessage
	if err := json.Unmarshal(raw, &rawClauses); err != nil {
		return nil, fmt.Errorf("constraints: %w", err)
	}
	if len(rawClauses) == 0 {
		return nil, errors.New("constraints: must contain at least one clause")
	}
	clauses := make([]Constraint, 0, len(rawClauses))
	for i, rc := range rawClauses {
		child, err := parseConstraint(rc, depth-1)
		if err != nil {
			return nil, fmt.Errorf("constraints[%d]: %w", i, err)
		}
		clauses = append(clauses, *child)
	}
	return clauses, nil
}

// Check is the §3.4 check predicate: does this constraint accept v?
//
// v is an argument value as encoding/json decodes it — float64 for numbers,
// []any for arrays, map[string]any for objects, nil for null.
func (c *Constraint) Check(v any) bool {
	return c.check(v, MaxConstraintDepth)
}

func (c *Constraint) check(v any, depth int) bool {
	if depth <= 0 {
		return false
	}
	switch c.Type {
	case TypeExact:
		return equal(v, c.Value)

	case TypeRange:
		n, ok := v.(float64)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
			return false
		}
		if c.Min != nil {
			if c.MinInclusive && n < *c.Min {
				return false
			}
			if !c.MinInclusive && n <= *c.Min {
				return false
			}
		}
		if c.Max != nil {
			if c.MaxInclusive && n > *c.Max {
				return false
			}
			if !c.MaxInclusive && n >= *c.Max {
				return false
			}
		}
		return true

	case TypeOneOf:
		return memberOf(v, c.Values)

	case TypeNotOneOf:
		return !memberOf(v, c.Excluded)

	case TypeContains:
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		for _, want := range c.Required {
			if !memberOf(want, arr) {
				return false
			}
		}
		return true

	case TypeSubset:
		arr, ok := v.([]any)
		if !ok {
			return false
		}
		for _, got := range arr {
			if !memberOf(got, c.Allowed) {
				return false
			}
		}
		return true

	case TypeWildcard:
		return true

	case TypeAll:
		for i := range c.Clauses {
			if !c.Clauses[i].check(v, depth-1) {
				return false
			}
		}
		return true

	case TypeAny:
		for i := range c.Clauses {
			if c.Clauses[i].check(v, depth-1) {
				return true
			}
		}
		return false
	}
	// §3.4: an unrecognized constraint_type denies. Unreachable for a parsed
	// constraint; reachable for a hand-built one, and it must not accept.
	return false
}

// Subsumes reports whether derived is at least as restrictive as parent — the
// §4.5 I4 relation, oriented as the draft writes it: subsumes(C_parent,
// C_child), with the arguments here in (derived, parent) order to match the
// soundness statement in §3.5.1 property 2.
//
// It is sound and conservative. A true result means that for every argument
// value v, derived.Check(v) implies parent.Check(v). A false result means only
// that this procedure could not establish that; §3.5.1 explicitly permits
// returning false for semantically subsuming pairs. Returning true for a
// non-subsuming pair is the one outcome that breaks attenuation.
func Subsumes(derived, parent *Constraint) bool {
	return subsumes(derived, parent, MaxConstraintDepth)
}

func subsumes(derived, parent *Constraint, depth int) bool {
	if depth <= 0 {
		return false
	}
	rule, ok := permitted[pair{parent: parent.Type, derived: derived.Type}]
	if !ok {
		// §4.5, closing sentence: any (parent type, derived type) pair not
		// explicitly permitted MUST be rejected. That rejection lives here, in
		// the *absence* of a table entry, so a rule nobody wrote fails closed.
		return false
	}
	return rule(derived, parent, depth-1)
}

type pair struct{ parent, derived string }

type rule func(derived, parent *Constraint, depth int) bool

// permitted is §4.5 as a table of PERMITTED (parent type, derived type) pairs.
// Every pair absent from it is rejected, including pairs that do not exist yet.
// There is deliberately no default branch and no list of forbidden pairs: the
// draft's closing sentence is a default-deny rule, and the only way to
// implement default-deny so that a forgotten entry fails closed is for the
// permission itself to be the thing that must be written down.
//
// Populated in init because the parent-wildcard row is nine identical entries
// derived from one sentence of §4.5 rather than nine independent decisions.
var permitted map[pair]rule

func init() {
	permitted = map[pair]rule{
		// §4.5 exact: a derived exact subsumes a parent exact with the same
		// value, a parent range whose interval contains the value, and a parent
		// one_of listing it. All three are the same test — derived exact
		// accepts only Value, so the parent must accept Value — which is also
		// why the soundness argument is one line: Cd.check(v) implies
		// v == Value, and Cp.check(Value) has already been established.
		{parent: TypeExact, derived: TypeExact}: parentAcceptsExactValue,
		{parent: TypeRange, derived: TypeExact}: parentAcceptsExactValue,
		{parent: TypeOneOf, derived: TypeExact}: parentAcceptsExactValue,

		// §4.5 same-type rules. Note who is absent: {one_of, not_one_of} is the
		// pair §4.5 calls out explicitly as invalid, and it is rejected here by
		// not being written down, like every other unlisted pair.
		{parent: TypeRange, derived: TypeRange}:       rangeSubsumes,
		{parent: TypeOneOf, derived: TypeOneOf}:       oneOfSubsumes,
		{parent: TypeNotOneOf, derived: TypeNotOneOf}: notOneOfSubsumes,
		{parent: TypeContains, derived: TypeContains}: containsSubsumes,
		{parent: TypeSubset, derived: TypeSubset}:     subsetSubsumes,
		{parent: TypeAll, derived: TypeAll}:           allSubsumes,
		{parent: TypeAny, derived: TypeAny}:           anySubsumes,
	}

	// §4.5 wildcard: any constraint type subsumes a parent wildcard, wildcard
	// included. The converse row does not exist — a derived wildcard is valid
	// only against a parent wildcard — so {parent: X, derived: wildcard} for
	// X != wildcard is absent and rejects. That asymmetry is the whole rule: a
	// wildcard parent constrains nothing, so nothing can widen it, while a
	// wildcard child widens everything except another wildcard.
	for _, t := range CoreTypes {
		permitted[pair{parent: TypeWildcard, derived: t}] = alwaysSubsumes
	}
}

func alwaysSubsumes(_, _ *Constraint, _ int) bool { return true }

func parentAcceptsExactValue(derived, parent *Constraint, depth int) bool {
	return parent.check(derived.Value, depth)
}

// rangeSubsumes implements §4.5 range: derived bounds at least as restrictive
// as the parent's, a missing derived bound valid only where the parent's is
// also missing, and derived exclusive valid against parent inclusive at an
// equal bound but not the reverse.
func rangeSubsumes(derived, parent *Constraint, _ int) bool {
	// Non-finite bounds cannot come from JSON, but a hand-built constraint can
	// carry them and every comparison below is false against NaN, which would
	// let a NaN-bounded parent (which accepts nothing) be "subsumed" by a
	// derived range that accepts something. Fail closed instead.
	for _, b := range []*float64{derived.Min, derived.Max, parent.Min, parent.Max} {
		if b != nil && (math.IsNaN(*b) || math.IsInf(*b, 0)) {
			return false
		}
	}

	if derived.Min == nil {
		// Unbounded below. Only valid where the parent is unbounded too.
		if parent.Min != nil {
			return false
		}
	} else if parent.Min != nil {
		if *derived.Min < *parent.Min {
			return false
		}
		// At an equal bound, exclusive is the tighter of the two: derived
		// exclusive against parent inclusive drops the endpoint and is valid,
		// derived inclusive against parent exclusive admits a value the parent
		// rejects and is not.
		if *derived.Min == *parent.Min && derived.MinInclusive && !parent.MinInclusive {
			return false
		}
	}

	if derived.Max == nil {
		if parent.Max != nil {
			return false
		}
	} else if parent.Max != nil {
		if *derived.Max > *parent.Max {
			return false
		}
		if *derived.Max == *parent.Max && derived.MaxInclusive && !parent.MaxInclusive {
			return false
		}
	}
	return true
}

// §4.5 one_of: derived value set is a subset of the parent's.
func oneOfSubsumes(derived, parent *Constraint, _ int) bool {
	return subsetOf(derived.Values, parent.Values)
}

// §4.5 not_one_of: derived excluded set is a superset of the parent's.
// Excluding more is a restriction; excluding less admits values the parent
// denies.
func notOneOfSubsumes(derived, parent *Constraint, _ int) bool {
	return subsetOf(parent.Excluded, derived.Excluded)
}

// §4.5 contains: derived required set is a superset of the parent's. Requiring
// more elements accepts fewer arrays.
func containsSubsumes(derived, parent *Constraint, _ int) bool {
	return subsetOf(parent.Required, derived.Required)
}

// §4.5 subset: derived allowed set is a subset of the parent's. Shrinking the
// allowed set is a restriction; adding to it would accept arrays the parent
// rejects.
func subsetSubsumes(derived, parent *Constraint, _ int) bool {
	return subsetOf(derived.Allowed, parent.Allowed)
}

// allSubsumes implements §4.5 all: every parent clause must be subsumed by a
// distinct derived clause. Extra derived clauses are permitted — they only add
// restrictions.
//
// DO NOT "restore conformance" by replacing this with §4.5's pseudocode.
//
// §4.5 gives naive backtracking as pseudocode and then, in the next sentence,
// says implementations MAY use "Hopcroft-Karp or similar maximum matching
// algorithms". This is Kuhn's augmenting-path matching: "similar", explicitly
// permitted, and deciding the identical question — does a matching saturating
// the parent clauses exist — so it returns the same answer for every input.
//
// The pseudocode is O(n!) in the clause count, and the clause count is bounded
// by MAX_TOKEN_SIZE, NOT by MAX_CONSTRAINT_DEPTH. An `all` with two thousand
// clauses is depth 2 and fits in a 64 KiB token, so the literal version is
// attacker-reachable: a single derived token stalls the enforcement point.
// Kuhn's is O(V*E).
//
// Greedy matching is the thing §4.5 warns against, and this is not greedy:
// augment() displaces an earlier assignment when a later parent clause has no
// other candidate, which is exactly the dead-end recovery the pseudocode's
// backtracking provides. TestAllRequiresBacktracking pins that behaviour.
func allSubsumes(derived, parent *Constraint, depth int) bool {
	// matchOf[i] is the parent clause assigned to derived clause i, or -1.
	matchOf := make([]int, len(derived.Clauses))
	for i := range matchOf {
		matchOf[i] = -1
	}
	for p := range parent.Clauses {
		seen := make([]bool, len(derived.Clauses))
		if !augment(p, derived.Clauses, parent.Clauses, matchOf, seen, depth) {
			return false
		}
	}
	return true
}

func augment(p int, derived, parent []Constraint, matchOf []int, seen []bool, depth int) bool {
	for d := range derived {
		if seen[d] || !subsumes(&derived[d], &parent[p], depth) {
			continue
		}
		seen[d] = true
		if matchOf[d] == -1 || augment(matchOf[d], derived, parent, matchOf, seen, depth) {
			matchOf[d] = p
			return true
		}
	}
	return false
}

// anySubsumes implements §4.5 any: every derived clause must be subsumed by at
// least one parent clause. Unlike all this is not a matching — several derived
// clauses may lean on the same parent clause, because the derived disjunction
// accepts a value only if one of its clauses does, and that clause's parent
// clause then accepts it too.
func anySubsumes(derived, parent *Constraint, depth int) bool {
	if len(derived.Clauses) == 0 {
		// §4.5: the derived any MUST contain at least one clause. ParseConstraint
		// already rejects this; a hand-built constraint gets the same answer.
		return false
	}
	for d := range derived.Clauses {
		matched := false
		for p := range parent.Clauses {
			if subsumes(&derived.Clauses[d], &parent.Clauses[p], depth) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// equal is JSON value equality. Values here are encoding/json output, so 1 and
// 1.0 have already become the same float64 — the same identification RFC 8785
// makes, which is what keeps this consistent with the JCS gate upstream.
func equal(a, b any) bool { return reflect.DeepEqual(a, b) }

func memberOf(v any, set []any) bool {
	for _, e := range set {
		if equal(v, e) {
			return true
		}
	}
	return false
}

// ponytail: O(n*m) set containment over slices. Constraint value sets are
// bounded by MAX_TOKEN_SIZE and are small in practice; a hash set would need a
// canonical string key per value, which means pulling the JCS serializer into
// core. Revisit if profiling ever shows this.
func subsetOf(sub, super []any) bool {
	for _, e := range sub {
		if !memberOf(e, super) {
			return false
		}
	}
	return true
}

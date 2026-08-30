package main

import "encoding/json"

// Case is one (parent, derived) pair presented to both implementations.
//
// Want is set only for the direction-probe category, where it is the verdict
// BOTH implementations must produce. A probe that comes back wrong means the
// argument mapping is inverted, and every other verdict in the run is void —
// see the gate in main.go.
type Case struct {
	ID       string          `json:"id"`
	Category string          `json:"-"`
	Why      string          `json:"-"`
	Parent   json.RawMessage `json:"parent"`
	Derived  json.RawMessage `json:"derived"`
	Want     *bool           `json:"-"`
}

func j(s string) json.RawMessage { return json.RawMessage(s) }

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

// Categories, in report order. The corpus is deliberately NOT a uniform sweep
// of the 81-pair matrix: §4.5 states the wildcard rule most explicitly, so
// agreement there is weak evidence and it sits in `control` where it cannot
// carry the headline. The weight is on readings that require interpretation.
const (
	catProbe    = "direction-probe"
	catNoWit    = "no-witness-cross-type"
	catRange    = "range-inclusivity"
	catAll      = "all-matching"
	catNotOneOf = "not_one_of-vs-one_of"
	catControl  = "control"
)

var categoryOrder = []string{catProbe, catNoWit, catRange, catAll, catNotOneOf, catControl}

var categoryWhy = map[string]string{
	catProbe:    "asserts the argument mapping; a wrong verdict here voids the run",
	catNoWit:    "§4.5 declares no rule; warden rejects by absence. no witness distinguishes the two",
	catRange:    "inclusivity at an equal bound and missing bounds, where the natural reading is wrong",
	catAll:      "§4.5's one-to-one clause assignment, including a greedy dead-end",
	catNotOneOf: "the one cross-type pair §4.5 invalidates in prose",
	catControl:  "rules §4.5 states plainly. reported separately so agreement is not carried by easy rows",
}

// categoryNote is appended under a category's table where the raw verdicts
// would otherwise be read as stronger evidence than they are.
var categoryNote = map[string]string{
	catAll: "`all-greedy-dead-end` agrees for a different reason on each side: " +
		"warden needs an augmenting path to find the matching, while tenuo has no " +
		"one-to-one requirement to dead-end against. Agreement on that row is not " +
		"evidence of matching parity; the two reuse rows are what separates them.",
}

func corpus() []Case {
	return []Case{
		// ---- direction-probe -------------------------------------------------
		// Each pair below flips its verdict under swap, so an inverted mapping
		// cannot pass all four. These are checked against Want on BOTH sides.
		{
			ID: "probe-range-narrow", Category: catProbe, Want: yes(),
			Why:     "derived [0,10] inside parent [0,100]",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":10}`),
		},
		{
			ID: "probe-range-widen", Category: catProbe, Want: no(),
			Why:     "probe-range-narrow swapped; must not permit",
			Parent:  j(`{"constraint_type":"range","min":0,"max":10}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":100}`),
		},
		{
			ID: "probe-oneof-to-exact", Category: catProbe, Want: yes(),
			Why:     "§4.5 exact: parent one_of listing the value",
			Parent:  j(`{"constraint_type":"one_of","values":["a","b","c"]}`),
			Derived: j(`{"constraint_type":"exact","value":"a"}`),
		},
		{
			ID: "probe-exact-to-oneof", Category: catProbe, Want: no(),
			Why:     "probe-oneof-to-exact swapped; (exact, one_of) is undeclared",
			Parent:  j(`{"constraint_type":"exact","value":"a"}`),
			Derived: j(`{"constraint_type":"one_of","values":["a","b","c"]}`),
		},

		// ---- no-witness cross-type default-deny ------------------------------
		// Every pair here is semantically narrower — the derived constraint
		// admits a non-empty subset of what the parent admits, so the M0b1
		// completeness probe would find NO WITNESS. §4.5 declares no rule for
		// the type pair, and warden rejects it by absence from the table. If
		// tenuo permits any of these, two implementations disagree on an
		// undeclared pair, which is the strongest finding available here.
		{
			ID: "nowit-range-to-oneof", Category: catNoWit,
			Why:     "derived {1,2,5} all inside parent [0,10]",
			Parent:  j(`{"constraint_type":"range","min":0,"max":10}`),
			Derived: j(`{"constraint_type":"one_of","values":[1,2,5]}`),
		},
		{
			ID: "nowit-oneof-to-range", Category: catNoWit,
			Why:     "derived [1,1] admits exactly 1, which parent lists",
			Parent:  j(`{"constraint_type":"one_of","values":[1,2,3]}`),
			Derived: j(`{"constraint_type":"range","min":1,"max":1}`),
		},
		{
			ID: "nowit-oneof-to-any", Category: catNoWit,
			Why:     "semantically identical to the parent",
			Parent:  j(`{"constraint_type":"one_of","values":[1,2]}`),
			Derived: j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":1},{"constraint_type":"exact","value":2}]}`),
		},
		{
			ID: "nowit-any-to-oneof", Category: catNoWit,
			Why:     "nowit-oneof-to-any in the other direction; also identical",
			Parent:  j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":1},{"constraint_type":"exact","value":2}]}`),
			Derived: j(`{"constraint_type":"one_of","values":[1,2]}`),
		},
		{
			ID: "nowit-any-to-exact", Category: catNoWit,
			Why:     "derived admits exactly what the parent's only clause admits",
			Parent:  j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":1}]}`),
			Derived: j(`{"constraint_type":"exact","value":1}`),
		},
		{
			ID: "nowit-all-to-range", Category: catNoWit,
			Why:     "parent conjunction is [0,10]; derived is [0,10]",
			Parent:  j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":10},{"constraint_type":"range","min":0,"max":50}]}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":10}`),
		},
		{
			ID: "nowit-range-to-all", Category: catNoWit,
			Why:     "derived conjunction is [0,5], inside parent [0,10]",
			Parent:  j(`{"constraint_type":"range","min":0,"max":10}`),
			Derived: j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":10},{"constraint_type":"range","min":0,"max":5}]}`),
		},
		{
			ID: "nowit-notoneof-to-oneof", Category: catNoWit,
			Why:     "derived {1,2} avoids the parent's only exclusion",
			Parent:  j(`{"constraint_type":"not_one_of","excluded":[5]}`),
			Derived: j(`{"constraint_type":"one_of","values":[1,2]}`),
		},
		{
			ID: "nowit-notoneof-to-exact", Category: catNoWit,
			Why:     `derived "y" is not the parent's excluded "x"`,
			Parent:  j(`{"constraint_type":"not_one_of","excluded":["x"]}`),
			Derived: j(`{"constraint_type":"exact","value":"y"}`),
		},

		// ---- range inclusivity ----------------------------------------------
		{
			ID: "range-derived-exclusive-tighter", Category: catRange,
			Why:     "§4.5: derived exclusive against parent inclusive at an equal bound is tighter",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":100,"min_inclusive":false}`),
		},
		{
			ID: "range-derived-inclusive-wider", Category: catRange,
			Why:     "the reverse admits the endpoint the parent excluded",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100,"min_inclusive":false}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":100,"min_inclusive":true}`),
		},
		{
			ID: "range-derived-exclusive-max-tighter", Category: catRange,
			Why:     "the same rule on the max bound",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":100,"max_inclusive":false}`),
		},
		{
			ID: "range-derived-inclusive-max-wider", Category: catRange,
			Why:     "max bound, reverse direction",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100,"max_inclusive":false}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":100,"max_inclusive":true}`),
		},
		{
			ID: "range-derived-drops-max", Category: catRange,
			Why:     "§4.5: a missing derived bound is valid only if the parent's is missing too",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100}`),
			Derived: j(`{"constraint_type":"range","min":0}`),
		},
		{
			ID: "range-derived-drops-min", Category: catRange,
			Why:     "the same on the min side",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100}`),
			Derived: j(`{"constraint_type":"range","max":100}`),
		},
		{
			ID: "range-derived-adds-min", Category: catRange,
			Why:     "parent unbounded below; adding a bound is a restriction",
			Parent:  j(`{"constraint_type":"range","max":100}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":100}`),
		},
		{
			ID: "range-both-unbounded-min", Category: catRange,
			Why:     "both missing on the same side is valid",
			Parent:  j(`{"constraint_type":"range","max":100}`),
			Derived: j(`{"constraint_type":"range","max":50}`),
		},
		{
			ID: "range-exclusive-both-equal", Category: catRange,
			Why:     "equal bounds, equal inclusivity, nothing tightened or widened",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100,"min_inclusive":false,"max_inclusive":false}`),
			Derived: j(`{"constraint_type":"range","min":0,"max":100,"min_inclusive":false,"max_inclusive":false}`),
		},

		// ---- all matching ----------------------------------------------------
		{
			ID: "all-clause-reuse-two-parents-one-derived", Category: catAll,
			Why:     "§4.5: a single derived clause MUST NOT satisfy more than one parent clause",
			Parent:  j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":100},{"constraint_type":"range","min":0,"max":50}]}`),
			Derived: j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":10}]}`),
		},
		{
			ID: "all-clause-reuse-wildcards", Category: catAll,
			Why:     "the same rule, minimal shape: two parent clauses, one derived clause",
			Parent:  j(`{"constraint_type":"all","constraints":[{"constraint_type":"wildcard"},{"constraint_type":"wildcard"}]}`),
			Derived: j(`{"constraint_type":"all","constraints":[{"constraint_type":"exact","value":5}]}`),
		},
		{
			ID: "all-greedy-dead-end", Category: catAll,
			Why:     "greedy assignment strands parent one_of[1]; only backtracking finds the matching",
			Parent:  j(`{"constraint_type":"all","constraints":[{"constraint_type":"one_of","values":[1,2,3]},{"constraint_type":"one_of","values":[1]}]}`),
			Derived: j(`{"constraint_type":"all","constraints":[{"constraint_type":"exact","value":1},{"constraint_type":"one_of","values":[1,2]}]}`),
		},
		{
			ID: "all-parent-clause-dropped", Category: catAll,
			Why:     "a parent clause with no derived match at all; both must deny",
			Parent:  j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":10},{"constraint_type":"one_of","values":["a"]}]}`),
			Derived: j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":5}]}`),
		},
		{
			ID: "all-derived-adds-clauses", Category: catAll,
			Why:     "§4.5: unmatched additional derived clauses are permitted",
			Parent:  j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":100}]}`),
			Derived: j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":10},{"constraint_type":"one_of","values":[1,2]}]}`),
		},
		{
			ID: "all-one-to-one-available", Category: catAll,
			Why:     "a genuine one-to-one assignment exists; no reuse needed",
			Parent:  j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":100},{"constraint_type":"one_of","values":[1,2,3]}]}`),
			Derived: j(`{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0,"max":10},{"constraint_type":"exact","value":1}]}`),
		},

		// ---- not_one_of against a parent one_of ------------------------------
		{
			ID: "notoneof-against-parent-oneof", Category: catNotOneOf,
			Why:     "§4.5 one_of: enforcement points MUST reject this cross-type pair",
			Parent:  j(`{"constraint_type":"one_of","values":["a","b","c"]}`),
			Derived: j(`{"constraint_type":"not_one_of","excluded":["d"]}`),
		},
		{
			ID: "notoneof-excluding-parent-member", Category: catNotOneOf,
			Why:     "still invalid even when the exclusion looks like a narrowing",
			Parent:  j(`{"constraint_type":"one_of","values":["a","b"]}`),
			Derived: j(`{"constraint_type":"not_one_of","excluded":["a"]}`),
		},
		{
			ID: "notoneof-adds-exclusion", Category: catNotOneOf,
			Why:     "§4.5 not_one_of: derived excluded set is a superset",
			Parent:  j(`{"constraint_type":"not_one_of","excluded":["a"]}`),
			Derived: j(`{"constraint_type":"not_one_of","excluded":["a","b"]}`),
		},
		{
			ID: "notoneof-removes-exclusion", Category: catNotOneOf,
			Why:     "dropping an exclusion admits what the parent denied",
			Parent:  j(`{"constraint_type":"not_one_of","excluded":["a","b"]}`),
			Derived: j(`{"constraint_type":"not_one_of","excluded":["a"]}`),
		},

		// ---- control ---------------------------------------------------------
		{
			ID: "ctl-wildcard-parent-to-exact", Category: catControl,
			Why:     "any type subsumes a parent wildcard",
			Parent:  j(`{"constraint_type":"wildcard"}`),
			Derived: j(`{"constraint_type":"exact","value":5}`),
		},
		{
			ID: "ctl-derived-wildcard-widens", Category: catControl,
			Why:     "a derived wildcard is valid only against a parent wildcard",
			Parent:  j(`{"constraint_type":"exact","value":5}`),
			Derived: j(`{"constraint_type":"wildcard"}`),
		},
		{
			ID: "ctl-wildcard-to-wildcard", Category: catControl,
			Why:     "the one permitted derived wildcard",
			Parent:  j(`{"constraint_type":"wildcard"}`),
			Derived: j(`{"constraint_type":"wildcard"}`),
		},
		{
			ID: "ctl-oneof-shrinks", Category: catControl,
			Why:     "derived value set is a subset",
			Parent:  j(`{"constraint_type":"one_of","values":["a","b","c"]}`),
			Derived: j(`{"constraint_type":"one_of","values":["a","b"]}`),
		},
		{
			ID: "ctl-oneof-grows", Category: catControl,
			Why:     "derived value set adds a member",
			Parent:  j(`{"constraint_type":"one_of","values":["a","b"]}`),
			Derived: j(`{"constraint_type":"one_of","values":["a","b","c"]}`),
		},
		{
			ID: "ctl-contains-requires-more", Category: catControl,
			Why:     "§4.5 contains: derived required set is a superset",
			Parent:  j(`{"constraint_type":"contains","required":["a"]}`),
			Derived: j(`{"constraint_type":"contains","required":["a","b"]}`),
		},
		{
			ID: "ctl-contains-requires-less", Category: catControl,
			Why:     "removing a required element widens",
			Parent:  j(`{"constraint_type":"contains","required":["a","b"]}`),
			Derived: j(`{"constraint_type":"contains","required":["a"]}`),
		},
		{
			ID: "ctl-subset-shrinks", Category: catControl,
			Why:     "§4.5 subset: derived allowed set is a subset",
			Parent:  j(`{"constraint_type":"subset","allowed":["a","b","c"]}`),
			Derived: j(`{"constraint_type":"subset","allowed":["a","b"]}`),
		},
		{
			ID: "ctl-subset-grows", Category: catControl,
			Why:     "adding an allowed element widens",
			Parent:  j(`{"constraint_type":"subset","allowed":["a","b"]}`),
			Derived: j(`{"constraint_type":"subset","allowed":["a","b","c"]}`),
		},
		{
			ID: "ctl-any-drops-clause", Category: catControl,
			Why:     "§4.5 any, the draft's own worked example",
			Parent:  j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":"pdf"},{"constraint_type":"exact","value":"csv"},{"constraint_type":"exact","value":"xlsx"}]}`),
			Derived: j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":"pdf"},{"constraint_type":"exact","value":"csv"}]}`),
		},
		{
			ID: "ctl-any-adds-clause", Category: catControl,
			Why:     "§4.5 any, the draft's own counter-example",
			Parent:  j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":"pdf"},{"constraint_type":"exact","value":"csv"}]}`),
			Derived: j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":"pdf"},{"constraint_type":"exact","value":"docx"}]}`),
		},
		{
			ID: "ctl-any-cross-type-clause", Category: catControl,
			Why:     "§4.5 any: cross-type subsumption between clauses is permitted",
			Parent:  j(`{"constraint_type":"any","constraints":[{"constraint_type":"one_of","values":["pdf","csv"]}]}`),
			Derived: j(`{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":"pdf"}]}`),
		},
		{
			ID: "ctl-exact-same-value", Category: catControl,
			Why:     "§4.5 exact against an equal parent exact",
			Parent:  j(`{"constraint_type":"exact","value":5}`),
			Derived: j(`{"constraint_type":"exact","value":5}`),
		},
		{
			ID: "ctl-exact-different-value", Category: catControl,
			Why:     "a different value is not subsumed",
			Parent:  j(`{"constraint_type":"exact","value":5}`),
			Derived: j(`{"constraint_type":"exact","value":6}`),
		},
		{
			ID: "ctl-range-to-exact-inside", Category: catControl,
			Why:     "§4.5 exact against a parent range containing the value",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100}`),
			Derived: j(`{"constraint_type":"exact","value":50}`),
		},
		{
			ID: "ctl-range-to-exact-outside", Category: catControl,
			Why:     "the value falls outside the parent interval",
			Parent:  j(`{"constraint_type":"range","min":0,"max":100}`),
			Derived: j(`{"constraint_type":"exact","value":500}`),
		},
	}
}

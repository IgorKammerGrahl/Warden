package core

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The second property of the milestone, quantified over chains rather than
// single constraints:
//
//	for all chains C0, C1, ..., Cn where CheckI4(C_{i+1}, C_i) == nil for every i,
//	and for all (tool, args):
//	    Cn.CheckInvocation(tool, args) == nil  =>  C0.CheckInvocation(tool, args) == nil
//
// In words: no sequence of valid derivations yields a leaf authorizing an
// invocation the root would deny. This is C(leaf) ⊆ C(root), the §4.1 lattice
// property, which I4 enforces one link at a time and which therefore has to
// survive composition.
//
// It is not implied by the single-link soundness property. That one says
// Subsumes is sound for one constraint pair; this one says the whole of step 4p
// — the tool-subset rule, the two different key-set rules, and the per-argument
// subsumption — composes down a chain without leaking authority. A key-set rule
// that were merely "subset" instead of "equal" would pass the first property
// and fail this one.

// toolPool and argPool are small for the same reason scalarPool is: the
// property says nothing unless the leaf actually authorizes the drawn
// invocation, and that requires collisions.
var (
	toolPool = []string{"read_file", "list_dir", "search"}
	argPool  = []string{"path", "mode", "limit"}
)

// genCapabilities draws a root capability set: a few tools, each with a
// constraint map that is sometimes empty (open-world) and sometimes not.
func genCapabilities() *rapid.Generator[*Capabilities] {
	return rapid.Custom(func(t *rapid.T) *Capabilities {
		if rapid.IntRange(0, 9).Draw(t, "empty_caps") == 0 {
			return &Capabilities{Tools: map[string]ConstraintMap{}}
		}
		tools := rapid.SliceOfNDistinct(rapid.SampledFrom(toolPool), 1, 3,
			func(s string) string { return s }).Draw(t, "tools")
		caps := &Capabilities{Tools: make(map[string]ConstraintMap, len(tools))}
		for _, tool := range tools {
			caps.Tools[tool] = genConstraintMap().Draw(t, "map_"+tool)
		}
		return caps
	})
}

func genConstraintMap() *rapid.Generator[ConstraintMap] {
	return rapid.Custom(func(t *rapid.T) ConstraintMap {
		args := rapid.SliceOfNDistinct(rapid.SampledFrom(argPool), 0, 3,
			func(s string) string { return s }).Draw(t, "args")
		cm := make(ConstraintMap, len(args))
		for _, arg := range args {
			c := genConstraint(2).Draw(t, "c_"+arg)
			cm[arg] = &c
		}
		return cm
	})
}

// genDerivation draws a candidate child of parent. Like genAttenuation, it is a
// generator of candidates and never an oracle: whether the candidate is a valid
// derivation is CheckI4's answer to give, and the property only looks at chains
// where every link said yes.
func genDerivation(parent *Capabilities) *rapid.Generator[*Capabilities] {
	return rapid.Custom(func(t *rapid.T) *Capabilities {
		child := &Capabilities{Tools: map[string]ConstraintMap{}}

		names := make([]string, 0, len(parent.Tools))
		for name := range parent.Tools {
			names = append(names, name)
		}
		sort.Strings(names) // rapid needs the draw sequence to be deterministic

		for _, name := range names {
			if rapid.IntRange(0, 3).Draw(t, "drop_"+name) == 0 {
				continue // dropping a tool is always valid attenuation
			}
			parentMap := parent.Tools[name]
			if len(parentMap) == 0 {
				// The 4p3 case: the child MAY introduce any key set here. Draw
				// one, sometimes empty, sometimes not.
				child.Tools[name] = genConstraintMap().Draw(t, "open_"+name)
				continue
			}
			// The 4p2 case. Usually keep the key set exactly and attenuate each
			// constraint; occasionally add or drop a key so the rule is being
			// exercised rather than assumed.
			cm := ConstraintMap{}
			args := make([]string, 0, len(parentMap))
			for arg := range parentMap {
				args = append(args, arg)
			}
			sort.Strings(args)
			for _, arg := range args {
				if rapid.IntRange(0, 19).Draw(t, "dropkey_"+name+"_"+arg) == 0 {
					continue
				}
				c := genAttenuation(*parentMap[arg]).Draw(t, "att_"+name+"_"+arg)
				cm[arg] = &c
			}
			if rapid.IntRange(0, 19).Draw(t, "addkey_"+name) == 0 {
				extra := genConstraint(2).Draw(t, "extra_"+name)
				cm["extra"] = &extra
			}
			child.Tools[name] = cm
		}

		// Occasionally try to smuggle in a tool the parent never had.
		if rapid.IntRange(0, 19).Draw(t, "addtool") == 0 {
			child.Tools[rapid.SampledFrom(toolPool).Draw(t, "newtool")] =
				genConstraintMap().Draw(t, "newmap")
		}
		return child
	})
}

// genInvocation draws a (tool, args) pair aimed at what the leaf authorizes, so
// that the implication is not vacuous. It still sometimes draws something wild.
func genInvocation(leaf *Capabilities) *rapid.Generator[invocation] {
	return rapid.Custom(func(t *rapid.T) invocation {
		names := make([]string, 0, len(leaf.Tools))
		for name := range leaf.Tools {
			names = append(names, name)
		}
		sort.Strings(names)

		tool := rapid.SampledFrom(toolPool).Draw(t, "wild_tool")
		if len(names) > 0 && rapid.IntRange(0, 9).Draw(t, "aim") != 0 {
			tool = rapid.SampledFrom(names).Draw(t, "aimed_tool")
		}

		args := map[string]any{}
		keys := argPool
		if cm, ok := leaf.Tools[tool]; ok && len(cm) > 0 &&
			rapid.IntRange(0, 9).Draw(t, "aim_args") != 0 {
			// Present exactly the constraint map's key set: anything else is
			// rejected by closed-world mode before a value is ever looked at.
			keys = keys[:0:0]
			for arg := range cm {
				keys = append(keys, arg)
			}
			sort.Strings(keys)
		}
		cm := leaf.Tools[tool]
		for _, arg := range keys {
			if len(keys) == len(argPool) && rapid.Bool().Draw(t, "omit_"+arg) {
				continue
			}
			if c, ok := cm[arg]; ok {
				args[arg] = genSatisfying(c).Draw(t, "v_"+arg)
				continue
			}
			args[arg] = genValue().Draw(t, "v_"+arg)
		}
		return invocation{tool: tool, args: args}
	})
}

type invocation struct {
	tool string
	args map[string]any
}

// TestChainAttenuationIsSound is the milestone's second deliverable.
func TestChainAttenuationIsSound(t *testing.T) {
	var chains, validChains, permits int

	rapid.Check(t, func(t *rapid.T) {
		root := genCapabilities().Draw(t, "root")
		links := rapid.IntRange(1, 4).Draw(t, "links")
		chains++

		leaf := root
		for i := 0; i < links; i++ {
			child := genDerivation(leaf).Draw(t, fmt.Sprintf("child%d", i))
			if err := CheckI4(child, leaf); err != nil {
				return // not a valid derivation; the property says nothing about it
			}
			leaf = child
		}
		validChains++

		for _, inv := range rapid.SliceOfN(genInvocation(leaf), 1, 3).Draw(t, "invocations") {
			if leaf.CheckInvocation(inv.tool, inv.args) != nil {
				continue
			}
			permits++
			if err := root.CheckInvocation(inv.tool, inv.args); err != nil {
				t.Fatalf("AUTHORITY LEAK: a chain of %d valid derivations produced a leaf "+
					"that authorizes an invocation the root denies\n"+
					"  root: %s\n  leaf: %s\n  tool: %q\n  args: %#v\n  root says: %v",
					links, renderCaps(root), renderCaps(leaf), inv.tool, inv.args, err)
			}
		}
	})

	if permits == 0 {
		t.Fatalf("vacuous: no leaf authorized any drawn invocation over %d chains (%d valid) — "+
			"the property asserted nothing", chains, validChains)
	}
	t.Logf("%d chains drawn, %d valid, %d leaf-authorized invocations checked against the root",
		chains, validChains, permits)
}

func renderCaps(c *Capabilities) string {
	if c == nil {
		return "<no capability entry>"
	}
	names := make([]string, 0, len(c.Tools))
	for name := range c.Tools {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s:", name)
		args := make([]string, 0, len(c.Tools[name]))
		for arg := range c.Tools[name] {
			args = append(args, arg)
		}
		sort.Strings(args)
		b.WriteByte('{')
		for j, arg := range args {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s=%s", arg, render(*c.Tools[name][arg]))
		}
		b.WriteByte('}')
	}
	b.WriteByte('}')
	return b.String()
}

// genSatisfying draws a value the constraint is likely to accept. It exists
// only to keep the property from being vacuous: an argument value drawn blind
// almost never satisfies a drawn constraint, so the leaf almost never
// authorizes anything and the implication holds for want of an antecedent.
//
// It is a generator of candidates, never an oracle. CheckInvocation decides
// whether the leaf authorizes the invocation, and one draw in five ignores the
// constraint entirely so that the wilder shapes stay reachable.
func genSatisfying(c *Constraint) *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		if rapid.IntRange(0, 4).Draw(t, "wild") == 0 {
			return genValue().Draw(t, "wild_value")
		}
		switch c.Type {
		case TypeExact:
			return c.Value
		case TypeOneOf:
			if len(c.Values) > 0 {
				return rapid.SampledFrom(c.Values).Draw(t, "member")
			}
		case TypeRange:
			lo, hi := -1.0, 4.0
			if c.Min != nil {
				lo = *c.Min
			}
			if c.Max != nil {
				hi = *c.Max
			}
			if lo <= hi {
				return rapid.SampledFrom([]float64{lo, hi, (lo + hi) / 2}).Draw(t, "in_range")
			}
		case TypeSubset:
			if len(c.Allowed) > 0 {
				return anySlice(rapid.SliceOfN(rapid.SampledFrom(c.Allowed), 0, len(c.Allowed)).
					Draw(t, "subset"))
			}
			return []any{}
		case TypeContains:
			return anySlice(append(append([]any{}, c.Required...),
				rapid.SliceOfN(genScalar(), 0, 1).Draw(t, "extra")...))
		case TypeAll, TypeAny:
			if len(c.Clauses) > 0 {
				i := rapid.IntRange(0, len(c.Clauses)-1).Draw(t, "clause")
				return genSatisfying(&c.Clauses[i]).Draw(t, "clause_value")
			}
		}
		// not_one_of, wildcard, and every degenerate case above: most values
		// pass, so the general generator is already the right one.
		return genValue().Draw(t, "value")
	})
}

// anySlice normalises to []any so Check sees the same shape it would get from
// a JSON decode.
func anySlice(v []any) any { return v }

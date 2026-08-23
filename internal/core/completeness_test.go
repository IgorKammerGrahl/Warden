package core

import (
	"fmt"
	"sort"
	"testing"

	"pgregory.net/rapid"
)

// TestCompletenessProbe measures how often Subsumes says "no" without a reason
// anyone can point at. It is a MEASUREMENT, NOT AN ASSERTION: it cannot fail
// the build, and it must never be made to.
//
// §3.5.1 property 2 permits conservative incompleteness — Subsumes MAY return
// false for a semantically subsuming pair — so there is no threshold here to
// hold anyone to. What the numbers are for is M4 triage. When an operator
// reports "warden denied a derivation that looks like a legitimate
// attenuation", the first question is whether the denial came from §4.5's rule
// or from our implementation being timid, and that question is much cheaper to
// answer against a recorded baseline than from scratch.
//
// Method: sample pairs where Subsumes(Cd, Cp) == false, then search for a
// witness — a value v with Cd.Check(v) && !Cp.Check(v), which proves the
// derived constraint really does admit something the parent rejects and the
// rejection was right. No witness found means one of three things, in
// decreasing order of interest:
//
//  1. the pair is semantically subsuming and our rule was timid;
//  2. the pair is semantically subsuming and §4.5's default-deny rejected it
//     on type grounds, which is the draft's choice, not ours;
//  3. a witness exists outside the sampled value space.
//
// The split below separates (1) from (2): a rejection on a pair that IS in the
// permitted table went through one of our rules, so no-witness there is a
// candidate for (1). A rejection on a pair absent from the table never
// evaluated anything, so no-witness there is (2) by construction.
func TestCompletenessProbe(t *testing.T) {
	type stat struct{ rejected, noWitness int }
	byPair := map[pair]*stat{}
	var ruled, ruledNoWitness, defaultDenied, defaultDeniedNoWitness int

	rapid.Check(t, func(t *rapid.T) {
		parent := genConstraint(3).Draw(t, "parent")
		derived := genConstraint(3).Draw(t, "derived")
		probe := rapid.SliceOfN(genValue(), 16, 32).Draw(t, "probe")

		if Subsumes(&derived, &parent) {
			return
		}

		found := false
		for _, v := range append(probe, valueUniverse...) {
			if derived.Check(v) && !parent.Check(v) {
				found = true
				break
			}
		}

		p := pair{parent: parent.Type, derived: derived.Type}
		if _, ok := byPair[p]; !ok {
			byPair[p] = &stat{}
		}
		byPair[p].rejected++
		if !found {
			byPair[p].noWitness++
		}

		if _, hasRule := permitted[p]; hasRule {
			ruled++
			if !found {
				ruledNoWitness++
			}
		} else {
			defaultDenied++
			if !found {
				defaultDeniedNoWitness++
			}
		}
	})

	pct := func(n, d int) string {
		if d == 0 {
			return "n/a"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(d))
	}

	t.Logf("completeness probe (non-fatal baseline)")
	t.Logf("  rejected by one of our §4.5 rules: %6d, no witness %6d (%s)",
		ruled, ruledNoWitness, pct(ruledNoWitness, ruled))
	t.Logf("  rejected by §4.5 default-deny:     %6d, no witness %6d (%s)",
		defaultDenied, defaultDeniedNoWitness, pct(defaultDeniedNoWitness, defaultDenied))

	// Per-pair, permitted pairs only — these are the rows where our own rule
	// produced the false and a high no-witness rate is worth a second look.
	t.Logf("  per permitted pair (parent -> derived), rejections and no-witness rate:")
	keys := make([]pair, 0, len(byPair))
	for p := range byPair {
		if _, hasRule := permitted[p]; hasRule {
			keys = append(keys, p)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].parent != keys[j].parent {
			return keys[i].parent < keys[j].parent
		}
		return keys[i].derived < keys[j].derived
	})
	for _, p := range keys {
		s := byPair[p]
		t.Logf("    %-10s -> %-10s  %6d rejected, %6d no witness (%s)",
			p.parent, p.derived, s.rejected, s.noWitness, pct(s.noWitness, s.rejected))
	}
}

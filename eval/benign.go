package main

import (
	"encoding/json"

	"github.com/igorkg/warden/internal/aat"
)

// The benign corpus.
//
// Every case here is a delegation an orchestrator would actually perform and a
// call warden SHOULD permit. Independence from the adversarial corpus is
// structural, not a flag: these chains are built exclusively through
// (*chain).derive, which mints via aat.Deriver — draft §6, warden's own issuer
// path. Adversarial chains are built through (*chain).forge, which signs a
// claim map directly and never touches the issuer. The two corpora share the
// trust anchor and the wire encoder and nothing else. See eval/METHOD.md,
// including what this construction cannot cover.

// Tool vocabulary. A grant with an empty constraint map is open-world for that
// tool (§3.3): any arguments. A non-empty map is closed-world, and §7 step 6b
// then requires every argument to be named and to satisfy its constraint.
const (
	toolsOrchestrator = `{"echo":{},"read_file":{},"write_file":{},"search":{}}`
	toolsPlanner      = `{"echo":{},"read_file":{},"search":{}}`
	toolsReader       = `{"echo":{},"read_file":{}}`
	toolsEcho         = `{"echo":{}}`
	toolsSearch       = `{"search":{}}`

	// Closed-world grants, for the §4.5 narrowing patterns.
	echoOneOf    = `{"echo":{"text":{"constraint_type":"one_of","values":["ping","pong"]}}}`
	echoExact    = `{"echo":{"text":{"constraint_type":"exact","value":"ping"}}}`
	echoWildcard = `{"echo":{"text":{"constraint_type":"wildcard"}}}`
	echoNotOneOf = `{"echo":{"text":{"constraint_type":"not_one_of","excluded":["rm","sudo"]}}}`
	echoNotMore  = `{"echo":{"text":{"constraint_type":"not_one_of","excluded":["rm","sudo","curl"]}}}`

	searchRangeWide   = `{"search":{"limit":{"constraint_type":"range","min":1,"max":100}}}`
	searchRangeNarrow = `{"search":{"limit":{"constraint_type":"range","min":1,"max":10}}}`

	writeSubsetWide   = `{"write_file":{"flags":{"constraint_type":"subset","allowed":["create","append","truncate"]}}}`
	writeSubsetNarrow = `{"write_file":{"flags":{"constraint_type":"subset","allowed":["create","append"]}}}`

	readContainsWide   = `{"read_file":{"tags":{"constraint_type":"contains","required":["public"]}}}`
	readContainsNarrow = `{"read_file":{"tags":{"constraint_type":"contains","required":["public","reviewed"]}}}`
)

// benignCases builds the benign corpus. now is the corpus clock.
func benignCases(w *world) []Case {
	var out []Case
	add := func(c Case) { out = append(out, c) }

	// 1. Direct invocation by the root holder. The shortest legitimate chain
	// there is: no delegation at all, depth 1.
	add(permitCase("root-direct-invocation", "direct",
		newChain(w, toolsOrchestrator, 8),
		"echo", `{"text":"hello"}`))

	// 2. An orchestrator narrows a tool set for a sub-agent: the canonical
	// delegation. Four tools become one.
	add(permitCase("orchestrator-narrows-tools", "tool-narrowing",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsEcho, nil),
		"echo", `{"text":"hello"}`))

	// 3. The same narrowing over three hops — orchestrator, planner, worker —
	// each hop dropping tools. Depth 3 is the shape ROADMAP's latency target
	// is stated against.
	add(permitCase("orchestrator-planner-worker", "tool-narrowing",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsPlanner, nil).
			derive(toolsEcho, nil),
		"echo", `{"text":"hello"}`))

	// 4. A holder shortens the TTL before handing the token on. exp moves in,
	// nothing else changes: I3's monotone direction.
	add(permitCase("holder-shortens-ttl", "ttl-narrowing",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsPlanner, func(d *aat.Derivation) { d.Expires -= 1800 }),
		"echo", `{"text":"hello"}`))

	// 5. Same-scope handoff: a transport hop that narrows nothing. §6's final
	// paragraph makes this valid, and warden records it on the permit rather
	// than refusing it. The audit record for this case should carry
	// chain.same_scope [1]; the report checks that it does.
	add(permitCase("same-scope-handoff", "same-scope",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsOrchestrator, nil),
		"echo", `{"text":"hello"}`,
		func(k *Case) { k.WantSameScope = []int{1} }))

	// 6. Open-world parent to closed-world child: the parent grants echo with
	// no constraints, the child pins the argument. §4.5's open-world
	// transition, and the case where attenuation is created rather than
	// tightened.
	add(permitCase("open-world-to-closed-world", "open-to-closed",
		newChain(w, toolsOrchestrator, 8).
			derive(echoExact, nil),
		"echo", `{"text":"ping"}`))

	// 7-11. Constraint narrowing, one §4.5 row each, all with a witness in
	// M0b1's probe: one_of -> exact and range -> range are the pairs the probe
	// measured at 0.0% and 21.4% no-witness respectively.
	add(permitCase("narrow-one_of-to-exact", "constraint-narrowing",
		newChain(w, echoOneOf, 8).
			derive(echoExact, nil),
		"echo", `{"text":"ping"}`))

	add(permitCase("narrow-range", "constraint-narrowing",
		newChain(w, searchRangeWide, 8).
			derive(searchRangeNarrow, nil),
		"search", `{"limit":5}`))

	add(permitCase("narrow-wildcard-to-exact", "constraint-narrowing",
		newChain(w, echoWildcard, 8).
			derive(echoExact, nil),
		"echo", `{"text":"ping"}`))

	add(permitCase("narrow-not_one_of", "constraint-narrowing",
		newChain(w, echoNotOneOf, 8).
			derive(echoNotMore, nil),
		"echo", `{"text":"hello"}`))

	add(permitCase("narrow-subset", "constraint-narrowing",
		newChain(w, writeSubsetWide, 8).
			derive(writeSubsetNarrow, nil),
		"write_file", `{"flags":["create"]}`))

	add(permitCase("narrow-contains", "constraint-narrowing",
		newChain(w, readContainsWide, 8).
			derive(readContainsNarrow, nil),
		"read_file", `{"tags":["public","reviewed","internal"]}`))

	// 12-13. Sibling delegation: one parent, two children with overlapping
	// sub-grants, each invoking under its own leaf key. Both must verify, and
	// neither sibling's chain may be usable by the other.
	sib := newChain(w, toolsOrchestrator, 8).derive(toolsPlanner, nil)
	add(permitCase("sibling-a-reader", "sibling-delegation",
		sib.clone().derive(toolsReader, nil),
		"read_file", `{"path":"/etc/hosts"}`))
	add(permitCase("sibling-b-search", "sibling-delegation",
		sib.clone().derive(toolsSearch, nil),
		"search", `{"query":"warden"}`))

	// 14. The delegation ceiling comes down: a parent that could delegate
	// eight deep hands out a child capped at two. I2's other half.
	add(permitCase("lower-delegation-ceiling", "depth-narrowing",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsPlanner, func(d *aat.Derivation) { d.MaxDelegationDepth = 2 }),
		"echo", `{"text":"hello"}`))

	// 15. A terminal leaf: del_depth == del_max_depth, a holder that may
	// invoke but not delegate (§4.3). Minting one is the point of the flag;
	// invoking with one must still work.
	add(permitCase("terminal-leaf-invokes", "depth-narrowing",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsEcho, func(d *aat.Derivation) { d.MaxDelegationDepth = 1 }),
		"echo", `{"text":"hello"}`))

	// 16. Depth 5: four hops of real narrowing. The deepest chain either
	// corpus presents, and the upper end of M2's latency table.
	add(permitCase("deep-chain-depth-5", "tool-narrowing",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsPlanner, nil).
			derive(toolsReader, nil).
			derive(toolsEcho, nil).
			derive(echoExact, nil),
		"echo", `{"text":"ping"}`))

	// 17. A fire-and-forget call: authorized, presented as a JSON-RPC
	// notification. warden must decide it exactly as it decides the request
	// form. It is here so the notification-bypass number in the adversarial
	// corpus is a statement about the decision and not about warden refusing
	// every notification it sees.
	add(permitCase("authorized-notification", "notification",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsEcho, nil),
		"echo", `{"text":"hello"}`,
		func(k *Case) { k.Notify = true }))

	// 18. A benign large-ish argument payload: nothing adversarial, just a
	// call whose JCS canonicalization and hta digest are not trivial.
	add(permitCase("nested-arguments", "direct",
		newChain(w, toolsOrchestrator, 8).
			derive(toolsEcho, nil),
		"echo", `{"text":"hello","opts":{"b":[1,2,3],"a":{"deep":{"deeper":true}}}}`))

	return out
}

// permitCase assembles a benign case. A chain that failed to build is emitted
// with BuildErr set and is never presented: see (*chain).err.
func permitCase(name, class string, c *chain, tool, args string, opts ...func(*Case)) Case {
	k := Case{
		Name:    name,
		Corpus:  "benign",
		Class:   class,
		Profile: "conformant",
		Expect:  "permit",
		Tool:    tool,
		Args:    json.RawMessage(args),
		Depth:   c.depth(),
	}
	if c.err != nil {
		k.BuildErr = c.err.Error()
	} else {
		k.Meta = c.bind(tool, k.Args)
	}
	for _, o := range opts {
		o(&k)
	}
	return k
}

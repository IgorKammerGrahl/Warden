package main

import (
	"encoding/json"
	"fmt"
)

// The nine tools @modelcontextprotocol/server-memory exposes, and the single
// argument each of them takes. Six of the nine take an array; four of those
// arrays hold objects.
//
//	create_entities     entities    [ {name, entityType, observations[]} ]
//	create_relations    relations   [ {from, to, relationType} ]
//	add_observations    observations[ {entityName, contents[]} ]
//	delete_observations deletions   [ {entityName, observations[]} ]
//	delete_relations    relations   [ {from, to, relationType} ]
//	delete_entities     entityNames [ string ]
//	open_nodes          names       [ string ]
//	search_nodes        query       string
//	read_graph          (none)
var toolArg = map[string]string{
	"create_entities":     "entities",
	"create_relations":    "relations",
	"add_observations":    "observations",
	"delete_observations": "deletions",
	"delete_relations":    "relations",
	"delete_entities":     "entityNames",
	"open_nodes":          "names",
	"search_nodes":        "query",
	"read_graph":          "",
}

var readTools = map[string]bool{"read_graph": true, "search_nodes": true, "open_nodes": true}

const wildcard = `{"constraint_type":"wildcard"}`

// capabilities builds the §3.3 tools map for one profile.
//
// The profiles exist to price the closed-world problem against object-valued
// arguments. §3.4's vocabulary has no type for "an object with these fields",
// so an issuer facing this server has exactly three moves for the six tools
// whose argument is an array of objects, and each profile is one of them.
func capabilities(profile string) (map[string]json.RawMessage, error) {
	tools := map[string]json.RawMessage{}
	switch profile {

	// observed: the honest operator attempt. Constrain what the vocabulary
	// can reach — the string argument and the two string arrays — and leave
	// the object-valued arguments wildcard, because nothing in Table 2
	// describes an object.
	case "observed":
		for tool, arg := range toolArg {
			switch tool {
			case "read_graph":
				tools[tool] = json.RawMessage(`{}`)
			case "search_nodes":
				// A string. one_of over the queries phase 1 actually issued
				// is the tightest core type available; there is no prefix,
				// pattern or length type.
				tools[tool] = cm(arg, oneOf(observedQueries))
			case "open_nodes", "delete_entities":
				// An array of strings. subset over the entity names that
				// existed at mint time.
				tools[tool] = cm(arg, subset(observedEntityNames))
			default:
				// An array of objects. wildcard is the only core option.
				tools[tool] = cm(arg, json.RawMessage(wildcard))
			}
		}

	// readonly: the attenuation test. Only the three read tools, same
	// constraints. Every write must be denied at §7 step 6b.
	case "readonly":
		for tool, arg := range toolArg {
			if !readTools[tool] {
				continue
			}
			switch tool {
			case "read_graph":
				tools[tool] = json.RawMessage(`{}`)
			case "search_nodes":
				tools[tool] = cm(arg, oneOf(observedQueries))
			default:
				tools[tool] = cm(arg, subset(observedEntityNames))
			}
		}

	// searchonly: authorizes one tool and one query. read_graph is NOT
	// authorized, so §7 step 6b must deny every attempt to read the graph
	// through the tool interface. Used with -probes to ask whether the
	// graph is reachable some other way.
	case "searchonly":
		tools["search_nodes"] = cm("query", oneOf([]string{"Ed25519"}))

	// wildcard: every tool, every argument unconstrained. The control. Any
	// denial under this profile is not the vocabulary's fault.
	case "wildcard":
		for tool, arg := range toolArg {
			if arg == "" {
				tools[tool] = json.RawMessage(`{}`)
				continue
			}
			tools[tool] = cm(arg, json.RawMessage(wildcard))
		}

	// exactobj: the experiment the brief asks for. §3.4 has no type for "an
	// object with these fields", so `exact` on the whole argument value is
	// the only way to say anything at all about an object. Written from the
	// phase-1 values, it is the tightest expressible policy — and it is a
	// whitelist of literal call arguments.
	case "exactobj":
		for tool, arg := range toolArg {
			if arg == "" {
				tools[tool] = json.RawMessage(`{}`)
				continue
			}
			vals := observedArgValues[tool]
			if len(vals) == 0 {
				tools[tool] = cm(arg, json.RawMessage(wildcard))
				continue
			}
			tools[tool] = cm(arg, oneOfRaw(vals))
		}

	// subsetobj: the other reading of Table 2, and the finest one. `exact` is
	// restricted to "value (any scalar)", so it cannot name an object at all;
	// `subset` says only that the argument "MUST be an array" and is silent on
	// what its elements may be. Read permissively, subset over the observed
	// *elements* constrains each object independently, which is strictly
	// tighter than one_of over whole argument values and strictly looser than
	// a transcript: it permits recombinations the recording never contained.
	case "subsetobj":
		for tool, arg := range toolArg {
			switch {
			case arg == "":
				tools[tool] = json.RawMessage(`{}`)
			case tool == "search_nodes":
				tools[tool] = cm(arg, oneOf(observedQueries))
			case len(observedElems[tool]) > 0:
				tools[tool] = cm(arg, subsetRaw(observedElems[tool]))
			default:
				tools[tool] = cm(arg, json.RawMessage(wildcard))
			}
		}

	default:
		return nil, fmt.Errorf("unknown profile %q", profile)
	}
	return tools, nil
}

func cm(arg string, constraint json.RawMessage) json.RawMessage {
	return mustMarshal(map[string]json.RawMessage{arg: constraint})
}

func oneOf(values []string) json.RawMessage {
	return mustMarshal(map[string]any{"constraint_type": "one_of", "values": values})
}

func oneOfRaw(values []json.RawMessage) json.RawMessage {
	return mustMarshal(map[string]any{"constraint_type": "one_of", "values": values})
}

func subsetRaw(values []json.RawMessage) json.RawMessage {
	return mustMarshal(map[string]any{"constraint_type": "subset", "allowed": values})
}

func subset(values []string) json.RawMessage {
	return mustMarshal(map[string]any{"constraint_type": "subset", "allowed": values})
}

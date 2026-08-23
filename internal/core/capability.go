package core

import (
	"encoding/json"
	"fmt"
)

// CapabilityType is the authorization_details entry type this specification
// profiles (§3.3). Entries of any other type are ignored.
const CapabilityType = "attenuating_agent_token"

// ConstraintMap is one tool's argument constraint set: argument name to
// constraint.
//
// Empty and nil mean the same thing and both are legal: §3.3 says a tool entry
// with an empty constraint map is authorized without argument restrictions
// (open-world). Non-empty switches that tool to closed-world, where the key set
// *is* the required invocation shape — unnamed arguments are forbidden and
// named ones are mandatory.
type ConstraintMap map[string]*Constraint

// Capabilities is the tools map of the single §3.3 attenuating_agent_token
// entry: what a token authorizes, with the wire encoding gone.
//
// A nil *Capabilities is the empty capability set, which §7 step 4n defines as
// the meaning of a token carrying no such entry. Every method here is nil-safe
// for exactly that reason — the step-4n definitions are load-bearing for the
// non-leaf empty-capability token, and a nil check scattered across callers is
// how one of them gets forgotten.
type Capabilities struct {
	Tools map[string]ConstraintMap
}

// ParseCapabilities projects an authorization_details array onto the domain,
// enforcing the structural rules of §3.3.
//
// It returns nil when the array carries no attenuating_agent_token entry: that
// is the empty capability set of §7 step 4n, valid for a non-leaf derived
// token. Callers that need §3.3's "exactly one" — the root (§7 step 3m) and the
// leaf (step 6a) — check for nil themselves, because leaf-ness is knowable only
// to whoever holds the chain.
//
// More than one such entry is invalid (§3.3) and is an error, not a choice of
// which one to believe.
//
// MAX_CONSTRAINT_DEPTH (§7 steps 3n and 4o) is enforced here by way of
// ParseConstraint, which rejects an over-deep tree.
//
// ponytail: no duplicate tool-identifier scan (§3.3.1). Tokens reach this
// through aat.Parse, which canonicalizes the whole payload and so already
// rejects a duplicate key at any nesting depth. Add a token-stream scan here
// only if a caller ever feeds this bytes that did not come through that path.
func ParseCapabilities(details []json.RawMessage) (*Capabilities, error) {
	var found *Capabilities
	for i, raw := range details {
		var entry struct {
			Type  string                     `json:"type"`
			Tools map[string]json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("core: authorization_details[%d]: %w", i, err)
		}
		if entry.Type != CapabilityType {
			continue // §3.3: entries of other types MUST be ignored.
		}
		if found != nil {
			return nil, Deny("§3.3",
				"core: authorization_details carries more than one %q entry; invalid",
				CapabilityType)
		}
		if entry.Tools == nil {
			return nil, Deny("§3.3",
				"core: %q entry has no tools member; MUST include one", CapabilityType)
		}
		caps := &Capabilities{Tools: make(map[string]ConstraintMap, len(entry.Tools))}
		for tool, rawMap := range entry.Tools {
			cm, err := parseConstraintMap(rawMap)
			if err != nil {
				return nil, fmt.Errorf("core: tool %q: %w", tool, err)
			}
			caps.Tools[tool] = cm
		}
		found = caps
	}
	return found, nil
}

func parseConstraintMap(raw json.RawMessage) (ConstraintMap, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("constraint map is not an object: %w", err)
	}
	// null is not {}: an absent map would read as open-world, which is the more
	// permissive reading of a malformed token.
	if obj == nil {
		return nil, Deny("§3.3", "constraint map is null")
	}
	cm := make(ConstraintMap, len(obj))
	for arg, rawConstraint := range obj {
		c, err := ParseConstraint(rawConstraint)
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", arg, err)
		}
		cm[arg] = c
	}
	return cm, nil
}

// tools is the nil-safe accessor §7 step 4n's definitions require: "the entry
// if present, or an empty capability entry with an empty tools map if absent".
func (c *Capabilities) tools() map[string]ConstraintMap {
	if c == nil {
		return nil
	}
	return c.Tools
}

// CheckI4 is capability monotonicity, §4.5 / §7 step 4p: tools(child) is a
// subset of tools(parent), and every shared constraint is at least as
// restrictive as the parent's.
//
// Either side may be nil (§7 step 4n): a nil child authorizes nothing and
// trivially passes, a nil parent authorizes nothing so any non-empty child
// fails at p1.
func CheckI4(child, parent *Capabilities) error {
	parentTools := parent.tools()
	for tool, childMap := range child.tools() {
		parentMap, ok := parentTools[tool]
		if !ok {
			return Deny("§7 step 4p1, I4",
				"core: child authorizes tool %q that the parent does not", tool)
		}

		// p2 and p3 are two different rules, not one subset check. p2 (parent
		// map non-empty) demands an EXACT key set: under closed-world semantics
		// an added key forbids an invocation shape the parent required, and a
		// dropped key permits one the parent forbade. Either way the child's
		// invocation set is disjoint from the parent's, not a subset. p3 (parent
		// map empty) is the open-to-closed-world transition, where the child may
		// carry ANY key set because every closed-world set is a subset of the
		// unrestricted one.
		if len(parentMap) > 0 {
			if len(childMap) != len(parentMap) {
				return Deny("§7 step 4p2, I4",
					"core: tool %q: child constraint map has %d argument keys, parent has %d; "+
						"a non-empty parent map requires exactly the same key set",
					tool, len(childMap), len(parentMap))
			}
			for arg := range parentMap {
				if _, ok := childMap[arg]; !ok {
					return Deny("§7 step 4p2, I4",
						"core: tool %q: child constraint map drops the parent's argument key %q",
						tool, arg)
				}
			}
		}

		// p4. When p3 applied the parent map is empty and this loop is empty
		// too; when p2 applied the key sets are equal and every lookup hits.
		for arg, parentConstraint := range parentMap {
			if !Subsumes(childMap[arg], parentConstraint) {
				return Deny("§4.5, §7 step 4p4, I4",
					"core: tool %q argument %q: child constraint does not subsume the parent's",
					tool, arg)
			}
		}
	}
	return nil
}

// CheckInvocation is §7 step 6b: does this capability set authorize calling
// tool with args?
//
// The closed-world rules of §3.3 are a security property, not a configuration
// option: when the tool's constraint map is non-empty, an argument it does not
// name is rejected and an argument it names but the invocation omits is
// rejected. An issuer who wants an unrestricted argument writes a wildcard;
// there is no optional-constraint mechanism.
func (c *Capabilities) CheckInvocation(tool string, args map[string]any) error {
	cm, ok := c.tools()[tool]
	if !ok {
		return Deny("§7 step 6b", "core: tool %q is not authorized", tool)
	}
	if len(cm) == 0 {
		return nil // §3.3: an empty constraint map is open-world.
	}
	for name := range args {
		if _, ok := cm[name]; !ok {
			return Deny("§7 step 6b, §3.3 closed-world",
				"core: tool %q: argument %q is not named in the constraint map",
				tool, name)
		}
	}
	for name, constraint := range cm {
		v, ok := args[name]
		if !ok {
			return Deny("§7 step 6b, §3.3 closed-world",
				"core: tool %q: constrained argument %q is absent from the invocation",
				tool, name)
		}
		if !constraint.Check(v) {
			// The ref names the constraint type because §6 wants the audit
			// trace to say which clause of §3.4 fired. Interpolating it is
			// safe in a way interpolating a tool name would not be:
			// ParseConstraint rejects any type outside Table 2, so this is a
			// validated enum, not attacker-chosen text.
			return Deny("§3.4 "+constraint.Type,
				"core: tool %q: argument %q does not satisfy its constraint", tool, name)
		}
	}
	return nil
}

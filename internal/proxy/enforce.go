package proxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/aat/jcs"
	"github.com/igorkg/warden/internal/audit"
	"github.com/igorkg/warden/internal/core"
)

// JSON-RPC error codes warden returns on its own behalf. Both sit in the
// -32000..-32099 range JSON-RPC 2.0 reserves for implementation-defined server
// errors, so neither collides with a method-level code from the upstream.
//
// The two are distinct on purpose. A proxy that starts refusing every call
// because its disk filled looks exactly like a proxy with an authorization bug,
// and a caller that cannot tell those apart retries the wrong thing forever.
const (
	// ErrCodeDenied is an authorization decision: the chain, the PoP or the
	// leaf's capabilities did not authorize this invocation.
	ErrCodeDenied = -32001
	// ErrCodeAuditUnavailable is not an authorization decision at all. The
	// audit sink failed, and §6 makes a guardrail that cannot log refuse to
	// act. Nothing about the caller's tokens is implicated.
	ErrCodeAuditUnavailable = -32002
)

// Enforcer is the ARCHITECTURE §3.2 pipeline for one tools/call: bind, verify
// chain, leaf capability check, PoP, and the stage-5 extension gate.
//
// Stages 2 through 4 are one call into aat.Verifier, because §5.3 fixes their
// order — chain verification (§7 steps 1-6) MUST complete before the PoP is
// evaluated, so that a valid PoP over an invalid chain cannot authorize — and
// splitting them here would move that ordering out of the package that states
// it and into a caller that could get it wrong.
type Enforcer struct {
	Verifier *aat.Verifier

	// InvocationConstraints reports whether the §2.4 extension member is
	// enabled. v1 has no implementation of it, so this is always false and
	// its only effect is the §3.2 stage-5 gate below: a chain carrying the
	// member is rejected, never ignored. Wiring the field now is what keeps
	// the gate from reading as an unconditional rule.
	InvocationConstraints bool
}

// decision is the outcome of the pipeline for one call.
type decision struct {
	allow bool
	trace []audit.Step
	// stage and ref are the wire-visible coordinates of a denial: which
	// pipeline stage refused, and the normative clause it cited. Deliberately
	// no detail — ARCHITECTURE §3.2 wants the caller to learn which check
	// failed without learning constraint values it was never shown. The
	// detail lives in the audit record.
	stage, ref string

	chain audit.Chain
	pop   audit.PoP
}

func (d *decision) step(stage, ref, outcome, detail string) {
	d.trace = append(d.trace, audit.Step{Stage: stage, Ref: ref, Outcome: outcome, Detail: detail})
}

// deny records the failing step and stops. The ref recorded is the finest
// citation the error carries; the stage's own ref is the floor, so a trace
// entry is never uncited even if a check somewhere forgot to name its clause.
func (d *decision) deny(stage, stageRef string, err error) *decision {
	ref := core.RefOf(err)
	if ref == "" {
		ref = stageRef
	}
	d.step(stage, ref, "deny", err.Error())
	d.stage, d.ref = stage, ref
	return d
}

// Decide runs the pipeline. tool is params.name, rawArgs is params.arguments
// exactly as it arrived, and meta is params._meta.
//
// First failure short-circuits (§3.2) and every stage appends to the trace, so
// the record of a denial names the stage that refused and the clause it cited.
func (e *Enforcer) Decide(tool string, rawArgs json.RawMessage, meta map[string]json.RawMessage) *decision {
	d := &decision{}

	// --- Stage 1: bind (ARCHITECTURE §3.1) --------------------------------
	b, err := d.bind(rawArgs, meta)
	if err != nil {
		return d.deny("bind", "ARCHITECTURE §3.1", err)
	}
	d.step("bind", "ARCHITECTURE §3.1", "bound",
		fmt.Sprintf("chain %d tokens, %dB; pop %dB", len(b.chain), b.chainBytes, len(b.pop)))

	// --- The unverified payload pass --------------------------------------
	//
	// INVARIANT: data read here comes from payloads whose signatures have not
	// been checked, and it may only ever ADD a denial — never authorize one.
	// It feeds exactly two consumers: the audit record's chain fields, which
	// are a log and not a decision, and the stage-5 gate below, which can only
	// refuse. Nothing on the permit path reads it.
	//
	// This is the general form of the §7 step 2c carve-out. The draft already
	// permits one pre-verification parse — the jti, for cycle detection — on
	// the same reasoning: an attacker who lies there can cause their own call
	// to be denied and nothing else. Every extension of that carve-out has to
	// meet the same bar, so any future reader added to this pass must be
	// checked against the invariant above before it is added.
	//
	// It runs before verification rather than after so that a DENY record
	// still carries root_jti and leaf_jti. A denial that cannot say which
	// chain produced it is the failure mode ARCHITECTURE §6 exists to prevent,
	// and it is exactly the denials, not the permits, that need explaining.
	facts := scanChain(b.chain)
	d.chain.RootJTI, d.chain.LeafJTI = facts.rootJTI, facts.leafJTI
	d.chain.Depth, d.chain.MaxDepth = facts.depth, facts.maxDepth

	// --- Stages 2, 3 and 4: §7 steps 1-8 ----------------------------------
	if err := e.Verifier.Verify(b.chain, tool, b.args, b.pop); err != nil {
		// One stage label for the three, because one call decided them and
		// claiming to know which of the three refused would mean reading it
		// back out of the error text. The ref is precise regardless: it comes
		// from the check that fired, not from this call site.
		return d.deny("verify", "§7", err)
	}
	d.step("verify", "§7 steps 1-6", "pass", "chain verified: signatures, I1-I5, depth, TTL, capability subsumption")
	d.step("capability", "§7 step 6b", "pass", "leaf authorizes the tool and every argument satisfies its constraint")
	d.step("pop", "§7 step 7", "pass", "PoP verified under the leaf holder key: aat_id, aat_tool, JCS hta, iat window")

	// The PoP's own identifiers, for the record. A bare payload decode rather
	// than a second ParsePoP: verification just parsed, canonicalized and
	// checked the signature over these bytes, so re-doing that work to read
	// two strings out of it would be paying twice for an answer already
	// established.
	var popProbe struct {
		JTI      string `json:"jti"`
		Audience string `json:"aat_aud"`
	}
	if err := decodePayload(b.pop, &popProbe); err == nil {
		d.pop.JTI, d.pop.Aud = popProbe.JTI, popProbe.Audience
	}

	// --- Stage 5: the warden extension gate (§2.4, §3.2 stage 5) ----------
	//
	// Collected during the payload pass, decided here. Those are separate on
	// purpose: §3.2 short-circuits on the FIRST failure in pipeline order, so a
	// chain that both carries the member and fails its signature check must
	// report the signature, not the gate. Reading the fact early and acting on
	// it late is what keeps the trace honest about which check actually fired.
	if facts.invocationConstraints && !e.InvocationConstraints {
		return d.deny("extensions", "ARCHITECTURE §2.4", core.Deny("ARCHITECTURE §2.4",
			"proxy: a token in this chain carries an invocation_constraints member and "+
				"extensions.invocation_constraints is disabled; warden rejects such a chain "+
				"rather than ignoring a restriction its issuer intended"))
	}

	// Stage 6, operator static policy (ARCHITECTURE §5), is not implemented.
	// Its absence cannot widen authority: it is a backstop applied to an
	// already-valid chain, so a missing backstop denies nothing that §7 would
	// have permitted.

	d.step("extensions", "ARCHITECTURE §2.4", "pass", "no disabled extension member present in the chain")

	// No forward step here. This function decides; the caller forwards, and it
	// appends the step that says whether the forward actually happened.
	d.allow = true
	return d
}

// --- stage 1 ---------------------------------------------------------------

// binding is the §3.1 transport binding, typed.
type binding struct {
	chain      []string
	chainBytes int
	pop        string
	spec       string
	args       map[string]any
}

// bind is ARCHITECTURE §3.1. Absent or malformed _meta is a DENY: there is no
// unauthenticated path through the proxy and no bearer fallback, so every
// failure in here is fail-closed by construction rather than by a policy flag.
//
// It fills the decision's chain and pop shape as it goes rather than on the way
// out, so that a call denied halfway through still records what had been
// established when it was refused. Presence and size are not decisions; they
// are the only honest thing warden can say about a binding it could not parse,
// and a record that omitted them would make a malformed chain and an absent one
// look identical.
func (d *decision) bind(rawArgs json.RawMessage, meta map[string]json.RawMessage) (binding, error) {
	const ref = "ARCHITECTURE §3.1"
	var b binding

	if meta == nil {
		return b, core.Deny(ref, "proxy: tools/call carries no params._meta")
	}

	rawChain, ok := meta[MetaChain]
	if !ok {
		return b, core.Deny(ref, "proxy: params._meta carries no %q", MetaChain)
	}
	// An array of JWT strings, never a delimiter-joined one: §3.1 says so, and
	// a decode failure here is the splitting-mismatch bug arriving as a clean
	// denial instead of as a silently mis-split chain.
	d.chain.Present = true
	d.chain.Bytes = len(rawChain)
	if err := json.Unmarshal(rawChain, &b.chain); err != nil {
		return b, core.Deny(ref, "proxy: %q is not a JSON array of strings: %w", MetaChain, err)
	}
	d.chain.Tokens = len(b.chain)
	if len(b.chain) == 0 {
		return b, core.Deny(ref, "proxy: %q is an empty array", MetaChain)
	}
	for i, tok := range b.chain {
		if tok == "" {
			return b, core.Deny(ref, "proxy: %q[%d] is an empty string", MetaChain, i)
		}
		b.chainBytes += len(tok)
	}
	d.chain.Bytes = b.chainBytes

	rawPoP, ok := meta[MetaPoP]
	if !ok {
		return b, core.Deny(ref, "proxy: params._meta carries no %q", MetaPoP)
	}
	d.pop.Present = true
	if err := json.Unmarshal(rawPoP, &b.pop); err != nil {
		return b, core.Deny(ref, "proxy: %q is not a JSON string: %w", MetaPoP, err)
	}
	d.pop.Bytes = len(b.pop)
	if b.pop == "" {
		return b, core.Deny(ref, "proxy: %q is an empty string", MetaPoP)
	}

	rawSpec, ok := meta[MetaSpec]
	if !ok {
		return b, core.Deny(ref, "proxy: params._meta carries no %q", MetaSpec)
	}
	if err := json.Unmarshal(rawSpec, &b.spec); err != nil {
		return b, core.Deny(ref, "proxy: %q is not a JSON string: %w", MetaSpec, err)
	}
	d.chain.Spec = b.spec
	// Exact match against the pinned identifier. This is also what refuses the
	// "+dev.warden.invocation_constraints" profile label of §3.1: a chain that
	// honestly declares the extension is turned away at the binding, before any
	// signature work. The gate at stage 5 catches one that does not declare it.
	if b.spec != SpecVersion {
		return b, core.Deny(ref, "proxy: %q is %q, want %q", MetaSpec, b.spec, SpecVersion)
	}

	// arguments: absent means no arguments, which §3.3's closed-world rules
	// then adjudicate against the leaf's constraint map like any other shape.
	b.args = map[string]any{}
	if len(rawArgs) > 0 && string(rawArgs) != "null" {
		// Before the decode, because the decode is what destroys the evidence.
		// §7 step 7f binds an invocation to its PoP by canonical bytes, and
		// RFC 8785 canonicalizes numbers through IEEE 754 doubles — so two
		// distinct integers above 2^53 produce the same canonical form and
		// step 7f cannot tell them apart. warden forwards the client's
		// original bytes upstream, so accepting one would let the server act
		// on a value the PoP never committed to and no constraint ever
		// checked. Refusing the ambiguity is the only reading under which
		// "the args the constraints are checked against are the request's
		// args" stays true. See jcs.CheckNumbers.
		if err := jcs.CheckNumbers(rawArgs); err != nil {
			return b, core.Deny("§7 step 7f", "proxy: params.arguments: %w", err)
		}
		if err := json.Unmarshal(rawArgs, &b.args); err != nil {
			return b, core.Deny(ref, "proxy: params.arguments is not a JSON object: %w", err)
		}
	}
	return b, nil
}

// --- the unverified payload pass -------------------------------------------

// chainFacts is what one pass over the chain's payloads yields. Read the
// INVARIANT in Decide before adding a field: everything here is unverified.
type chainFacts struct {
	rootJTI, leafJTI string
	depth, maxDepth  *int

	// invocationConstraints is true when ANY token in the chain carries the
	// §2.4 member. Any, not just the leaf: §7 step 4p2 pins an argument key set
	// into every descendant, but the extension member has no such rule, so a
	// restriction an ancestor intended is only visible by looking at it.
	invocationConstraints bool
}

// scanChain decodes each token's payload once and reads the few members the
// audit record and the stage-5 gate need. Signatures are not checked and are
// not the point: a token that lies here can only cause its own call to be
// denied or its own audit record to carry a jti it does not own.
//
// Errors are swallowed rather than returned. A payload this cannot decode is a
// payload aat.Verify is about to reject with a far better message, and turning
// a scan failure into the reported denial would put an unverified parse ahead
// of the verification it is supposed to be subordinate to.
func scanChain(chain []string) chainFacts {
	var f chainFacts
	for i, compact := range chain {
		var probe struct {
			JTI      string `json:"jti"`
			Depth    *int   `json:"del_depth"`
			MaxDepth *int   `json:"del_max_depth"`
			Details  []struct {
				InvocationConstraints json.RawMessage `json:"invocation_constraints"`
			} `json:"authorization_details"`
		}
		if err := decodePayload(compact, &probe); err != nil {
			continue
		}
		for _, det := range probe.Details {
			if len(det.InvocationConstraints) > 0 {
				f.invocationConstraints = true
			}
		}
		if i == 0 {
			f.rootJTI = probe.JTI
		}
		if i == len(chain)-1 {
			f.leafJTI = probe.JTI
			f.depth, f.maxDepth = probe.Depth, probe.MaxDepth
		}
	}
	return f
}

func decodePayload(compact string, v any) error {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return errors.New("not a JWS compact serialization")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}

// --- the wire error --------------------------------------------------------

// rpcError renders a JSON-RPC 2.0 error response for id.
//
// The client must see a refusal. A dropped message or a closed pipe is
// indistinguishable from the upstream hanging, and an agent that cannot tell a
// denial from a hang cannot adapt to it — it retries, which is the behaviour
// ARCHITECTURE §3.2 wants a machine-readable code to prevent.
func rpcError(id json.RawMessage, code int, message string, data map[string]string) []byte {
	var buf strings.Builder
	buf.WriteString(`{"jsonrpc":"2.0","id":`)
	buf.Write(id)
	buf.WriteString(`,"error":{"code":`)
	buf.WriteString(strconv.Itoa(code))
	buf.WriteString(`,"message":`)
	writeJSONString(&buf, message)
	if len(data) > 0 {
		buf.WriteString(`,"data":{`)
		first := true
		// Fixed key order so the response is byte-stable across runs; the
		// data object is small and warden-defined, so this is cheaper and
		// more predictable than a map marshal.
		for _, k := range []string{"stage", "ref"} {
			v, ok := data[k]
			if !ok {
				continue
			}
			if !first {
				buf.WriteByte(',')
			}
			first = false
			writeJSONString(&buf, k)
			buf.WriteByte(':')
			writeJSONString(&buf, v)
		}
		buf.WriteString(`}`)
	}
	buf.WriteString(`}}`)
	return []byte(buf.String())
}

func writeJSONString(w *strings.Builder, s string) {
	b, _ := json.Marshal(s)
	w.Write(b)
}

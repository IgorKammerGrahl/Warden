package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/igorkg/warden/internal/aat/aattest"
	"github.com/igorkg/warden/internal/audit"
)

var b64 = base64.RawURLEncoding

func TestFixtureSpecVersionMatches(t *testing.T) {
	if aattest.SpecVersion != SpecVersion {
		t.Fatalf("aattest.SpecVersion = %q, proxy.SpecVersion = %q; the fixture "+
			"would bind a spec the proxy rejects", aattest.SpecVersion, SpecVersion)
	}
}

func enforcer(f *aattest.Fixture) *Enforcer {
	return &Enforcer{Verifier: f.Verifier()}
}

func rawArgs(t testing.TB, args map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("Marshal args: %v", err)
	}
	return b
}

// TestDecidePermits is the milestone's exit criterion at the pipeline level: a
// three-token chain authorizes a permitted call.
func TestDecidePermits(t *testing.T) {
	f := aattest.New(t, 3)
	d := enforcer(f).Decide(aattest.Read, rawArgs(t, aattest.Allowed),
		f.Meta(t, aattest.Read, aattest.Allowed))
	if !d.allow {
		t.Fatalf("Decide denied a permitted call at %s/%s: %v", d.stage, d.ref, d.trace)
	}

	// Every stage that ran said so, and the record can name the chain.
	var stages []string
	for _, s := range d.trace {
		stages = append(stages, s.Stage)
		if s.Ref == "" {
			t.Errorf("trace step %q carries no ref", s.Stage)
		}
	}
	want := []string{"bind", "verify", "capability", "pop", "extensions"}
	if strings.Join(stages, ",") != strings.Join(want, ",") {
		t.Errorf("trace stages = %v, want %v", stages, want)
	}
	if d.chain.RootJTI == "" || d.chain.LeafJTI == "" || d.chain.Tokens != 3 {
		t.Errorf("chain facts = %+v, want a root jti, a leaf jti and 3 tokens", d.chain)
	}
	if d.chain.Depth == nil || *d.chain.Depth != 2 {
		t.Errorf("chain depth = %v, want 2", d.chain.Depth)
	}
	if d.pop.JTI == "" {
		t.Errorf("pop jti is empty; a permit should record what it verified")
	}
}

func TestDecidePermitsAtEveryDepth(t *testing.T) {
	for _, depth := range []int{1, 2, 3, 5, 8} {
		f := aattest.New(t, depth)
		d := enforcer(f).Decide(aattest.Read, rawArgs(t, aattest.Allowed),
			f.Meta(t, aattest.Read, aattest.Allowed))
		if !d.allow {
			t.Errorf("depth %d: denied at %s/%s", depth, d.stage, d.ref)
		}
	}
}

// denied runs one call and requires a DENY that names a clause.
func denied(t *testing.T, e *Enforcer, tool string, args json.RawMessage,
	meta map[string]json.RawMessage, wantRef string) *decision {
	t.Helper()
	d := e.Decide(tool, args, meta)
	if d.allow {
		t.Fatalf("Decide permitted; want DENY citing %q", wantRef)
	}
	if d.ref == "" {
		t.Fatalf("DENY at stage %q carries no ref; the trace could not explain it", d.stage)
	}
	if !strings.Contains(d.ref, wantRef) {
		t.Errorf("DENY ref = %q, want one containing %q (trace: %+v)", d.ref, wantRef, d.trace)
	}
	last := d.trace[len(d.trace)-1]
	if last.Outcome != "deny" || last.Ref != d.ref {
		t.Errorf("last trace step = %+v, want the denying step carrying ref %q", last, d.ref)
	}
	if last.Detail == "" {
		t.Errorf("denying step %+v carries no detail", last)
	}
	return d
}

// TestDecideDeniesOutOfAuthority is the other half of the exit criterion: the
// leaf may read one file, and the call asks for another.
func TestDecideDeniesOutOfAuthority(t *testing.T) {
	f := aattest.New(t, 3)
	d := denied(t, enforcer(f), aattest.Read, rawArgs(t, aattest.OutOfAuthority),
		f.Meta(t, aattest.Read, aattest.OutOfAuthority), "§3.4")
	// The denial still names the chain it came from. A DENY that cannot say
	// which chain produced it is the failure ARCHITECTURE §6 exists to prevent.
	if d.chain.RootJTI == "" || d.chain.LeafJTI == "" {
		t.Errorf("denied call recorded no chain identity: %+v", d.chain)
	}
}

// TestDecideDeniesUnauthorizedTool: list_dir is the root's alone.
func TestDecideDeniesUnauthorizedTool(t *testing.T) {
	f := aattest.New(t, 3)
	args := map[string]any{}
	denied(t, enforcer(f), aattest.List, rawArgs(t, args),
		f.Meta(t, aattest.List, args), "§7 step 6b")
}

// TestBindFailClosed covers every way the §3.1 transport binding can be absent
// or malformed. Each one denies, and each one says which clause it denied
// under. None of them reaches a signature verification.
func TestBindFailClosed(t *testing.T) {
	f := aattest.New(t, 3)
	good := func() map[string]json.RawMessage { return f.Meta(t, aattest.Read, aattest.Allowed) }

	without := func(key string) map[string]json.RawMessage {
		m := good()
		delete(m, key)
		return m
	}
	with := func(key, raw string) map[string]json.RawMessage {
		m := good()
		m[key] = json.RawMessage(raw)
		return m
	}

	cases := []struct {
		name string
		args json.RawMessage
		meta map[string]json.RawMessage
	}{
		{"no _meta at all", rawArgs(t, aattest.Allowed), nil},
		{"empty _meta", rawArgs(t, aattest.Allowed), map[string]json.RawMessage{}},
		{"no chain key", rawArgs(t, aattest.Allowed), without(MetaChain)},
		{"no pop key", rawArgs(t, aattest.Allowed), without(MetaPoP)},
		{"no spec key", rawArgs(t, aattest.Allowed), without(MetaSpec)},
		{"chain is a string, not an array", rawArgs(t, aattest.Allowed), with(MetaChain, `"a.b.c"`)},
		{"chain is an array of objects", rawArgs(t, aattest.Allowed), with(MetaChain, `[{"jwt":"a.b.c"}]`)},
		{"chain is empty", rawArgs(t, aattest.Allowed), with(MetaChain, `[]`)},
		{"chain holds an empty token", rawArgs(t, aattest.Allowed), with(MetaChain, `["a.b.c",""]`)},
		{"chain is null", rawArgs(t, aattest.Allowed), with(MetaChain, `null`)},
		{"pop is an object", rawArgs(t, aattest.Allowed), with(MetaPoP, `{"jwt":"a.b.c"}`)},
		{"pop is empty", rawArgs(t, aattest.Allowed), with(MetaPoP, `""`)},
		{"spec is a different draft", rawArgs(t, aattest.Allowed),
			with(MetaSpec, `"draft-niyikiza-oauth-attenuating-agent-tokens-02"`)},
		{"spec carries the extension profile label", rawArgs(t, aattest.Allowed),
			with(MetaSpec, `"draft-niyikiza-oauth-attenuating-agent-tokens-01+dev.warden.invocation_constraints"`)},
		{"spec is a number", rawArgs(t, aattest.Allowed), with(MetaSpec, `1`)},
		{"arguments are an array", json.RawMessage(`[1,2,3]`), good()},
		{"arguments are a bare string", json.RawMessage(`"hello"`), good()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			denied(t, enforcer(f), aattest.Read, tc.args, tc.meta, "ARCHITECTURE §3.1")
		})
	}
}

// TestBindDeniesAmbiguousNumbers is the §7 step 7f guard: an integer above 2^53
// canonicalizes to a different value, so the PoP could not have committed to
// the value the upstream would receive.
func TestBindDeniesAmbiguousNumbers(t *testing.T) {
	f := aattest.New(t, 3)
	args := json.RawMessage(`{"path":"/data/q3.pdf","mode":"r","offset":9007199254740993}`)
	denied(t, enforcer(f), aattest.Read, args, f.Meta(t, aattest.Read, aattest.Allowed), "§7 step 7f")
}

// TestDecideDeniesMalformedChain: a token that is not a JWS at all, and a token
// whose signature has been flipped. Both fail-closed inside §7.
func TestDecideDeniesMalformedChain(t *testing.T) {
	f := aattest.New(t, 3)

	t.Run("not a JWS", func(t *testing.T) {
		m := f.Meta(t, aattest.Read, aattest.Allowed)
		m[MetaChain] = json.RawMessage(`["not-a-jwt","also-not"]`)
		denied(t, enforcer(f), aattest.Read, rawArgs(t, aattest.Allowed), m, "§7")
	})

	t.Run("tampered signature", func(t *testing.T) {
		m := f.Meta(t, aattest.Read, aattest.Allowed)
		chain := append([]string(nil), f.Chain...)
		leaf := []byte(chain[len(chain)-1])
		leaf[len(leaf)-1] ^= 0x01 // flip a bit of the leaf's signature
		chain[len(chain)-1] = string(leaf)
		b, err := json.Marshal(chain)
		if err != nil {
			t.Fatal(err)
		}
		m[MetaChain] = b
		denied(t, enforcer(f), aattest.Read, rawArgs(t, aattest.Allowed), m, "§7")
	})
}

// TestDecideDeniesUnparseablePoP and its siblings: the PoP is where a valid
// chain still fails to authorize this particular call.
func TestDecideDeniesPoP(t *testing.T) {
	f := aattest.New(t, 3)

	t.Run("unparseable", func(t *testing.T) {
		m := f.Meta(t, aattest.Read, aattest.Allowed)
		m[MetaPoP] = json.RawMessage(`"not.a.pop"`)
		denied(t, enforcer(f), aattest.Read, rawArgs(t, aattest.Allowed), m, "§")
	})

	t.Run("committed to different args", func(t *testing.T) {
		// A root-only chain, because its one_of admits three files and the
		// leaf of a delegated chain admits exactly one. Both files satisfy
		// the constraints, so nothing else can be what refuses this: the
		// only difference is that the PoP committed to the other one, and
		// §7 step 7f compares canonical bytes to notice.
		root := aattest.New(t, 1)
		m := root.Meta(t, aattest.Read, aattest.Allowed)
		other := map[string]any{"path": "/data/q4.pdf", "mode": "r"}
		denied(t, enforcer(root), aattest.Read, rawArgs(t, other), m, "§7 step 7f")
	})

	t.Run("committed to a different tool", func(t *testing.T) {
		m := map[string]json.RawMessage{
			MetaChain: mustMarshal(t, f.Chain),
			MetaPoP:   mustMarshal(t, f.PoP(t, aattest.List, aattest.Allowed)),
			MetaSpec:  mustMarshal(t, SpecVersion),
		}
		denied(t, enforcer(f), aattest.Read, rawArgs(t, aattest.Allowed), m, "§7 step 7e")
	})

	t.Run("outside the iat window", func(t *testing.T) {
		e := enforcer(f)
		// §7 step 7g is stateless, and it is the only replay resistance
		// warden has: the jti set is deferred. +1000s is past the ±30s
		// tolerance and still inside every token's exp, so the PoP is what
		// fails and not the chain.
		e.Verifier.Now = func() int64 { return aattest.Now + 1000 }
		denied(t, e, aattest.Read, rawArgs(t, aattest.Allowed),
			f.Meta(t, aattest.Read, aattest.Allowed), "§7 step 7g")
	})
}

// TestCapabilityPrecedesPoP pins the §5.3 ordering that makes the pipeline
// sound: chain verification, steps 1 through 6, completes before the PoP is
// evaluated, so a valid PoP over an invalid chain cannot authorize.
//
// The observable consequence is that a call whose args violate the leaf's
// constraints is refused by §3.4 even though its PoP would also have failed
// step 7f. If this ever starts reporting 7f, the two halves have swapped and a
// PoP is being trusted ahead of the authority it is supposed to prove
// possession of.
func TestCapabilityPrecedesPoP(t *testing.T) {
	f := aattest.New(t, 3)
	other := map[string]any{"path": "/data/q4.pdf", "mode": "r"}
	d := denied(t, enforcer(f), aattest.Read, rawArgs(t, other),
		f.Meta(t, aattest.Read, aattest.Allowed), "§3.4")
	if strings.Contains(d.ref, "§7 step 7") {
		t.Errorf("ref = %q: the PoP was evaluated before the chain's own "+
			"capability check, which §5.3 forbids", d.ref)
	}
}

// TestDecideDeniesInvocationConstraints is the §2.4 gate: a chain carrying the
// extension member is rejected, never ignored, while the extension is off.
func TestDecideDeniesInvocationConstraints(t *testing.T) {
	f := aattest.New(t, 3)
	m := f.Meta(t, aattest.Read, aattest.Allowed)

	// Splice the member into the leaf's payload without re-signing. That the
	// signature no longer verifies is the point of the second half of this
	// test: §3.2 short-circuits on the FIRST failure in pipeline order, and
	// the gate sits behind verification, so the signature must be what is
	// reported even though the gate would also have fired.
	spliced := spliceLeafPayload(t, f.Chain, `"invocation_constraints":{"dev.warden/budget":{"limit":5}},`)
	chain := append([]string(nil), f.Chain...)
	chain[len(chain)-1] = spliced
	m[MetaChain] = mustMarshal(t, chain)

	d := denied(t, enforcer(f), aattest.Read, rawArgs(t, aattest.Allowed), m, "§7")
	if strings.Contains(d.ref, "§2.4") {
		t.Errorf("ref = %q: the gate reported before the signature check that "+
			"precedes it in the §3.2 pipeline", d.ref)
	}
	if d.stage != "verify" {
		t.Errorf("stage = %q, want verify", d.stage)
	}
}

func mustMarshal(t testing.TB, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

// spliceLeafPayload injects raw JSON into the leaf token's payload object,
// leaving the signature stale.
func spliceLeafPayload(t testing.TB, chain []string, inject string) string {
	t.Helper()
	leaf := chain[len(chain)-1]
	parts := strings.Split(leaf, ".")
	if len(parts) != 3 {
		t.Fatalf("leaf is not a JWS compact serialization")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode leaf payload: %v", err)
	}
	if payload[0] != '{' {
		t.Fatalf("leaf payload is not a JSON object")
	}
	spliced := append([]byte("{"+inject), payload[1:]...)
	return parts[0] + "." + b64.EncodeToString(spliced) + "." + parts[2]
}

// --- the wire error --------------------------------------------------------

func TestRPCErrorShape(t *testing.T) {
	raw := rpcError(json.RawMessage(`7`), ErrCodeDenied, "warden: denied",
		map[string]string{"stage": "verify", "ref": "§7 step 4c, I1"})

	var got struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int               `json:"code"`
			Message string            `json:"message"`
			Data    map[string]string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the denial is not valid JSON-RPC: %v (%s)", err, raw)
	}
	if got.JSONRPC != "2.0" || string(got.ID) != "7" {
		t.Errorf("envelope = %s, want jsonrpc 2.0 and id 7", raw)
	}
	if got.Error.Code != ErrCodeDenied {
		t.Errorf("code = %d, want %d", got.Error.Code, ErrCodeDenied)
	}
	if got.Error.Data["ref"] != "§7 step 4c, I1" || got.Error.Data["stage"] != "verify" {
		t.Errorf("data = %v, want the stage and the ref", got.Error.Data)
	}
	// -32001 and -32002 are both inside JSON-RPC 2.0's implementation-defined
	// server-error range, so neither collides with a method-level code.
	for _, code := range []int{ErrCodeDenied, ErrCodeAuditUnavailable} {
		if code < -32099 || code > -32000 {
			t.Errorf("code %d is outside the -32099..-32000 reserved range", code)
		}
	}
	if ErrCodeDenied == ErrCodeAuditUnavailable {
		t.Error("an authorization denial and a broken audit sink share a code; " +
			"a client cannot tell a policy decision from a full disk")
	}
}

// TestRPCErrorIDsAreEchoedVerbatim: JSON-RPC ids are strings, numbers or null,
// and a response that changes the type does not correlate.
func TestRPCErrorIDsAreEchoedVerbatim(t *testing.T) {
	for _, id := range []string{`7`, `"abc"`, `null`, `"id with \"quotes\""`} {
		raw := rpcError(json.RawMessage(id), ErrCodeDenied, "denied", nil)
		var got struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("id %s produced invalid JSON: %v (%s)", id, err, raw)
		}
		if string(got.ID) != id {
			t.Errorf("id %s came back as %s", id, got.ID)
		}
	}
}

// --- the audit latch -------------------------------------------------------

type breakingWriter struct{ n int }

func (b *breakingWriter) Write(p []byte) (int, error) {
	b.n++
	if b.n > 1 {
		return 0, errors.New("no space left on device")
	}
	return len(p), nil
}

// TestAuditLatchRefusesEverythingAfterAWriteFailure. The audit sink is checked
// before any signature work, so a latched proxy denies a perfectly valid chain,
// under a code that is not the authorization code, and forwards nothing.
func TestAuditLatchRefusesEverythingAfterAWriteFailure(t *testing.T) {
	f := aattest.New(t, 3)
	aw := audit.NewWriter(&breakingWriter{})

	// Two successful decisions' worth of records; the second write fails.
	for i := 0; i < 2; i++ {
		if err := aw.Write(audit.Record{Decision: audit.DecisionPermit}, audit.Timing{}); err != nil {
			if i == 0 {
				t.Fatalf("the first audit write failed: %v", err)
			}
		}
	}
	if aw.Err() == nil {
		t.Fatal("the writer did not latch after a failed write")
	}

	var upstream, client bytes.Buffer
	p := &Proxy{
		ClientOut: &client,
		ServerIn:  &upstream,
		Audit:     aw,
		Log:       log.New(io.Discard, "", 0),
		Enforce:   enforcer(f),
	}
	c := &call{key: "9", tool: aattest.Read, args: rawArgs(t, aattest.Allowed),
		rawMeta: f.Meta(t, aattest.Read, aattest.Allowed)}
	if p.authorize(c) {
		t.Fatal("a latched proxy authorized a call it could not record")
	}
	if upstream.Len() != 0 {
		t.Errorf("the call reached the upstream anyway: %s", upstream.Bytes())
	}
	if c.dec != nil {
		t.Error("the pipeline ran; the latch is supposed to short-circuit ahead of " +
			"every signature verification, which is also what keeps a valid and an " +
			"invalid chain indistinguishable in time when the outcome is the same")
	}

	var got struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(client.Bytes()), &got); err != nil {
		t.Fatalf("client did not receive valid JSON-RPC: %v (%s)", err, client.Bytes())
	}
	if got.Error.Code != ErrCodeAuditUnavailable {
		t.Errorf("client saw code %d, want %d: a full disk must not look like an "+
			"authorization decision", got.Error.Code, ErrCodeAuditUnavailable)
	}

	// And it never clears.
	if aw.Err() == nil {
		t.Error("the latch cleared; recovery is an operator action, not a retry")
	}
}

// --- the relay, enforcing --------------------------------------------------

func toolCall(t testing.TB, id string, tool string, args map[string]any,
	meta map[string]json.RawMessage) string {
	t.Helper()
	params := map[string]any{"name": tool, "arguments": args}
	if meta != nil {
		params["_meta"] = meta
	}
	msg := map[string]any{"jsonrpc": "2.0", "method": "tools/call", "params": params}
	if id != "" {
		msg["id"] = json.RawMessage(id)
	}
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	return string(b) + "\n"
}

// TestEnforcingRelayPermits: an authorized call reaches the upstream unchanged
// and its response reaches the client unchanged.
func TestEnforcingRelayPermits(t *testing.T) {
	f := aattest.New(t, 3)
	r := newRigWith(t, enforcer(f))

	req := toolCall(t, `1`, aattest.Read, aattest.Allowed, f.Meta(t, aattest.Read, aattest.Allowed))
	r.send(t, req)
	if got := r.forwarded(t); got != strings.TrimSuffix(req, "\n") {
		t.Errorf("forwarded %s, want the client's own bytes %s", got, req)
	}
	r.reply(t, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`+"\n")

	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	recs := r.records(t)
	if len(recs) != 1 || recs[0].Decision != audit.DecisionPermit {
		t.Fatalf("records = %+v, want one permit", recs)
	}
	if recs[0].Chain.RootJTI == "" || recs[0].Chain.LeafJTI == "" {
		t.Errorf("permit recorded no chain identity: %+v", recs[0].Chain)
	}
}

// TestEnforcingRelayDenies is the milestone's exit criterion at the wire: an
// out-of-authority call never reaches the upstream, the client receives a
// JSON-RPC error rather than a dropped message, and the audit trace names the
// exact clause that fired.
func TestEnforcingRelayDenies(t *testing.T) {
	f := aattest.New(t, 3)
	r := newRigWith(t, enforcer(f))

	r.send(t, toolCall(t, `1`, aattest.Read, aattest.OutOfAuthority,
		f.Meta(t, aattest.Read, aattest.OutOfAuthority)))
	// A permitted call after it, so that "nothing was forwarded" is proved by
	// the next message arriving rather than by a timeout.
	r.send(t, toolCall(t, `2`, aattest.Read, aattest.Allowed,
		f.Meta(t, aattest.Read, aattest.Allowed)))

	var fwd struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal([]byte(r.forwarded(t)), &fwd); err != nil {
		t.Fatalf("forwarded message is not JSON: %v", err)
	}
	if string(fwd.ID) != "2" {
		t.Fatalf("the upstream received id %s; the denied call was forwarded", fwd.ID)
	}
	r.reply(t, `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`+"\n")

	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The client saw a refusal, not a hang.
	var resp struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code    int               `json:"code"`
			Message string            `json:"message"`
			Data    map[string]string `json:"data"`
		} `json:"error"`
	}
	lines := splitLines(r.clientOut.String())
	if len(lines) != 2 {
		t.Fatalf("client received %d messages, want the denial and the reply: %q", len(lines), lines)
	}
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("the denial is not valid JSON-RPC: %v (%s)", err, lines[0])
	}
	if resp.Error == nil || resp.Error.Code != ErrCodeDenied || string(resp.ID) != "1" {
		t.Fatalf("client received %s, want a -32001 error on id 1", lines[0])
	}
	if resp.Error.Data["ref"] == "" || resp.Error.Data["stage"] == "" {
		t.Errorf("the denial carries no stage/ref: %s", lines[0])
	}
	// The constraint's own values are the parent's policy, not the child's to
	// read back out of a denial.
	if strings.Contains(lines[0], "/data/q3.pdf") || strings.Contains(lines[0], "one_of") {
		t.Errorf("the denial leaks the constraint it refused under: %s", lines[0])
	}

	recs := r.records(t)
	if len(recs) != 2 {
		t.Fatalf("records = %d, want the deny and the permit", len(recs))
	}
	deny := recs[0]
	if deny.Decision != audit.DecisionDeny {
		t.Fatalf("first record = %q, want deny", deny.Decision)
	}
	last := deny.Trace[len(deny.Trace)-1]
	if last.Outcome != "deny" || last.Ref == "" {
		t.Fatalf("the deny trace does not end at a cited refusal: %+v", deny.Trace)
	}
	if !strings.Contains(last.Ref, "§3.4") {
		t.Errorf("trace ref = %q, want the §3.4 constraint that refused", last.Ref)
	}
	if !strings.Contains(last.Detail, "path") {
		t.Errorf("trace detail = %q, want the argument named", last.Detail)
	}
	if deny.Chain.RootJTI == "" || deny.Chain.LeafJTI == "" {
		t.Errorf("the deny record cannot say which chain produced it: %+v", deny.Chain)
	}
	// The client's version and the log's version agree on the citation.
	if resp.Error.Data["ref"] != last.Ref {
		t.Errorf("client saw ref %q, the audit recorded %q", resp.Error.Data["ref"], last.Ref)
	}
}

// TestNotificationIsNotABypass is the sharpest hole in a proxy built around
// correlated requests: a tools/call with no id has no response to pair with, so
// a pipeline that keys work off the pending-request map never sees it and
// forwards it unverified. The caller does not need the response for the side
// effect to land — that is the whole point of sending it as a notification.
//
// Enforcing, it must be denied and dropped. There is nowhere to put a JSON-RPC
// error, since JSON-RPC defines no response to a notification, so the evidence
// is that the upstream never received it and the audit says why.
func TestNotificationIsNotABypass(t *testing.T) {
	f := aattest.New(t, 3)
	r := newRigWith(t, enforcer(f))

	// No id, and no binding at all: the shape an attacker would reach for.
	r.send(t, toolCall(t, "", aattest.Read, aattest.OutOfAuthority, nil))
	// A well-formed authorized call behind it, so the assertion below is that
	// the upstream's FIRST message is this one, not that nothing ever arrived.
	r.send(t, toolCall(t, `9`, aattest.Read, aattest.Allowed,
		f.Meta(t, aattest.Read, aattest.Allowed)))

	var fwd struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal([]byte(r.forwarded(t)), &fwd); err != nil {
		t.Fatalf("forwarded message is not JSON: %v", err)
	}
	if string(fwd.ID) != "9" {
		t.Fatalf("the upstream received %s first: the unbound notification was forwarded, "+
			"and the tool ran with no chain behind it", fwd.ID)
	}
	r.reply(t, `{"jsonrpc":"2.0","id":9,"result":{"content":[]}}`+"\n")

	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	recs := r.records(t)
	if len(recs) != 2 || recs[0].Decision != audit.DecisionDeny {
		t.Fatalf("records = %+v, want the denied notification and the permit", recs)
	}
	if got := recs[0].Trace[len(recs[0].Trace)-1].Ref; !strings.Contains(got, "ARCHITECTURE §3.1") {
		t.Errorf("the notification was denied citing %q, want the absent binding", got)
	}
	// Invisible to the client either way, so it has to be visible to the operator.
	if !strings.Contains(r.stderr.String(), "notification") {
		t.Errorf("nothing on stderr explains the dropped notification: %q", r.stderr.String())
	}
}

// TestPassthroughStillIgnoresNotifications: the control measurement must be the
// same relay M1 measured, so passthrough keeps forwarding an id-less call and
// keeps not recording it.
func TestPassthroughStillIgnoresNotifications(t *testing.T) {
	f := aattest.New(t, 3)
	r := newRig(t)

	req := toolCall(t, "", aattest.Read, aattest.OutOfAuthority, nil)
	r.send(t, req)
	if got := r.forwarded(t); got != strings.TrimSuffix(req, "\n") {
		t.Errorf("passthrough forwarded %s, want the client's own bytes", got)
	}
	_ = f
	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if recs := r.records(t); len(recs) != 0 {
		t.Errorf("passthrough recorded %+v for an id-less call; M1 recorded none", recs)
	}
}

// TestEnforcingRefusesUnclassified is the general form of the batch bypass.
// The defect was never really about batches: inspect decoded into one struct,
// any failure returned nil, and nil meant "relay it", so every shape that
// failed that Unmarshal reached the upstream unauthorized. A batch was one.
// These are the others, and each is an ordinary tools/call with one member of
// the wrong JSON type — nothing a client has to work at.
//
// Two outcomes are correct here, and which one is correct is the point. A
// message warden cannot classify at all is refused at the frame with a null
// id, because its id is one of the things it could not read. A message it can
// classify as a tools/call whose _meta is merely the wrong shape reaches bind
// and is denied there on its own id, citing §3.1 — which is what ARCHITECTURE
// §3.1 asks for when it lists "an empty array" beside "_meta absent entirely".
func TestEnforcingRefusesUnclassified(t *testing.T) {
	for _, tc := range []struct {
		name, params string
		wantStage    string
		wantID       string
	}{
		{"params is a string", `"notanobject"`, "frame", "null"},
		{"params is an array", `[1,2]`, "frame", "null"},
		{"name is not a string", `{"name":123,"arguments":{}}`, "frame", "null"},
		{"top-level scalar", "", "frame", "null"},
		{"_meta is an array", `{"name":"read","arguments":{},"_meta":[]}`, "bind", "1"},
		{"_meta is a string", `{"name":"read","arguments":{},"_meta":"x"}`, "bind", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := aattest.New(t, 3)
			r := newRigWith(t, enforcer(f))

			msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + tc.params + "}"
			if tc.params == "" {
				msg = `"a bare string is valid JSON and is not a JSON-RPC message"`
			}
			r.send(t, msg+"\n")
			// A permitted call after it, so "nothing was forwarded" is proved
			// by the next message arriving rather than by a timeout.
			r.send(t, toolCall(t, `2`, aattest.Read, aattest.Allowed,
				f.Meta(t, aattest.Read, aattest.Allowed)))

			var fwd struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(r.forwarded(t)), &fwd); err != nil {
				t.Fatalf("forwarded message is not JSON: %v", err)
			}
			if string(fwd.ID) != "2" {
				t.Fatalf("the upstream received id %s; the unclassified message was forwarded", fwd.ID)
			}
			r.reply(t, `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`+"\n")
			if err := r.shutdown(t); err != nil {
				t.Fatalf("Run: %v", err)
			}

			var resp struct {
				ID    json.RawMessage `json:"id"`
				Error *struct {
					Code int               `json:"code"`
					Data map[string]string `json:"data"`
				} `json:"error"`
			}
			lines := splitLines(r.clientOut.String())
			if len(lines) != 2 {
				t.Fatalf("client received %d messages, want the denial and the reply: %q", len(lines), lines)
			}
			if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
				t.Fatalf("the denial is not valid JSON-RPC: %v (%s)", err, lines[0])
			}
			if resp.Error == nil || resp.Error.Code != ErrCodeDenied {
				t.Fatalf("client received %s, want a -32001 denial", lines[0])
			}
			if string(resp.ID) != tc.wantID {
				t.Errorf("denial carries id %s, want %s", resp.ID, tc.wantID)
			}
			if resp.Error.Data["stage"] != tc.wantStage {
				t.Errorf("denial fired at stage %q, want %q", resp.Error.Data["stage"], tc.wantStage)
			}
			if recs := r.records(t); len(recs) != 2 || recs[0].Decision != audit.DecisionDeny {
				t.Errorf("audit does not hold the denial: %+v", recs)
			}
		})
	}
}

// TestEnforcingRefusesBatch closes a bypass a real client found. inspect
// reads one JSON-RPC object; a top-level array parsed as neither a tools/call
// nor an error, so before the frame check a call wrapped in a one-element
// batch was forwarded upstream having never been authorized. The call inside
// this batch is one the enforcer would permit, which is the point: the
// refusal has to come from the frame, not from the authority.
func TestEnforcingRefusesBatch(t *testing.T) {
	f := aattest.New(t, 3)
	r := newRigWith(t, enforcer(f))

	inner := strings.TrimSuffix(toolCall(t, `1`, aattest.Read, aattest.Allowed,
		f.Meta(t, aattest.Read, aattest.Allowed)), "\n")
	r.send(t, "["+inner+"]\n")
	// A permitted call after it, so "the batch was not forwarded" is proved
	// by the next message arriving rather than by a timeout.
	r.send(t, toolCall(t, `2`, aattest.Read, aattest.Allowed,
		f.Meta(t, aattest.Read, aattest.Allowed)))

	fwd := r.forwarded(t)
	if strings.HasPrefix(strings.TrimSpace(fwd), "[") {
		t.Fatalf("the upstream received a batch: %s", fwd)
	}
	var got struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal([]byte(fwd), &got); err != nil {
		t.Fatalf("forwarded message is not JSON: %v", err)
	}
	if string(got.ID) != "2" {
		t.Fatalf("the upstream received id %s; the batch was forwarded", got.ID)
	}
	r.reply(t, `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`+"\n")

	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The client saw a refusal on a null id: JSON-RPC 2.0 §6 answers a
	// rejected batch with one error object, and warden never opened the array
	// to learn an element id.
	var resp struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code int               `json:"code"`
			Data map[string]string `json:"data"`
		} `json:"error"`
	}
	lines := splitLines(r.clientOut.String())
	if len(lines) != 2 {
		t.Fatalf("client received %d messages, want the denial and the reply: %q", len(lines), lines)
	}
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("the denial is not valid JSON-RPC: %v (%s)", err, lines[0])
	}
	if resp.Error == nil || resp.Error.Code != ErrCodeDenied || string(resp.ID) != "null" {
		t.Fatalf("client received %s, want a -32001 error on a null id", lines[0])
	}
	if resp.Error.Data["stage"] != "frame" || resp.Error.Data["ref"] == "" {
		t.Errorf("the denial does not name the frame check: %s", lines[0])
	}

	// A refusal warden does not record is a refusal an operator cannot see.
	recs := r.records(t)
	if len(recs) != 2 {
		t.Fatalf("audit holds %d records, want the batch denial and the permit", len(recs))
	}
	if recs[0].Decision != audit.DecisionDeny {
		t.Errorf("the batch was recorded as %q, want deny", recs[0].Decision)
	}
	if recs[0].Request.Tool != "" {
		t.Errorf("the record names tool %q; warden refused the frame without "+
			"opening the array, so it knows of no tool", recs[0].Request.Tool)
	}
	if len(recs[0].Trace) == 0 || recs[0].Trace[0].Stage != "frame" ||
		recs[0].Trace[0].Ref == "" || recs[0].Trace[0].Detail == "" {
		t.Errorf("the batch denial trace does not explain itself: %+v", recs[0].Trace)
	}
}

// TestPassthroughForwardsBatch pins the deliberate half of the split above.
// §3.1 makes M1 the one mode that does not shape traffic, and there is no
// enforcement in it to bypass, so a batch is relayed byte for byte like
// anything else warden does not recognize.
func TestPassthroughForwardsBatch(t *testing.T) {
	r := newRig(t)
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}]`
	r.send(t, batch+"\n")

	if fwd := r.forwarded(t); fwd != batch {
		t.Fatalf("passthrough altered a batch:\n got %s\nwant %s", fwd, batch)
	}
	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestEnforcingRefusesUnauthorizableMethod closes the shakedown-2 bypass. It
// is the same class as the batch: a shape warden could not authorize was
// forwarded anyway, because inspect's "this is not a tools/call" was being
// read as "this is safe to relay".
//
// A real server made it concrete. @modelcontextprotocol/server-memory
// publishes its whole knowledge graph twice — through the read_graph tool and
// at memory://knowledge-graph — so a capability that withholds read_graph
// withholds nothing: six denials at §7 step 6b, then one resources/read
// returned the graph with no decision and no audit record. §3.3 capabilities
// describe tools, so there was never anything to check that method against.
//
// The handshake and the discovery lists still relay; everything else is
// refused at the frame, on its own id, because warden read the method
// perfectly well and is refusing it, not failing to parse it.
func TestEnforcingRefusesUnauthorizableMethod(t *testing.T) {
	for _, tc := range []struct {
		name, msg string
		wantRelay bool
		wantID    string
	}{
		{"resources/read", `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"memory://knowledge-graph"}}`, false, `1`},
		{"prompts/get", `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"p"}}`, false, `1`},
		{"resources/subscribe", `{"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"file:///x"}}`, false, `1`},
		{"completion/complete", `{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{}}`, false, `1`},
		{"a method nobody has invented yet", `{"jsonrpc":"2.0","id":1,"method":"memory/dump","params":{}}`, false, `1`},
		{"no method and no result", `{"jsonrpc":"2.0","id":1,"params":{}}`, false, `null`},
		{"tools/list", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, true, ``},
		{"resources/list", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, true, ``},
		{"initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, true, ``},
		{"initialized notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, true, ``},
		// A response to a server-initiated request carries no method. The
		// filesystem server's roots/list produced these for real.
		{"response to roots/list", `{"jsonrpc":"2.0","id":7,"result":{"roots":[]}}`, true, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := aattest.New(t, 3)
			r := newRigWith(t, enforcer(f))

			r.send(t, tc.msg+"\n")
			// Drained before the next send: the pipes are unbuffered, so a
			// relayed message has to be read before the proxy can accept
			// another one.
			if tc.wantRelay {
				if got := r.forwarded(t); got != tc.msg {
					t.Fatalf("the upstream received %s, want the message relayed verbatim", got)
				}
			}
			// A permitted call after it, so "nothing was forwarded" is proved
			// by the next message arriving rather than by a timeout.
			r.send(t, toolCall(t, `2`, aattest.Read, aattest.Allowed,
				f.Meta(t, aattest.Read, aattest.Allowed)))

			var fwd struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(r.forwarded(t)), &fwd); err != nil {
				t.Fatalf("forwarded message is not JSON: %v", err)
			}
			if string(fwd.ID) != "2" {
				t.Fatalf("the upstream received id %s; the message was forwarded unauthorized", fwd.ID)
			}
			r.reply(t, `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}`+"\n")
			if err := r.shutdown(t); err != nil {
				t.Fatalf("Run: %v", err)
			}

			lines := splitLines(r.clientOut.String())
			if tc.wantRelay {
				if len(lines) != 1 {
					t.Fatalf("client received %d messages, want only the reply: %q", len(lines), lines)
				}
				if recs := r.records(t); len(recs) != 1 {
					t.Fatalf("audit holds %d records, want only the permitted call", len(recs))
				}
				return
			}

			var resp struct {
				ID    json.RawMessage `json:"id"`
				Error *struct {
					Code int               `json:"code"`
					Data map[string]string `json:"data"`
				} `json:"error"`
			}
			if len(lines) != 2 {
				t.Fatalf("client received %d messages, want the denial and the reply: %q", len(lines), lines)
			}
			if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
				t.Fatalf("the denial is not valid JSON-RPC: %v (%s)", err, lines[0])
			}
			if resp.Error == nil || resp.Error.Code != ErrCodeDenied {
				t.Fatalf("client received %s, want a -32001 denial", lines[0])
			}
			if resp.Error.Data["stage"] != "frame" {
				t.Errorf("denial fired at stage %q, want frame", resp.Error.Data["stage"])
			}
			// A method warden read is refused on its own id; a message whose
			// method it could not read is answered on null.
			if string(resp.ID) != tc.wantID {
				t.Errorf("denial carries id %s, want %s", resp.ID, tc.wantID)
			}
			if recs := r.records(t); len(recs) != 2 || recs[0].Decision != audit.DecisionDeny {
				t.Errorf("audit does not hold the denial: %+v", recs)
			}
		})
	}
}

// Package proxy relays MCP JSON-RPC between a client and one upstream server
// over stdio, auditing every tools/call.
//
// The proxy runs in exactly one of two modes, and Run refuses to start unless
// exactly one is configured.
//
// PassthroughOnly forwards every message and denies nothing: no call into
// aat.Verifier is reachable from this path. That is deliberate and load-bearing
// rather than a leftover — it is the control M4's enforcement overhead is
// measured against, so it must contain no authorization decision at all. A
// Verify call here whose result was discarded would still put Ed25519 work into
// the baseline and silently deflate the reported overhead.
//
// Enforce runs the ARCHITECTURE §3.2 pipeline before forwarding, and a call it
// refuses is never written upstream. The client is answered with a JSON-RPC
// error rather than a dropped message or a closed pipe: an agent that cannot
// distinguish a refusal from a hang retries instead of adapting.
package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/igorkg/warden/internal/audit"
)

// The ARCHITECTURE §3.1 transport binding: the chain and the PoP travel in the
// _meta object of the tools/call request params, under a reserved prefix.
const (
	MetaChain = "dev.warden/chain"
	MetaPoP   = "dev.warden/pop"
	MetaSpec  = "dev.warden/spec"
)

// SpecVersion is the pinned draft identifier (ARCHITECTURE §3.1). Passthrough
// records what arrived and compares nothing; enforcing, a mismatch is a denial
// at the binding stage, before any signature work.
const SpecVersion = "draft-niyikiza-oauth-attenuating-agent-tokens-01"

// Proxy relays one client to one upstream MCP server.
type Proxy struct {
	ClientIn  io.Reader // client -> proxy
	ClientOut io.Writer // proxy -> client. PROTOCOL BYTES ONLY.
	ServerIn  io.Writer // proxy -> upstream
	ServerOut io.Reader // upstream -> proxy

	Audit *audit.Writer
	Log   *log.Logger // diagnostics; must not be backed by ClientOut

	// PassthroughOnly relays without deciding. It is what lets M1's baseline
	// be re-measured on a binary that has enforcement compiled in, which is
	// the only reason the enforcement overhead figure means anything.
	PassthroughOnly bool

	// Enforce runs the §3.2 pipeline. Exactly one of this and
	// PassthroughOnly must be set; see Run.
	Enforce *Enforcer

	mu      sync.Mutex
	pending map[string]*call
	seq     uint64

	// outMu serializes writes to ClientOut. Both pumps write there once
	// denials exist — the relay pump forwards responses and the request pump
	// answers refusals — and two interleaved writes would splice two JSON
	// values into one unparseable line.
	outMu sync.Mutex
	outFr framer
}

// call is a tools/call awaiting its response.
type call struct {
	// key is the raw JSON-RPC id bytes as a string. That is the only thing
	// pairing a response to its request, and it is client-chosen, so it is
	// used verbatim rather than normalized: 1 and 1.0 are different keys
	// here because a client that sends both gets both back unchanged.
	key   string
	corr  string
	tool  string
	args  []byte
	meta  metaInfo
	t0    time.Time // first byte read from the client
	tSend time.Time // first byte written to upstream

	// rawMeta is params._meta, kept only until the decision is made and
	// then released: a chain is up to MAX_STACK_SIZE bytes and a pending
	// call has no further use for one.
	rawMeta map[string]json.RawMessage
	// dec is the §3.2 outcome, nil in passthrough.
	dec *decision
}

var (
	errNoMode = errors.New("proxy: neither PassthroughOnly nor Enforce is set; " +
		"a proxy with no mode would relay unauthorized calls, so it does not start")
	errBothModes = errors.New("proxy: PassthroughOnly and Enforce are both set; " +
		"passthrough is the unenforced control measurement and enforcing is the guardrail, " +
		"and a flag that can mean either silently means neither")
)

// Run relays in both directions until either side ends, then stops the other.
//
// Exactly one mode, checked here rather than defaulted: the default that reads
// as safe (enforce) turns a misconfigured operator into a broken deployment,
// and the default that reads as convenient (passthrough) turns one into an open
// proxy. Refusing to start is the only outcome that is wrong in neither
// direction.
func (p *Proxy) Run() error {
	switch {
	case p.PassthroughOnly && p.Enforce != nil:
		return errBothModes
	case !p.PassthroughOnly && p.Enforce == nil:
		return errNoMode
	}
	p.pending = make(map[string]*call)

	cr := newStampReader(p.ClientIn)
	sr := newStampReader(p.ServerOut)

	errc := make(chan error, 2)
	go func() { errc <- p.clientToServer(cr) }()
	go func() { errc <- p.serverToClient(sr) }()

	first := <-errc
	// Unblock the other direction. Closing upstream's stdin makes a healthy
	// server exit; closing the client pipe unblocks a read that is waiting
	// for a peer that has already gone. Both are pipes, so Go's poller
	// returns ErrClosed to the blocked Read rather than hanging.
	closeIf(p.ServerIn)
	closeIf(p.ClientIn)
	second := <-errc

	if p.Audit != nil {
		p.reportOrphans()
	}
	if first != nil {
		return first
	}
	return second
}

func closeIf(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}

// clientToServer forwards requests and records the ones that are tools/call.
func (p *Proxy) clientToServer(cr *stampReader) error {
	dec := json.NewDecoder(cr)
	var fr framer
	for {
		cr.arm()
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return p.endOfStream("client", err)
		}
		t0 := cr.firstByte()

		// Inspect a copy; forward the original bytes. Never the other way
		// round: re-serializing a decoded message reorders object members
		// and can reformat numbers, and in a project that carries a JCS
		// implementation precisely because those two things invalidate a
		// signature, forwarding the exact received bytes is a correctness
		// requirement, not a performance shortcut. Do not "clean this up"
		// into a decode/encode round trip.
		// THE RULE: in enforcing mode a message the proxy cannot fully
		// classify is denied, never forwarded. Absence of a positive
		// authorization is a denial, not a pass. inspect returns known=false
		// for bytes it cannot place, and that is the whole of the check —
		// there is deliberately no list of bad shapes to keep up to date,
		// because the batch bypass was exactly a shape nobody listed.
		c, known := p.inspect(raw, t0)
		if !known && p.Enforce != nil {
			p.denyUnclassified(raw, t0)
			continue
		}
		if c != nil && c.key == "" && p.PassthroughOnly {
			// A tools/call with no id has no response to pair with, so
			// passthrough has nothing to time and does not record it.
			// Enforcing does not get that luxury; see authorize.
			c = nil
		}

		if c != nil && p.Enforce != nil && !p.authorize(c) {
			// Refused. Never written upstream — that is the whole point —
			// and the client has already been answered and the record
			// already written by authorize.
			continue
		}

		// Registered before the write, not after. A fast upstream can have
		// its response decoded by the other pump before a post-write
		// registration lands, and that response would find no pending call
		// and go unaudited — a race that gets rarer, never absent, as the
		// upstream gets slower.
		if c != nil && c.key != "" {
			c.tSend = time.Now()
			p.mu.Lock()
			p.pending[c.key] = c
			p.mu.Unlock()
		}
		if err := fr.write(p.ServerIn, raw); err != nil {
			if c != nil && c.key != "" {
				p.mu.Lock()
				delete(p.pending, c.key)
				p.mu.Unlock()
			}
			return p.endOfStream("upstream-write", err)
		}
		if c != nil && c.key == "" {
			// An authorized tools/call notification. Nothing will come back
			// to close the record out, so it is closed here; the upstream
			// span is unmeasurable rather than zero, and is recorded as
			// zero with that stated in the trace.
			c.tSend = time.Now()
			p.emitNoResponse(c)
		}
	}
}

// serverToClient forwards responses and closes out the audit record for any
// tools/call it answers.
func (p *Proxy) serverToClient(sr *stampReader) error {
	dec := json.NewDecoder(sr)
	for {
		sr.arm()
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return p.endOfStream("upstream", err)
		}
		t2 := sr.lastByte()

		key := responseKey(raw)

		if err := p.writeClient(raw); err != nil {
			return p.endOfStream("client-write", err)
		}
		t3 := time.Now()

		if key == "" {
			continue
		}
		p.mu.Lock()
		c := p.pending[key]
		delete(p.pending, key)
		p.mu.Unlock()
		if c == nil {
			continue
		}
		// Audited after the client has its bytes: the audit write is
		// outside the measured span by construction, so disk latency
		// never enters the baseline and never delays a caller.
		p.emit(c, isError(raw), audit.Timing{Total: t3.Sub(c.t0), Upstream: t2.Sub(c.tSend)})
	}
}

// endOfStream turns a stream error into a diagnostic on stderr and a return.
// A JSON syntax error ends the direction rather than trying to resynchronize:
// once a JSON-RPC stream contains bytes that are not a value, there is no
// defined point to resume at, and guessing one is how a proxy starts forwarding
// attacker-chosen message boundaries.
func (p *Proxy) endOfStream(side string, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.ErrUnexpectedEOF) {
		p.logf("%s stream closed", side)
		return nil
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		// Loud on purpose. From the client's side a terminated direction just
		// looks like the connection dying, so this diagnostic is the only
		// place the reason can appear: which direction carried the bad bytes,
		// where in the stream they were, and that the proxy closed it on
		// purpose rather than crashed.
		p.logf("PROTOCOL ERROR: malformed JSON on the %s direction at byte offset %d: %v", direction(side), se.Offset, err)
		p.logf("PROTOCOL ERROR: %s direction terminated deliberately (not a crash, not a panic) — a JSON stream "+
			"has no defined resume point after malformed bytes, so resynchronizing would mean forwarding "+
			"message boundaries chosen by whatever produced them", direction(side))
		return nil
	}
	// A read on a handle the other direction closed is an ordinary
	// shutdown, not a failure: Run closes both ends to stop the surviving
	// pump once either one finishes.
	if errors.Is(err, os.ErrClosed) {
		p.logf("%s stream closed", side)
		return nil
	}
	p.logf("%s stream: %v", side, err)
	return fmt.Errorf("%s: %w", side, err)
}

// direction renders a side label as the flow it names, so a diagnostic says
// which way the bad bytes were travelling rather than which variable held them.
func direction(side string) string {
	switch side {
	case "client":
		return "client -> proxy"
	case "client-write":
		return "proxy -> client"
	case "upstream":
		return "upstream -> proxy"
	case "upstream-write":
		return "proxy -> upstream"
	}
	return side
}

// reportOrphans emits a record for every tools/call still waiting when the
// relay stops — an upstream that died mid-request leaves the call unanswered,
// and a proxy that silently drops it makes exactly that failure invisible.
func (p *Proxy) reportOrphans() {
	p.mu.Lock()
	orphans := make([]*call, 0, len(p.pending))
	for k, c := range p.pending {
		orphans = append(orphans, c)
		delete(p.pending, k)
	}
	p.mu.Unlock()

	now := time.Now()
	for _, c := range orphans {
		r := p.record(c)
		r.Trace = append(r.Trace, audit.Step{
			Stage: "forward", Ref: "ARCHITECTURE §3.2.7", Outcome: "unanswered",
			Detail: "upstream stream ended before a response arrived",
		})
		_ = p.Audit.Write(r, audit.Timing{Total: now.Sub(c.t0), Upstream: now.Sub(c.tSend)})
	}
}

// writeClient frames one message to the client under outMu.
func (p *Proxy) writeClient(raw []byte) error {
	p.outMu.Lock()
	defer p.outMu.Unlock()
	return p.outFr.write(p.ClientOut, raw)
}

// authorize runs the §3.2 pipeline for one tools/call and reports whether it may
// be forwarded. A false return has already answered the client and written the
// record; the caller only has to not forward.
func (p *Proxy) authorize(c *call) bool {
	// The audit sink is checked before anything else, ahead of every
	// signature verification, because §6 makes a guardrail that cannot record
	// its decisions refuse to make them. This is not an authorization
	// outcome: no chain was examined, nothing about the caller's tokens is
	// implicated, and the refusal deliberately carries a different error code
	// and a different diagnostic so an operator is not sent looking at a
	// token chain when the real problem is a full disk.
	if p.Audit != nil {
		if err := p.Audit.Err(); err != nil {
			p.logf("AUDIT SINK FAILED — refusing every call until wardend is restarted. "+
				"The cause is the audit sink, not the token chain: %v", err)
			p.replyError(c, ErrCodeAuditUnavailable,
				"warden: audit sink unavailable; the proxy will not authorize a call it cannot record", nil)
			return false
		}
	}

	c.dec = p.Enforce.Decide(c.tool, c.args, c.rawMeta)
	c.rawMeta = nil
	if c.dec.allow {
		return true
	}
	// stage and ref only. The client learns which check refused and which
	// clause of the specification says so, which is what lets a well-behaved
	// agent adapt; it does not learn the constraint it violated, because the
	// values in a constraint are the parent's policy and not the child's to
	// read back out of a denial.
	p.replyError(c, ErrCodeDenied, "warden: request denied by the authorization policy",
		map[string]string{"stage": c.dec.stage, "ref": c.dec.ref})
	p.emitNoResponse(c)
	return false
}

// replyError answers one refused call with a JSON-RPC error.
func (p *Proxy) replyError(c *call, code int, message string, data map[string]string) {
	if c.key == "" {
		// A tools/call sent as a notification. JSON-RPC defines no response
		// to one, so there is nowhere to put the refusal — but dropping the
		// message is still the right outcome and the only one that is not a
		// bypass. It is logged because it is otherwise invisible to
		// everyone: the client expects no answer and gets none either way.
		p.logf("denied a tools/call %q sent as a notification (no id, so no error response is possible): %s",
			c.tool, message)
		return
	}
	if err := p.writeClient(rpcError(json.RawMessage(c.key), code, message, data)); err != nil {
		p.logf("failed to deliver the denial to the client: %v", err)
	}
}

// emitNoResponse closes out a record for a call that will never have an
// upstream response: one that was refused, or an authorized notification.
func (p *Proxy) emitNoResponse(c *call) {
	if p.Audit == nil {
		return
	}
	r := p.record(c)
	if err := p.Audit.Write(r, audit.Timing{Total: time.Since(c.t0)}); err != nil {
		p.logf("audit write failed: %v", err)
	}
}

func (p *Proxy) emit(c *call, upstreamErr bool, t audit.Timing) {
	if p.Audit == nil {
		return
	}
	r := p.record(c)
	outcome := "forwarded"
	if upstreamErr {
		outcome = "forwarded-upstream-error"
	}
	r.Trace = append(r.Trace, audit.Step{
		Stage: "forward", Ref: "ARCHITECTURE §3.2.7", Outcome: outcome,
	})
	if err := p.Audit.Write(r, t); err != nil {
		p.logf("audit write failed: %v", err)
	}
}

// record builds the §6 record for a call.
//
// Passthrough gets the observed binding and a single bind-stage trace entry:
// there is no verify stage, no capability stage and no PoP stage, because none
// of them ran, and an empty entry claiming otherwise would be worse than their
// absence. Enforcing gets the decision's own trace, one entry per §3.2 stage
// that executed, ending at the one that refused.
func (p *Proxy) record(c *call) audit.Record {
	m := c.meta
	r := audit.Record{
		TS:          time.Now().UTC().Format(time.RFC3339Nano),
		SpecVersion: SpecVersion,
		Decision:    audit.DecisionPassthrough,
		Corr:        c.corr,
		Request:     audit.Request{Tool: c.tool, ArgsDigest: audit.ArgsDigest(c.args)},
		Chain: audit.Chain{
			Present: m.chainPresent, Tokens: m.chainTokens,
			Bytes: m.chainBytes, Spec: m.spec,
		},
		PoP: audit.PoP{Present: m.popPresent, Bytes: m.popBytes},
	}
	if c.dec == nil {
		r.Trace = append(r.Trace, audit.Step{
			Stage: "bind", Ref: "ARCHITECTURE §3.1", Outcome: m.outcome(), Detail: m.detail(),
		})
		return r
	}
	r.Chain, r.PoP = c.dec.chain, c.dec.pop

	r.Decision = audit.DecisionDeny
	if c.dec.allow {
		r.Decision = audit.DecisionPermit
	}
	r.Trace = append(r.Trace, c.dec.trace...)
	return r
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Log != nil {
		p.Log.Printf(format, args...)
	}
}

// framer emits newline-delimited JSON-RPC messages. MCP's stdio transport
// delimits by newline and forbids embedded newlines; raw came from a
// json.RawMessage, so it is one value with no trailing newline of its own.
//
// Message and terminator go out in a single Write. Two writes would leave a
// peer momentarily holding a message with no terminator, and on an unbuffered
// pipe a reader that stops at the end of a value never unblocks the second
// write. buf is reused so framing a 256 KiB chain does not allocate on every
// message; each direction owns its own framer, so there is no sharing.
type framer struct{ buf []byte }

func (f *framer) write(w io.Writer, raw []byte) error {
	f.buf = append(append(f.buf[:0], raw...), '\n')
	_, err := w.Write(f.buf)
	return err
}

// isBatch reports whether a client message is a JSON-RPC batch: a top-level
// array. It selects a denial message, not a decision — denyUnclassified
// refuses the bytes either way. The decoder hands back the value's own bytes,
// but leading whitespace is skipped here anyway rather than relying on that.
func isBatch(raw []byte) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// denyUnclassified refuses a message inspect could not place, and records it.
//
// The error carries a null id because the id is one of the things that could
// not be read: the message may be an array, or an object whose members are not
// the shapes JSON-RPC gives them. JSON-RPC 2.0 §6 answers a rejected batch with
// one error object on a null id, and the same answer is the honest one for any
// message whose id warden will not claim to have parsed.
//
// The audit record names no tool for the same reason. Warden refused the frame
// without learning what the message held, and recording a guess would be a
// claim it did not verify.
//
// Passthrough is unchanged: §3.1 makes M1 the one mode that does not shape
// traffic, and there is no enforcement in it to bypass.
func (p *Proxy) denyUnclassified(raw []byte, t0 time.Time) {
	p.mu.Lock()
	p.seq++
	corr := "c" + strconv.FormatUint(p.seq, 10)
	p.mu.Unlock()

	// A batch is called by name because it is the one unclassifiable shape a
	// well-behaved client sends on purpose, and "warden does not open batches"
	// is a different thing for an operator to read than "warden could not
	// parse this".
	detail := "unclassifiable client message refused: warden could not read it as a " +
		"JSON-RPC message it is able to decide about, and §3.2 denies what it cannot classify"
	if isBatch(raw) {
		detail = "JSON-RPC batch refused: warden authorizes one tools/call at a time " +
			"and does not open a batch array"
	}
	const ref = "ARCHITECTURE §3.2"
	c := &call{corr: corr, t0: t0, dec: &decision{
		stage: "frame", ref: ref,
		trace: []audit.Step{{Stage: "frame", Ref: ref, Outcome: "deny", Detail: detail}},
	}}
	if err := p.writeClient(rpcError(json.RawMessage("null"), ErrCodeDenied,
		"warden: request denied by the authorization policy",
		map[string]string{"stage": c.dec.stage, "ref": c.dec.ref})); err != nil {
		p.logf("failed to deliver the frame denial to the client: %v", err)
	}
	p.emitNoResponse(c)
}

// inspect classifies a client message and, for a tools/call, extracts what M1
// records. The second return is whether the message was classified at all.
//
// Three outcomes, and the third is the one that matters:
//
//	(c, true)     a tools/call — decide about it
//	(nil, true)   classified, and it is not a tools/call — relay it
//	(nil, false)  valid JSON that warden cannot place — the caller denies it
//	              in enforcing mode
//
// It never rejects on its own: an absent or malformed _meta is recorded and
// forwarded here, because fail-closed is M2 (§3.1 says so explicitly, naming
// M1 as the sole exception).
//
// This used to be one Unmarshal into one struct, with any error returning nil
// and nil meaning "relay it". That conflated the second outcome with the third
// and was a full enforcement bypass: a top-level array, a params that is not
// an object, a name that is not a string — all failed the Unmarshal, all
// returned nil, all were forwarded to the upstream having never been
// authorized. Real clients found it. Keep the stages separate.
func (p *Proxy) inspect(raw []byte, t0 time.Time) (*call, bool) {
	// Stage 1, the envelope. Only what is needed to classify is typed;
	// everything else stays raw, so a legal-but-unusual id or params cannot
	// make the classification itself fail. Nothing that is a valid JSON-RPC
	// message fails here — an array or a scalar does, and neither is one.
	var env struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		ID     json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, false
	}
	if env.Method != "tools/call" {
		// Includes a response to a server-initiated request, which carries no
		// method at all. Real servers send those; see responseKey.
		return nil, true
	}

	// Stage 2, the params of something that has named itself a tools/call.
	// A failure here is not "some other message" — the client said what this
	// is — it is a tools/call whose shape warden cannot read, and forwarding
	// it would authorize nothing. _meta stays raw: a malformed one is a
	// decision for bind to make, not a classification failure.
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      json.RawMessage `json:"_meta"`
	}
	if len(env.Params) > 0 {
		if err := json.Unmarshal(env.Params, &params); err != nil {
			return nil, false
		}
	}

	// Stage 3, the §3.1 keys. A _meta that is not an object — an array, a
	// string, a number — leaves the map nil, which is the same state as no
	// _meta at all and reaches the same denial at bind. That is what
	// ARCHITECTURE §3.1 asks for: it lists "an empty array" beside "_meta
	// absent entirely" as a fail-closed case, and the citation an operator
	// should see for it is §3.1, not a frame-stage "could not parse".
	var meta map[string]json.RawMessage
	if len(params.Meta) > 0 {
		if err := json.Unmarshal(params.Meta, &meta); err != nil {
			meta = nil
		}
	}

	// A missing id is kept, not skipped. It means the client sent the call as
	// a notification, and in enforcing mode dropping it from consideration
	// would be a bypass: the tool still runs upstream, and the client simply
	// gives up the response it was never going to read. The caller decides
	// what an id-less call means in its mode.
	p.mu.Lock()
	p.seq++
	corr := "c" + strconv.FormatUint(p.seq, 10)
	p.mu.Unlock()

	return &call{
		key:  string(env.ID),
		corr: corr,
		tool: params.Name,
		args: params.Arguments,
		// Enforcing, bind reads the same keys with meaning attached, so
		// readMeta here would be the second parse of the same chain for an
		// answer the first one already produces.
		meta:    p.observeMeta(meta),
		rawMeta: meta,
		t0:      t0,
	}, true
}

// metaInfo is what the §3.1 keys held. Presence and size, never meaning: M1
// does not parse a token, and the absence of a key is not an error here.
type metaInfo struct {
	chainPresent bool
	chainTokens  int
	chainBytes   int
	chainMalform bool
	popPresent   bool
	popBytes     int
	spec         string
}

// observeMeta records presence, size and shape without interpreting anything.
// Enforcing has no use for it: bind reads the same three keys and its findings
// land on the decision, so running both would parse every chain twice.
func (p *Proxy) observeMeta(m map[string]json.RawMessage) metaInfo {
	if p.Enforce != nil {
		return metaInfo{}
	}
	return readMeta(m)
}

func readMeta(m map[string]json.RawMessage) metaInfo {
	var mi metaInfo
	if raw, ok := m[MetaChain]; ok {
		mi.chainPresent = true
		var chain []string
		if err := json.Unmarshal(raw, &chain); err == nil {
			mi.chainTokens = len(chain)
			for _, tok := range chain {
				mi.chainBytes += len(tok)
			}
		} else {
			// §3.1 requires an array of strings. M1 records the shape
			// failure instead of denying it; the size still gets logged
			// so an oversize malformed chain is visible.
			mi.chainMalform = true
			mi.chainBytes = len(raw)
		}
	}
	if raw, ok := m[MetaPoP]; ok {
		mi.popPresent = true
		var pop string
		if err := json.Unmarshal(raw, &pop); err == nil {
			mi.popBytes = len(pop)
		} else {
			mi.popBytes = len(raw)
		}
	}
	if raw, ok := m[MetaSpec]; ok {
		var spec string
		if err := json.Unmarshal(raw, &spec); err == nil {
			mi.spec = spec
		}
	}
	return mi
}

func (m metaInfo) outcome() string {
	switch {
	case m.chainMalform:
		return "malformed"
	case m.chainPresent && m.popPresent:
		return "observed"
	case m.chainPresent || m.popPresent:
		return "partial"
	default:
		return "absent"
	}
}

func (m metaInfo) detail() string {
	if !m.chainPresent && !m.popPresent {
		return "no dev.warden/ keys in params._meta"
	}
	d := "chain "
	switch {
	case !m.chainPresent:
		d += "absent"
	case m.chainMalform:
		d += "malformed (" + strconv.Itoa(m.chainBytes) + "B, not an array of strings)"
	default:
		d += strconv.Itoa(m.chainTokens) + " tokens, " + strconv.Itoa(m.chainBytes) + "B"
	}
	d += "; pop "
	if m.popPresent {
		d += strconv.Itoa(m.popBytes) + "B"
	} else {
		d += "absent"
	}
	return d
}

// responseKey returns the pending-map key for a response message, or "" if the
// message is not a response (a notification, or an upstream-initiated request).
func responseKey(raw []byte) string {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method *string         `json:"method"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return ""
	}
	if msg.Method != nil || len(msg.ID) == 0 {
		return ""
	}
	return string(msg.ID)
}

func isError(raw []byte) bool {
	var msg struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}
	return len(msg.Error) > 0 && string(msg.Error) != "null"
}

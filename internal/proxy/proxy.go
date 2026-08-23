// Package proxy relays MCP JSON-RPC between a client and one upstream server
// over stdio, auditing every tools/call.
//
// M1 is passthrough: every message is forwarded, nothing is denied, and there
// is no call into aat.Verifier anywhere in this file. That is deliberate and
// load-bearing — M1's latency numbers are the control M4's enforcement overhead
// is measured against, so the request path must contain no authorization
// decision. Enforcement is M2 (ARCHITECTURE §3.2, which ships live there).
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

// SpecVersion is the pinned draft identifier (ARCHITECTURE §3.1). M1 records
// what arrived and compares nothing; a mismatch is an M2 denial.
const SpecVersion = "draft-niyikiza-oauth-attenuating-agent-tokens-01"

// Proxy relays one client to one upstream MCP server.
type Proxy struct {
	ClientIn  io.Reader // client -> proxy
	ClientOut io.Writer // proxy -> client. PROTOCOL BYTES ONLY.
	ServerIn  io.Writer // proxy -> upstream
	ServerOut io.Reader // upstream -> proxy

	Audit *audit.Writer
	Log   *log.Logger // diagnostics; must not be backed by ClientOut

	// PassthroughOnly is redundant in M1 and load-bearing in M2: it is what
	// lets M1's baseline be re-measured on a binary that has enforcement
	// compiled in. M1 refuses to run with it false so that the flag cannot
	// silently mean nothing.
	PassthroughOnly bool

	mu      sync.Mutex
	pending map[string]*call
	seq     uint64
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
}

var errNotPassthrough = errors.New("proxy: M1 runs in passthrough-only mode; PassthroughOnly must be set")

// Run relays in both directions until either side ends, then stops the other.
func (p *Proxy) Run() error {
	if !p.PassthroughOnly {
		return errNotPassthrough
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
		c := p.inspect(raw, t0)

		// Registered before the write, not after. A fast upstream can have
		// its response decoded by the other pump before a post-write
		// registration lands, and that response would find no pending call
		// and go unaudited — a race that gets rarer, never absent, as the
		// upstream gets slower.
		if c != nil {
			c.tSend = time.Now()
			p.mu.Lock()
			p.pending[c.key] = c
			p.mu.Unlock()
		}
		if err := fr.write(p.ServerIn, raw); err != nil {
			if c != nil {
				p.mu.Lock()
				delete(p.pending, c.key)
				p.mu.Unlock()
			}
			return p.endOfStream("upstream-write", err)
		}
	}
}

// serverToClient forwards responses and closes out the audit record for any
// tools/call it answers.
func (p *Proxy) serverToClient(sr *stampReader) error {
	dec := json.NewDecoder(sr)
	var fr framer
	for {
		sr.arm()
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return p.endOfStream("upstream", err)
		}
		t2 := sr.lastByte()

		key := responseKey(raw)

		if err := fr.write(p.ClientOut, raw); err != nil {
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

// record builds the §6 record for a call, with the M1 bind-stage trace. There
// is no verify stage, no capability stage and no PoP stage: those are M2, and
// an empty entry claiming otherwise would be worse than their absence.
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
	r.Trace = append(r.Trace, audit.Step{
		Stage: "bind", Ref: "ARCHITECTURE §3.1", Outcome: m.outcome(), Detail: m.detail(),
	})
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

// inspect extracts what M1 records from a client message, and returns nil for
// anything that is not a tools/call request. It never rejects: an absent or
// malformed _meta is recorded and forwarded, because fail-closed is M2 (§3.1
// says so explicitly, naming M1 as the sole exception).
func (p *Proxy) inspect(raw []byte, t0 time.Time) *call {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name      string                     `json:"name"`
			Arguments json.RawMessage            `json:"arguments"`
			Meta      map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		// Well-formed JSON that is not a JSON-RPC message we recognize.
		// Forward it; shaping the client's traffic is not M1's job.
		return nil
	}
	if msg.Method != "tools/call" || len(msg.ID) == 0 {
		return nil // notifications carry no id and get no response to pair with
	}
	p.mu.Lock()
	p.seq++
	corr := "c" + strconv.FormatUint(p.seq, 10)
	p.mu.Unlock()

	return &call{
		key:  string(msg.ID),
		corr: corr,
		tool: msg.Params.Name,
		args: msg.Params.Arguments,
		meta: readMeta(msg.Params.Meta),
		t0:   t0,
	}
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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/aat/aattest"
	"github.com/igorkg/warden/internal/audit"
	"github.com/igorkg/warden/internal/proxy"
	"github.com/igorkg/warden/internal/testserver"
)

// TestMain doubles as the upstream MCP server. Re-execing the test binary is
// the os/exec stdlib pattern; it gives the e2e a real peer process with no
// network fetch, so the test runs offline and in CI.
func TestMain(m *testing.M) {
	if os.Getenv("WARDEN_TEST_ROLE") == "server" {
		_ = testserver.Serve(os.Stdin, os.Stdout)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// --- a small MCP client ---------------------------------------------------

type client struct {
	out io.Writer
	dec *json.Decoder
}

func newClient(out io.Writer, in io.Reader) *client {
	return &client{out: out, dec: json.NewDecoder(in)}
}

// call sends one request and returns the response exactly as it arrived.
func (c *client) call(t *testing.T, msg string) string {
	t.Helper()
	if _, err := io.WriteString(c.out, msg+"\n"); err != nil {
		t.Fatalf("send: %v", err)
	}
	var raw json.RawMessage
	if err := c.dec.Decode(&raw); err != nil {
		t.Fatalf("receive: %v", err)
	}
	return string(raw)
}

func (c *client) notify(t *testing.T, msg string) {
	t.Helper()
	if _, err := io.WriteString(c.out, msg+"\n"); err != nil {
		t.Fatalf("notify: %v", err)
	}
}

// The conversation a real MCP client has: handshake, the initialized
// notification that carries no id and must draw no response, discovery, then
// two tool calls — one carrying the §3.1 binding, one without it.
const (
	msgInitialize  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warden-e2e","version":"0"}}}`
	msgInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	msgToolsList   = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	msgCallBound   = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"},"_meta":{"dev.warden/chain":["eyJhbGciOiJFZERTQSJ9.e30.sig-root","eyJhbGciOiJFZERTQSJ9.e30.sig-leaf"],"dev.warden/pop":"eyJhbGciOiJFZERTQSJ9.e30.sig-pop","dev.warden/spec":"draft-niyikiza-oauth-attenuating-agent-tokens-01"}}}`
	msgCallBare    = `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`
)

func converse(t *testing.T, c *client) []string {
	t.Helper()
	var got []string
	got = append(got, c.call(t, msgInitialize))
	c.notify(t, msgInitialized)
	got = append(got, c.call(t, msgToolsList))
	got = append(got, c.call(t, msgCallBound))
	got = append(got, c.call(t, msgCallBare))
	return got
}

// --- peers ----------------------------------------------------------------

// directServer starts the upstream and returns a client wired straight to it.
func directServer(t *testing.T) *client {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "WARDEN_TEST_ROLE=server")
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		cmd.Wait()
	})
	return newClient(in, out)
}

type proxied struct {
	c        *client
	stderr   *syncBuf
	auditLog string
	closeIn  func()
	wait     func(t *testing.T)
}

// proxiedServer runs wardend in passthrough: the unenforced control.
func proxiedServer(t *testing.T) *proxied {
	t.Helper()
	return wardend(t, "-passthrough-only")
}

// enforcingServer runs wardend enforcing against f's trust anchor, with the
// upstream spawned exactly as it would be in production.
func enforcingServer(t *testing.T, f *aattest.Fixture) *proxied {
	t.Helper()
	anchors := t.TempDir() + "/anchors.json"
	b, err := json.Marshal([]*aat.JWK{f.Anchor})
	if err != nil {
		t.Fatalf("marshal anchors: %v", err)
	}
	if err := os.WriteFile(anchors, b, 0o600); err != nil {
		t.Fatalf("write anchors: %v", err)
	}
	return wardend(t, "-trust-anchors", anchors)
}

// wardend runs wardend's own entry point over pipes with the given flags.
func wardend(t *testing.T, flags ...string) *proxied {
	t.Helper()
	t.Setenv("WARDEN_TEST_ROLE", "server") // inherited by the upstream wardend spawns

	clientR, clientW := io.Pipe() // test -> wardend stdin
	outR, outW := io.Pipe()       // wardend stdout -> test
	stderr := &syncBuf{}
	logPath := t.TempDir() + "/audit.jsonl"

	args := append([]string{"-audit", logPath}, flags...)
	args = append(args, os.Args[0])

	done := make(chan error, 1)
	go func() {
		err := run(args, clientR, outW, stderr)
		outW.Close()
		done <- err
	}()

	return &proxied{
		c: newClient(clientW, outR), stderr: stderr, auditLog: logPath,
		closeIn: func() { clientW.Close() },
		wait: func(t *testing.T) {
			t.Helper()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("wardend: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("wardend did not shut down")
			}
		},
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// --- the e2e --------------------------------------------------------------

// The whole claim of M1 is that the proxy is invisible, so this compares the
// response payloads byte for byte rather than checking that both calls merely
// succeeded.
func TestProxyIsInvisible(t *testing.T) {
	direct := converse(t, directServer(t))

	p := proxiedServer(t)
	through := converse(t, p.c)
	p.closeIn()
	p.wait(t)

	if len(direct) != len(through) {
		t.Fatalf("got %d responses direct, %d through the proxy", len(direct), len(through))
	}
	for i := range direct {
		if direct[i] != through[i] {
			t.Errorf("response %d differs:\n direct: %s\n proxied: %s", i+1, direct[i], through[i])
		}
	}
	if !strings.Contains(through[2], `"echo: hello"`) {
		t.Fatalf("tool call did not return its result: %s", through[2])
	}

	// Exactly one record per tools/call — the handshake and the notification
	// are relayed but are not decisions.
	recs := readAudit(t, p.auditLog)
	if len(recs) != 2 {
		t.Fatalf("want 2 audit records, got %d", len(recs))
	}
	for _, r := range recs {
		if r.Decision != audit.DecisionPassthrough {
			t.Errorf("decision = %q, want passthrough", r.Decision)
		}
		if r.Request.Tool != "echo" || r.Request.ArgsDigest == "" {
			t.Errorf("request = %+v", r.Request)
		}
		if r.SpecVersion == "" || r.Corr == "" || r.LatencyUS <= 0 {
			t.Errorf("record incomplete: %+v", r)
		}
	}
	// Presence recorded for the bound call, absence for the bare one; absence
	// is not an error in M1.
	if !recs[0].Chain.Present || recs[0].Chain.Tokens != 2 || !recs[0].PoP.Present {
		t.Errorf("bound call: chain %+v pop %+v", recs[0].Chain, recs[0].PoP)
	}
	if recs[0].Chain.Spec == "" {
		t.Error("bound call: spec key not recorded")
	}
	if recs[1].Chain.Present || recs[1].PoP.Present {
		t.Errorf("bare call: chain %+v pop %+v", recs[1].Chain, recs[1].PoP)
	}
	// Same tool, same arguments, so the digests must match — which is the
	// property that makes args_digest comparable across records at all.
	if recs[0].Request.ArgsDigest != recs[1].Request.ArgsDigest {
		t.Error("identical arguments produced different digests")
	}
	if !strings.Contains(p.stderr.String(), "latency over 2 tools/call") {
		t.Errorf("no latency report on stderr:\n%s", p.stderr.String())
	}
}

func readAudit(t *testing.T, path string) []audit.Record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []audit.Record
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("audit line: %v (%q)", err, l)
		}
		recs = append(recs, r)
	}
	return recs
}

// TestLatencyBaseline produces the number M4's enforcement overhead is measured
// against. It asserts almost nothing — the point is the report — but it fails
// if the spans come out incoherent, which is the one way the baseline could be
// wrong without looking wrong.
func TestLatencyBaseline(t *testing.T) {
	const n = 500

	p := proxiedServer(t)
	converse(t, p.c) // handshake first, as a real client would
	for i := 0; i < n; i++ {
		msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`, 100+i)
		p.c.call(t, msg)
	}
	p.closeIn()
	p.wait(t)

	recs := readAudit(t, p.auditLog)
	if len(recs) != n+2 {
		t.Fatalf("want %d records, got %d", n+2, len(recs))
	}
	var total, upstream, overhead []int64
	for _, r := range recs {
		// Within a microsecond: each span is truncated to whole microseconds
		// independently, so the three fields can disagree by one ulp without
		// anything being wrong.
		if d := r.OverheadUS - (r.LatencyUS - r.UpstreamUS); d > 1 || d < -1 {
			t.Fatalf("overhead is not total-upstream: %+v", r)
		}
		if r.UpstreamUS > r.LatencyUS {
			t.Fatalf("upstream span exceeds total: %+v", r)
		}
		total = append(total, r.LatencyUS)
		upstream = append(upstream, r.UpstreamUS)
		overhead = append(overhead, r.OverheadUS)
	}
	t.Logf("latency over %d tools/call, nearest-rank percentiles, microseconds\n"+
		"  total    p50 %6d  p99 %6d   first byte in from client -> last byte out to client\n"+
		"  upstream p50 %6d  p99 %6d   first byte out to upstream -> last byte in from upstream\n"+
		"  overhead p50 %6d  p99 %6d   total - upstream\n"+
		"  upstream includes pipe transit in both directions.",
		len(recs),
		p50(total), p99(total), p50(upstream), p99(upstream), p50(overhead), p99(overhead))
}

func p50(v []int64) int64 { return nearestRank(v, 0.50) }
func p99(v []int64) int64 { return nearestRank(v, 0.99) }

func nearestRank(v []int64, p float64) int64 {
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	r := int(p*float64(len(s))+0.999999) - 1
	if r < 0 {
		r = 0
	}
	if r >= len(s) {
		r = len(s) - 1
	}
	return s[r]
}

// --- the enforcing e2e -----------------------------------------------------

// boundCall renders a tools/call carrying the §3.1 binding for f.
func boundCall(t *testing.T, f *aattest.Fixture, id int, tool string, args map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": args,
			"_meta":     f.Meta(t, tool, args),
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(b)
}

// TestEnforcingE2EPermits is the milestone's exit criterion: a three-token
// chain authorizes a permitted call end to end through the proxy, against a
// real upstream process, and the client gets the upstream's own answer.
func TestEnforcingE2EPermits(t *testing.T) {
	f := aattest.NewLive(t, 3)
	p := enforcingServer(t, f)
	converse(t, p.c) // handshake, as a real client would

	got := p.c.call(t, boundCall(t, f, 10, aattest.Echo, aattest.EchoAllowed))
	if !strings.Contains(got, "echo: hello") {
		t.Fatalf("response = %s, want the upstream's echo", got)
	}
	p.closeIn()
	p.wait(t)

	recs := readAudit(t, p.auditLog)
	var permits int
	for _, r := range recs {
		if r.Decision == audit.DecisionPermit {
			permits++
			if r.Chain.Depth == nil || *r.Chain.Depth != 2 || r.Chain.Tokens != 3 {
				t.Errorf("permit record does not describe the chain: %+v", r.Chain)
			}
			if r.PoP.JTI == "" {
				t.Errorf("permit record names no PoP: %+v", r.PoP)
			}
		}
	}
	if permits != 1 {
		t.Fatalf("want exactly one permit, got %d in %d records", permits, len(recs))
	}
}

// TestEnforcingE2EDenies is the other half: an out-of-authority call, an error
// the client can parse, an upstream that never saw it, and an audit trace that
// names the clause.
//
// The upstream implements echo for any text, so if the call reached it the
// client would receive "echo: goodbye". That the client receives an error
// instead is the enforcement, not a coincidence of the fixture.
func TestEnforcingE2EDenies(t *testing.T) {
	f := aattest.NewLive(t, 3)
	p := enforcingServer(t, f)
	converse(t, p.c)

	got := p.c.call(t, boundCall(t, f, 11, aattest.Echo, aattest.EchoDenied))
	if strings.Contains(got, "goodbye") {
		t.Fatalf("the call reached the upstream: %s", got)
	}

	var resp struct {
		ID    int `json:"id"`
		Error *struct {
			Code    int               `json:"code"`
			Message string            `json:"message"`
			Data    map[string]string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("the client did not receive valid JSON-RPC: %v (%s)", err, got)
	}
	if resp.Error == nil || resp.Error.Code != proxy.ErrCodeDenied || resp.ID != 11 {
		t.Fatalf("response = %s, want a -32001 error correlated to id 11", got)
	}
	if resp.Error.Data["ref"] == "" {
		t.Fatalf("the denial names no clause: %s", got)
	}

	// The proxy is still usable afterwards. A denial is a decision about one
	// call, not a reason to tear down the session.
	if ok := p.c.call(t, boundCall(t, f, 12, aattest.Echo, aattest.EchoAllowed)); !strings.Contains(ok, "echo: hello") {
		t.Fatalf("the session did not survive the denial: %s", ok)
	}

	p.closeIn()
	p.wait(t)

	recs := readAudit(t, p.auditLog)
	var deny *audit.Record
	for i := range recs {
		if recs[i].Decision == audit.DecisionDeny {
			deny = &recs[i]
		}
	}
	if deny == nil {
		t.Fatalf("no deny record in %d records", len(recs))
	}
	last := deny.Trace[len(deny.Trace)-1]
	if last.Outcome != "deny" || last.Ref == "" {
		t.Fatalf("the trace does not end at a cited refusal: %+v", deny.Trace)
	}
	if !strings.Contains(last.Ref, "§3.4") || !strings.Contains(last.Detail, "text") {
		t.Errorf("trace step = %+v, want the §3.4 constraint on the text argument", last)
	}
	if resp.Error.Data["ref"] != last.Ref {
		t.Errorf("the client saw ref %q and the audit recorded %q", resp.Error.Data["ref"], last.Ref)
	}
	if deny.Chain.RootJTI == "" || deny.Chain.LeafJTI == "" {
		t.Errorf("the deny record cannot say which chain produced it: %+v", deny.Chain)
	}
}

// TestEnforcingRefusesUnboundCalls: a tools/call with no _meta at all is denied
// fail-closed. There is no unauthenticated path through an enforcing wardend.
func TestEnforcingRefusesUnboundCalls(t *testing.T) {
	f := aattest.NewLive(t, 3)
	p := enforcingServer(t, f)
	converse(t, p.c)

	got := p.c.call(t, `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`)
	if strings.Contains(got, "echo: hello") {
		t.Fatalf("an unbound call was served: %s", got)
	}
	if !strings.Contains(got, "ARCHITECTURE") {
		t.Errorf("response = %s, want a denial citing the transport binding", got)
	}
	p.closeIn()
	p.wait(t)
}

// TestEnforcingRequiresTrustAnchors: wardend refuses to start rather than
// denying every call for a reason that looks like the client's fault.
func TestEnforcingRequiresTrustAnchors(t *testing.T) {
	err := run([]string{"-audit", "-", os.Args[0]}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("enforcing wardend started with no -trust-anchors")
	}
	if !strings.Contains(err.Error(), "trust-anchors") {
		t.Errorf("error = %v, want one naming the missing flag", err)
	}

	// And the two modes cannot be combined, since one of them was meant and
	// it is not knowable which.
	err = run([]string{"-audit", "-", "-passthrough-only", "-trust-anchors", "/dev/null", os.Args[0]},
		strings.NewReader(""), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("wardend accepted -trust-anchors together with -passthrough-only")
	}
}

// --- the number that means something ---------------------------------------

// TestEnforcementLatency reports passthrough against enforcing at three chain
// depths on the same binary.
//
// Read the absolute microseconds, not the ratio. internal/testserver answers in
// about 20µs, so any overhead expressed as a percentage of it is a statement
// about how trivial the peer is, not about warden. Against a real MCP server
// doing real work the same absolute cost would render as a flattering fraction
// that says nothing.
//
// Depth is broken out because §7 verifies one Ed25519 signature per token, so
// the cost is linear in chain length and a single number would be a number for
// one topology.
func TestEnforcementLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement")
	}
	const n = 300

	measure := func(t *testing.T, p *proxied, call func(i int) string) (tot, up, over []int64) {
		t.Helper()
		converse(t, p.c)
		for i := 0; i < n; i++ {
			got := p.c.call(t, call(i))
			if !strings.Contains(got, "echo: hello") {
				t.Fatalf("call %d did not succeed: %s", i, got)
			}
		}
		p.closeIn()
		p.wait(t)
		for _, r := range readAudit(t, p.auditLog) {
			if r.Request.Tool != aattest.Echo {
				continue
			}
			tot = append(tot, r.LatencyUS)
			up = append(up, r.UpstreamUS)
			over = append(over, r.OverheadUS)
		}
		// converse's own handshake ends with an echo, so keep the tail.
		if len(tot) < n {
			t.Fatalf("measured %d calls, want at least %d", len(tot), n)
		}
		return tot[len(tot)-n:], up[len(up)-n:], over[len(over)-n:]
	}

	report := func(label string, tot, up, over []int64) {
		t.Logf("%-20s  total p50 %5d p99 %6d | upstream p50 %5d | overhead p50 %5d p99 %6d",
			label, p50(tot), p99(tot), p50(up), p50(over), p99(over))
	}

	t.Logf("all figures in microseconds, nearest-rank, over %d tools/call each", n)
	t.Logf("%-20s  %s", "", "overhead = total - upstream, i.e. what warden added")

	// The control: the same binary, deciding nothing.
	baseTot, baseUp, baseOver := measure(t, proxiedServer(t), func(i int) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}`, 100+i)
	})
	report("passthrough", baseTot, baseUp, baseOver)

	for _, depth := range []int{1, 3, 5} {
		f := aattest.NewLive(t, depth)
		tot, up, over := measure(t, enforcingServer(t, f), func(i int) string {
			return boundCall(t, f, 100+i, aattest.Echo, aattest.EchoAllowed)
		})
		report(fmt.Sprintf("enforcing depth %d", depth), tot, up, over)
		t.Logf("%-20s  enforcement cost over the control: p50 %+dµs  p99 %+dµs",
			"", p50(over)-p50(baseOver), p99(over)-p99(baseOver))
	}
	t.Logf("the upstream answers in p50 %dµs, so overhead as a percentage of it "+
		"is a statement about the peer, not about warden", p50(baseUp))
}

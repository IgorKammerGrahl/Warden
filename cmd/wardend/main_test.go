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

	"github.com/igorkg/warden/internal/audit"
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

// proxiedServer runs wardend's own entry point over pipes, with the upstream
// spawned exactly as it would be in production.
func proxiedServer(t *testing.T) *proxied {
	t.Helper()
	t.Setenv("WARDEN_TEST_ROLE", "server") // inherited by the upstream wardend spawns

	clientR, clientW := io.Pipe() // test -> wardend stdin
	outR, outW := io.Pipe()       // wardend stdout -> test
	stderr := &syncBuf{}
	logPath := t.TempDir() + "/audit.jsonl"

	done := make(chan error, 1)
	go func() {
		err := run([]string{"-audit", logPath, "-passthrough-only", os.Args[0]}, clientR, outW, stderr)
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

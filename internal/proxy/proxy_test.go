package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/igorkg/warden/internal/audit"
	"github.com/igorkg/warden/internal/testserver"
)

// TestMain doubles as three upstream servers. Re-execing the test binary is the
// os/exec stdlib pattern: it gives the failure tests a real process to kill
// without committing a second binary or reaching for the network.
func TestMain(m *testing.M) {
	switch os.Getenv("WARDEN_TEST_ROLE") {
	case "server":
		_ = testserver.Serve(os.Stdin, os.Stdout)
		os.Exit(0)
	case "die-after-request":
		// Consume one request, then exit without answering it. This is the
		// upstream that dies mid-request.
		var raw json.RawMessage
		_ = json.NewDecoder(os.Stdin).Decode(&raw)
		os.Exit(0)
	case "garbage":
		os.Stdout.Write([]byte("<html>503 Service Unavailable</html>\n"))
		io.Copy(io.Discard, os.Stdin) // stay alive until our stdin closes
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperCmd(t *testing.T, role string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "WARDEN_TEST_ROLE="+role)
	return cmd
}

// --- goroutine instrument -------------------------------------------------

// goroutinesSettled waits, bounded, for the goroutine count to come back to
// base and returns what it actually was at the end.
//
// runtime.NumGoroutine is a sample, not a barrier: a relay pump can have
// returned from Run while its goroutine is still a few instructions from
// exiting, so comparing immediately is flaky in the direction that fails a
// healthy proxy. Polling to a deadline removes that flake without ever hiding
// a real leak — a goroutine blocked forever on a read from a closed pipe, the
// exact failure a bidirectional stdio relay produces, never goes away.
func goroutinesSettled(base int, within time.Duration) int {
	deadline := time.Now().Add(within)
	n := runtime.NumGoroutine()
	for n > base && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}

func checkNoLeak(t *testing.T, base int) {
	t.Helper()
	if n := goroutinesSettled(base, 2*time.Second); n > base {
		buf := make([]byte, 1<<16)
		buf = buf[:runtime.Stack(buf, true)]
		t.Errorf("goroutine leak: %d before, %d after teardown\n%s", base, n, buf)
	}
}

// --- helpers --------------------------------------------------------------

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
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

// waitLines polls until buf holds n newline-terminated messages. Polling, not a
// reader goroutine, so the goroutine instrument above measures the proxy and
// not the test's own scaffolding.
func waitLines(t *testing.T, buf *syncBuf, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		lines := splitLines(buf.String())
		if len(lines) >= n {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d messages, got %d: %q", n, len(lines), buf.String())
		}
		time.Sleep(time.Millisecond)
	}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// rig wires a Proxy to pipes with the test standing in for both peers.
type rig struct {
	clientW   *io.PipeWriter // test -> proxy, as the client
	clientOut *syncBuf       // proxy -> client. Protocol bytes only.
	upDec     *json.Decoder  // what the proxy forwarded upstream
	upW       *io.PipeWriter // test -> proxy, as the upstream
	stderr    *syncBuf
	auditBuf  *syncBuf
	aw        *audit.Writer
	done      chan error
}

func newRig(t *testing.T) *rig {
	t.Helper()
	clientR, clientW := io.Pipe()
	srvR, srvW := io.Pipe()
	upR, upW := io.Pipe()

	r := &rig{
		clientW:   clientW,
		clientOut: &syncBuf{},
		upDec:     json.NewDecoder(srvR),
		upW:       upW,
		stderr:    &syncBuf{},
		auditBuf:  &syncBuf{},
		done:      make(chan error, 1),
	}
	r.aw = audit.NewWriter(r.auditBuf)

	p := &Proxy{
		ClientIn:        clientR,
		ClientOut:       r.clientOut,
		ServerIn:        srvW,
		ServerOut:       upR,
		Audit:           r.aw,
		Log:             log.New(r.stderr, "", 0),
		PassthroughOnly: true,
	}
	go func() { r.done <- p.Run() }()
	return r
}

func (r *rig) send(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(r.clientW, s); err != nil {
		t.Fatalf("client write: %v", err)
	}
}

// forwarded returns the next message the proxy sent upstream, byte for byte.
func (r *rig) forwarded(t *testing.T) string {
	t.Helper()
	var raw json.RawMessage
	if err := r.upDec.Decode(&raw); err != nil {
		t.Fatalf("read forwarded message: %v", err)
	}
	return string(raw)
}

func (r *rig) reply(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(r.upW, s); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
}

func (r *rig) shutdown(t *testing.T) error {
	t.Helper()
	r.clientW.Close()
	r.upW.Close()
	select {
	case err := <-r.done:
		r.aw.Close()
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s")
		return nil
	}
}

func (r *rig) records(t *testing.T) []audit.Record {
	t.Helper()
	var recs []audit.Record
	for _, l := range splitLines(r.auditBuf.String()) {
		var rec audit.Record
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("audit line is not a record: %v (%q)", err, l)
		}
		recs = append(recs, rec)
	}
	return recs
}

// --- tests ----------------------------------------------------------------

func TestPassthroughOnlyIsRequired(t *testing.T) {
	p := &Proxy{ClientIn: strings.NewReader(""), ClientOut: io.Discard,
		ServerIn: io.Discard, ServerOut: strings.NewReader("")}
	if err := p.Run(); err == nil {
		t.Fatal("Run with PassthroughOnly=false must refuse to start")
	}
}

// A message split across reads, two messages in one read, and a notification
// with no id: the three shapes that break a line-oriented reader.
func TestFraming(t *testing.T) {
	base := runtime.NumGoroutine()
	r := newRig(t)

	// One message, four writes, split mid-token.
	r.send(t, `{"jsonrpc":"2.0","id":1,"met`)
	r.send(t, `hod":"tools/call","params":{"name":"echo",`)
	r.send(t, `"arguments":{"text":"hi"}`)
	r.send(t, "}}\n")
	if got := r.forwarded(t); got != `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}` {
		t.Fatalf("split message not reassembled: %s", got)
	}

	// Two messages in one write, the second a notification with no id.
	r.send(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	if got := r.forwarded(t); got != `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` {
		t.Fatalf("first of a batched pair: %s", got)
	}
	if got := r.forwarded(t); got != `{"jsonrpc":"2.0","method":"notifications/initialized"}` {
		t.Fatalf("second of a batched pair: %s", got)
	}

	r.reply(t, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`+"\n")
	waitLines(t, r.clientOut, 1)

	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(r.records(t)); n != 1 {
		t.Fatalf("want 1 audit record (the tools/call), got %d", n)
	}
	checkNoLeak(t, base)
}

// Byte-identical forwarding. Member order and number formatting survive in both
// directions, because a re-serializing proxy silently invalidates every
// signature computed over the original bytes.
func TestForwardingIsByteIdentical(t *testing.T) {
	base := runtime.NumGoroutine()
	r := newRig(t)

	req := `{"zeta":1.0,"jsonrpc":"2.0","id":7,"method":"tools/call","alpha":1e2,"params":{"name":"echo","arguments":{"b":2,"a":1.50}}}`
	r.send(t, req+"\n")
	if got := r.forwarded(t); got != req {
		t.Fatalf("request altered in flight:\n want %s\n  got %s", req, got)
	}

	resp := `{"jsonrpc":"2.0","id":7,"result":{"z":1.0,"a":1e2,"content":[{"type":"text","text":"echo: hi"}]}}`
	r.reply(t, resp+"\n")
	lines := waitLines(t, r.clientOut, 1)
	if lines[0] != resp {
		t.Fatalf("response altered in flight:\n want %s\n  got %s", resp, lines[0])
	}

	if err := r.shutdown(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	checkNoLeak(t, base)
}

func TestMetaExtraction(t *testing.T) {
	tok := strings.Repeat("a", 40)
	cases := []struct {
		name    string
		meta    string
		present bool
		tokens  int
		pop     bool
		spec    string
		outcome string
	}{
		{
			name: "present", present: true, tokens: 2, pop: true,
			spec:    SpecVersion,
			outcome: "observed",
			meta: `,"_meta":{"` + MetaChain + `":["` + tok + `","` + tok + `"],"` +
				MetaPoP + `":"` + tok + `","` + MetaSpec + `":"` + SpecVersion + `"}`,
		},
		// Absent is not an error in M1: fail-closed is M2 behaviour.
		{name: "absent", meta: ``, outcome: "absent"},
		{name: "no _meta member at all", meta: `,"_meta":{}`, outcome: "absent"},
		{name: "chain only", meta: `,"_meta":{"` + MetaChain + `":["` + tok + `"]}`,
			present: true, tokens: 1, outcome: "partial"},
		{name: "malformed chain", meta: `,"_meta":{"` + MetaChain + `":"not-an-array"}`,
			present: true, outcome: "malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := runtime.NumGoroutine()
			r := newRig(t)
			r.send(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}`+tc.meta+`}}`+"\n")
			r.forwarded(t)
			r.reply(t, `{"jsonrpc":"2.0","id":1,"result":{}}`+"\n")
			waitLines(t, r.clientOut, 1)
			if err := r.shutdown(t); err != nil {
				t.Fatalf("Run: %v", err)
			}

			recs := r.records(t)
			if len(recs) != 1 {
				t.Fatalf("want 1 record, got %d", len(recs))
			}
			rec := recs[0]
			if rec.Decision != audit.DecisionPassthrough {
				t.Errorf("decision = %q, want %q", rec.Decision, audit.DecisionPassthrough)
			}
			if rec.Chain.Present != tc.present {
				t.Errorf("chain present = %v, want %v", rec.Chain.Present, tc.present)
			}
			if rec.Chain.Tokens != tc.tokens {
				t.Errorf("chain tokens = %d, want %d", rec.Chain.Tokens, tc.tokens)
			}
			if tc.present && !tc.pop && rec.Chain.Bytes == 0 {
				t.Error("chain bytes not recorded")
			}
			if rec.PoP.Present != tc.pop {
				t.Errorf("pop present = %v, want %v", rec.PoP.Present, tc.pop)
			}
			if rec.Chain.Spec != tc.spec {
				t.Errorf("spec = %q, want %q", rec.Chain.Spec, tc.spec)
			}
			// Two steps and no more: the bind stage, and the forward that
			// answered it. There is no verify, capability or PoP stage —
			// those are M2, and an empty step claiming one ran would be
			// worse than its absence.
			if len(rec.Trace) != 2 {
				t.Fatalf("trace = %+v, want exactly the bind and forward steps", rec.Trace)
			}
			if rec.Trace[0].Outcome != tc.outcome {
				t.Errorf("bind outcome = %q, want %q", rec.Trace[0].Outcome, tc.outcome)
			}
			if rec.Trace[1].Stage != "forward" || rec.Trace[1].Outcome != "forwarded" {
				t.Errorf("forward step = %+v, want stage forward outcome forwarded", rec.Trace[1])
			}
			if rec.Trace[0].Ref != "ARCHITECTURE §3.1" {
				t.Errorf("trace ref = %q, want the normative citation", rec.Trace[0].Ref)
			}
			// M2's fields must stay absent, not appear as zeroes.
			if rec.Chain.RootJTI != "" || rec.Chain.Depth != nil {
				t.Errorf("M1 must not populate token-derived fields: %+v", rec.Chain)
			}
			if rec.Request.Tool != "echo" || rec.Request.ArgsDigest == "" {
				t.Errorf("request = %+v, want tool and args digest", rec.Request)
			}
			if rec.Corr == "" {
				t.Error("no correlation id")
			}
			checkNoLeak(t, base)
		})
	}
}

// --- failure modes --------------------------------------------------------

// subrig runs a Proxy against a real upstream process.
type subrig struct {
	cmd       *exec.Cmd
	clientW   *io.PipeWriter
	clientOut *syncBuf
	stderr    *syncBuf
	auditBuf  *syncBuf
	aw        *audit.Writer
	done      chan error
}

func newSubrig(t *testing.T, role string) *subrig {
	t.Helper()
	cmd := helperCmd(t, role)
	sin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	sout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	s := &subrig{cmd: cmd, clientOut: &syncBuf{}, stderr: &syncBuf{},
		auditBuf: &syncBuf{}, done: make(chan error, 1)}
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	clientR, clientW := io.Pipe()
	s.clientW = clientW
	s.aw = audit.NewWriter(s.auditBuf)
	p := &Proxy{
		ClientIn: clientR, ClientOut: s.clientOut,
		ServerIn: sin, ServerOut: sout,
		Audit: s.aw, Log: log.New(s.stderr, "", 0),
		PassthroughOnly: true,
	}
	go func() { s.done <- p.Run() }()
	return s
}

func (s *subrig) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.done:
		s.aw.Close()
		return err
	case <-time.After(5 * time.Second):
		s.cmd.Process.Kill()
		t.Fatal("Run did not return within 5s — the relay hung")
		return nil
	}
}

// stdoutIsProtocolOnly fails if anything on the client's stdout is not a
// JSON-RPC message. A diagnostic that lands here corrupts the stream, and it is
// the single most common way a stdio proxy breaks.
func stdoutIsProtocolOnly(t *testing.T, out string) {
	t.Helper()
	for _, l := range splitLines(out) {
		if !json.Valid([]byte(l)) {
			t.Errorf("non-protocol bytes on stdout: %q", l)
		}
	}
}

func TestUpstreamDiesMidRequest(t *testing.T) {
	base := runtime.NumGoroutine()
	s := newSubrig(t, "die-after-request")

	io.WriteString(s.clientW, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`+"\n")

	if err := s.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := s.cmd.Wait(); err != nil {
		t.Fatalf("upstream exit: %v", err)
	}
	s.clientW.Close()

	// The call the upstream never answered must still be in the log; a proxy
	// that drops it makes exactly this failure invisible.
	recs := parseRecords(t, s.auditBuf.String())
	if len(recs) != 1 {
		t.Fatalf("want 1 orphan record, got %d: %s", len(recs), s.auditBuf.String())
	}
	if got := recs[0].Trace[len(recs[0].Trace)-1].Outcome; got != "unanswered" {
		t.Errorf("orphan outcome = %q, want %q", got, "unanswered")
	}
	if !strings.Contains(s.stderr.String(), "stream closed") {
		t.Errorf("no diagnostic on stderr: %q", s.stderr.String())
	}
	stdoutIsProtocolOnly(t, s.clientOut.String())
	checkNoLeak(t, base)
}

func TestUpstreamEmitsNonJSON(t *testing.T) {
	base := runtime.NumGoroutine()
	s := newSubrig(t, "garbage")

	if err := s.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := s.cmd.Wait(); err != nil {
		t.Fatalf("upstream exit: %v", err)
	}
	s.clientW.Close()

	got := s.stderr.String()
	for _, want := range []string{"PROTOCOL ERROR", "upstream -> proxy", "byte offset", "deliberately"} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr diagnostic missing %q:\n%s", want, got)
		}
	}
	stdoutIsProtocolOnly(t, s.clientOut.String())
	checkNoLeak(t, base)
}

func TestClientClosesStdin(t *testing.T) {
	base := runtime.NumGoroutine()
	s := newSubrig(t, "server")

	io.WriteString(s.clientW, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	waitLines(t, s.clientOut, 1)
	s.clientW.Close()

	if err := s.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Closing the client's stdin must close the upstream's, so a healthy
	// server exits on its own rather than being left running.
	if err := s.cmd.Wait(); err != nil {
		t.Fatalf("upstream exit: %v", err)
	}
	stdoutIsProtocolOnly(t, s.clientOut.String())
	checkNoLeak(t, base)
}

func parseRecords(t *testing.T, s string) []audit.Record {
	t.Helper()
	var recs []audit.Record
	for _, l := range splitLines(s) {
		var r audit.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("audit line is not a record: %v (%q)", err, l)
		}
		recs = append(recs, r)
	}
	return recs
}

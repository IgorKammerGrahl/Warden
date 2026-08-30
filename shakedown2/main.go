// Command shakedown2 replays a captured real-client MCP stream through an
// enforcing wardend that fronts a real upstream MCP server.
//
// It is the phase-2 half of docs/SHAKEDOWN-2.md. Phase 1 captured the stream
// with `tee` on all four sides; this program mints a capability from what
// phase 1 actually asked for, injects the §3.1 transport binding into every
// tools/call, and replays the capture unchanged otherwise.
//
// Not a test and not part of the build: it is run by hand against a live
// server, and its output is a report, not an assertion.
//
// Reproducing a phase-2 row of docs/SHAKEDOWN-2.md, given a phase-1 capture and
// the graph file as it stood when the capture started:
//
//	cp mem-snapshot.json work/mem.json
//	shakedown2 -capture cap/c2w.jsonl -wardend ./wardend -work work \
//	    -upstream ./upstream.sh -profile subsetobj -depth 1 [-probes]
//
// where upstream.sh execs the real server against work/mem.json. -probes adds
// the fourteen hand-written shapes; without it the run is the capture alone.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/core"
	"github.com/igorkg/warden/internal/proxy"
)

const rootIssuer = "https://issuer.shakedown2.warden.dev"

func main() {
	capture := flag.String("capture", "", "path to the phase-1 client->warden capture (JSONL)")
	upstream := flag.String("upstream", "", "command wardend spawns as its upstream MCP server")
	bin := flag.String("wardend", "", "path to the wardend binary")
	work := flag.String("work", "", "directory for anchors.json and the audit log")
	depth := flag.Int("depth", 1, "chain depth to present: 1 = root only, 2 = one derivation")
	profile := flag.String("profile", "observed", "capability profile: observed | readonly | searchonly | wildcard | subsetobj | exactobj")
	probes := flag.Bool("probes", false, "append the framing probes after the replay")
	flag.Parse()
	if *capture == "" || *upstream == "" || *bin == "" || *work == "" {
		flag.Usage()
		os.Exit(2)
	}

	msgs, err := readCapture(*capture)
	if err != nil {
		die(err)
	}

	w := newWorld()
	if err := w.writeAnchors(*work + "/anchors.json"); err != nil {
		die(err)
	}
	ch, err := w.chain(*profile, *depth)
	if err != nil {
		die(err)
	}
	fmt.Printf("chain: depth %d, %d bytes, profile %q\n", len(ch.raws), ch.bytes(), *profile)

	auditPath := *work + "/audit-p2.jsonl"
	_ = os.Remove(auditPath)
	p, err := start(*bin, auditPath, *work+"/anchors.json", *upstream)
	if err != nil {
		die(err)
	}
	defer p.stop()

	r := &run{p: p, ch: ch, w: w}
	for _, m := range msgs {
		r.send(m)
	}
	if *probes {
		r.runProbes()
	}
	p.stop()
	time.Sleep(300 * time.Millisecond)

	r.report(auditPath)
}

// --- capture ---------------------------------------------------------------

type message struct {
	raw    json.RawMessage
	method string
	id     json.RawMessage
	tool   string
	args   json.RawMessage
}

func readCapture(path string) ([]message, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []message
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var env struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			return nil, fmt.Errorf("capture line: %w", err)
		}
		// The capture concatenates two client sessions, so handshake
		// messages repeat. Replaying a second initialize would confuse the
		// upstream; the tools/call stream is what phase 2 is about.
		if env.Method != "tools/call" {
			k := env.Method + "|" + string(env.ID)
			if seen[k] {
				continue
			}
			seen[k] = true
		}
		out = append(out, message{
			raw: json.RawMessage(line), method: env.Method, id: env.ID,
			tool: env.Params.Name, args: env.Params.Arguments,
		})
	}
	return out, sc.Err()
}

// --- chain -----------------------------------------------------------------

type world struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	now  int64
	seq  int
}

func newWorld() *world {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die(err)
	}
	return &world{pub: pub, priv: priv, now: time.Now().Unix()}
}

func (w *world) jti() string {
	w.seq++
	return fmt.Sprintf("01957a41-0081-7c20-bf3a-%012x", w.seq)
}

func (w *world) writeAnchors(path string) error {
	b, err := json.Marshal([]*aat.JWK{aat.NewJWK(w.pub)})
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

type chain struct {
	raws   []string
	toks   []*aat.Token
	holder []ed25519.PrivateKey
}

func (c *chain) bytes() int {
	n := 0
	for _, r := range c.raws {
		n += len(r)
	}
	return n
}

func (w *world) chain(profile string, depth int) (*chain, error) {
	tools, err := capabilities(profile)
	if err != nil {
		return nil, err
	}
	details := map[string]any{"type": "attenuating_agent_token", "tools": tools}
	root, err := aat.Mint(aat.Claims{
		JTI: w.jti(), Issuer: rootIssuer,
		IssuedAt: w.now - 60, Expires: w.now + 3600,
		Confirmation:       aat.Confirmation{JWK: aat.NewJWK(w.pub)},
		DelegationDepth:    0,
		MaxDelegationDepth: 4,
		AuthorizationDetails: []json.RawMessage{
			mustMarshal(details),
		},
	}, w.priv)
	if err != nil {
		return nil, fmt.Errorf("mint root: %w", err)
	}
	c := &chain{raws: []string{root.Compact()}, toks: []*aat.Token{root}, holder: []ed25519.PrivateKey{w.priv}}

	dv := &aat.Deriver{Limits: core.DefaultLimits}
	for len(c.raws) < depth {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		parent := c.toks[len(c.toks)-1]
		child, err := dv.Derive(parent, c.holder[len(c.holder)-1], aat.Derivation{
			JTI:                w.jti(),
			IssuedAt:           parent.Claims.IssuedAt,
			Expires:            parent.Claims.Expires,
			HolderKey:          aat.NewJWK(pub),
			MaxDelegationDepth: parent.Claims.MaxDelegationDepth,
			Tools:              sameTools(parent),
		})
		if err != nil {
			return nil, fmt.Errorf("derive: %w", err)
		}
		c.raws = append(c.raws, child.Compact())
		c.toks = append(c.toks, child)
		c.holder = append(c.holder, priv)
	}
	return c, nil
}

func sameTools(parent *aat.Token) map[string]json.RawMessage {
	var d struct {
		Tools map[string]json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(parent.Claims.AuthorizationDetails[0], &d); err != nil {
		die(err)
	}
	return d.Tools
}

func (w *world) meta(c *chain, tool string, args json.RawMessage) json.RawMessage {
	leaf := len(c.holder) - 1
	pop, err := aat.SignPoP(aat.PoPClaims{
		JTI: w.jti(), IssuedAt: time.Now().Unix(),
		TokenID: c.toks[leaf].Claims.JTI, Tool: tool,
		Args: argMap(args),
	}, c.holder[leaf])
	if err != nil {
		die(err)
	}
	return mustMarshal(map[string]any{
		proxy.MetaChain: c.raws,
		proxy.MetaPoP:   pop,
		proxy.MetaSpec:  proxy.SpecVersion,
	})
}

// --- wardend ---------------------------------------------------------------

type wardend struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	dec  *json.Decoder
	done bool
}

func start(bin, auditPath, anchors, upstream string) (*wardend, error) {
	cmd := exec.Command(bin, "-audit", auditPath, "-stats=false",
		"-trust-anchors", anchors, "--", upstream)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &wardend{cmd: cmd, in: in, dec: json.NewDecoder(out)}, nil
}

func (w *wardend) stop() {
	if w.done {
		return
	}
	w.done = true
	w.in.Close()
	w.cmd.Wait()
}

// --- replay ----------------------------------------------------------------

type outcome struct {
	tool, kind, stage, ref, detail string
}

type run struct {
	p       *wardend
	ch      *chain
	w       *world
	results []outcome
	nCalls  int
}

func (r *run) send(m message) {
	raw := m.raw
	if m.method == "tools/call" {
		raw = inject(m.raw, r.w.meta(r.ch, m.tool, m.args))
		r.nCalls++
	}
	if _, err := r.p.in.Write(append([]byte(raw), '\n')); err != nil {
		die(err)
	}
	if len(m.id) == 0 || string(m.id) == "null" {
		return
	}
	var resp struct {
		ID     json.RawMessage `json:"id"`
		Result *struct {
			IsError bool            `json:"isError"`
			Content json.RawMessage `json:"content"`
		} `json:"result"`
		Error *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := r.p.dec.Decode(&resp); err != nil {
		die(fmt.Errorf("decode response for %s: %w", m.method, err))
	}
	if m.method != "tools/call" {
		return
	}
	o := outcome{tool: m.tool}
	switch {
	case resp.Error != nil:
		var d struct{ Stage, Ref string }
		_ = json.Unmarshal(resp.Error.Data, &d)
		o.kind, o.stage, o.ref = "deny", d.Stage, d.Ref
	case resp.Result != nil && resp.Result.IsError:
		o.kind = "permit-upstream-error"
	default:
		o.kind = "permit"
	}
	r.results = append(r.results, o)
}

// inject rewrites params._meta on a tools/call. This is the ONE place the
// replay is not byte-verbatim, and it has to be: a real client does not carry
// warden's transport binding, so phase 2 cannot exist without adding it.
func inject(raw json.RawMessage, meta json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		die(err)
	}
	var p map[string]json.RawMessage
	if err := json.Unmarshal(m["params"], &p); err != nil {
		die(err)
	}
	p["_meta"] = meta
	m["params"] = mustMarshal(p)
	return mustMarshal(m)
}

// --- probes ----------------------------------------------------------------

// runProbes sends shapes the real client never sent but a real peer could.
//
// Two families. The framing probes ask whether a message can reach the
// upstream without a decision. The parser-agreement probes ask something
// sharper: warden classifies with encoding/json and the upstream parses with
// V8, and every duplicate JSON member is a place those two could disagree.
// A disagreement is a full bypass, because the PoP is signed over the tool
// name and arguments *warden* read.
//
// Each probe that warden classifies as a tools/call is presented with a
// legitimate binding for the tool warden reads, so it reaches a real decision
// instead of dying at bind.
func (r *run) runProbes() {
	send := func(label, line string) map[string]json.RawMessage {
		if _, err := r.p.in.Write([]byte(line + "\n")); err != nil {
			die(err)
		}
		var resp map[string]json.RawMessage
		if err := r.p.dec.Decode(&resp); err != nil {
			fmt.Printf("probe %-30s -> no response: %v\n", label, err)
			return nil
		}
		b, _ := json.Marshal(resp)
		fmt.Printf("probe %-30s -> %s\n", label, truncate(string(b), 200))
		return resp
	}
	// bound builds a tools/call body carrying a valid binding for tool/args.
	bound := func(tool string, args string) string {
		m := r.w.meta(r.ch, tool, json.RawMessage(args))
		return fmt.Sprintf(`"name":%q,"arguments":%s,"_meta":%s`, tool, args, m)
	}
	authorized := bound("search_nodes", `{"query":"Ed25519"}`)

	fmt.Println("\n--- framing: can a message reach the upstream without a decision? ---")
	send("resources/read", `{"jsonrpc":"2.0","id":9001,"method":"resources/read","params":{"uri":"memory://knowledge-graph"}}`)
	send("resources/list", `{"jsonrpc":"2.0","id":9002,"method":"resources/list"}`)
	send("batch[tools/call]", `[{"jsonrpc":"2.0","id":9003,"method":"tools/call","params":{`+authorized+`}}]`)
	send("params as array", `{"jsonrpc":"2.0","id":9004,"method":"tools/call","params":[{`+authorized+`}]}`)
	send("tools/call, no params", `{"jsonrpc":"2.0","id":9005,"method":"tools/call"}`)
	send("arguments as array", `{"jsonrpc":"2.0","id":9006,"method":"tools/call","params":{"name":"search_nodes","arguments":[]}}`)
	send("two values on one line", `{"jsonrpc":"2.0","id":9009,"method":"tools/list"} {"jsonrpc":"2.0","id":9010,"method":"tools/call","params":{`+authorized+`}}`)
	var second map[string]json.RawMessage
	_ = r.p.dec.Decode(&second)
	b, _ := json.Marshal(second)
	fmt.Printf("probe %-30s -> %s\n", "  (its second value)", truncate(string(b), 200))

	fmt.Println("\n--- parser agreement: encoding/json vs V8 on duplicate members ---")
	// method: warden reads the last. If the upstream read the first it would
	// execute a tools/call warden classified as a list and never authorized.
	send("dup method, call then list", `{"jsonrpc":"2.0","id":9011,"method":"tools/call","method":"tools/list","params":{`+authorized+`}}`)
	send("dup method, list then call", `{"jsonrpc":"2.0","id":9012,"method":"tools/list","method":"tools/call","params":{`+authorized+`}}`)
	// name: the sharpest one. warden reads search_nodes, authorizes it, and
	// signs a PoP over it. If the upstream read read_graph it would run an
	// unauthorized tool under a valid PoP for a different one.
	send("dup name, read then search", `{"jsonrpc":"2.0","id":9013,"method":"tools/call","params":{"name":"read_graph",`+authorized+`}}`)
	send("dup name, search then read", `{"jsonrpc":"2.0","id":9014,"method":"tools/call","params":{`+authorized+`,"name":"read_graph"}}`)
	// arguments: same question about the values the constraint checked.
	send("dup arguments", `{"jsonrpc":"2.0","id":9015,"method":"tools/call","params":{"name":"search_nodes","arguments":{"query":"Ed25519"},"arguments":{"query":"trust anchor"},"_meta":`+string(r.w.meta(r.ch, "search_nodes", json.RawMessage(`{"query":"Ed25519"}`)))+`}}`)
	// The method name spelled with a JSON escape. Both parsers unescape; a
	// proxy that compared raw bytes would not classify this as a tools/call.
	send("escaped method name", `{"jsonrpc":"2.0","id":9016,"method":"\u0074ools/call","params":{`+authorized+`}}`)

	// A tools/call as a notification: no id, so nothing comes back. It must
	// still produce an audit record.
	if _, err := r.p.in.Write([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{` + bound("read_graph", `{}`) + `}}` + "\n")); err != nil {
		die(err)
	}
	fmt.Printf("probe %-30s -> (notification; no response expected)\n", "tools/call notification")
	time.Sleep(300 * time.Millisecond)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// --- report ----------------------------------------------------------------

func (r *run) report(auditPath string) {
	permits, denies := 0, 0
	byTool := map[string]map[string]int{}
	for _, o := range r.results {
		if byTool[o.tool] == nil {
			byTool[o.tool] = map[string]int{}
		}
		byTool[o.tool][o.kind]++
		if o.kind == "deny" {
			denies++
		} else {
			permits++
		}
	}
	fmt.Printf("\nreplayed %d tools/call: %d permitted, %d denied\n", r.nCalls, permits, denies)
	tools := make([]string, 0, len(byTool))
	for t := range byTool {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	for _, t := range tools {
		fmt.Printf("  %-20s %v\n", t, byTool[t])
	}

	// The count check. Every message the proxy forwards under enforcement
	// must have an audit record behind it, and the audit log is the only
	// place that can prove it.
	f, err := os.Open(auditPath)
	if err != nil {
		fmt.Println("audit log:", err)
		return
	}
	defer f.Close()
	n := 0
	stages := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		n++
		var rec struct {
			Decision string `json:"decision"`
			Request  struct {
				Tool string `json:"tool"`
			} `json:"request"`
			Trace []struct{ Stage, Ref, Outcome, Detail string } `json:"trace"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		last := rec.Trace[len(rec.Trace)-1]
		key := rec.Decision + " @" + last.Stage + " " + last.Ref
		if rec.Decision == "deny" {
			key += " :: " + first(last.Detail, 90)
		}
		stages[key]++
	}
	fmt.Printf("\naudit records: %d\n", n)
	keys := make([]string, 0, len(stages))
	for k := range stages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %4d  %s\n", stages[k], k)
	}
}

func first(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// --- helpers ---------------------------------------------------------------

func argMap(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	if len(raw) == 0 || string(raw) == "null" {
		return m
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		die(err)
	}
	return m
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		die(err)
	}
	return b
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "shakedown2:", err)
	os.Exit(1)
}

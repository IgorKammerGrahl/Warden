package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/igorkg/warden/internal/audit"
)

// roleEnv re-execs this binary as the upstream MCP server. wardend spawns its
// upstream as a subprocess, so the harness needs a command to hand it, and
// os.Executable() is one that exists under `go run` too.
const roleEnv = "WARDEN_EVAL_ROLE"

// wardend is one running proxy under measurement.
type wardend struct {
	cmd       *exec.Cmd
	in        io.WriteCloser
	dec       *json.Decoder
	auditPath string
	id        int
}

// startWardend launches the proxy with the given flags, its upstream being
// this binary in server role.
func startWardend(bin, auditPath string, flags ...string) (*wardend, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// wardend opens the audit log O_APPEND. A file left by an earlier run would
	// arrive as extra records and abort the join, so the run starts from empty.
	if err := os.Remove(auditPath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	args := append([]string{"-audit", auditPath, "-stats=false"}, flags...)
	args = append(args, "--", self)

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), roleEnv+"=server")
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
	w := &wardend{cmd: cmd, in: in, dec: json.NewDecoder(out), auditPath: auditPath}
	return w, w.handshake()
}

type rpcResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func (w *wardend) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.in.Write(append(b, '\n'))
	return err
}

func (w *wardend) call(v any) (rpcResponse, error) {
	var r rpcResponse
	if err := w.send(v); err != nil {
		return r, err
	}
	return r, w.dec.Decode(&r)
}

// handshake runs the MCP opening exchange. It is not measured and produces no
// audit records: warden decides tools/call and relays everything else.
func (w *wardend) handshake() error {
	w.id++
	if _, err := w.call(map[string]any{
		"jsonrpc": "2.0", "id": w.id, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "warden-eval", "version": "0.1.0"},
		},
	}); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	return w.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

// invoke presents one case. It returns the wire response, or the zero value
// for a notification, which by construction has none.
func (w *wardend) invoke(k Case) (rpcResponse, error) {
	params := map[string]json.RawMessage{
		"name":      mustMarshal(k.Tool),
		"arguments": k.Args,
	}
	if k.Meta != nil {
		params["_meta"] = k.Meta
	}
	msg := map[string]any{"jsonrpc": "2.0", "method": "tools/call", "params": params}
	if k.Notify {
		return rpcResponse{}, w.send(msg)
	}
	w.id++
	msg["id"] = w.id
	return w.call(msg)
}

func (w *wardend) close() {
	_ = w.in.Close()
	// Drain whatever is still in flight so the proxy's own shutdown path runs
	// and the audit writer flushes before Wait returns.
	for {
		var v json.RawMessage
		if err := w.dec.Decode(&v); err != nil {
			break
		}
	}
	_ = w.cmd.Wait()
}

// readAudit loads the JSONL the run produced.
func readAudit(path string) ([]audit.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []audit.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Result is one case's outcome: what warden decided, and how that compares
// with what the case said warden should decide.
type Result struct {
	Case
	// Decision is read from the audit record, not from the wire. It is the
	// only oracle that works uniformly: a notification has no response at all,
	// and a permitted call's upstream error is not warden's decision.
	Decision string `json:"decision"`
	// Ref is the clause the trace cited, "" on a permit.
	Ref string `json:"ref"`
	// Stage is the §3.2 pipeline stage that refused.
	Stage string `json:"stage"`
	// Detail is the trace's message, the sentence an operator actually reads.
	// It is reported beside the ref because a coarse ref with a precise message
	// is a different defect from a ref that names the wrong clause outright.
	Detail string `json:"detail,omitempty"`
	// SameScope is chain.same_scope from the record.
	SameScope []int `json:"same_scope,omitempty"`
	// WireCode is the JSON-RPC error code the client saw, 0 for a result or a
	// notification. -32001 is warden's denial; anything else came from the
	// upstream, which means warden forwarded.
	WireCode int `json:"wire_code"`
	// OK is whether Decision matched Expect.
	OK bool `json:"ok"`
	// RefMismatch marks a denial that fired at a clause the case did not
	// predict. Not a failure — a denial for the wrong reason is still a block —
	// but it is reported, because it usually means the case does not test what
	// its name says.
	RefMismatch bool  `json:"ref_mismatch"`
	OverheadUS  int64 `json:"overhead_us"`
	LatencyUS   int64 `json:"latency_us"`
	UpstreamUS  int64 `json:"upstream_us"`
}

// inCorrOrder puts records back into presentation order and refuses to guess.
//
// The join key is audit.Record.Corr, "c<n>", assigned when the proxy READS a
// tools/call — so it is presentation order by construction, and it survives
// records being WRITTEN out of order. That is not hypothetical: M1 had exactly
// that bug, a pending call registered after the forward with a fast response
// arriving first, and file order is a permit's response time versus a denial's
// decision time. Position would silently absorb it.
//
// Any of the three failures below shifts every case after it, so one lost
// record reads as fifty findings. All three abort the run instead.
func inCorrOrder(recs []audit.Record, want int) ([]audit.Record, error) {
	if len(recs) != want {
		return nil, fmt.Errorf("audit join: %d records for %d presented calls; the join is "+
			"only valid one-to-one", len(recs), want)
	}
	out := make([]audit.Record, want)
	seen := make([]bool, want)
	for _, r := range recs {
		n, err := strconv.Atoi(strings.TrimPrefix(r.Corr, "c"))
		if !strings.HasPrefix(r.Corr, "c") || err != nil || n < 1 || n > want {
			return nil, fmt.Errorf("audit join: record carries corr %q, want c1..c%d", r.Corr, want)
		}
		if seen[n-1] {
			return nil, fmt.Errorf("audit join: corr %q appears twice", r.Corr)
		}
		out[n-1], seen[n-1] = r, true
	}
	return out, nil
}

// runCorpus presents every case in order and joins the audit records back to
// them by correlation id. Each joined record is then cross-checked against the
// case's tool name and argument digest, which is a second, independent way for
// a slipped join to announce itself rather than be reported as a result.
func runCorpus(bin, dir string, cases []Case) ([]Result, error) {
	auditPath := filepath.Join(dir, "corpus-audit.jsonl")
	w, err := startWardend(bin, auditPath, "-trust-anchors", filepath.Join(dir, "anchors.json"))
	if err != nil {
		return nil, err
	}

	var sent []Case
	results := make([]Result, 0, len(cases))
	codes := map[string]int{}
	for _, k := range cases {
		if k.BuildErr != "" {
			continue // never presented; reported separately
		}
		resp, err := w.invoke(k)
		if err != nil {
			w.close()
			return nil, fmt.Errorf("case %s: %w", k.Name, err)
		}
		if resp.Error != nil {
			codes[k.Name] = resp.Error.Code
		}
		sent = append(sent, k)
	}
	w.close()

	recs, err := readAudit(auditPath)
	if err != nil {
		return nil, err
	}
	ordered, err := inCorrOrder(recs, len(sent))
	if err != nil {
		return nil, err
	}
	for i, k := range sent {
		r := ordered[i]
		if r.Request.Tool != k.Tool {
			return nil, fmt.Errorf("audit join: record %d is for tool %q, case %s expects %q",
				i, r.Request.Tool, k.Name, k.Tool)
		}
		if d := audit.ArgsDigest(k.Args); r.Request.ArgsDigest != d {
			return nil, fmt.Errorf("audit join: record %d has args digest %q, case %s sent %q",
				i, r.Request.ArgsDigest, k.Name, d)
		}
		res := Result{
			Case: k, Decision: r.Decision, SameScope: r.Chain.SameScope,
			WireCode: codes[k.Name], LatencyUS: r.LatencyUS,
			UpstreamUS: r.UpstreamUS, OverheadUS: r.OverheadUS,
		}
		if last := len(r.Trace) - 1; last >= 0 && r.Trace[last].Outcome == "deny" {
			res.Ref, res.Stage, res.Detail = r.Trace[last].Ref, r.Trace[last].Stage, r.Trace[last].Detail
		}
		res.OK = res.Decision == k.Expect
		res.RefMismatch = res.Decision == "deny" && k.WantRef != "" && res.Ref != k.WantRef
		results = append(results, res)
	}
	return results, nil
}

// --- latency ---------------------------------------------------------------

// LatencySample is one measured configuration.
type LatencySample struct {
	Config string `json:"config"` // "enforcing" | "passthrough-bound" | "passthrough-bare"
	Depth  int    `json:"depth"`  // chain length in tokens; 0 when no chain is presented
	N      int    `json:"n"`

	TotalP50    int64 `json:"total_p50_us"`
	TotalP99    int64 `json:"total_p99_us"`
	UpstreamP50 int64 `json:"upstream_p50_us"`
	UpstreamP99 int64 `json:"upstream_p99_us"`
	OverheadP50 int64 `json:"overhead_p50_us"`
	OverheadP99 int64 `json:"overhead_p99_us"`
}

// measure runs n permitted calls per depth against one wardend and reports the
// distributions with M1's convention: nearest-rank percentiles, overhead =
// total - upstream, microseconds.
func measure(bin, dir, config string, n int, cases []Case, flags ...string) ([]LatencySample, error) {
	auditPath := filepath.Join(dir, "latency-"+config+".jsonl")
	w, err := startWardend(bin, auditPath, flags...)
	if err != nil {
		return nil, err
	}
	for _, k := range cases {
		for i := 0; i < n; i++ {
			if _, err := w.invoke(k); err != nil {
				w.close()
				return nil, err
			}
		}
	}
	w.close()

	recs, err := readAudit(auditPath)
	if err != nil {
		return nil, err
	}
	ordered, err := inCorrOrder(recs, n*len(cases))
	if err != nil {
		return nil, fmt.Errorf("latency %s: %w", config, err)
	}
	out := make([]LatencySample, 0, len(cases))
	for i, k := range cases {
		s := LatencySample{Config: config, Depth: k.Depth, N: n}
		batch := ordered[i*n : (i+1)*n]
		s.TotalP50, s.TotalP99 = percentiles(batch, func(r audit.Record) int64 { return r.LatencyUS })
		s.UpstreamP50, s.UpstreamP99 = percentiles(batch, func(r audit.Record) int64 { return r.UpstreamUS })
		s.OverheadP50, s.OverheadP99 = percentiles(batch, func(r audit.Record) int64 { return r.OverheadUS })
		out = append(out, s)
	}
	return out, nil
}

// percentiles is audit.pct's nearest-rank rule, applied to a field of the
// records. Same rule as M1 and M2 so the three numbers are comparable.
func percentiles(recs []audit.Record, f func(audit.Record) int64) (p50, p99 int64) {
	v := make([]int64, len(recs))
	for i, r := range recs {
		v[i] = f(r)
	}
	if len(v) == 0 {
		return 0, 0
	}
	sortInt64(v)
	at := func(p float64) int64 {
		r := int(p*float64(len(v))+0.999999) - 1
		if r < 0 {
			r = 0
		}
		if r >= len(v) {
			r = len(v) - 1
		}
		return v[r]
	}
	return at(0.50), at(0.99)
}

func sortInt64(v []int64) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// buildWardend compiles the binary under measurement from this working tree.
func buildWardend(dir string) (string, error) {
	bin := filepath.Join(dir, "wardend")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/wardend")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build wardend: %w", err)
	}
	return bin, nil
}

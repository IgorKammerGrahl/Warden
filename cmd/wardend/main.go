// Command wardend fronts one upstream MCP server over stdio.
//
// wardend spawns the upstream server as a subprocess, relays JSON-RPC between
// the client on its own stdin/stdout and the server's, and writes one audit
// record per tools/call.
//
// By default it enforces: every tools/call runs the ARCHITECTURE §3.2 pipeline
// against the AAT chain in its _meta binding, and a call that does not verify is
// answered with a JSON-RPC error and never reaches the upstream. -passthrough-only
// relays without deciding; it exists to re-measure the unenforced control on a
// binary that has enforcement compiled in, and it is not a mode to serve traffic
// in.
//
// stdout carries protocol bytes only. Every diagnostic, the upstream's own
// stderr, and the closing latency report all go to stderr; the audit log goes
// to its own file. A single stray Println on stdout corrupts the JSON-RPC
// stream and the failure looks like a client bug, so there is exactly one
// writer to stdout in this program and it is the proxy.
//
// Usage:
//
//	wardend [flags] -- <server-command> [server-args...]
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/audit"
	"github.com/igorkg/warden/internal/core"
	"github.com/igorkg/warden/internal/proxy"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "wardend:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("wardend", flag.ContinueOnError)
	fs.SetOutput(stderr)
	auditPath := fs.String("audit", "wardend-audit.jsonl", "audit log path (JSONL); \"-\" writes to stderr")
	// The unenforced control measurement, and the only reason the enforcement
	// overhead figure means anything: it is the same binary, measured twice.
	// It defaults off because a guardrail whose default is "guard nothing" is
	// one flag away from being nothing in production too.
	passthroughOnly := fs.Bool("passthrough-only", false,
		"relay every message and deny nothing; the unenforced control measurement, not a mode to serve traffic in")
	anchorsPath := fs.String("trust-anchors", "",
		"path to a JSON array of trust-anchor JWKs; required unless -passthrough-only")
	audience := fs.String("audience", "",
		"require every PoP to carry a matching aat_aud (§7 step 7d); empty means this deployment does not require audience binding")
	maxDepth := fs.Int("max-delegation-depth", 8,
		"the deployment's MAX_DELEGATION_DEPTH (§4.3); the draft recommends no value, topology decides")
	stats := fs.Bool("stats", true, "print the latency distributions to stderr on exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmdline := fs.Args()
	if len(cmdline) == 0 {
		fs.Usage()
		return fmt.Errorf("no upstream server command given")
	}

	// Built before the audit file is opened and before the upstream is
	// spawned, so a misconfigured enforcing wardend fails without leaving a
	// subprocess behind or a log file that records nothing.
	enforcer, err := buildEnforcer(*passthroughOnly, *anchorsPath, *audience, *maxDepth)
	if err != nil {
		return err
	}

	logger := log.New(stderr, "wardend: ", log.LstdFlags|log.Lmicroseconds)

	var auditOut io.Writer = stderr
	if *auditPath != "-" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		auditOut = f
	}
	aw := audit.NewWriter(auditOut)
	defer aw.Close()

	cmd := exec.Command(cmdline[0], cmdline[1:]...)
	cmd.Stderr = stderr // the upstream's diagnostics are diagnostics, not protocol
	sin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	sout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upstream %q: %w", cmdline[0], err)
	}

	p := &proxy.Proxy{
		ClientIn:        stdin,
		ClientOut:       stdout,
		ServerIn:        sin,
		ServerOut:       sout,
		Audit:           aw,
		Log:             logger,
		PassthroughOnly: *passthroughOnly,
		Enforce:         enforcer,
	}
	relayErr := p.Run()

	// Wait after the relay: Run has already closed the upstream's stdin, which
	// is how a well-behaved stdio server is told to exit.
	waitErr := cmd.Wait()

	if *stats {
		reportStats(stderr, aw.Stats())
	}
	if relayErr != nil {
		return relayErr
	}
	if waitErr != nil {
		logger.Printf("upstream exited: %v", waitErr)
	}
	return nil
}

// buildEnforcer returns the §3.2 pipeline, or nil in passthrough.
//
// -trust-anchors is mandatory to enforce, and the failure is a refusal to start
// rather than a warning. An enforcing wardend with an empty anchor set denies
// every call, which looks from the outside exactly like a correctly configured
// wardend facing a client with bad tokens — the operator would go debugging the
// client. There is also no defensible default: a trust anchor is the deployment
// naming who may issue authority, and guessing that is guessing the answer to
// the only question the operator has to answer.
func buildEnforcer(passthroughOnly bool, anchorsPath, audience string, maxDepth int) (*proxy.Enforcer, error) {
	if passthroughOnly {
		if anchorsPath != "" {
			return nil, errors.New("-trust-anchors was given with -passthrough-only, " +
				"which verifies nothing; drop one of the two rather than leaving it ambiguous " +
				"which was meant")
		}
		return nil, nil
	}
	if anchorsPath == "" {
		return nil, errors.New("-trust-anchors is required when enforcing: without it every " +
			"chain fails at §7 step 3b and wardend would deny every call for a reason that " +
			"looks like the client's fault (pass -passthrough-only to relay without deciding)")
	}
	anchors, err := loadAnchors(anchorsPath)
	if err != nil {
		return nil, err
	}
	return &proxy.Enforcer{
		Verifier: &aat.Verifier{
			TrustAnchors: anchors,
			Limits: core.Limits{
				MaxDelegationDepth: maxDepth,
				MaxIATSkew:         30,             // §4.4 RECOMMENDED
				MaxTokenLifetime:   90 * 24 * 3600, // §4.4 RECOMMENDED upper bound
			},
			PoPSkew:  aat.DefaultPoPSkew,
			Audience: audience,
		},
	}, nil
}

// loadAnchors reads a JSON array of public JWKs.
func loadAnchors(path string) ([]*aat.JWK, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust anchors: %w", err)
	}
	var anchors []*aat.JWK
	if err := json.Unmarshal(data, &anchors); err != nil {
		return nil, fmt.Errorf("parse trust anchors %s: %w (expected a JSON array of JWKs)", path, err)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("trust anchors %s holds no keys; an enforcing wardend with no "+
			"anchor denies every call", path)
	}
	return anchors, nil
}

// reportStats prints the three distributions and the convention behind them.
// The convention is printed with the numbers because M4 compares its own
// figures against these and a percentile is meaningless without knowing where
// the span started.
func reportStats(w io.Writer, s audit.Stats) {
	if s.N == 0 {
		fmt.Fprintln(w, "wardend: no tool calls recorded; no latency to report")
		return
	}
	fmt.Fprintf(w, `wardend: latency over %d tools/call (nearest-rank percentiles)
  total     p50 %8.3fms  p99 %8.3fms   first byte in from client -> last byte out to client
  upstream  p50 %8.3fms  p99 %8.3fms   first byte out to upstream -> last byte in from upstream
  overhead  p50 %8.3fms  p99 %8.3fms   total - upstream
  note: upstream includes pipe transit in both directions; that residue is
        booked to the server's column by convention, not by measurement.
`,
		s.N,
		ms(s.TotalP50), ms(s.TotalP99),
		ms(s.UpstreamP50), ms(s.UpstreamP99),
		ms(s.OverheadP50), ms(s.OverheadP99))
}

func ms(d interface{ Microseconds() int64 }) float64 {
	return float64(d.Microseconds()) / 1000
}

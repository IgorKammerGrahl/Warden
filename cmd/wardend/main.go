// Command wardend fronts one upstream MCP server over stdio.
//
// M1 is passthrough: every message is relayed unchanged and nothing is denied.
// wardend spawns the upstream server as a subprocess, relays JSON-RPC between
// the client on its own stdin/stdout and the server's, and writes one audit
// record per tools/call.
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
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"

	"github.com/igorkg/warden/internal/audit"
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
	// Redundant in M1, which has no enforcement to turn off, and load-bearing
	// in M2: it is what lets M1's latency baseline be re-measured on a binary
	// that has enforcement compiled in. Without it the control is a number
	// from a binary that no longer exists. Proxy.Run refuses to start unless
	// it is set, so the flag cannot quietly mean nothing.
	passthroughOnly := fs.Bool("passthrough-only", true, "relay every message and deny nothing (M1: required)")
	stats := fs.Bool("stats", true, "print the latency distributions to stderr on exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmdline := fs.Args()
	if len(cmdline) == 0 {
		fs.Usage()
		return fmt.Errorf("no upstream server command given")
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

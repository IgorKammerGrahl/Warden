// Command eval is the M4 measurement harness: it builds both corpora, presents
// every case to a live wardend over MCP stdio, and reports what warden decided
// against what each case says warden should decide.
//
//	go run ./eval
//
// One command, because a number nobody can reproduce is an anecdote. See
// eval/METHOD.md for how the two corpora are constructed and why the benign one
// is independent of the adversarial one.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/testserver"
)

func main() {
	// wardend spawns its upstream as a subprocess, so the harness re-execs
	// itself in server role rather than shipping a second binary.
	if os.Getenv(roleEnv) == "server" {
		if err := testserver.Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "eval upstream:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(1)
	}
}

func run() error {
	n := flag.Int("n", 200, "latency samples per configuration")
	out := flag.String("out", "eval/results", "output directory for the corpora, the raw records and the report")
	flag.Parse()

	dir := *out
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// One clock for both corpora, taken once: every iat and exp in the corpus
	// is relative to it, and wardend runs on the real clock beside it.
	w := newWorld(time.Now().Unix())
	anchors := filepath.Join(dir, "anchors.json")
	if err := writeJSON(anchors, []*aat.JWK{w.Anchor()}); err != nil {
		return err
	}

	bin, err := buildWardend(dir)
	if err != nil {
		return err
	}

	cases := append(benignCases(w), adversarialCases(w)...)
	if err := writeJSON(filepath.Join(dir, "corpus.json"), cases); err != nil {
		return err
	}
	results, err := runCorpus(bin, dir, cases)
	if err != nil {
		return err
	}

	// Latency. Enforcing at three depths, and the same binary relaying without
	// deciding as the control — bound (the _meta is there, nothing reads it)
	// and bare (no _meta at all), which brackets what the binding itself costs.
	lat := latencyCases(w)
	samples, err := measure(bin, dir, "enforcing", *n, lat, "-trust-anchors", anchors)
	if err != nil {
		return err
	}
	pb, err := measure(bin, dir, "passthrough-bound", *n, lat, "-passthrough-only")
	if err != nil {
		return err
	}
	bare, err := measure(bin, dir, "passthrough-bare", *n, bareCases(), "-passthrough-only")
	if err != nil {
		return err
	}
	samples = append(append(samples, pb...), bare...)

	control, err := checkPassthroughForwardsBatch(bin, dir)
	if err != nil {
		return err
	}

	return report(dir, cases, results, samples, control)
}

// latencyCases are permitted invocations at chain depths 1, 3 and 5, presented
// with the full §3.1 binding. Every hop shortens the TTL by a second, so no
// link is same-scope and the record carries nothing but the timing.
func latencyCases(w *world) []Case {
	var out []Case
	for _, depth := range []int{1, 3, 5} {
		c := newChain(w, `{"echo":{}}`, 8)
		for i := 1; i < depth; i++ {
			c = c.derive(`{"echo":{}}`, func(d *aat.Derivation) { d.Expires-- })
		}
		c.must()
		out = append(out, Case{
			Name: fmt.Sprintf("latency-depth-%d", depth), Corpus: "latency",
			Tool: "echo", Depth: depth, Args: json.RawMessage(goodArgs),
			Meta: c.bind("echo", json.RawMessage(goodArgs)),
		})
	}
	return out
}

// bareCases is the passthrough control with no transport binding at all: the
// cost of the relay with nothing to bind.
func bareCases() []Case {
	return []Case{{
		Name: "latency-bare", Corpus: "latency",
		Tool: "echo", Depth: 0, Args: json.RawMessage(goodArgs),
	}}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

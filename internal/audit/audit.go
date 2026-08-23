// Package audit writes warden decision records.
//
// The record shape is ARCHITECTURE §6. AAT draft-01 specifies no audit format;
// this is warden's, and getting it right is most of what M1 exists to do. M1
// emits decision "passthrough" and fills only the fields it can reach without
// interpreting a token: M2 fills the jti/depth fields once §7 verification runs
// in the request path.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/igorkg/warden/internal/aat/jcs"
)

// Decision values. M1 only ever emits Passthrough.
const (
	DecisionPassthrough = "passthrough"
)

// Record is one decision, one JSONL line. Field names and nesting are
// ARCHITECTURE §6; the additions are documented per field.
type Record struct {
	TS          string `json:"ts"`
	SpecVersion string `json:"spec_version"`
	Decision    string `json:"decision"`

	// Corr correlates request and response. Not in §6, which assumed a
	// synchronous decision; a proxy sees the two halves on different
	// goroutines and needs the link to be in the record.
	Corr string `json:"corr"`

	Request Request `json:"request"`
	Chain   Chain   `json:"chain"`
	PoP     PoP     `json:"pop"`
	Trace   []Step  `json:"trace"`

	// BudgetState is null until M2 has counters to report.
	BudgetState any `json:"budget_state"`

	// LatencyUS is §6's field: total wall clock, first byte in from the
	// client to last byte out to the client. UpstreamUS and OverheadUS
	// split it; see Timing.
	LatencyUS  int64 `json:"latency_us"`
	UpstreamUS int64 `json:"upstream_us"`
	OverheadUS int64 `json:"overhead_us"`
}

type Request struct {
	Tool string `json:"tool"`
	// ArgsDigest is SHA-256 over the JCS-canonical (RFC 8785) form of the
	// arguments, never the raw arguments: §6 keeps args out of the log by
	// default because they carry secrets. Canonical, not raw, so the digest
	// is stable across encodings and comparable with the PoP hta digest M2
	// will log beside it.
	ArgsDigest string `json:"args_digest"`
}

// Chain reports what the dev.warden/chain _meta key held. M1 records presence
// and size only — it does not parse a token, so RootJTI, LeafJTI, Depth and
// MaxDepth are absent and stay absent until M2.
type Chain struct {
	Present bool   `json:"present"`
	Tokens  int    `json:"tokens"`
	Bytes   int    `json:"bytes"`
	Spec    string `json:"spec,omitempty"`

	RootJTI  string `json:"root_jti,omitempty"`
	LeafJTI  string `json:"leaf_jti,omitempty"`
	Depth    *int   `json:"depth,omitempty"`
	MaxDepth *int   `json:"max_depth,omitempty"`
}

type PoP struct {
	Present bool `json:"present"`
	Bytes   int  `json:"bytes"`

	JTI string `json:"jti,omitempty"`
	Aud string `json:"aud,omitempty"`
}

// Step is one entry in the decision trace. Ref is the normative citation for
// what fired — a draft section, an invariant, a constraint path — which is what
// makes the trace an explanation rather than a log line.
type Step struct {
	Stage   string `json:"stage"`
	Ref     string `json:"ref"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// ArgsDigest hashes arguments for a Record. raw is the arguments member exactly
// as it arrived. A JCS failure is not an audit failure: we fall back to hashing
// the raw bytes and mark it, because a malformed argument map is exactly the
// case where a record is most worth having.
func ArgsDigest(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if c, err := jcs.Canonicalize(raw); err == nil {
		sum := sha256.Sum256(c)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return "sha256-raw:" + hex.EncodeToString(sum[:])
}

// Timing holds one record's three spans. The definitions are fixed here
// because M4 measures its enforcement overhead against M1's numbers and the
// two must be the same measurement.
//
// Total    first byte read from the client -> last byte written to the client.
// Upstream first byte written to upstream  -> last byte read from upstream.
// Overhead Total - Upstream.
//
// Upstream includes pipe transit in both directions. That residue is real
// proxy-attributable cost booked to the server's column by convention; it is
// stated rather than silently split because a different convention moves the
// overhead figure and M4 needs to know which one produced the baseline.
type Timing struct {
	Total    time.Duration
	Upstream time.Duration
}

// Writer appends records as JSONL and keeps the latency distributions.
type Writer struct {
	mu  sync.Mutex
	w   *bufio.Writer
	c   io.Closer
	enc *json.Encoder

	total, upstream, overhead []time.Duration
}

func NewWriter(w io.Writer) *Writer {
	bw := bufio.NewWriter(w)
	aw := &Writer{w: bw, enc: json.NewEncoder(bw)}
	if c, ok := w.(io.Closer); ok {
		aw.c = c
	}
	return aw
}

// Write emits one record. Callers write the response to the client before
// calling this: the audit write is deliberately outside the measured span, so
// a disk hiccup never lands in the latency baseline and never delays a client.
//
// ponytail: synchronous under a mutex, not §6's async writer. One tool call per
// record is not a throughput problem; make it async when a measurement says so.
// §6's "audit failure => fail closed" is an M2 obligation — M1 denies nothing,
// so there is no decision to withhold.
func (a *Writer) Write(r Record, t Timing) error {
	overhead := t.Total - t.Upstream
	r.LatencyUS = t.Total.Microseconds()
	r.UpstreamUS = t.Upstream.Microseconds()
	r.OverheadUS = overhead.Microseconds()

	a.mu.Lock()
	defer a.mu.Unlock()
	a.total = append(a.total, t.Total)
	a.upstream = append(a.upstream, t.Upstream)
	a.overhead = append(a.overhead, overhead)
	if err := a.enc.Encode(r); err != nil {
		return err
	}
	return a.w.Flush()
}

func (a *Writer) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.w.Flush(); err != nil {
		return err
	}
	if a.c != nil {
		return a.c.Close()
	}
	return nil
}

// Stats is the latency report. Zero-valued when no calls were recorded.
type Stats struct {
	N                        int
	TotalP50, TotalP99       time.Duration
	UpstreamP50, UpstreamP99 time.Duration
	OverheadP50, OverheadP99 time.Duration
}

func (a *Writer) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Stats{N: len(a.total)}
	s.TotalP50, s.TotalP99 = pct(a.total)
	s.UpstreamP50, s.UpstreamP99 = pct(a.upstream)
	s.OverheadP50, s.OverheadP99 = pct(a.overhead)
	return s
}

// pct returns the p50 and p99 of d by nearest-rank on a sorted copy. Nearest
// rank, not interpolation: with the sample counts a proxy run produces,
// interpolating invents a value between two observations that were never seen.
func pct(d []time.Duration) (p50, p99 time.Duration) {
	if len(d) == 0 {
		return 0, 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	at := func(p float64) time.Duration {
		r := int(p*float64(len(s))+0.999999) - 1
		if r < 0 {
			r = 0
		}
		if r >= len(s) {
			r = len(s) - 1
		}
		return s[r]
	}
	return at(0.50), at(0.99)
}

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"

	"github.com/igorkg/warden/internal/aat"
	"github.com/igorkg/warden/internal/audit"
	"github.com/igorkg/warden/internal/proxy"
)

// The plumbing. wardend is normally a subprocess speaking stdio to a client on
// one side and an MCP server on the other; here all three are goroutines joined
// by pipes, so the demo is one `go run` with nothing to install. The proxy and
// the enforcement pipeline are the real ones.

type wire struct {
	out  *json.Encoder // client -> proxy
	in   *json.Decoder // proxy -> client
	recs <-chan audit.Record
	id   int
}

type rpcResp struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func start(enf *proxy.Enforcer) (*wire, func(), error) {
	clientIn, clientW := io.Pipe()  // client -> proxy
	clientR, clientOut := io.Pipe() // proxy -> client
	serverIn, serverW := io.Pipe()  // proxy -> server
	serverR, serverOut := io.Pipe() // server -> proxy
	auditR, auditW := io.Pipe()     // proxy -> this file

	p := &proxy.Proxy{
		ClientIn: clientIn, ClientOut: clientOut,
		ServerIn: serverW, ServerOut: serverR,
		Audit:   audit.NewWriter(auditW),
		Enforce: enf,
	}
	go func() { _ = serveTools(serverIn, serverOut) }()
	go func() { _ = p.Run() }()

	// The audit sink, drained into a channel. Reading the record back is what
	// lets the demo print warden's own account of each call rather than its
	// own guess at one; the buffer is only so a record never blocks the proxy.
	recs := make(chan audit.Record, 16)
	go func() {
		defer close(recs)
		dec := json.NewDecoder(auditR)
		for {
			var r audit.Record
			if err := dec.Decode(&r); err != nil {
				return
			}
			recs <- r
		}
	}()

	w := &wire{out: json.NewEncoder(clientW), in: json.NewDecoder(clientR), recs: recs}
	return w, func() { _ = clientW.Close() }, w.handshake()
}

func (w *wire) handshake() error {
	w.id++
	if err := w.out.Encode(map[string]any{
		"jsonrpc": "2.0", "id": w.id, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "warden-demo", "version": "0.1.0"},
		},
	}); err != nil {
		return err
	}
	var r rpcResp
	if err := w.in.Decode(&r); err != nil {
		return err
	}
	// warden decides tools/call and relays everything else, so nothing so far
	// has produced an audit record.
	return w.out.Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

// call sends one tools/call and returns both halves of the outcome: what the
// client sees on the wire, and what warden wrote to the audit log about it.
func (w *wire) call(tool string, args json.RawMessage, meta map[string]json.RawMessage) (rpcResp, audit.Record, error) {
	var r rpcResp
	w.id++
	if err := w.out.Encode(map[string]any{
		"jsonrpc": "2.0", "id": w.id, "method": "tools/call",
		"params": map[string]json.RawMessage{
			"name":      mustJSON(tool),
			"arguments": args,
			"_meta":     mustJSON(meta),
		},
	}); err != nil {
		return r, audit.Record{}, err
	}
	if err := w.in.Decode(&r); err != nil {
		return r, audit.Record{}, err
	}
	rec, ok := <-w.recs
	if !ok {
		return r, rec, errors.New("audit stream closed before the record arrived")
	}
	return r, rec, nil
}

// --- small helpers ---------------------------------------------------------
//
// ponytail: these panic. Every input to them in this package is a string
// literal a few lines above the call, so a failure is a typo in the demo, not
// a condition the demo should have a path for.

func caps(tools string) json.RawMessage {
	return mustJSON(json.RawMessage(`{"type":"attenuating_agent_token","tools":` + tools + `}`))
}

func toolMap(tools string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(tools), &m); err != nil {
		panic(err)
	}
	return m
}

func thumbURI(pub ed25519.PublicKey) string {
	uri, err := aat.NewJWK(pub).ThumbprintURI()
	if err != nil {
		panic(err)
	}
	return uri
}

// argMap decodes the arguments exactly as they go on the wire, so the PoP's
// hta commits to the same values the constraints are checked against.
func argMap(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			panic(err)
		}
	}
	return m
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

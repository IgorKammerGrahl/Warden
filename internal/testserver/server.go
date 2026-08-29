// Package testserver is a minimal MCP server over stdio: enough of the
// protocol for a real client conversation (initialize, the initialized
// notification, tools/list, tools/call) and nothing more.
//
// It exists so the e2e has a real peer without a network fetch. Depending on
// npx @modelcontextprotocol/server-everything would make the test fail offline
// and in CI, and a test that only runs when the registry is reachable is not a
// test the proxy's transparency claim can rest on.
package testserver

import (
	"encoding/json"
	"fmt"
	"io"
)

// ProtocolVersion is what this server reports at initialize. It is a real MCP
// revision string so a real client accepts the handshake.
const ProtocolVersion = "2025-06-18"

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// Serve reads newline-delimited JSON-RPC from in and answers on out until in
// ends. Nothing is ever written to out but protocol bytes; diagnostics, if any,
// belong on the caller's stderr.
func Serve(in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(in)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		// A message this server cannot read — a JSON-RPC batch array, or an
		// object whose members are the wrong types — is answered Invalid
		// Request rather than ending the stream. It exists for the proxy
		// tests: if warden ever forwards a shape it should have refused, the
		// harness needs a distinguishable wire code to see it by, and a dead
		// upstream would instead cascade into every later case failing. MCP
		// removed batching in 2025-06-18, so refusing one is also correct.
		var req request
		if err := json.Unmarshal(raw, &req); err != nil {
			b, mErr := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil,
				"error": map[string]any{"code": -32600, "message": "invalid request: " + err.Error()}})
			if mErr != nil {
				return mErr
			}
			if _, err := out.Write(append(b, '\n')); err != nil {
				return err
			}
			continue
		}
		// No id means a notification: MCP's initialized handshake step lands
		// here and must produce no response at all.
		if len(req.ID) == 0 {
			continue
		}
		result, rpcErr := dispatch(req)
		resp := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID)}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		b, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if _, err := out.Write(append(b, '\n')); err != nil {
			return err
		}
	}
}

func dispatch(req request) (any, map[string]any) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "warden-testserver", "version": "0.1.0"},
		}, nil
	case "tools/list":
		return map[string]any{"tools": []any{
			map[string]any{
				"name":        "echo",
				"description": "Returns its text argument.",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{"text": map[string]any{"type": "string"}},
					"required":   []any{"text"},
				},
			},
		}}, nil
	case "tools/call":
		if req.Params.Name != "echo" {
			return nil, map[string]any{"code": -32602, "message": "unknown tool: " + req.Params.Name}
		}
		var args struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, map[string]any{"code": -32602, "message": "bad arguments"}
		}
		return map[string]any{
			"content": []any{map[string]any{"type": "text", "text": "echo: " + args.Text}},
			"isError": false,
		}, nil
	default:
		return nil, map[string]any{"code": -32601, "message": fmt.Sprintf("method not found: %s", req.Method)}
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// The toy MCP server. It offers three tools and trusts everyone: it has no
// idea warden exists and no idea who is calling. That is the point of the
// demo — every "no" in the transcript below is warden's, and this file is
// what would happily have said yes.

type rpcRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

func serveTools(in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(in)
	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(req.ID) == 0 { // a notification; the initialized handshake step
			continue
		}
		resp := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID)}
		result, rpcErr := dispatch(req)
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

func dispatch(req rpcRequest) (any, map[string]any) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "demo-tools", "version": "0.1.0"},
		}, nil
	case "tools/call":
		var a struct {
			Source string  `json:"source"`
			Limit  float64 `json:"limit"`
			Host   string  `json:"host"`
			Path   string  `json:"path"`
		}
		_ = json.Unmarshal(req.Params.Arguments, &a)
		switch req.Params.Name {
		case "search":
			hits := make([]string, 0, int(a.Limit))
			for i := 1; i <= int(a.Limit); i++ {
				hits = append(hits, fmt.Sprintf("%s/result-%d", a.Source, i))
			}
			return text(strings.Join(hits, ", ")), nil
		case "fetch_url":
			return text("200 OK from https://" + a.Host + a.Path), nil
		case "delete_file":
			return text("deleted " + a.Path), nil
		}
		return nil, map[string]any{"code": -32602, "message": "unknown tool: " + req.Params.Name}
	default:
		return nil, map[string]any{"code": -32601, "message": "method not found: " + req.Method}
	}
}

func text(s string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": s}},
		"isError": false,
	}
}

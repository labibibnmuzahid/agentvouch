package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

func serve(args []string, reg *Registry, supplier *Agent) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	host := fs.String("host", "agentvouch.us", "public hostname advertised in the agent card")
	fs.Parse(args)

	page, _ := webFS.ReadFile("web/index.html")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.HandleFunc("GET /api/run", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		writeJSON(w, http.StatusOK, RunDemo(ctx, reg, supplier))
	})
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, agentCard(*host))
	})
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		handleMCP(w, r, func() Report { return RunDemo(ctx, reg, supplier) })
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("AgentVouch serving %s on %s", *host, *addr)
	log.Fatal(srv.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func agentCard(host string) map[string]any {
	base := "https://" + host
	return map[string]any{
		"name":            "AgentVouch",
		"description":     "Buyer-side payment agent that verifies a seller's ANS identity, liveness, proof-of-possession and signed quote before any money moves, and refuses impostors.",
		"url":             base,
		"version":         "1.0.0",
		"protocolVersion": "1.0",
		"provider":        map[string]any{"organization": "AgentVouch", "url": base},
		"capabilities": map[string]any{
			"streaming": false,
			"extensions": []map[string]any{{
				"uri":         "https://modelcontextprotocol.io",
				"description": "MCP server exposing the verification demo.",
				"params":      map[string]any{"endpoint": base + "/mcp", "transport": "streamable-http", "protocolVersion": mcpProtocolVersion},
			}},
		},
		"defaultInputModes":  []string{"application/json"},
		"defaultOutputModes": []string{"application/json"},
		"skills": []map[string]any{{
			"id":          "run_scenarios",
			"name":        "Verify-then-pay scenarios",
			"description": "Verifies sellers against the live GoDaddy ANS transparency log: one legitimate payment and five blocked attacks (impostor certificate, copied certificate, replay, swapped quote, genuine-but-unauthorized payee), with evidence and the hash-chained audit ledger.",
			"tags":        []string{"ANS", "verification", "payments"},
		}},
	}
}

const mcpProtocolVersion = "2025-03-26"

type rpcRequest struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// handleMCP is a minimal streamable-HTTP MCP server with a single tool.
func handleMCP(w http.ResponseWriter, r *http.Request, run func() Report) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, rpcError(nil, -32700, "parse error"))
		return
	}
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var result any
	switch req.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "agentvouch", "version": "1.0.0"},
		}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": []map[string]any{{
			"name":        "run_scenarios",
			"description": "Run AgentVouch's verify-then-pay scenarios against live ANS: one legitimate payment and five blocked attacks, with evidence and the audit ledger.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		}}}
	case "tools/call":
		if req.Params.Name != "run_scenarios" {
			writeJSON(w, http.StatusOK, rpcError(req.ID, -32602, "unknown tool: "+req.Params.Name))
			return
		}
		body, _ := json.Marshal(run())
		result = map[string]any{"content": []map[string]any{{"type": "text", "text": string(body)}}, "isError": false}
	default:
		writeJSON(w, http.StatusOK, rpcError(req.ID, -32601, "method not found: "+req.Method))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

func rpcError(id json.RawMessage, code int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}}
}

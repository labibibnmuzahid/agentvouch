package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html web/app.css web/app.js
var webFS embed.FS

const mcpProtocolVersion = "2025-03-26"

type server struct {
	host     string
	reg      *Registry
	buyer    *Buyer
	fleet    Fleet
	supplier *Agent
	ans      *ttlCache[*ANSEvidence]
	cardSigs *ttlCache[signedCard]
	ledger   *Ledger
	anchorer *Anchorer
	store    *Store
	sol      *Solana
	llm      *Gemini
	rail     PaymentRail

	lastMu sync.Mutex
	last   *Report

	perIP  *limiter
	global *limiter
}

// persona is the agent a request's hostname addresses. Each of our ANS agents
// answers as itself, with its own identity certificate and cards.
type persona struct {
	host     string
	agent    *Agent
	supplier bool
}

func (s *server) personaFor(r *http.Request) persona {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch {
	case host == supplierHost && s.fleet.Supplier != nil:
		return persona{host, s.fleet.Supplier, true}
	case host == buyerHost && s.fleet.Buyer != nil:
		return persona{host, s.fleet.Buyer, false}
	}
	return persona{s.host, s.fleet.Root, false}
}

func serve(args []string, reg *Registry, buyer *Buyer, fleet Fleet, rail PaymentRail) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	host := fs.String("host", "agentvouch.us", "public hostname advertised in the agent card")
	fs.Parse(args)

	s := &server{
		host: *host, reg: reg, buyer: buyer, fleet: fleet, supplier: fleet.supplier(), rail: rail,
		ans:      newTTLCache[*ANSEvidence](10 * time.Minute),
		cardSigs: newTTLCache[signedCard](time.Hour),
		perIP:    newLimiter(1, 20),
		global:   newLimiter(5, 20),
	}
	stateDir := os.Getenv("STATE_DIRECTORY")
	if stateDir == "" {
		stateDir = "state"
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Fatal(err)
	}
	ledger, err := OpenLedger(filepath.Join(stateDir, "ledger.jsonl"))
	if err != nil {
		log.Fatal(err)
	}
	if !ledger.Verify() {
		log.Printf("LEDGER INTEGRITY FAILURE: %s does not verify", filepath.Join(stateDir, "ledger.jsonl"))
	}
	sol, err := loadSolana()
	if err != nil {
		log.Printf("solana anchoring disabled: %v", err)
		sol = nil
	}
	anchorer, err := NewAnchorer(sol, ledger, filepath.Join(stateDir, "anchors.jsonl"))
	if err != nil {
		log.Fatal(err)
	}
	go anchorer.Run(context.Background())
	s.ledger, s.anchorer, s.sol = ledger, anchorer, sol

	// MongoDB Atlas holds the durable, queryable replica. It is optional and
	// never on the decision path: it connects in the background, and if it is
	// unreachable the checks and the local chain carry on unchanged.
	if store := newStore(); store == nil {
		log.Printf("mongodb atlas: no MONGODB_URI, the ledger stays local")
	} else {
		go store.Run(context.Background())
		store.MirrorLedger(ledger.All())
		s.store, anchorer.store = store, store
		for _, a := range anchorer.History(10) {
			store.RecordAnchor(a)
		}
	}
	s.initLLM()

	page, _ := webFS.ReadFile("web/index.html")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The dashboard's script and stylesheet are served as their own files, so
		// the policy can refuse inline script entirely rather than allowing it.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Write(page)
	})
	for _, asset := range []struct{ path, file, mime string }{
		{"GET /app.css", "web/app.css", "text/css; charset=utf-8"},
		{"GET /app.js", "web/app.js", "text/javascript; charset=utf-8"},
	} {
		body, _ := webFS.ReadFile(asset.file)
		mime := asset.mime
		mux.HandleFunc(asset.path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", mime)
			w.Header().Set("Cache-Control", "no-cache")
			w.Write(body)
		})
	}
	mux.Handle("POST /{$}", s.limited(s.handleA2A))
	mux.Handle("GET /api/run", s.limited(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.run(r.Context()))
	}))
	mux.Handle("GET /api/vouch", s.limited(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.vouch(r.Context(), r.URL.Query().Get("host")))
	}))
	mux.Handle("POST /mcp", s.limited(s.handleMCP))
	mux.HandleFunc("GET /api/ledger", s.handleLedger)
	mux.Handle("POST /api/ask", s.limited(s.handleAsk))
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.signedAgentCard(r.Context(), s.personaFor(r)))
	})
	mux.HandleFunc("GET /.well-known/ans/trust-card.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.trustCard(r.Context(), s.personaFor(r)))
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{publicJWK(s.personaFor(r).agent.Cert())}})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	// DNS-AID: the documents the _dnsid TXT record points at, plus the
	// organization index that lists every agent we run.
	if key := loadOperatorKey(); key != nil {
		jwks := operatorJWKS(key)
		mux.HandleFunc("GET /.well-known/dnsid/op-keys.json", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, jwks)
		})
		mux.HandleFunc("GET /.well-known/dnsid/status.json", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ACTIVE"})
		})
	} else {
		log.Printf("dns-aid: no operator key, _dnsid documents are not served")
	}
	if ids, err := fleetHosts(); err == nil {
		index := agentsIndex(ids)
		mux.HandleFunc("GET /.well-known/agents-index.json", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, index)
		})
	} else {
		log.Printf("dns-aid: no agent index (%v)", err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	log.Printf("AgentVouch serving %s on %s", *host, *addr)
	log.Fatal(srv.ListenAndServe())
}

func (s *server) run(ctx context.Context) Report {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rep := RunDemo(ctx, s.reg, s.buyer, s.supplier, s.ledger, s.rail)
	s.anchorer.Kick()
	rep.Anchor, rep.AnchorState = s.anchorer.Latest()
	s.store.MirrorLedger(rep.Ledger)
	s.store.RecordDecisions(newNonce()[:12], rep.Scenarios)
	for _, sc := range rep.Scenarios {
		s.store.ObserveAgent(strings.ToLower(sc.Evidence.FQDN), sc.Evidence.ANS)
	}
	s.lastMu.Lock()
	s.last = &rep
	s.lastMu.Unlock()
	return rep
}

func (s *server) lastRun() *Report {
	s.lastMu.Lock()
	defer s.lastMu.Unlock()
	return s.last
}

// initLLM enables Gemini replies when a key is configured. Its tools are
// read-only views of the deterministic checks.
func (s *server) initLLM() {
	g := loadGemini()
	if g == nil {
		log.Printf("gemini: no GEMINI_API_KEY, using rule-based replies")
		return
	}
	g.addTool("vouch",
		"Verify an agent by hostname against the GoDaddy ANS transparency log. Returns the verdict, ANS name, status, transparency-log leaf, sealed certificate fingerprint and advisory Trust Index.",
		map[string]any{"type": "OBJECT", "required": []string{"host"}, "properties": map[string]any{
			"host": map[string]any{"type": "STRING", "description": "agent hostname, e.g. supplier.webmesh.ai"},
		}},
		func(ctx context.Context, args map[string]any) (any, error) {
			h, _ := args["host"].(string)
			return s.vouch(ctx, h), nil
		})
	g.addTool("run_scenarios",
		"Run the verify-then-pay demo live: one legitimate payment and eight attacks, each with the check that decided it.",
		nil,
		func(ctx context.Context, _ map[string]any) (any, error) { return summarize(s.run(ctx)), nil })
	g.addTool("recent_decisions",
		"Return the most recent verify-then-pay decisions with their evidence, plus the audit ledger's state and Solana anchor, without running anything new.",
		nil,
		func(ctx context.Context, _ map[string]any) (any, error) {
			if r := s.lastRun(); r != nil {
				return summarize(*r), nil
			}
			return map[string]any{"note": "no decisions yet in this session; call run_scenarios"}, nil
		})
	if s.store != nil {
		g.addTool("agent_history",
			"Look up AgentVouch's own record of one hostname in MongoDB Atlas: what ANS said about it each time it was resolved (status, sealed certificate fingerprint, advisory Trust Index) and every payment it has been refused, with the reason and how often. Use it for questions about the past, or about whether an agent has changed.",
			map[string]any{"type": "OBJECT", "required": []string{"host"}, "properties": map[string]any{
				"host": map[string]any{"type": "STRING", "description": "agent hostname, e.g. supplier.agentvouch.us"},
			}},
			func(ctx context.Context, args map[string]any) (any, error) {
				h, _ := args["host"].(string)
				if h, ok := normalizeHost(h); ok {
					return s.store.HostReport(ctx, h)
				}
				return nil, errors.New("not a public DNS hostname")
			})
	}
	s.llm = g
	log.Printf("gemini: enabled (%s)", g.model)
}

// summarize is the compact view of a run that the model reasons over.
func summarize(r Report) map[string]any {
	var sc []map[string]any
	for _, x := range r.Scenarios {
		m := map[string]any{"id": x.ID, "title": x.Title, "paid": x.Paid, "amountUsd": x.Amount}
		if p := x.Payment; p != nil {
			m["payment"] = map[string]any{"rail": p.Rail, "transfer": p.TxID, "status": p.Status, "paidToAccount": p.PayTo}
		}
		if x.Evidence.Reason != "" {
			m["blockedBecause"] = x.Evidence.Reason
		}
		if a := x.Evidence.ANS; a != nil {
			m["ansName"], m["ansStatus"], m["transparencyLogLeaf"] = a.ANSName, a.Status, a.LeafIndex
			m["sealedCert"] = short(a.SealedFingerprint, 12)
			if a.TrustScore != nil {
				m["trustIndex"] = *a.TrustScore
			}
		}
		sc = append(sc, m)
	}
	out := map[string]any{"scenarios": sc, "ledgerEntries": r.LedgerSize, "ledgerIntact": r.LedgerOK, "anchorState": r.AnchorState}
	if r.Anchor != nil {
		out["solanaAnchor"] = map[string]any{"entriesCovered": r.Anchor.Entries, "tx": r.Anchor.Signature, "explorer": r.Anchor.Explorer}
	}
	return out
}

// handleAsk lets a person on the dashboard talk to AgentVouch the same way
// other agents do over A2A.
func (s *server) handleAsk(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Text) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "send {\"text\": \"...\"}"})
		return
	}
	reply, data, engine := s.respond(r.Context(), s.personaFor(r), req.Text)
	writeJSON(w, http.StatusOK, map[string]any{"reply": reply, "evidence": data, "engine": engine})
}

// handleLedger publishes the chain and its Solana anchors so anyone can
// recompute every seal and compare the head against the on-chain memo.
func (s *server) handleLedger(w http.ResponseWriter, r *http.Request) {
	n := 100
	if r.URL.Query().Get("all") == "1" {
		n = 5000
	}
	size, head := s.ledger.Head()
	latest, state := s.anchorer.Latest()
	out := map[string]any{
		"size": size, "head": head, "ok": s.ledger.Verify(),
		"entries": s.ledger.Tail(n), "anchors": s.anchorer.History(10),
		"latestAnchor": latest, "anchorState": state, "cluster": "devnet",
		"seal":       "sha256 over canonical JSON (sorted keys) of {detail, event, index, prev, time}",
		"memoFormat": anchorMemo(0, "<seal>"),
	}
	if latest != nil {
		out["latestAnchorHeadMatches"] = func() bool { h, ok := s.ledger.HeadAt(latest.Entries); return ok && h == latest.Head }()
		// Read the anchor back off-chain-independent: fetch the memo Solana stored.
		if s.sol != nil && r.URL.Query().Get("onchain") == "1" {
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			memo, err := s.sol.Memo(ctx, latest.Signature)
			switch {
			case err != nil:
				out["onChainMemo"] = "could not read: " + err.Error()
			default:
				head, ok := s.ledger.HeadAt(latest.Entries)
				out["onChainMemo"] = memo
				out["onChainMatchesLedger"] = ok && memo == anchorMemo(latest.Entries, head)
			}
		}
	}
	if s.sol != nil {
		out["wallet"] = s.sol.Address()
	}
	if s.store != nil {
		out["atlas"] = s.store.State(r.Context())
		if top, err := s.store.Refusals(r.Context(), "", 5); err == nil {
			out["atlasRefusals"] = top
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) vouch(ctx context.Context, host string) VouchResult {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	res := Vouch(ctx, s.reg, host)
	s.store.ObserveAgent(res.Host, res.ANS)
	return res
}

// ansInfo is one of our agents' own transparency-log record, for the cards.
func (s *server) ansInfo(ctx context.Context, p persona) *ANSEvidence {
	if a, ok := s.ans.get(p.host); ok {
		return a
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	a := ansEvidence(s.reg.Resolve(ctx, p.agent.Cert()).Badge)
	if a != nil {
		s.ans.put(p.host, a)
	}
	return a
}

func (s *server) agentCard(ctx context.Context, p persona) map[string]any {
	base := "https://" + p.host
	if p.supplier {
		return s.supplierCard(ctx, p)
	}
	card := map[string]any{
		"name":            "AgentVouch",
		"description":     "Buyer-side payment agent that verifies who it is paying through GoDaddy ANS (sealed identity certificate, liveness, proof-of-possession, signed single-use quote) and refuses impostors. Ask it to vouch for any agent by hostname.",
		"url":             base,
		"version":         "1.0.0",
		"protocolVersion": "1.0",
		"provider":        map[string]any{"organization": "AgentVouch", "url": base},
		"supportedInterfaces": []map[string]any{
			{"url": base, "protocolBinding": "jsonrpc", "protocolVersion": "1.0"},
			{"url": base + "/mcp", "protocolBinding": "MCP", "protocolVersion": mcpProtocolVersion, "transport": "streamable-http"},
		},
		"capabilities": map[string]any{
			"streaming":         false,
			"pushNotifications": false,
			"extensions": []map[string]any{{
				"uri":         "https://modelcontextprotocol.io",
				"description": "MCP server with the vouch and run_scenarios tools.",
				"params":      map[string]any{"endpoint": base + "/mcp", "transport": "streamable-http", "protocolVersion": mcpProtocolVersion},
			}},
		},
		"securitySchemes": map[string]any{
			"noAuth": map[string]any{"type": "noAuth", "description": "Public and read-only: vouching and the demo scenarios need no credential. Rate limited per client."},
		},
		"securityRequirements": []map[string]any{{"noAuth": []string{}}},
		"defaultInputModes":    []string{"text/plain", "application/json"},
		"defaultOutputModes":   []string{"text/plain", "application/json"},
		"skills": []map[string]any{
			{
				"id":          "vouch",
				"name":        "Vouch for an agent",
				"description": "Given a hostname, fetches the agent's ANS trust card and verifies its identity certificate against the GoDaddy ANS transparency log (sealed fingerprint, hostname, ANS name, liveness), plus its advisory Trust Index score.",
				"tags":        []string{"ANS", "verification", "trust"},
				"examples":    []string{"vouch for supplier.webmesh.ai", "is rogue-supplier.webmesh.ai who it claims to be?"},
			},
			{
				"id":          "run_scenarios",
				"name":        "Verify-then-pay scenarios",
				"description": "Pays one genuinely verified supplier and blocks eight attacks (impostor certificate, copied certificate, replayed challenge, tampered quote, replayed quote, wrong-audience quote, over-limit payment, genuine-but-unauthorized payee), with evidence and a hash-chained audit ledger.",
				"tags":        []string{"ANS", "payments", "fraud"},
				"examples":    []string{"run scenarios"},
			},
		},
	}
	s.addIdentity(ctx, p, card)
	return card
}

type signedCard struct {
	payload string
	sigs    []map[string]any
}

// signedAgentCard signs the card with the agent's ANS identity key. The
// signature is reused while the card is unchanged, so watchers hashing the
// card see it stable between fetches.
func (s *server) signedAgentCard(ctx context.Context, p persona) map[string]any {
	card := s.agentCard(ctx, p)
	payload := string(canonicalJSON(card))
	if c, ok := s.cardSigs.get(p.host); ok && c.payload == payload {
		card["signatures"] = c.sigs
		return card
	}
	sigs := signAgentCard(p.agent, "https://"+p.host+"/.well-known/jwks.json", card)
	s.cardSigs.put(p.host, signedCard{payload: payload, sigs: sigs})
	card["signatures"] = sigs
	return card
}

func (s *server) supplierCard(ctx context.Context, p persona) map[string]any {
	base := "https://" + p.host
	card := map[string]any{
		"name":            "AgentVouch Demo Supplier",
		"description":     "Demo parts supplier for AgentVouch. Signs single-use quotes bound to one buyer, one amount and a short expiry with its ANS identity key; buyers verify it through GoDaddy ANS before paying.",
		"url":             base,
		"version":         "1.0.0",
		"protocolVersion": "1.0",
		"provider":        map[string]any{"organization": "AgentVouch", "url": "https://" + s.host},
		"supportedInterfaces": []map[string]any{
			{"url": base, "protocolBinding": "jsonrpc", "protocolVersion": "1.0"},
			{"url": base + "/mcp", "protocolBinding": "MCP", "protocolVersion": mcpProtocolVersion, "transport": "streamable-http"},
		},
		"capabilities": map[string]any{
			"streaming":         false,
			"pushNotifications": false,
			"extensions": []map[string]any{{
				"uri":         "https://modelcontextprotocol.io",
				"description": "MCP server with the vouch and run_scenarios tools.",
				"params":      map[string]any{"endpoint": base + "/mcp", "transport": "streamable-http", "protocolVersion": mcpProtocolVersion},
			}},
		},
		"securitySchemes": map[string]any{
			"noAuth": map[string]any{"type": "noAuth", "description": "Public, read-only description endpoint. Rate limited per client."},
		},
		"securityRequirements": []map[string]any{{"noAuth": []string{}}},
		"defaultInputModes":    []string{"text/plain"},
		"defaultOutputModes":   []string{"text/plain"},
		"skills": []map[string]any{{
			"id":          "issue_quote",
			"name":        "Issue signed quote",
			"description": "Signs quotes over quote ID, supplier, buyer, amount and expiry with the ANS-certified key, inside AgentVouch's verify-then-pay flow.",
			"tags":        []string{"quote", "payments"},
		}},
	}
	if _, simulated := s.rail.(simulatedRail); !simulated {
		// The account buyers must pay, attested under this card's ANS signature.
		card["x-payment"] = map[string]any{"rail": s.rail.Name(), "payTo": s.rail.SupplierAccount(), "currency": "USD"}
	}
	s.addIdentity(ctx, p, card)
	return card
}

func (s *server) addIdentity(ctx context.Context, p persona, card map[string]any) {
	card["x-security-note"] = "Reading is public and unauthenticated (noAuth): vouching, the scenarios and this card need no credential, and none of them move money. What is enforced is on the paying side: AgentVouch pays only a payee in its mandate, whose ANS-sealed identity certificate answered a fresh possession challenge, against a single-use quote signed by that same key, to an account attested in this signed card. The card is signed with the ANS identity key itself, so its signature ties it to the transparency log rather than to a key published beside it."
	a := s.ansInfo(ctx, p)
	if a == nil {
		return
	}
	card["x-identity"] = map[string]any{"ans": map[string]any{
		"uri":             a.ANSName,
		"trustCard":       "https://" + p.host + "/.well-known/ans/trust-card.json",
		"transparencyLog": a.BadgeURL,
	}}
	card["x-discovery"] = map[string]any{
		"ans_registered": "prod",
		"ans_name":       a.ANSName,
		"tl_badge":       a.BadgeURL,
		"trust_index": map[string]any{
			"score_url":   "https://api.godaddy.com/v1/ans/registered-agents?query=" + p.host,
			"score_field": "scores.trustScore",
			"auth":        "sso-key",
			"note":        "Advisory only. AgentVouch never authorizes a payment by score.",
		},
		"dns_aid_svcb": p.host + " IN SVCB 1 . alpn=a2a,h2",
		"dns_aid_txt":  "_dnsid." + p.host,
		"agents_index": "https://" + s.host + "/.well-known/agents-index.json",
	}
}

func (s *server) trustCard(ctx context.Context, p persona) map[string]any {
	base := "https://" + p.host
	name := "AgentVouch"
	endpoints := []map[string]any{
		{"protocol": "A2A", "agentUrl": base, "metaDataUrl": base + "/.well-known/agent-card.json"},
		{"protocol": "MCP", "agentUrl": base + "/mcp"},
	}
	if p.supplier {
		name, endpoints = "AgentVouch Demo Supplier", endpoints[:1]
	}
	card := map[string]any{
		"agentDisplayName": name,
		"agentHost":        p.host,
		"version":          "1.0.0",
		"endpoints":        endpoints,
		"keys":             []any{publicJWK(p.agent.Cert())},
	}
	if a := s.ansInfo(ctx, p); a != nil {
		card["ansName"], card["agentId"], card["transparencyLog"] = a.ANSName, a.AgentID, a.BadgeURL
	}
	return card
}

// ---- A2A (JSON-RPC, protocol 1.0) -------------------------------------------

var mentionedHostRE = regexp.MustCompile(`(?i)\b[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}\b`)

func (s *server) handleA2A(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Message struct {
				ContextID string `json:"contextId"`
				Parts     []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"message"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, rpcError(nil, -32700, "parse error"))
		return
	}
	log.Printf("a2a %s from %s ua=%q", req.Method, clientIP(r), r.UserAgent())
	if req.Method != "SendMessage" && req.Method != "message/send" {
		writeJSON(w, http.StatusOK, rpcError(req.ID, -32601, "method not found: "+req.Method+" (supported: SendMessage, message/send)"))
		return
	}
	var text strings.Builder
	for _, p := range req.Params.Message.Parts {
		text.WriteString(p.Text + " ")
	}
	reply, data := s.answer(r.Context(), s.personaFor(r), text.String())
	contextID := req.Params.Message.ContextID
	if contextID == "" {
		contextID = newNonce()
	}
	if req.Method == "message/send" {
		// A2A 0.3: a completed Task whose artifact carries the reply.
		parts := []map[string]any{{"kind": "text", "text": reply}}
		if data != nil {
			parts = append(parts, map[string]any{"kind": "data", "data": data})
		}
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
			"kind": "task", "id": newNonce(), "contextId": contextID,
			"status":    map[string]any{"state": "completed"},
			"artifacts": []map[string]any{{"artifactId": "result", "name": "agentvouch-result", "parts": parts}},
		}})
		return
	}
	parts := []map[string]any{{"text": reply}}
	if data != nil {
		parts = append(parts, map[string]any{"data": data})
	}
	taskID := newNonce()
	// A2A 1.0 SendMessageResponse: a Task whose final status carries the reply
	// message, with the same content as an artifact.
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
		"task": map[string]any{
			"id":        taskID,
			"contextId": contextID,
			"status": map[string]any{
				"state": "TASK_STATE_COMPLETED",
				"message": map[string]any{
					"messageId": newNonce(), "contextId": contextID, "taskId": taskID,
					"role": "ROLE_AGENT", "parts": parts,
				},
			},
			"artifacts": []map[string]any{{"artifactId": "result", "name": "agentvouch-result", "parts": parts}},
		},
	}})
}

// answer handles a free-text request without an LLM: vouch for any hostname
// mentioned, run the scenarios on request, otherwise describe the agent.
func (s *server) answer(ctx context.Context, p persona, text string) (string, any) {
	reply, data, _ := s.respond(ctx, p, text)
	return reply, data
}

// respond answers with Gemini when configured, and falls back to the
// rule-based reply if Gemini is missing, over budget or failing.
func (s *server) respond(ctx context.Context, p persona, text string) (string, any, string) {
	if s.llm != nil && !p.supplier {
		if r := []rune(text); len(r) > 2000 {
			text = string(r[:2000])
		}
		lctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		reply, used, err := s.llm.Answer(lctx, text)
		cancel()
		if err == nil {
			var data any
			if len(used) > 0 {
				data = used[len(used)-1]
			}
			return reply, data, "gemini"
		}
		log.Printf("gemini: %v (falling back to rules)", err)
	}
	reply, data := s.rulesAnswer(ctx, p, text)
	return reply, data, "rules"
}

func (s *server) rulesAnswer(ctx context.Context, p persona, text string) (string, any) {
	if p.supplier {
		name := "AgentVouch Demo Supplier"
		if a := s.ansInfo(ctx, p); a != nil {
			name += " (" + a.ANSName + ")"
		}
		return name + " signs single-use quotes, bound to one buyer, one amount and a short expiry, with its ANS identity key. " +
			"Buyers verify it through GoDaddy ANS before paying. To watch it get paid while impostors are refused, " +
			"ask https://" + buyerHost + " to \"run scenarios\".", nil
	}
	for _, h := range mentionedHostRE.FindAllString(text, 5) {
		if host, ok := normalizeHost(h); ok {
			v := s.vouch(ctx, host)
			msg := fmt.Sprintf("%s: %s. %s", v.Host, v.Verdict, v.Reason)
			if v.ANS != nil && v.ANS.TrustScore != nil {
				msg += fmt.Sprintf(" Trust Index %d (advisory).", *v.ANS.TrustScore)
			}
			return msg + " " + v.Note, v
		}
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "scenario") || strings.Contains(lower, "demo") || strings.Contains(lower, "run") {
		rep := s.run(ctx)
		var b strings.Builder
		for _, sc := range rep.Scenarios {
			verdict := "BLOCKED: " + sc.Evidence.Reason
			if sc.Paid {
				verdict = "PAID"
			}
			fmt.Fprintf(&b, "[%s] %s -> %s\n", sc.ID, sc.Title, verdict)
		}
		fmt.Fprintf(&b, "Ledger integrity: %v", rep.LedgerOK)
		return b.String(), rep
	}
	name := "AgentVouch"
	if a := s.ansInfo(ctx, p); a != nil {
		name += " (" + a.ANSName + ")"
	}
	return name + " is a buyer-side payment agent: before any money moves it verifies who it is paying through GoDaddy ANS " +
		"(identity certificate sealed in the transparency log, liveness, proof-of-possession, signed single-use quote) and refuses impostors. " +
		"Send me a hostname, e.g. \"vouch for supplier.webmesh.ai\", and I will check that agent's ANS identity and Trust Index. " +
		"Say \"run scenarios\" to watch me pay a verified supplier and block eight attacks. MCP: https://" + p.host + "/mcp", nil
}

// ---- MCP (streamable HTTP, JSON responses) ----------------------------------

func (s *server) handleMCP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		ID     json.RawMessage `json:"id,omitempty"`
		Method string          `json:"method"`
		Params struct {
			Name      string `json:"name"`
			Arguments struct {
				Host string `json:"host"`
			} `json:"arguments"`
		} `json:"params"`
	}
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
		result = map[string]any{"tools": []map[string]any{
			{
				"name":        "vouch",
				"description": "Verify an agent by hostname against the GoDaddy ANS transparency log: sealed identity certificate, hostname, ANS name, liveness, and advisory Trust Index score.",
				"inputSchema": map[string]any{"type": "object", "required": []string{"host"}, "properties": map[string]any{
					"host": map[string]any{"type": "string", "description": "agent hostname, e.g. supplier.webmesh.ai"},
				}},
			},
			{
				"name":        "run_scenarios",
				"description": "Run AgentVouch's verify-then-pay scenarios against live ANS: one legitimate payment and eight blocked attacks, with evidence and the audit ledger.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			},
		}}
	case "tools/call":
		var out any
		switch req.Params.Name {
		case "vouch":
			out = s.vouch(r.Context(), req.Params.Arguments.Host)
		case "run_scenarios":
			out = s.run(r.Context())
		default:
			writeJSON(w, http.StatusOK, rpcError(req.ID, -32602, "unknown tool: "+req.Params.Name))
			return
		}
		body, _ := json.Marshal(out)
		result = map[string]any{"content": []map[string]any{{"type": "text", "text": string(body)}}, "isError": false}
	default:
		writeJSON(w, http.StatusOK, rpcError(req.ID, -32601, "method not found: "+req.Method))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func rpcError(id json.RawMessage, code int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}}
}

// ---- hardening --------------------------------------------------------------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// limited guards endpoints that trigger outbound ANS, Trust Index and trust
// card lookups, so nobody can use us to hammer those services (which would get
// us throttled and, since we fail closed, block every payment).
func (s *server) limited(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.global.allow("*") || !s.perIP.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		h(w, r)
	})
}

// clientIP trusts X-Forwarded-For only from the local reverse proxy (Caddy),
// which replaces any client-supplied value with the real peer address.
func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return host
}

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
}

func newLimiter(perSecond, burst float64) *limiter {
	return &limiter{rate: perSecond, burst: burst, buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.buckets) > 10000 {
		clear(l.buckets)
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

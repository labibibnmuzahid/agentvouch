package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	buyerFQDN = "buyer.acme-treasury.example"
	fraudHost = "fraud.webmesh.ai"
)

func newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

type Scenario struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Expect   string   `json:"expect"`
	Evidence Evidence `json:"evidence"`
	Amount   int      `json:"amount"`
	Paid     bool     `json:"paid"`
	Tx       string   `json:"tx,omitempty"`
}

type Report struct {
	Scenarios []Scenario `json:"scenarios"`
	Ledger    []Entry    `json:"ledger"`
	LedgerOK  bool       `json:"ledgerOK"`
}

func main() {
	supplier, err := loadSupplier()
	if err != nil {
		log.Fatal(err)
	}
	reg := NewRegistry()

	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve(os.Args[2:], reg, supplier)
		return
	}

	fmt.Println("AgentVouch - agents that verify who they pay, and refuse impostors")
	fmt.Println("GoDaddy ANS (identity, live) . Capital One Nessie (payment) . auditable ledger (Peraton)")
	fmt.Println("Threat model: lookalike/impostor cert . copied card . forged signature . replay . swapped quote . genuine-but-unauthorized payee")
	fmt.Println("=================================================================================")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := RunDemo(ctx, reg, supplier)
	for _, s := range r.Scenarios {
		fmt.Printf("\n[%s] %s\n", s.ID, s.Title)
		s.Evidence.Print()
		if s.Paid {
			fmt.Printf("      [OK] verified - paid $%d via Capital One Nessie (tx %s)\n", s.Amount, s.Tx)
		} else {
			fmt.Printf("      [X] BLOCKED - %s\n      [X] payment refused. No money moved.\n", s.Evidence.Reason)
		}
	}

	fmt.Println("\nAudit ledger (hash-chained):")
	for i, e := range r.Ledger {
		fmt.Printf("  #%d %-16s %s | %s | seal %s\n", i, e.Event, e.Time, e.Detail, e.Hash[:12])
	}
	fmt.Printf("\nLedger integrity: %v\n", r.LedgerOK)
}

// RunDemo plays the success path and the attacks, verifying every seller
// against the live ANS transparency log.
func RunDemo(ctx context.Context, reg *Registry, supplier *Agent) Report {
	rc := NewReplayCache()
	ledger := &Ledger{}
	host := supplier.Cert().DNSNames[0]
	mandate := Mandate{Payees: []string{host}}

	amt := 50000
	var out []Scenario
	run := func(id, expect, title string, seller Peer, q Quote, nonce string) {
		s := settle(ctx, reg, rc, mandate, ledger, seller, q, nonce)
		s.ID, s.Expect, s.Title = id, expect, title
		out = append(out, s)
	}

	nA := newNonce()
	run("A", "pay", fmt.Sprintf("SUCCESS PATH - buyer pays the real ANS-registered supplier %s ($%d)", host, amt),
		supplier, IssueQuote(supplier, amt, newNonce()), nA)

	impostor := newImpostor(supplier.Cert())
	run("B", "block", "REFUSAL - impostor presents its own certificate claiming "+host,
		impostor, IssueQuote(impostor, amt, newNonce()), newNonce())

	run("C", "block", "REFUSAL - attacker copies "+host+"'s real ANS certificate but cannot sign for it",
		newForgedPeer(supplier.Cert()), IssueQuote(supplier, amt, newNonce()), newNonce())

	run("D", "block", "REFUSAL - attacker replays scenario A's challenge nonce",
		supplier, IssueQuote(supplier, amt, newNonce()), nA)

	qE := IssueQuote(supplier, amt, newNonce())
	qE.AmountUSD = amt * 10
	run("E", "block", fmt.Sprintf("REFUSAL - man-in-the-middle swaps the quote to $%d after signing", amt*10),
		supplier, qE, newNonce())

	title := "REFUSAL - " + fraudHost + " is a real, live ANS agent, but not in the buyer's mandate"
	if fraud, err := fetchTrustCardAgent(ctx, fraudHost); err != nil {
		ev := Evidence{FQDN: fraudHost, Reason: "identity: could not fetch " + fraudHost + " trust card, failing closed: " + err.Error()}
		ledger.Append("PAYMENT_BLOCKED", fraudHost+" - "+ev.Reason)
		out = append(out, Scenario{ID: "F", Expect: "block", Title: title, Evidence: ev, Amount: amt})
	} else {
		run("F", "block", title, fraud, IssueQuote(fraud, amt, newNonce()), newNonce())
	}

	return Report{Scenarios: out, Ledger: ledger.Entries(), LedgerOK: ledger.Verify()}
}

func settle(ctx context.Context, reg *Registry, rc *ReplayCache, m Mandate, ledger *Ledger, seller Peer, q Quote, nonce string) Scenario {
	ev := Authenticate(ctx, reg, rc, m, seller, q, nonce)
	s := Scenario{Evidence: ev, Amount: q.AmountUSD}
	if !ev.OK {
		ledger.Append("PAYMENT_BLOCKED", ev.FQDN+" - "+ev.Reason)
		return s
	}
	tx, _ := Transfer(buyerFQDN, ev.FQDN, q.AmountUSD)
	s.Paid, s.Tx = true, tx
	ledger.Append("PAYMENT_SENT", fmt.Sprintf("$%d to %s tx %s | ANS %s leaf %d", q.AmountUSD, ev.FQDN, tx, ev.ANS.ANSName, ev.ANS.LeafIndex))
	return s
}

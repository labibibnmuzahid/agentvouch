package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
)

func newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ForgedPeer presents the real supplier's card (copied public key) but cannot
// sign for it - it holds a different private key.
type ForgedPeer struct {
	card Card
	priv ed25519.PrivateKey
}

func (f ForgedPeer) Card() Card             { return f.card }
func (f ForgedPeer) Sign(msg []byte) []byte { return ed25519.Sign(f.priv, msg) }

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
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve(os.Args[2:])
		return
	}

	fmt.Println("AgentVouch - agents that verify who they pay, and refuse impostors")
	fmt.Println("GoDaddy ANS (identity) . Capital One Nessie (payment) . auditable ledger (Peraton)")
	fmt.Println("Threat model: lookalike domain . copied card . forged signature . replay . swapped quote")
	fmt.Println("=================================================================================")

	r := RunDemo()
	for _, s := range r.Scenarios {
		fmt.Printf("\n[%s] %s\n", s.ID, s.Title)
		s.Evidence.Print()
		if s.Paid {
			fmt.Printf("      [OK] verified - paid $%d via Capital One Nessie (tx %s)\n", s.Amount, s.Tx)
		} else {
			fmt.Printf("      [X] BLOCKED - %s\n      [X] payment refused. No money moved.\n", s.Evidence.Reason)
		}
	}

	fmt.Println("\nAudit ledger (hash-chained transparency log):")
	for i, e := range r.Ledger {
		fmt.Printf("  #%d %-16s %s | %s | seal %s\n", i, e.Event, e.Time, e.Detail, e.Hash[:12])
	}
	fmt.Printf("\nLedger integrity: %v\n", r.LedgerOK)
}

// RunDemo plays the success path and the four attacks against a fresh registry.
func RunDemo() Report {
	reg := NewRegistry()
	rc := NewReplayCache()
	ledger := &Ledger{}

	buyer := NewAgent("buyer.acme-treasury.example", "buyer")
	supplier := NewAgent("supplier.parts-co.example", "supplier")
	reg.Register(buyer)
	reg.Register(supplier)
	ledger.Append("ANS_REGISTER", "supplier.parts-co.example key "+keyID(supplier.Card().Pub))

	amt := 50000
	var out []Scenario
	run := func(id, expect, title string, seller Peer, q Quote, nonce string) {
		s := settle(reg, rc, ledger, buyer, seller, q, nonce)
		s.ID, s.Expect, s.Title = id, expect, title
		out = append(out, s)
	}

	nA := newNonce()
	run("A", "pay", fmt.Sprintf("SUCCESS PATH - buyer pays the REAL supplier ($%d)", amt),
		supplier, supplier.IssueQuote(amt, newNonce()), nA)

	rogue := NewAgent("supplier.parts-co.example", "supplier")
	run("B", "block", "REFUSAL - impostor reuses supplier.parts-co.example with its OWN key",
		rogue, rogue.IssueQuote(amt, newNonce()), newNonce())

	_, fakePriv, _ := ed25519.GenerateKey(rand.Reader)
	run("C", "block", "REFUSAL - attacker copies the supplier's card but cannot sign for it",
		ForgedPeer{card: supplier.Card(), priv: fakePriv}, supplier.IssueQuote(amt, newNonce()), newNonce())

	run("D", "block", "REFUSAL - attacker replays scenario A's challenge nonce",
		supplier, supplier.IssueQuote(amt, newNonce()), nA)

	qE := supplier.IssueQuote(amt, newNonce())
	qE.AmountUSD = amt * 10
	run("E", "block", fmt.Sprintf("REFUSAL - man-in-the-middle swaps the quote to $%d after signing", amt*10),
		supplier, qE, newNonce())

	return Report{Scenarios: out, Ledger: ledger.Entries(), LedgerOK: ledger.Verify()}
}

func settle(reg *Registry, rc *ReplayCache, ledger *Ledger, buyer *Agent, seller Peer, q Quote, nonce string) Scenario {
	ev := Authenticate(reg, rc, seller, q, nonce)
	s := Scenario{Evidence: ev, Amount: q.AmountUSD}
	if !ev.OK {
		ledger.Append("PAYMENT_BLOCKED", ev.FQDN+" - "+ev.Reason)
		return s
	}
	tx, _ := Transfer(buyer.FQDN, ev.FQDN, q.AmountUSD)
	s.Paid, s.Tx = true, tx
	ledger.Append("PAYMENT_SENT", fmt.Sprintf("$%d to %s tx %s", q.AmountUSD, ev.FQDN, tx))
	return s
}

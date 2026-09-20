package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	buyerFQDN      = "buyer.acme-treasury.example"
	otherBuyerFQDN = "buyer.other-corp.example"
	fraudHost      = "fraud.webmesh.ai"
	mandateLimit   = 100000
	buyerHost      = "buyer.agentvouch.us"
	supplierHost   = "supplier.agentvouch.us"
)

// Fleet holds our ANS identities: the root agentvouch.us agent, AgentVouch's
// buyer agent, and the demo supplier. Buyer and Supplier stay nil until their
// registrations exist on this machine; until then the root agent stands in.
type Fleet struct {
	Root, Buyer, Supplier *Agent
}

func loadFleet() (Fleet, error) {
	var f Fleet
	var err error
	if f.Root, err = loadAgent("identity", "certs"); err != nil {
		return f, err
	}
	for _, m := range []struct {
		name, host string
		dst        **Agent
	}{{"buyer", buyerHost, &f.Buyer}, {"supplier", supplierHost, &f.Supplier}} {
		a, err := loadAgent(m.name, filepath.Join("certs", m.host))
		switch {
		case err == nil:
			*m.dst = a
		case errors.Is(err, fs.ErrNotExist):
			log.Printf("no %s identity yet, %s stands in", m.host, certHost(f.Root.Cert()))
		default:
			return f, err
		}
	}
	return f, nil
}

func (f Fleet) supplier() *Agent {
	if f.Supplier != nil {
		return f.Supplier
	}
	return f.Root
}

func (f Fleet) buyerName() string {
	if f.Buyer != nil {
		return certHost(f.Buyer.Cert())
	}
	return buyerFQDN
}

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
	Payment  *Payment `json:"payment,omitempty"`
}

type Report struct {
	Scenarios   []Scenario `json:"scenarios"`
	Ledger      []Entry    `json:"ledger"`
	LedgerOK    bool       `json:"ledgerOK"`
	LedgerSize  int        `json:"ledgerSize"`
	Anchor      *Anchor    `json:"anchor,omitempty"`
	AnchorState string     `json:"anchorState,omitempty"`
}

func main() {
	if len(os.Args) > 1 {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var run func(context.Context) error
		switch os.Args[1] {
		case "nessie-setup":
			run = nessieSetup
		case "mongo-check":
			run = mongoCheck
		case "dnsid-key":
			run = func(context.Context) error { return newOperatorKey() }
		case "dns-records":
			run = func(context.Context) error { return dnsRecords() }
		}
		if run != nil {
			if err := run(ctx); err != nil {
				log.Fatal(err)
			}
			cancel()
			return
		}
		cancel()
	}
	fleet, err := loadFleet()
	if err != nil {
		log.Fatal(err)
	}
	reg := NewRegistry()
	supplier := fleet.supplier()
	rail := newRail()
	payee := PayeeResolver(signedCardPayee)
	if _, simulated := rail.(simulatedRail); simulated {
		payee = simulatedPayee(supplier.Cert(), rail)
	}
	buyer := NewBuyer(fleet.buyerName(), Mandate{Payees: []string{certHost(supplier.Cert())}, MaxAmountUSD: mandateLimit}, payee)

	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve(os.Args[2:], reg, buyer, fleet, rail)
		return
	}

	fmt.Println("AgentVouch - agents that verify who they pay, and refuse impostors")
	fmt.Println("GoDaddy ANS (identity, live) . Capital One Nessie (payment) . auditable ledger (Peraton)")
	fmt.Println("Threat model: impostor cert . copied cert . replayed challenge . tampered quote . replayed quote . wrong-audience quote . over-limit payment . genuine-but-unauthorized payee")
	fmt.Println("=================================================================================")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ledger, _ := OpenLedger("")
	r := RunDemo(ctx, reg, buyer, supplier, ledger, rail)
	for _, s := range r.Scenarios {
		fmt.Printf("\n[%s] %s\n", s.ID, s.Title)
		s.Evidence.Print()
		if s.Paid {
			fmt.Printf("      [OK] verified - paid $%d via %s (tx %s)\n", s.Amount, s.Payment.Rail, s.Tx)
		} else {
			fmt.Printf("      [X] BLOCKED - %s\n      [X] payment refused. No money moved.\n", s.Evidence.Reason)
		}
	}

	fmt.Println("\nAudit ledger (hash-chained):")
	for _, e := range r.Ledger {
		fmt.Printf("  #%d %-16s %s | %s | seal %s\n", e.Index, e.Event, e.Time, e.Detail, e.Hash[:12])
	}
	fmt.Printf("\nLedger integrity: %v\n", r.LedgerOK)
}

// RunDemo plays the success path and the attacks, verifying every seller
// against the live ANS transparency log.
func RunDemo(ctx context.Context, reg *Registry, buyer *Buyer, supplier *Agent, ledger *Ledger, rail PaymentRail) Report {
	host := certHost(supplier.Cert())
	amt := 50000

	var out []Scenario
	var logged []Entry
	run := func(id, expect, title string, seller Peer, q Quote, nonce string) {
		s, e := settle(ctx, reg, buyer, ledger, rail, seller, q, nonce)
		s.ID, s.Expect, s.Title = id, expect, title
		out = append(out, s)
		logged = append(logged, e)
	}
	payTo := rail.SupplierAccount()
	quote := func(seller Peer, to string, amount int) Quote {
		return IssueQuote(seller, newQuoteTerms(certHost(seller.Cert()), to, amount, payTo))
	}

	nA := newNonce()
	qA := quote(supplier, buyer.Name, amt)
	run("A", "pay", fmt.Sprintf("SUCCESS PATH - %s pays the real ANS-registered supplier %s ($%d)", buyer.Name, host, amt),
		supplier, qA, nA)

	impostor := newImpostor(supplier.Cert())
	run("B", "block", "REFUSAL - impostor presents its own certificate claiming "+host,
		impostor, quote(impostor, buyer.Name, amt), newNonce())

	forged := newForgedPeer(supplier.Cert())
	run("C", "block", "REFUSAL - attacker copies "+host+"'s real ANS certificate but cannot sign for it",
		forged, quote(supplier, buyer.Name, amt), newNonce())

	run("D", "block", "REFUSAL - attacker replays scenario A's challenge nonce",
		supplier, quote(supplier, buyer.Name, amt), nA)

	qE := quote(supplier, buyer.Name, amt)
	qE.Terms.AmountUSD = 95000
	run("E", "block", "REFUSAL - man-in-the-middle raises the signed $50000 quote to $95000",
		supplier, qE, newNonce())

	run("F", "block", "REFUSAL - attacker replays scenario A's genuinely signed quote in a new session",
		supplier, qA, newNonce())

	run("G", "block", "REFUSAL - attacker forwards a quote the supplier signed for a different buyer",
		supplier, quote(supplier, otherBuyerFQDN, amt), newNonce())

	run("H", "block", fmt.Sprintf("REFUSAL - genuine, correctly signed quote for $250000 exceeds the $%d mandate", mandateLimit),
		supplier, quote(supplier, buyer.Name, 250000), newNonce())

	title := "REFUSAL - " + fraudHost + " is a real, live ANS agent, but not in the buyer's mandate"
	if fraud, err := fetchTrustCardAgent(ctx, fraudHost); err != nil {
		ev := Evidence{FQDN: fraudHost, Reason: "identity: could not fetch " + fraudHost + "'s ANS trust card, failing closed"}
		log.Printf("trust card %s: %v", fraudHost, err)
		logged = append(logged, ledger.Append("PAYMENT_BLOCKED", fraudHost+" - "+ev.Reason))
		out = append(out, Scenario{ID: "I", Expect: "block", Title: title, Evidence: ev, Amount: amt})
	} else {
		run("I", "block", title, fraud, quote(fraud, buyer.Name, amt), newNonce())
	}

	run("J", "block", "REFUSAL - a genuinely signed quote routes the payment to a bank account "+host+" never attested",
		supplier, IssueQuote(supplier, newQuoteTerms(host, buyer.Name, amt, rail.AttackerAccount())), newNonce())

	size, _ := ledger.Head()
	return Report{Scenarios: out, Ledger: logged, LedgerOK: ledger.Verify(), LedgerSize: size}
}

func settle(ctx context.Context, reg *Registry, buyer *Buyer, ledger *Ledger, rail PaymentRail, seller Peer, q Quote, nonce string) (Scenario, Entry) {
	ev := buyer.Authenticate(ctx, reg, seller, q, nonce)
	s := Scenario{Evidence: ev, Amount: q.Terms.AmountUSD}
	if !ev.OK {
		return s, ledger.Append("PAYMENT_BLOCKED", ev.FQDN+" - "+ev.Reason)
	}
	// Money moves only here, after every check has passed.
	p, err := rail.Pay(ctx, q.Terms.PayTo, q.Terms.AmountUSD, "AgentVouch "+q.Terms.QuoteID+" to "+ev.FQDN)
	if err != nil {
		log.Printf("payment failed: %v", err)
		s.Evidence.OK = false
		s.Evidence.Reason = "payment: " + rail.Name() + " transfer failed after every check passed (" + err.Error() + "); nothing was paid"
		return s, ledger.Append("PAYMENT_FAILED", ev.FQDN+" - "+s.Evidence.Reason)
	}
	s.Paid, s.Tx, s.Payment = true, p.TxID, &p
	return s, ledger.Append("PAYMENT_SENT", fmt.Sprintf("$%d to %s via %s tx %s (account %s) | quote %s | ANS %s leaf %d",
		q.Terms.AmountUSD, ev.FQDN, p.Rail, p.TxID, short(p.PayTo, 12), q.Terms.QuoteID, ev.ANS.ANSName, ev.ANS.LeafIndex))
}

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Payment is what the buyer did after every check passed.
type Payment struct {
	Rail       string `json:"rail"`
	TxID       string `json:"tx"`
	Withdrawal string `json:"withdrawal,omitempty"`
	Deposit    string `json:"deposit,omitempty"`
	Status     string `json:"status"`
	PayTo      string `json:"payTo"`
}

// PaymentRail moves money once the buyer has verified the payee.
type PaymentRail interface {
	Name() string
	SupplierAccount() string
	AttackerAccount() string
	Pay(ctx context.Context, payTo string, amountUSD int, memo string) (Payment, error)
}

// newRail uses Capital One Nessie when it is configured, and otherwise a
// clearly labelled simulation.
func newRail() PaymentRail {
	n, err := loadNessie()
	switch {
	case err != nil:
		log.Printf("nessie disabled: %v", err)
	case n == nil:
		log.Printf("nessie: no NESSIE_API_KEY, payments are simulated")
	case !n.ready():
		log.Printf("nessie: key set but no accounts yet (run: go run . nessie-setup), payments are simulated")
	default:
		return nessieRail{n}
	}
	return simulatedRail{}
}

type simulatedRail struct{}

func (simulatedRail) Name() string            { return "simulated" }
func (simulatedRail) SupplierAccount() string { return "sim-supplier-account" }
func (simulatedRail) AttackerAccount() string { return "sim-attacker-account" }
func (simulatedRail) Pay(_ context.Context, payTo string, _ int, _ string) (Payment, error) {
	return Payment{Rail: "simulated", TxID: "sim-" + newNonce()[:12], Status: "simulated", PayTo: payTo}, nil
}

type nessieRail struct{ n *Nessie }

func (r nessieRail) Name() string            { return "capital-one-nessie" }
func (r nessieRail) SupplierAccount() string { return r.n.Accounts.Supplier }
func (r nessieRail) AttackerAccount() string {
	if r.n.Accounts.Attacker != "" {
		return r.n.Accounts.Attacker
	}
	return "unattested-account"
}

// Pay records the payment as Nessie transactions. This Nessie version keeps
// withdrawals and deposits as records without updating stored account
// balances, so the evidence is the two transaction records, not balances.
func (r nessieRail) Pay(ctx context.Context, payTo string, amountUSD int, memo string) (Payment, error) {
	p := Payment{Rail: r.Name(), PayTo: payTo}
	w, d, err := r.n.Move(ctx, r.n.Accounts.Buyer, payTo, amountUSD, memo)
	if err != nil {
		return p, err
	}
	p.Withdrawal, p.Deposit, p.TxID, p.Status = w, d, d, "completed"
	return p, nil
}

// PayeeResolver returns the payment account an ANS-verified seller attests.
type PayeeResolver func(ctx context.Context, cert *x509.Certificate) (string, error)

var payeeCards = newTTLCache[string](2 * time.Minute)

// signedCardPayee reads the account a seller attests in its agent card, and
// accepts it only if the card's signature verifies under the seller's
// ANS-verified identity certificate.
func signedCardPayee(ctx context.Context, cert *x509.Certificate) (string, error) {
	host := certHost(cert)
	cacheKey := host + "|" + fingerprint(cert)
	if v, ok := payeeCards.get(cacheKey); ok {
		return v, nil
	}
	u := url.URL{Scheme: "https", Host: host, Path: "/.well-known/agent-card.json"}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not fetch %s's agent card", host)
	}
	defer resp.Body.Close()
	var card map[string]any
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&card) != nil {
		return "", fmt.Errorf("could not read %s's agent card", host)
	}
	if !verifyAgentCard(card, cert) {
		return "", fmt.Errorf("%s's agent card is not signed by its ANS identity key", host)
	}
	pay, _ := card["x-payment"].(map[string]any)
	payTo, _ := pay["payTo"].(string)
	if payTo == "" {
		return "", fmt.Errorf("%s's signed agent card attests no payment account", host)
	}
	payeeCards.put(cacheKey, payTo)
	return payTo, nil
}

// simulatedPayee stands in for the signed card when payments are simulated.
func simulatedPayee(supplier *x509.Certificate, rail PaymentRail) PayeeResolver {
	return func(_ context.Context, cert *x509.Certificate) (string, error) {
		if strings.EqualFold(certHost(cert), certHost(supplier)) {
			return rail.SupplierAccount(), nil
		}
		return "", errors.New("no attested payment account")
	}
}

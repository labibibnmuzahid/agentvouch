package main

import (
	"crypto/x509"
	"encoding/json"
	"time"
)

// Signing contexts keep one kind of signature from being accepted as another:
// a possession proof over bytes the buyer chose can never double as a quote.
const (
	popContext   = "agentvouch/pop/v1"
	quoteContext = "agentvouch/quote/v1"
	maxQuoteTTL  = 10 * time.Minute
)

// QuoteTerms is everything the seller commits to. The signature covers all of
// it, so a quote is bound to one supplier, one buyer, one amount and a short
// validity window, and its ID can be spent only once. PayTo is the bank
// account to pay, which must match the one the seller attests in its signed card.
type QuoteTerms struct {
	QuoteID   string `json:"quoteId"`
	Supplier  string `json:"supplier"`
	Buyer     string `json:"buyer"`
	AmountUSD int    `json:"amountUsd"`
	PayTo     string `json:"payTo"`
	ExpiresAt int64  `json:"expiresAt"`
}

type Quote struct {
	Terms QuoteTerms
	Sig   []byte
}

func contextMessage(context string, payload []byte) []byte {
	return append([]byte(context+"\x00"), payload...)
}

func (t QuoteTerms) signingBytes() []byte {
	b, _ := json.Marshal(t)
	return contextMessage(quoteContext, b)
}

func popMessage(buyer, nonce string) []byte {
	return contextMessage(popContext, []byte(buyer+"\x00"+nonce))
}

func newQuoteTerms(supplier, buyer string, amountUSD int, payTo string) QuoteTerms {
	return QuoteTerms{
		QuoteID:   "q-" + newNonce()[:16],
		Supplier:  supplier,
		Buyer:     buyer,
		AmountUSD: amountUSD,
		PayTo:     payTo,
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
}

func IssueQuote(seller Peer, t QuoteTerms) Quote {
	return Quote{Terms: t, Sig: seller.SignQuote(t)}
}

func verifyQuoteSig(sellerCert *x509.Certificate, q Quote) bool {
	return verifySig(sellerCert, q.Terms.signingBytes(), q.Sig)
}

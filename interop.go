package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Each of our agents exposes only what its card advertises: the supplier issues
// quotes, the buyer verifies them. These are the tools another agent can
// actually call, so the fleet is a real counterparty rather than a description
// of one.

// wireQuote is the interchange form of a quote: the signed terms plus the
// signature, so any agent can carry one between our supplier and our buyer.
type wireQuote struct {
	Terms     QuoteTerms `json:"terms"`
	Signature string     `json:"signature"`
}

func toWire(q Quote) wireQuote {
	return wireQuote{Terms: q.Terms, Signature: base64.StdEncoding.EncodeToString(q.Sig)}
}

func (w wireQuote) quote() (Quote, error) {
	sig, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		return Quote{}, errors.New("signature is not base64")
	}
	return Quote{Terms: w.Terms, Sig: sig}, nil
}

const maxQuotableUSD = 1_000_000

// validAudience keeps a quote's audience a plausible agent name. The signature
// binds whatever it says, and our buyer pays only quotes naming itself, so this
// only stops junk being sealed into a signed document.
func validAudience(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// issueQuote signs a single-use quote for a caller. Issuing one moves no money:
// it is an offer, bound to this supplier, that buyer, that amount and a short
// expiry, payable only to the account this supplier attests in its signed card.
func (s *server) issueQuote(p persona, buyer string, amountUSD int) any {
	buyer = strings.TrimSpace(buyer)
	if !validAudience(buyer) {
		return map[string]any{"error": "buyer must be the ANS name or hostname of the agent the quote is for"}
	}
	if amountUSD == 0 {
		amountUSD = 50000
	}
	if amountUSD < 1 || amountUSD > maxQuotableUSD {
		return map[string]any{"error": fmt.Sprintf("amountUsd must be between 1 and %d", maxQuotableUSD)}
	}
	host := certHost(p.agent.Cert())
	q := IssueQuote(p.agent, newQuoteTerms(host, buyer, amountUSD, s.rail.SupplierAccount()))
	return map[string]any{
		"quote":    toWire(q),
		"supplier": host,
		"signedWith": map[string]any{
			"key":         "the ANS identity key of " + host,
			"fingerprint": fingerprint(p.agent.Cert()),
			"trustCard":   "https://" + p.host + "/.well-known/ans/trust-card.json",
		},
		"expiresIn": time.Until(time.Unix(q.Terms.ExpiresAt, 0)).Round(time.Second).String(),
		"howToVerify": "Resolve " + host + " through ANS, check the sealed identity certificate matches the fingerprint above, " +
			"then check this signature over the canonical terms. payTo must equal x-payment.payTo in this supplier's signed agent card. " +
			"Hand the quote to the verify_quote tool at https://" + buyerHost + "/mcp to see every check run.",
		"note": "A quote is an offer, not a payment. It is single use, bound to this buyer and amount, and expires shortly. " +
			"Changing any term, reusing it, or redirecting payTo invalidates it.",
	}
}

// verifyQuoteReport runs the buyer's checks over a quote another agent presents
// and reports what it found, without paying and without consuming the quote's
// single use. It is the verify-then-pay logic, minus the pay, callable by anyone.
func (s *server) verifyQuoteReport(ctx context.Context, raw json.RawMessage) any {
	var w wireQuote
	if len(raw) == 0 || json.Unmarshal(raw, &w) != nil {
		return map[string]any{"error": `send {"quote": {"terms": {...}, "signature": "<base64>"}} as issue_quote returned it`}
	}
	q, err := w.quote()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	host, ok := normalizeHost(q.Terms.Supplier)
	if !ok {
		return map[string]any{"error": "terms.supplier is not a public DNS hostname"}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	checks := map[string]any{}
	out := map[string]any{"supplier": host, "quoteId": q.Terms.QuoteID, "amountUsd": q.Terms.AmountUSD,
		"addressedTo": q.Terms.Buyer, "checks": checks,
		"note": "Verification only: nothing was paid and the quote's single use was not consumed."}

	seller, err := fetchTrustCardAgent(ctx, host)
	if err != nil {
		checks["identity"] = "FAIL: no usable ANS trust card at " + host
		out["verdict"] = "WOULD REFUSE"
		return out
	}
	res := Vouch(ctx, s.reg, host)
	out["ans"] = res.ANS
	if !res.Verified {
		checks["identity"] = "FAIL: " + res.Reason
		out["verdict"] = "WOULD REFUSE"
		return out
	}
	checks["identity"] = "PASS: certificate sealed in the transparency log"
	checks["liveness"] = "PASS: ANS status " + res.ANS.Status

	refuse := func(check, why string) any {
		checks[check] = "FAIL: " + why
		out["verdict"] = "WOULD REFUSE"
		return out
	}
	if !verifyQuoteSig(seller.Cert(), q) {
		return refuse("quote", "signature does not verify under the ANS-certified key of "+host+" (tampered, forged, or signed by a different agent)")
	}
	checks["quote"] = fmt.Sprintf("PASS: $%d signed by %s over quote %s", q.Terms.AmountUSD, host, q.Terms.QuoteID)

	switch left := time.Until(time.Unix(q.Terms.ExpiresAt, 0)); {
	case left <= 0:
		return refuse("expiry", "the quote expired "+(-left).Round(time.Second).String()+" ago")
	case left > maxQuoteTTL:
		return refuse("expiry", "validity window is longer than the "+maxQuoteTTL.String()+" AgentVouch accepts")
	default:
		checks["expiry"] = "PASS: valid for another " + left.Round(time.Second).String()
	}
	if !strings.EqualFold(q.Terms.Buyer, s.buyer.Name) {
		return refuse("audience", "addressed to "+q.Terms.Buyer+", not "+s.buyer.Name+"; AgentVouch pays only quotes naming itself")
	}
	checks["audience"] = "PASS: addressed to " + s.buyer.Name
	if !s.buyer.Mandate.Allows(host) {
		return refuse("authorization", host+" is a genuine ANS agent but not a payee in the buyer's mandate")
	}
	if q.Terms.AmountUSD > s.buyer.Mandate.MaxAmountUSD {
		return refuse("authorization", fmt.Sprintf("$%d exceeds the mandate limit of $%d", q.Terms.AmountUSD, s.buyer.Mandate.MaxAmountUSD))
	}
	checks["authorization"] = fmt.Sprintf("PASS: in mandate, max $%d", s.buyer.Mandate.MaxAmountUSD)

	attested, err := s.buyer.Payee(ctx, seller.Cert())
	switch {
	case err != nil:
		return refuse("payee", "no payment account attested in "+host+"'s signed agent card")
	case attested != q.Terms.PayTo:
		return refuse("payee", "quote pays account "+short(q.Terms.PayTo, 12)+", but "+host+" attests "+short(attested, 12))
	}
	checks["payee"] = "PASS: payTo matches the account attested in the signed card"
	out["verdict"] = "WOULD PAY"
	out["ifPaid"] = "AgentVouch would settle $" + fmt.Sprint(q.Terms.AmountUSD) + " to " + short(attested, 12) + " via " + s.rail.Name() +
		" after a fresh possession challenge, and seal the decision in its audit ledger."
	return out
}

// mcpTools is what this persona advertises and will answer, matching the skills
// in its agent card. An agent that says it issues quotes should not also run a
// buyer's payment scenarios.
func (s *server) mcpTools(p persona) []map[string]any {
	if p.supplier {
		return []map[string]any{{
			"name":        "issue_quote",
			"description": "Issue a single-use quote signed with this supplier's ANS identity key, bound to one buyer, one amount and a short expiry, payable only to the account the supplier attests in its signed agent card. Issuing a quote moves no money.",
			"inputSchema": map[string]any{"type": "object", "required": []string{"buyer"}, "properties": map[string]any{
				"buyer":     map[string]any{"type": "string", "description": "the ANS name or hostname of the agent the quote is for, e.g. buyer.agentvouch.us"},
				"amountUsd": map[string]any{"type": "integer", "description": "amount in whole US dollars (default 50000)"},
			}},
		}}
	}
	return []map[string]any{
		{
			"name":        "vouch",
			"description": "Verify an agent by hostname against the GoDaddy ANS transparency log: sealed identity certificate, hostname, ANS name, liveness, and advisory Trust Index score.",
			"inputSchema": map[string]any{"type": "object", "required": []string{"host"}, "properties": map[string]any{
				"host": map[string]any{"type": "string", "description": "agent hostname, e.g. supplier.webmesh.ai"},
			}},
		},
		{
			"name":        "verify_quote",
			"description": "Run every check AgentVouch runs before paying, over a quote you present, and report what it found: ANS identity and liveness of the signer, the signature over the terms, expiry, audience, mandate, and whether payTo matches the account the signer attests. Pays nothing.",
			"inputSchema": map[string]any{"type": "object", "required": []string{"quote"}, "properties": map[string]any{
				"quote": map[string]any{"type": "object", "description": "a quote as supplier.agentvouch.us issue_quote returned it: {terms, signature}"},
			}},
		},
		{
			"name":        "run_scenarios",
			"description": "Run AgentVouch's verify-then-pay scenarios against live ANS: one legitimate payment and nine blocked attacks, with evidence and the audit ledger.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

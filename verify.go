package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
)

// Evidence is what we SHOW the judge: each proof, its reason, and the
// transparency-log record it was checked against.
type Evidence struct {
	FQDN          string       `json:"fqdn"`
	Presented     string       `json:"presentedFingerprint"`
	Identity      string       `json:"identity"`
	Liveness      string       `json:"liveness"`
	Authorization string       `json:"authorization"`
	Possession    string       `json:"possession"`
	Quote         string       `json:"quote"`
	Payee         string       `json:"payee"`
	OK            bool         `json:"ok"`
	Reason        string       `json:"reason,omitempty"`
	ANS           *ANSEvidence `json:"ans,omitempty"`
}

func (e Evidence) Print() {
	mark := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	fmt.Printf("      evidence: identity[%s] liveness[%s] authz[%s] possession[%s] quote[%s] payee[%s]\n",
		mark(e.Identity), mark(e.Liveness), mark(e.Authorization), mark(e.Possession), mark(e.Quote), mark(e.Payee))
	if a := e.ANS; a != nil {
		ti := "n/a"
		if a.TrustScore != nil {
			ti = fmt.Sprint(*a.TrustScore)
		}
		fmt.Printf("      ans: %s  agent %s  TL leaf %d of %d  Trust Index %s\n", a.ANSName, a.AgentID, a.LeafIndex, a.TreeSize, ti)
	}
}

// Mandate is the buyer's authorization policy. ANS proves WHO a seller is;
// only the mandate decides whether, and how much, we may pay them.
type Mandate struct {
	Payees       []string
	MaxAmountUSD int
}

func (m Mandate) Allows(fqdn string) bool {
	for _, p := range m.Payees {
		if strings.EqualFold(p, fqdn) {
			return true
		}
	}
	return false
}

// Buyer is the paying side: the name quotes must be addressed to, its
// mandate, and single-use caches that persist across requests.
type Buyer struct {
	Name       string
	Mandate    Mandate
	Payee      PayeeResolver
	challenges *ReplayCache
	quotes     *ReplayCache
}

func NewBuyer(name string, m Mandate, payee PayeeResolver) *Buyer {
	ttl := maxQuoteTTL + 5*time.Minute
	return &Buyer{Name: name, Mandate: m, Payee: payee, challenges: NewReplayCache(ttl), quotes: NewReplayCache(ttl)}
}

// Authenticate runs the buyer's checks BEFORE paying. Identity + Liveness come
// from the live ANS transparency log via the ANS SDK; Authorization from the
// buyer's mandate; Possession is a fresh single-use challenge signed with the
// key ANS certified; Quote integrity binds the signed terms to this seller,
// this buyer, a short window and a single use; Payee binding pays only the
// account the seller attests in its ANS-signed agent card.
// Any failure means refuse. "Never let discovery alone authorize an action."
func (b *Buyer) Authenticate(ctx context.Context, reg *Registry, peer Peer, q Quote, challengeNonce string) Evidence {
	cert := peer.Cert()
	fqdn := certHost(cert)
	ev := Evidence{FQDN: fqdn, Presented: fingerprint(cert)}

	// PROOF 1 - IDENTITY: the presented certificate is the one the ANS
	// transparency log sealed for this hostname and ANS name.
	// PROOF 2 - LIVENESS: that registration is live (not revoked or expired).
	out := reg.Resolve(ctx, cert)
	ev.ANS = ansEvidence(out.Badge)
	if ev.ANS != nil {
		ev.ANS.TrustScore = reg.TrustScore(ctx, fqdn, ev.ANS.DisplayName)
	}
	switch out.Type {
	case verify.OutcomeVerified:
	case verify.OutcomeInvalidStatus:
		ev.Identity = "sealed:" + short(ev.ANS.SealedFingerprint, 12)
		ev.Reason = "liveness: ANS registration for " + fqdn + " is " + string(out.Status)
		return ev
	default:
		ev.Reason = "identity: " + identityFailure(out, fqdn)
		return ev
	}
	ev.Identity = "sealed:" + short(ev.ANS.SealedFingerprint, 12)
	ev.Liveness = ev.ANS.Status

	// AUTHORIZATION: a genuine, live identity is still not permission to pay,
	// and never permission to pay more than the mandate allows.
	if !b.Mandate.Allows(fqdn) {
		ev.Reason = "authorization: " + fqdn + " is a genuine ANS agent, but not a payee in the buyer's mandate"
		return ev
	}
	if q.Terms.AmountUSD > b.Mandate.MaxAmountUSD {
		ev.Reason = fmt.Sprintf("authorization: $%d exceeds the buyer's mandate limit of $%d", q.Terms.AmountUSD, b.Mandate.MaxAmountUSD)
		return ev
	}
	ev.Authorization = fmt.Sprintf("in mandate, max $%d", b.Mandate.MaxAmountUSD)

	// PROOF 3 - POSSESSION: the peer signs a FRESH, single-use challenge, bound
	// to this buyer, with the key ANS certified.
	if !b.challenges.Use(challengeNonce) {
		ev.Reason = "possession: challenge nonce already used (replay)"
		return ev
	}
	if !verifySig(cert, popMessage(b.Name, challengeNonce), peer.ProvePossession(b.Name, challengeNonce)) {
		ev.Reason = "possession: signature does not verify against the ANS-certified key (forged)"
		return ev
	}
	ev.Possession = "fresh-pop:" + short(challengeNonce, 8)

	// QUOTE INTEGRITY: signed by this seller, addressed to this buyer, inside
	// its validity window, and never seen before.
	t := q.Terms
	now := time.Now().Unix()
	switch {
	case !verifyQuoteSig(cert, q):
		ev.Reason = fmt.Sprintf("quote: $%d is not what %s signed (tampered)", t.AmountUSD, fqdn)
	case !strings.EqualFold(t.Supplier, fqdn):
		ev.Reason = "quote: issued for " + t.Supplier + ", not by the verified seller " + fqdn
	case t.Buyer != b.Name:
		ev.Reason = "quote: addressed to " + t.Buyer + ", not to this buyer (wrong audience)"
	case now >= t.ExpiresAt:
		ev.Reason = "quote: expired at " + time.Unix(t.ExpiresAt, 0).UTC().Format(time.RFC3339)
	case t.ExpiresAt-now > int64(maxQuoteTTL/time.Second):
		ev.Reason = "quote: validity window longer than the buyer accepts"
	case !b.quotes.Use(t.QuoteID):
		ev.Reason = "quote: " + t.QuoteID + " was already used (replayed quote)"
	}
	if ev.Reason != "" {
		return ev
	}
	ev.Quote = fmt.Sprintf("signed:$%d %s", t.AmountUSD, t.QuoteID)

	// PAYEE BINDING: pay only the account the verified seller attests in its
	// signed agent card, so even a genuinely signed quote cannot redirect money.
	want, err := b.Payee(ctx, cert)
	if err != nil {
		ev.Reason = "payee: " + err.Error() + ", failing closed"
		return ev
	}
	if t.PayTo != want {
		ev.Reason = fmt.Sprintf("payee: quote pays account %s, but %s's signed agent card attests %s (redirected payment)", short(t.PayTo, 12), fqdn, short(want, 12))
		return ev
	}
	ev.Payee = "attested:" + short(want, 12)

	ev.OK = true
	return ev
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

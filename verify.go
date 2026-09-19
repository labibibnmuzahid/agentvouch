package main

import (
	"context"
	"fmt"
	"strings"

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
	fmt.Printf("      evidence: identity[%s] liveness[%s] authz[%s] possession[%s] quote[%s]\n",
		mark(e.Identity), mark(e.Liveness), mark(e.Authorization), mark(e.Possession), mark(e.Quote))
	if a := e.ANS; a != nil {
		fmt.Printf("      ans: %s  agent %s  TL leaf %d of %d\n", a.ANSName, a.AgentID, a.LeafIndex, a.TreeSize)
	}
}

// Mandate is the buyer's authorization policy. ANS proves WHO a seller is;
// only the mandate decides whether we may pay them.
type Mandate struct{ Payees []string }

func (m Mandate) Allows(fqdn string) bool {
	for _, p := range m.Payees {
		if strings.EqualFold(p, fqdn) {
			return true
		}
	}
	return false
}

// Authenticate runs the buyer's checks BEFORE paying. Identity + Liveness come
// from the live ANS transparency log via the ANS SDK; Authorization from the
// buyer's mandate; Possession is a fresh single-use challenge signed with the
// key ANS certified; Quote integrity is the amount signed with that same key.
// Any failure means refuse. "Never let discovery alone authorize an action."
func Authenticate(ctx context.Context, reg *Registry, rc *ReplayCache, m Mandate, peer Peer, q Quote, challengeNonce string) Evidence {
	cert := peer.Cert()
	fqdn := cert.Subject.CommonName
	if len(cert.DNSNames) > 0 {
		fqdn = cert.DNSNames[0]
	}
	ev := Evidence{FQDN: fqdn, Presented: fingerprint(cert)}

	// PROOF 1 - IDENTITY: the presented certificate is the one the ANS
	// transparency log sealed for this hostname and ANS name.
	// PROOF 2 - LIVENESS: that registration is live (not revoked or expired).
	out := reg.Resolve(ctx, cert)
	ev.ANS = ansEvidence(out.Badge)
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

	// AUTHORIZATION: a genuine, live identity is still not permission to pay.
	if !m.Allows(fqdn) {
		ev.Reason = "authorization: " + fqdn + " is a genuine ANS agent, but not a payee in the buyer's mandate"
		return ev
	}
	ev.Authorization = "mandate:" + fqdn

	// PROOF 3 - POSSESSION: the peer signs a FRESH, single-use challenge with the
	// key ANS certified. Blocks copied certificates and replays.
	if !rc.Use(challengeNonce) {
		ev.Reason = "possession: challenge nonce already used (replay)"
		return ev
	}
	if !verifySig(cert, []byte(challengeNonce), peer.Sign([]byte(challengeNonce))) {
		ev.Reason = "possession: signature does not verify against the ANS-certified key (forged)"
		return ev
	}
	ev.Possession = "fresh-pop:" + short(challengeNonce, 8)

	// QUOTE INTEGRITY: the amount about to be paid is signed with that key.
	if !verifyQuote(cert, q) {
		ev.Reason = fmt.Sprintf("quote: amount $%d not signed by %s (swapped)", q.AmountUSD, fqdn)
		return ev
	}
	ev.Quote = fmt.Sprintf("signed:$%d", q.AmountUSD)

	ev.OK = true
	return ev
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

// Peer is anything a buyer might transact with.
type Peer interface {
	Card() Card
	Sign(msg []byte) []byte
}

// Evidence is what we SHOW the judge: each proof and its reason. Mirrors the
// artifacts a real verifier surfaces (cert, TL receipt/badge, status token).
type Evidence struct {
	FQDN       string `json:"fqdn"`
	KeyID      string `json:"keyId"`
	Identity   string `json:"identity"`
	Liveness   string `json:"liveness"`
	Possession string `json:"possession"`
	Quote      string `json:"quote"`
	OK         bool   `json:"ok"`
	Reason     string `json:"reason,omitempty"`
}

func (e Evidence) Print() {
	mark := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	fmt.Printf("      evidence: identity[%s] liveness[%s] possession[%s] quote[%s]\n",
		mark(e.Identity), mark(e.Liveness), mark(e.Possession), mark(e.Quote))
}

// Authenticate runs the buyer's checks BEFORE paying. It reproduces, in
// miniature, ans.NewAgentClient(WithAgentClientFailurePolicy(verify.Strict)):
// Identity (sealed?) + Liveness (ACTIVE?) + Possession (fresh signed challenge,
// single-use) + Quote integrity (amount signed by the seller). Any failure
// means refuse. "Never let discovery alone authorize an action."
func Authenticate(reg *Registry, rc *ReplayCache, peer Peer, q Quote, challengeNonce string) Evidence {
	card := peer.Card()
	ev := Evidence{FQDN: card.FQDN, KeyID: keyID(card.Pub)}

	// PROOF 1 - IDENTITY: FQDN sealed in ANS, and the presented key is the one
	// pinned for it. Blocks lookalike domains and copied/forged cards.
	rec, err := reg.Resolve(card.FQDN)
	if err != nil {
		ev.Reason = "identity: " + err.Error()
		return ev
	}
	if !bytes.Equal(card.Pub, rec.Pub) {
		ev.Reason = "identity: presented key is not the key ANS pinned for " + card.FQDN
		return ev
	}
	ev.Identity = "sealed:" + keyID(rec.Pub)

	// PROOF 2 - LIVENESS: registration ACTIVE right now (not revoked).
	if rec.Status != Active {
		ev.Reason = "liveness: registration is " + string(rec.Status)
		return ev
	}
	ev.Liveness = string(rec.Status)

	// PROOF 3 - POSSESSION: peer signs a FRESH, single-use challenge with the
	// pinned key. Blocks forged signatures (bad sig) and replays (used nonce).
	if !rc.Use(challengeNonce) {
		ev.Reason = "possession: challenge nonce already used (replay)"
		return ev
	}
	if !ed25519.Verify(rec.Pub, []byte(challengeNonce), peer.Sign([]byte(challengeNonce))) {
		ev.Reason = "possession: proof-of-possession signature invalid (forged)"
		return ev
	}
	ev.Possession = "fresh-pop:" + short(challengeNonce)

	// QUOTE INTEGRITY: the amount about to be paid is signed by the seller.
	// Blocks swapped quotes.
	if !verifyQuote(rec.Pub, q) {
		ev.Reason = fmt.Sprintf("quote: amount $%d not signed by %s (swapped)", q.AmountUSD, card.FQDN)
		return ev
	}
	ev.Quote = fmt.Sprintf("signed:$%d", q.AmountUSD)

	ev.OK = true
	return ev
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

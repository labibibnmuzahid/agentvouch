package main

import (
	"crypto/ed25519"
	"encoding/binary"
)

// Quote is a price the seller commits to. The seller SIGNS (amount || nonce)
// so a man-in-the-middle cannot swap the amount without breaking the signature.
type Quote struct {
	AmountUSD int
	Nonce     string
	Sig       []byte
}

func quoteBytes(amountUSD int, nonce string) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(amountUSD))
	return append(b, []byte(nonce)...)
}

// IssueQuote has the seller sign the amount + nonce.
func (a *Agent) IssueQuote(amountUSD int, nonce string) Quote {
	return Quote{AmountUSD: amountUSD, Nonce: nonce, Sig: a.Sign(quoteBytes(amountUSD, nonce))}
}

// verifyQuote checks the seller's signature over the EXACT amount the buyer is
// about to pay. Returns false if the amount was altered after signing.
func verifyQuote(sellerKey ed25519.PublicKey, q Quote) bool {
	return ed25519.Verify(sellerKey, quoteBytes(q.AmountUSD, q.Nonce), q.Sig)
}

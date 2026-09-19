package main

import (
	"crypto/x509"
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
func IssueQuote(seller Peer, amountUSD int, nonce string) Quote {
	return Quote{AmountUSD: amountUSD, Nonce: nonce, Sig: seller.Sign(quoteBytes(amountUSD, nonce))}
}

// verifyQuote checks the seller's signature, under its ANS-certified key, over
// the EXACT amount the buyer is about to pay.
func verifyQuote(sellerCert *x509.Certificate, q Quote) bool {
	return verifySig(sellerCert, quoteBytes(q.AmountUSD, q.Nonce), q.Sig)
}

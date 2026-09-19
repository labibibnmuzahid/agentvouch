package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
)

// Agent has a domain-anchored identity. In real ANS the keypair backs the
// identity certificate and proof-of-possession (pop) signatures; FQDN is the
// ans:// name anchor.
type Agent struct {
	FQDN string
	Role string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func NewAgent(fqdn, role string) *Agent {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Agent{FQDN: fqdn, Role: role, pub: pub, priv: priv}
}

// Card is presented on connect: the claimed FQDN + the key to be trusted under.
type Card struct {
	FQDN string
	Pub  ed25519.PublicKey
}

func (a *Agent) Card() Card             { return Card{FQDN: a.FQDN, Pub: a.pub} }
func (a *Agent) Sign(msg []byte) []byte { return ed25519.Sign(a.priv, msg) }

func keyID(pub ed25519.PublicKey) string {
	if len(pub) < 6 {
		return "??"
	}
	return hex.EncodeToString(pub[:6])
}

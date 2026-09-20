package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
	"time"
)

func testAgent() *Agent {
	return newImpostor(&x509.Certificate{Subject: pkix.Name{CommonName: "seller.example"}, DNSNames: []string{"seller.example"}})
}

func TestPossessionProofCannotBeUsedAsQuote(t *testing.T) {
	a := testAgent()
	terms := newQuoteTerms(certHost(a.Cert()), buyerFQDN, 900000, "acct-1")
	// A malicious buyer picks a challenge equal to the exact bytes a quote signs.
	challenge := string(terms.signingBytes())
	pop := a.ProvePossession(buyerFQDN, challenge)
	if verifyQuoteSig(a.Cert(), Quote{Terms: terms, Sig: pop}) {
		t.Fatal("a possession proof verified as a signed quote")
	}
	if !verifyQuoteSig(a.Cert(), IssueQuote(a, terms)) {
		t.Fatal("a genuine quote did not verify")
	}
}

func TestQuoteSignatureCoversEveryTerm(t *testing.T) {
	a := testAgent()
	q := IssueQuote(a, newQuoteTerms(certHost(a.Cert()), buyerFQDN, 50000, "acct-1"))
	for name, mutate := range map[string]func(*QuoteTerms){
		"amount":   func(t *QuoteTerms) { t.AmountUSD++ },
		"buyer":    func(t *QuoteTerms) { t.Buyer = otherBuyerFQDN },
		"quote id": func(t *QuoteTerms) { t.QuoteID = "q-other" },
		"expiry":   func(t *QuoteTerms) { t.ExpiresAt += 3600 },
		"supplier": func(t *QuoteTerms) { t.Supplier = "evil.example" },
		"payee":    func(t *QuoteTerms) { t.PayTo = "attacker-acct" },
	} {
		tampered := q
		mutate(&tampered.Terms)
		if verifyQuoteSig(a.Cert(), tampered) {
			t.Errorf("changing the %s did not break the signature", name)
		}
	}
}

func TestReplayCacheRejectsReuse(t *testing.T) {
	c := NewReplayCache(time.Minute)
	if !c.Use("n1") || c.Use("n1") {
		t.Fatal("second use of a nonce was accepted")
	}
}

func TestNormalizeHostRejectsNonPublicNames(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "169.254.169.254", "printer.local", "a..b", "x", "evil.example:8080", "http://x.com"} {
		if _, ok := normalizeHost(h); ok {
			t.Errorf("%q accepted as a vouchable host", h)
		}
	}
	if h, ok := normalizeHost("Supplier.WebMesh.ai."); !ok || h != "supplier.webmesh.ai" {
		t.Errorf("valid host rejected or not normalized: %q %v", h, ok)
	}
}

func TestAgentCardSignature(t *testing.T) {
	a := testAgent()
	card := map[string]any{"name": "AgentVouch", "url": "https://seller.example", "skills": []map[string]any{{"id": "vouch", "tags": []string{"ANS"}}}}
	card["signatures"] = signAgentCard(a, "https://seller.example/.well-known/jwks.json", card)

	// Verify the way a remote client would: after a JSON round trip.
	var got map[string]any
	if err := json.Unmarshal(canonicalJSON(card), &got); err != nil {
		t.Fatal(err)
	}
	if !verifyAgentCard(got, a.Cert()) {
		t.Fatal("signed card did not verify")
	}
	got["url"] = "https://evil.example"
	if verifyAgentCard(got, a.Cert()) {
		t.Fatal("tampered card verified")
	}
	if verifyAgentCard(card, testAgent().Cert()) {
		t.Fatal("card verified under a different agent's key")
	}
}

// TestAgentCardSignatureAlgorithms covers the key types ANS issues in the wild:
// P-256 to us, RSA to the webmesh fleet, plus EdDSA-signed cards.
func TestAgentCardSignatureAlgorithms(t *testing.T) {
	card := map[string]any{"name": "Travel Supplier", "url": "https://seller.example"}
	payload := b64url.EncodeToString(canonicalJSON(card))

	sign := func(alg string, key crypto.Signer) map[string]any {
		protected := b64url.EncodeToString(canonicalJSON(map[string]any{"alg": alg, "typ": "agent-card+jws"}))
		input := []byte(protected + "." + payload)
		var sig []byte
		switch k := key.(type) {
		case ed25519.PrivateKey:
			sig = ed25519.Sign(k, input)
		case *rsa.PrivateKey:
			sum := sha256.Sum256(input)
			sig, _ = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		}
		return map[string]any{"protected": protected, "signature": b64url.EncodeToString(sig)}
	}

	edPub, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		alg  string
		key  crypto.Signer
		pub  any
	}{
		{"ed25519", "EdDSA", edKey, edPub},
		{"rsa", "RS256", rsaKey, &rsaKey.PublicKey},
	} {
		signed := map[string]any{}
		for k, v := range card {
			signed[k] = v
		}
		signed["signatures"] = []any{sign(tc.alg, tc.key)}
		cert := &x509.Certificate{PublicKey: tc.pub}
		if !verifyAgentCard(signed, cert) {
			t.Fatalf("%s: genuine card did not verify", tc.name)
		}
		signed["url"] = "https://evil.example"
		if verifyAgentCard(signed, cert) {
			t.Fatalf("%s: tampered card verified", tc.name)
		}
	}

	// An attacker may not pick the algorithm: a signature made with one key type
	// must not verify when the header claims another.
	confused := map[string]any{}
	for k, v := range card {
		confused[k] = v
	}
	confused["signatures"] = []any{sign("ES256", edKey)}
	if verifyAgentCard(confused, &x509.Certificate{PublicKey: edPub}) {
		t.Fatal("EdDSA signature accepted while the header claimed ES256")
	}
}

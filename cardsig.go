package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

var b64url = base64.RawURLEncoding

// canonicalJSON serializes maps with sorted keys and no HTML escaping, which
// matches RFC 8785 (JCS) for cards made of strings, booleans, objects and arrays.
func canonicalJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func withoutSignatures(card map[string]any) map[string]any {
	c := make(map[string]any, len(card))
	for k, v := range card {
		if k != "signatures" {
			c[k] = v
		}
	}
	return c
}

// signAgentCard returns an A2A AgentCardSignature: a detached ES256 JWS over
// the canonical card, made with the agent's ANS identity key.
func signAgentCard(a *Agent, jku string, card map[string]any) []map[string]any {
	kid := publicJWK(a.Cert())["kid"]
	protected := b64url.EncodeToString(canonicalJSON(map[string]any{
		"alg": "ES256", "typ": "agent-card+jws", "kid": kid, "jku": jku,
	}))
	signingInput := protected + "." + b64url.EncodeToString(canonicalJSON(withoutSignatures(card)))
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, sum[:])
	if err != nil {
		return nil
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return []map[string]any{{"protected": protected, "signature": b64url.EncodeToString(raw), "header": map[string]any{"kid": kid}}}
}

// verifyAgentCard checks that some signature on the card verifies under the
// certificate's key. Cards in the wild are signed with whatever key type the
// agent's CA issued - ANS issues P-256 to us and RSA to the webmesh fleet - so
// ES256, RS256 and EdDSA are all accepted. The key must still be the one sealed
// in the transparency log: a signature made with a key an agent merely
// publishes beside its card proves only that the document is self-consistent.
func verifyAgentCard(card map[string]any, cert *x509.Certificate) bool {
	var sigs []struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	}
	b, _ := json.Marshal(card["signatures"])
	if json.Unmarshal(b, &sigs) != nil {
		return false
	}
	payload := b64url.EncodeToString(canonicalJSON(withoutSignatures(card)))
	for _, sg := range sigs {
		hdr, err := b64url.DecodeString(sg.Protected)
		if err != nil {
			continue
		}
		var h struct {
			Alg string `json:"alg"`
		}
		raw, err := b64url.DecodeString(sg.Signature)
		if json.Unmarshal(hdr, &h) != nil || err != nil {
			continue
		}
		if verifySignature(cert.PublicKey, h.Alg, []byte(sg.Protected+"."+payload), raw) {
			return true
		}
	}
	return false
}

// verifySignature checks one JWS signature under the algorithm its header
// names, refusing any pairing of algorithm and key the header did not claim.
func verifySignature(pub any, alg string, signingInput, sig []byte) bool {
	sum := sha256.Sum256(signingInput)
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return false
		}
		return ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case *rsa.PublicKey:
		if alg != "RS256" {
			return false
		}
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) == nil
	case ed25519.PublicKey:
		// EdDSA signs the input itself; it does not take a pre-hash.
		return alg == "EdDSA" && ed25519.Verify(key, signingInput, sig)
	}
	return false
}

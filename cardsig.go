package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
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
// certificate's key.
func verifyAgentCard(card map[string]any, cert *x509.Certificate) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
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
		if json.Unmarshal(hdr, &h) != nil || h.Alg != "ES256" || err != nil || len(raw) != 64 {
			continue
		}
		sum := sha256.Sum256([]byte(sg.Protected + "." + payload))
		if ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
			return true
		}
	}
	return false
}

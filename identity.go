package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Peer is anything a buyer might transact with: it presents an ANS identity
// certificate and signs challenges and quotes with the key behind it.
type Peer interface {
	Cert() *x509.Certificate
	Sign(msg []byte) []byte
}

// Agent holds an ANS identity certificate and, when we control it, its key.
type Agent struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (a *Agent) Cert() *x509.Certificate { return a.cert }

func (a *Agent) Sign(msg []byte) []byte {
	if a.key == nil {
		return nil
	}
	sum := sha256.Sum256(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, sum[:])
	return sig
}

func verifySig(cert *x509.Certificate, msg, sig []byte) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || sig == nil {
		return false
	}
	sum := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, sum[:], sig)
}

// loadSupplier loads the ANS identity certificate + key that ANS issued for
// our supplier agent. Under systemd they arrive via LoadCredential.
func loadSupplier() (*Agent, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		dir = "certs"
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if err != nil {
		return nil, fmt.Errorf("ANS identity certificate: %w (fetch it with: ans-cli get-identity-certs <agentId> --json)", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "identity.key"))
	if err != nil {
		return nil, fmt.Errorf("ANS identity key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("identity.crt / identity.key are not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := parseECKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("identity.key does not match identity.crt - the key ANS certified is not on this machine")
	}
	return &Agent{cert: cert, key: key}, nil
}

func parseECKey(der []byte) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not ECDSA")
	}
	return ec, nil
}

// newImpostor mints a self-signed certificate that claims the victim's
// hostname and ANS name, with the attacker's own key.
func newImpostor(victim *x509.Certificate) *Agent {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: victim.Subject.CommonName},
		DNSNames:     victim.DNSNames,
		URIs:         victim.URIs,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return &Agent{cert: cert, key: key}
}

// ForgedPeer presents a copied certificate but signs with a different key.
type ForgedPeer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newForgedPeer(copied *x509.Certificate) ForgedPeer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return ForgedPeer{cert: copied, key: key}
}

func (f ForgedPeer) Cert() *x509.Certificate { return f.cert }
func (f ForgedPeer) Sign(msg []byte) []byte  { return (&Agent{key: f.key}).Sign(msg) }

// fetchTrustCardAgent reads a remote agent's ANS identity certificate from its
// published trust card. We know its certificate but not its key.
func fetchTrustCardAgent(ctx context.Context, host string) (*Agent, error) {
	u := url.URL{Scheme: "https", Host: host, Path: "/.well-known/ans/trust-card.json"}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust card: HTTP %d", resp.StatusCode)
	}
	var card struct {
		Keys []struct {
			X5C []string `json:"x5c"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&card); err != nil {
		return nil, err
	}
	for _, k := range card.Keys {
		if len(k.X5C) == 0 {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(k.X5C[0])
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return &Agent{cert: cert}, nil
	}
	return nil, errors.New("trust card has no x5c certificate")
}

var httpClient = &http.Client{Timeout: 8 * time.Second}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

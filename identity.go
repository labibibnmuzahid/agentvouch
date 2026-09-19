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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Peer is anything a buyer might transact with: it presents an ANS identity
// certificate, proves it holds the key, and signs quotes with it. The signer
// adds its own signing context, so neither method is a general signing oracle.
type Peer interface {
	Cert() *x509.Certificate
	ProvePossession(buyer, nonce string) []byte
	SignQuote(t QuoteTerms) []byte
}

// Agent holds an ANS identity certificate and, when we control it, a key.
// The key does not have to match the certificate: that is how the forged
// peer is modelled.
type Agent struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (a *Agent) Cert() *x509.Certificate { return a.cert }

func (a *Agent) ProvePossession(buyer, nonce string) []byte {
	return a.sign(popMessage(buyer, nonce))
}

func (a *Agent) SignQuote(t QuoteTerms) []byte { return a.sign(t.signingBytes()) }

func (a *Agent) sign(msg []byte) []byte {
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

// loadAgent loads an ANS identity certificate + key. Locally they live in
// dir/identity.{crt,key}; under systemd the whole /etc/agentvouch directory
// arrives via LoadCredential as av_<name>.crt / av_<name>.key.
func loadAgent(name, dir string) (*Agent, error) {
	crtPath, keyPath := filepath.Join(dir, "identity.crt"), filepath.Join(dir, "identity.key")
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
		crtPath, keyPath = filepath.Join(cd, "av_"+name+".crt"), filepath.Join(cd, "av_"+name+".key")
	}
	certPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, fmt.Errorf("ANS identity certificate for %s: %w", name, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ANS identity key for %s: %w", name, err)
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("%s identity files are not PEM", name)
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
		return nil, fmt.Errorf("%s identity key does not match its certificate - the key ANS certified is not on this machine", name)
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

// newForgedPeer presents a copied certificate but holds a different key.
func newForgedPeer(copied *x509.Certificate) *Agent {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &Agent{cert: copied, key: key}
}

func certHost(c *x509.Certificate) string {
	if len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	return c.Subject.CommonName
}

// httpClient only dials public addresses and never follows redirects, so a
// caller-supplied hostname cannot be used to reach internal services.
var httpClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         publicOnlyDial,
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConns:        20,
		IdleConnTimeout:     30 * time.Second,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !cgnat.Contains(ip)
}

func publicOnlyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	for _, ip := range ips {
		if isPublicIP(ip.IP) {
			return d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}
	}
	return nil, fmt.Errorf("%s has no public address", host)
}

var trustCards = newTTLCache[*x509.Certificate](2 * time.Minute)

// fetchTrustCardAgent reads a remote agent's ANS identity certificate from its
// published trust card. We know its certificate but not its key.
func fetchTrustCardAgent(ctx context.Context, host string) (*Agent, error) {
	if c, ok := trustCards.get(host); ok {
		return &Agent{cert: c}, nil
	}
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&card); err != nil {
		return nil, fmt.Errorf("trust card: %w", err)
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
		trustCards.put(host, cert)
		return &Agent{cert: cert}, nil
	}
	return nil, errors.New("trust card has no x5c certificate")
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// publicJWK renders an ECDSA P-256 certificate key as a JWK with its RFC 7638
// thumbprint as kid and the certificate as x5c.
func publicJWK(cert *x509.Certificate) map[string]any {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	ecdh, err := pub.ECDH()
	if err != nil {
		return nil
	}
	raw := ecdh.Bytes()
	b64 := base64.RawURLEncoding.EncodeToString
	x, y := b64(raw[1:33]), b64(raw[33:65])
	tp := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return map[string]any{
		"kty": "EC", "crv": "P-256", "x": x, "y": y, "use": "sig", "alg": "ES256",
		"kid": b64(tp[:]),
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
}

type ttlEntry[V any] struct {
	v   V
	exp time.Time
}

type ttlCache[V any] struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]ttlEntry[V]
}

func newTTLCache[V any](ttl time.Duration) *ttlCache[V] {
	return &ttlCache[V]{ttl: ttl, m: map[string]ttlEntry[V]{}}
}

func (c *ttlCache[V]) get(k string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || time.Now().After(e.exp) {
		var zero V
		return zero, false
	}
	return e.v, true
}

func (c *ttlCache[V]) put(k string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 1000 {
		clear(c.m)
	}
	c.m[k] = ttlEntry[V]{v: v, exp: time.Now().Add(c.ttl)}
}

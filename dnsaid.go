package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DNS-AID (draft-mozleywilliams-dnsop-dnsaid) makes an agent discoverable from
// DNS alone: an SVCB record says how to connect, a _dnsid TXT record points at
// the agent's card, operator keys, status and transparency-log receipt, and an
// organization index lists the whole fleet. GoDaddy's own verifier reports
// dnsid=absent for agents that publish none of it.
//
// The record is signed with an Ed25519 OPERATOR key - the organization's key
// for its DNS assertions, separate from each agent's ANS identity key.
const (
	dnsidVersion = "v=DNSid1"
	dnsidOrg     = "agentvouch.us"
)

func operatorKeyPath() string {
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
		return filepath.Join(cd, "av_dnsid.key")
	}
	return filepath.Join("certs", "dnsid.key")
}

// loadOperatorKey reads the Ed25519 operator key, or returns nil when there is
// none (the DNS-AID endpoints then simply aren't served).
func loadOperatorKey() ed25519.PrivateKey {
	b, err := os.ReadFile(operatorKeyPath())
	if err != nil {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil
	}
	return ed25519.PrivateKey(raw)
}

// newOperatorKey writes a fresh operator key, refusing to overwrite one that
// published records already depend on.
func newOperatorKey() error {
	path := operatorKeyPath()
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite the key the published _dnsid records are signed with", path)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o400); err != nil {
		return err
	}
	fmt.Println("wrote", path)
	return nil
}

func operatorJWKS(key ed25519.PrivateKey) map[string]any {
	pub := key.Public().(ed25519.PublicKey)
	return map[string]any{"keys": []any{map[string]any{
		"kty": "OKP", "crv": "Ed25519", "use": "sig",
		"x": b64url.EncodeToString(pub),
	}}}
}

// dnsidRecord builds the _dnsid TXT value for one host. sg signs everything
// before it, so the pointers cannot be edited in DNS without breaking it.
func dnsidRecord(key ed25519.PrivateKey, host, agentID string) string {
	base := "https://" + host
	body := strings.Join([]string{
		dnsidVersion,
		"cu=" + base + "/.well-known/agent-card.json",
		"ku=" + base + "/.well-known/dnsid/op-keys.json",
		"lr=scitt:" + transparencyBase + "/" + agentID + "/receipt",
		"oi=" + dnsidOrg,
		"su=" + base + "/.well-known/dnsid/status.json",
	}, ";")
	return body + ";sg=" + b64url.EncodeToString(ed25519.Sign(key, []byte(body)))
}

const transparencyBase = "https://transparency.ans.godaddy.com/v1/agents"

// fleetHosts maps each of our hosts to its ANS agent id: on the server from the
// deployed agent-ids.json credential, locally from the files register.sh saved.
// The ids are public - they are in the _ans-badge records and the log itself.
func fleetHosts() (map[string]string, error) {
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
		b, err := os.ReadFile(filepath.Join(cd, "av_agent-ids.json"))
		if err != nil {
			return nil, err
		}
		var ids map[string]string
		if err := json.Unmarshal(b, &ids); err != nil {
			return nil, err
		}
		return ids, nil
	}
	out := map[string]string{}
	for host, path := range map[string]string{
		"agentvouch.us": ".ans-agent-id",
		buyerHost:       filepath.Join("certs", buyerHost, "agent-id"),
		supplierHost:    filepath.Join("certs", supplierHost, "agent-id"),
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out[host] = strings.TrimSpace(string(b))
	}
	return out, nil
}

// agentsIndex is the organization index (DNS-AID use case 2): one machine
// readable document listing every agent we run.
func agentsIndex(ids map[string]string) map[string]any {
	type entry struct{ host, name, summary string }
	meta := map[string]entry{
		"agentvouch.us": {"agentvouch.us", "AgentVouch", "Verify-then-pay demo: pays one verified supplier and blocks nine attacks, with evidence."},
		buyerHost:       {buyerHost, "AgentVouch", "Buyer-side payment agent. Verifies a seller through GoDaddy ANS before any money moves, and vouches for any agent by hostname."},
		supplierHost:    {supplierHost, "AgentVouch Demo Supplier", "Issues single-use quotes bound to one buyer, amount and expiry, signed with its ANS identity key."},
	}
	var agents []any
	hosts := make([]string, 0, len(ids))
	for h := range ids {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		m := meta[h]
		base := "https://" + h
		agents = append(agents, map[string]any{
			"name":        m.name,
			"ownerName":   h,
			"protocols":   []string{"a2a", "mcp"},
			"agentCard":   base + "/.well-known/agent-card.json",
			"trustCard":   base + "/.well-known/ans/trust-card.json",
			"mcpEndpoint": base + "/mcp",
			"a2aEndpoint": base + "/",
			"tlBadge":     transparencyBase + "/" + ids[h],
			"summary":     m.summary,
		})
	}
	return map[string]any{
		"schemaVersion": "0.1",
		"spec":          "draft-mozleywilliams-dnsop-dnsaid-02",
		"organization":  dnsidOrg,
		"description":   "Organization agent index (DNS-AID use case 2). Each agent's SVCB record at its ownerName carries connection details (use case 1).",
		"agents":        agents,
	}
}

// dnsRecords prints every DNS record our agents should publish, so they can be
// pasted into the zone exactly as shown.
func dnsRecords() error {
	key := loadOperatorKey()
	if key == nil {
		return fmt.Errorf("no operator key at %s; run: go run . dnsid-key", operatorKeyPath())
	}
	ids, err := fleetHosts()
	if err != nil {
		return err
	}
	hosts := make([]string, 0, len(ids))
	for h := range ids {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	fmt.Println("Add these at the DNS host. Names are shown as full names; most panels")
	fmt.Println("want only the part before \"" + dnsidOrg + "\" (use @ for the bare domain).")
	for _, h := range hosts {
		fmt.Printf("\n--- %s\n", h)
		fmt.Printf("  SVCB  %-34s  1 . alpn=\"a2a,h2\"\n", h)
		fmt.Printf("  TXT   %-34s  %q\n", "_dnsid."+h, dnsidRecord(key, h, ids[h]))
	}
	fmt.Printf("\n--- email (the domain sends no mail)\n")
	fmt.Printf("  TXT   %-34s  %q\n", dnsidOrg, "v=spf1 -all")
	fmt.Printf("  TXT   %-34s  %q\n", "_dmarc."+dnsidOrg, "v=DMARC1; p=reject; sp=reject")
	fmt.Printf("  MX    %-34s  0 .\n", dnsidOrg)
	fmt.Printf("\n--- delete\n")
	fmt.Printf("  CNAME %-34s  (wildcard to Porkbun parking: every bogus subdomain resolves)\n", "*."+dnsidOrg)
	fmt.Printf("  TLSA  %-34s  (pins an ANS server certificate we do not serve)\n", "_443._tcp."+dnsidOrg)
	fmt.Printf("  TXT   %-34s  (leftover ACME validation)\n", "_acme-challenge."+dnsidOrg)
	return nil
}

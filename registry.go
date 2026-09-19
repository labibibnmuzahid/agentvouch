package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
)

const (
	transparencyLogURL = "https://transparency.ans.godaddy.com/v1/agents/"
	trustIndexURL      = "https://api.godaddy.com/v1/ans/registered-agents"
)

// Registry resolves agents through the live GoDaddy ANS: the _ans-badge DNS
// record points to the transparency log, whose badge seals the agent's
// identity-certificate fingerprint, hostname, ANS name and lifecycle status.
// Fail-closed: if ANS cannot be reached, nobody gets paid.
type Registry struct {
	v      *verify.ClientVerifier
	scores *ttlCache[*int]
}

func NewRegistry() *Registry {
	return &Registry{
		v: verify.NewClientVerifier(
			verify.WithFailurePolicy(verify.FailClosed),
			verify.WithCache(verify.NewBadgeCacheWithDefaults()),
		),
		scores: newTTLCache[*int](10 * time.Minute),
	}
}

func (r *Registry) Resolve(ctx context.Context, cert *x509.Certificate) *verify.VerificationOutcome {
	return r.v.Verify(ctx, verify.CertIdentityFromX509(cert))
}

// TrustScore looks up the agent's GoDaddy Trust Index score. It is advisory
// only: a low score warns, a high score never authorizes. The registry search
// ranks by text relevance, so fall back to the agent's display name when the
// hostname alone does not surface it.
func (r *Registry) TrustScore(ctx context.Context, host, displayName string) *int {
	host = strings.ToLower(host)
	if s, ok := r.scores.get(host); ok {
		return s
	}
	score := r.searchScore(ctx, host, host)
	if score == nil && displayName != "" {
		score = r.searchScore(ctx, displayName, host)
	}
	r.scores.put(host, score)
	return score
}

func (r *Registry) searchScore(ctx context.Context, query, host string) *int {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, trustIndexURL+"?query="+url.QueryEscape(query), nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var body struct {
		Items []struct {
			AgentHost string `json:"agentHost"`
			Scores    struct {
				TrustScore *float64 `json:"trustScore"`
			} `json:"scores"`
		} `json:"items"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&body) != nil {
		return nil
	}
	for _, it := range body.Items {
		if strings.EqualFold(it.AgentHost, host) && it.Scores.TrustScore != nil {
			s := int(*it.Scores.TrustScore)
			return &s
		}
	}
	return nil
}

// ANSEvidence is the transparency-log record a decision was checked against.
type ANSEvidence struct {
	AgentID           string `json:"agentId"`
	ANSName           string `json:"ansName"`
	Status            string `json:"status"`
	SealedFingerprint string `json:"sealedFingerprint"`
	LeafIndex         int64  `json:"leafIndex"`
	TreeSize          int64  `json:"treeSize"`
	BadgeURL          string `json:"badgeUrl"`
	DisplayName       string `json:"displayName"`
	TrustScore        *int   `json:"trustScore,omitempty"`
}

func ansEvidence(b *models.Badge) *ANSEvidence {
	if b == nil {
		return nil
	}
	e := &ANSEvidence{
		AgentID:           b.AgentID(),
		ANSName:           b.AgentName(),
		Status:            string(b.Status),
		SealedFingerprint: strings.TrimPrefix(b.IdentityCertFingerprint(), "SHA256:"),
		BadgeURL:          transparencyLogURL + b.AgentID(),
		DisplayName:       b.Payload.Producer.Event.Agent.Name,
	}
	if p := b.MerkleProof; p != nil {
		e.TreeSize = p.TreeSize
		if p.LeafIndex != nil {
			e.LeafIndex = *p.LeafIndex
		}
	}
	return e
}

func identityFailure(o *verify.VerificationOutcome, host string) string {
	switch o.Type {
	case verify.OutcomeFingerprintMismatch:
		return "presented certificate " + short(strings.TrimPrefix(o.Actual, "SHA256:"), 12) +
			" is not the one ANS sealed for " + host + " (" + short(strings.TrimPrefix(o.Expected, "SHA256:"), 12) + ")"
	case verify.OutcomeNotAnsAgent:
		return "no ANS badge published in DNS for " + host
	case verify.OutcomeHostnameMismatch, verify.OutcomeAnsNameMismatch:
		return "certificate names do not match the ANS record for " + host
	case verify.OutcomeDNSError, verify.OutcomeTlogError:
		log.Printf("ANS lookup for %s failed: %v", host, o.Error)
		return "could not resolve " + host + " via ANS right now, failing closed"
	case verify.OutcomeCertError:
		return "certificate carries no ANS name for " + host
	}
	log.Printf("ANS verification for %s: outcome %d: %v", host, o.Type, o.ToError())
	return "not verified by ANS"
}

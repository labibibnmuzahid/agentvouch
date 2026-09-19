package main

import (
	"context"
	"crypto/x509"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
)

const transparencyLogURL = "https://transparency.ans.godaddy.com/v1/agents/"

// Registry resolves agents through the live GoDaddy ANS: the _ans-badge DNS
// record points to the transparency log, whose badge seals the agent's
// identity-certificate fingerprint, hostname, ANS name and lifecycle status.
// Fail-closed: if ANS cannot be reached, nobody gets paid.
type Registry struct{ v *verify.ClientVerifier }

func NewRegistry() *Registry {
	return &Registry{v: verify.NewClientVerifier(
		verify.WithFailurePolicy(verify.FailClosed),
		verify.WithCache(verify.NewBadgeCacheWithDefaults()),
	)}
}

func (r *Registry) Resolve(ctx context.Context, cert *x509.Certificate) *verify.VerificationOutcome {
	return r.v.Verify(ctx, verify.CertIdentityFromX509(cert))
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
		return "could not resolve " + host + " via ANS, failing closed: " + o.Error.Error()
	}
	if err := o.ToError(); err != nil {
		return err.Error()
	}
	return "unverified"
}

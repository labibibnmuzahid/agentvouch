package main

import (
	"context"
	"net"
	"regexp"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/verify"
)

// VouchResult answers "is the agent at this hostname who it claims to be?"
type VouchResult struct {
	Host      string       `json:"host"`
	Verified  bool         `json:"verified"`
	Verdict   string       `json:"verdict"`
	Reason    string       `json:"reason,omitempty"`
	Presented string       `json:"presentedFingerprint,omitempty"`
	ANS       *ANSEvidence `json:"ans,omitempty"`
	Note      string       `json:"note"`
}

const vouchNote = "ANS proves identity and liveness only. It does not vouch for behavior: an agent can be genuinely registered and still dishonest, so AgentVouch pays only payees in its mandate."

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func normalizeHost(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if len(h) > 253 || !hostRE.MatchString(h) || net.ParseIP(h) != nil ||
		strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".localhost") {
		return h, false
	}
	return h, true
}

// Vouch verifies an arbitrary agent: fetch the identity certificate it
// publishes in its ANS trust card, then check it against the transparency log.
func Vouch(ctx context.Context, reg *Registry, host string) VouchResult {
	host, ok := normalizeHost(host)
	res := VouchResult{Host: host, Note: vouchNote}
	if !ok {
		res.Verdict, res.Reason = "INVALID", "not a public DNS hostname"
		return res
	}
	agent, err := fetchTrustCardAgent(ctx, host)
	if err != nil {
		res.Verdict = "UNVERIFIED"
		res.Reason = "no usable ANS trust card at https://" + host + "/.well-known/ans/trust-card.json (" + err.Error() + ")"
		return res
	}
	cert := agent.Cert()
	res.Presented = fingerprint(cert)
	if got := strings.ToLower(certHost(cert)); got != host {
		res.Verdict, res.Reason = "REJECTED", "trust card presents a certificate for "+got+", not "+host
		return res
	}
	out := reg.Resolve(ctx, cert)
	res.ANS = ansEvidence(out.Badge)
	if res.ANS != nil {
		reg.Enrich(ctx, res.ANS)
	}
	switch out.Type {
	case verify.OutcomeVerified:
		res.Verified = true
		res.Verdict = "VERIFIED"
		res.Reason = "genuine ANS agent " + res.ANS.ANSName + ", status " + res.ANS.Status + ", certificate sealed in the transparency log"
	case verify.OutcomeInvalidStatus:
		res.Verdict, res.Reason = "REJECTED", "ANS registration is "+string(out.Status)
	default:
		res.Verdict, res.Reason = "REJECTED", identityFailure(out, host)
	}
	return res
}

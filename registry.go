package main

import (
	"crypto/ed25519"
	"errors"
)

// Status models the ANS lifecycle state used for the LIVENESS proof.
type Status string

const (
	Active  Status = "ACTIVE"
	Revoked Status = "REVOKED"
)

type Record struct {
	Pub    ed25519.PublicKey
	Status Status
}

// Registry mimics the ANS Registration Authority + Transparency Log + DNS
// anchor: one pinned key per verified FQDN, plus its lifecycle status.
// Real build: swap for ans.Client (RegisterAgent / GetAgentDetails / VerifyDNS)
// plus the verify package's DNS/TLSA + transparency-log checks.
type Registry struct{ recs map[string]Record }

func NewRegistry() *Registry { return &Registry{recs: map[string]Record{}} }

func (r *Registry) Register(a *Agent) { r.recs[a.FQDN] = Record{Pub: a.pub, Status: Active} }

func (r *Registry) Revoke(fqdn string) {
	if rec, ok := r.recs[fqdn]; ok {
		rec.Status = Revoked
		r.recs[fqdn] = rec
	}
}

var ErrUnknownAgent = errors.New("no ANS record for that domain")

func (r *Registry) Resolve(fqdn string) (Record, error) {
	rec, ok := r.recs[fqdn]
	if !ok {
		return Record{}, ErrUnknownAgent
	}
	return rec, nil
}

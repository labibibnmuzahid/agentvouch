package main

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Ledger is a hash-chained, append-only audit log - a miniature of the ANS
// transparency log. Every decision is sealed, so the record is tamper-evident.
// [Peraton] auditable, resilient trail for critical financial infrastructure.
type Entry struct {
	Time   string `json:"time"`
	Event  string `json:"event"`
	Detail string `json:"detail"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}
type Ledger struct{ entries []Entry }

func (l *Ledger) Append(event, detail string) {
	prev := ""
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].Hash
	}
	e := Entry{Time: time.Now().UTC().Format(time.RFC3339), Event: event, Detail: detail, Prev: prev}
	sum := sha256.Sum256([]byte(e.Time + e.Event + e.Detail + e.Prev))
	e.Hash = hex.EncodeToString(sum[:])
	l.entries = append(l.entries, e)
}

func (l *Ledger) Verify() bool {
	prev := ""
	for _, e := range l.entries {
		sum := sha256.Sum256([]byte(e.Time + e.Event + e.Detail + prev))
		if hex.EncodeToString(sum[:]) != e.Hash || e.Prev != prev {
			return false
		}
		prev = e.Hash
	}
	return true
}

func (l *Ledger) Entries() []Entry { return append([]Entry(nil), l.entries...) }

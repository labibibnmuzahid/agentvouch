package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Ledger is a hash-chained, append-only audit log: a miniature of the ANS
// transparency log. Each entry's seal is SHA-256 over its canonical JSON
// {index, time, event, detail, prev}, so changing, removing or reordering any
// entry breaks every later seal. Its head is anchored on Solana, so even we
// cannot rewrite history without it showing.
// [Peraton] auditable, resilient trail for critical financial infrastructure.
type Entry struct {
	Index  int    `json:"index"`
	Time   string `json:"time"`
	Event  string `json:"event"`
	Detail string `json:"detail"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}

func (e Entry) seal() string {
	sum := sha256.Sum256(canonicalJSON(map[string]any{
		"index": e.Index, "time": e.Time, "event": e.Event, "detail": e.Detail, "prev": e.Prev,
	}))
	return hex.EncodeToString(sum[:])
}

type Ledger struct {
	mu      sync.Mutex
	entries []Entry
	file    *os.File
}

// OpenLedger loads the chain from path (JSON lines) and appends to it. An empty
// path keeps the ledger in memory only.
func OpenLedger(path string) (*Ledger, error) {
	l := &Ledger{}
	if path == "" {
		return l, nil
	}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e Entry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				f.Close()
				return nil, fmt.Errorf("ledger %s: entry %d: %w", path, len(l.entries), err)
			}
			l.entries = append(l.entries, e)
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.file = f
	return l, nil
}

func (l *Ledger) Append(event, detail string) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Index: len(l.entries), Time: time.Now().UTC().Format(time.RFC3339), Event: event, Detail: detail}
	if n := len(l.entries); n > 0 {
		e.Prev = l.entries[n-1].Hash
	}
	e.Hash = e.seal()
	l.entries = append(l.entries, e)
	if l.file != nil {
		b, _ := json.Marshal(e)
		l.file.Write(append(b, '\n'))
	}
	return e
}

// Verify recomputes every seal and link from the first entry.
func (l *Ledger) Verify() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	for i, e := range l.entries {
		if e.Index != i || e.Prev != prev || e.seal() != e.Hash {
			return false
		}
		prev = e.Hash
	}
	return true
}

// Head returns the number of entries and the latest seal.
func (l *Ledger) Head() (int, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return 0, ""
	}
	return len(l.entries), l.entries[len(l.entries)-1].Hash
}

// Tail returns up to the last n entries.
func (l *Ledger) Tail(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.entries) {
		n = len(l.entries)
	}
	return append([]Entry(nil), l.entries[len(l.entries)-n:]...)
}

// HeadAt returns the seal of the entry that ends the first n entries.
func (l *Ledger) HeadAt(n int) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n < 1 || n > len(l.entries) {
		return "", false
	}
	return l.entries[n-1].Hash, true
}

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Anchor records that the first Entries ledger entries, ending in seal Head,
// were written to Solana devnet in transaction Signature.
type Anchor struct {
	Entries   int    `json:"entries"`
	Head      string `json:"head"`
	Memo      string `json:"memo"`
	Signature string `json:"signature,omitempty"`
	Explorer  string `json:"explorer,omitempty"`
	Status    string `json:"status"`
	Time      string `json:"time"`
	Error     string `json:"error,omitempty"`
}

func anchorMemo(entries int, head string) string {
	return fmt.Sprintf("agentvouch-ledger v1 entries=%d head=%s", entries, head)
}

// Anchorer periodically writes the ledger head to Solana. It never blocks a
// payment decision: anchoring runs in the background and only records what it
// managed to publish.
type Anchorer struct {
	sol    *Solana
	ledger *Ledger
	kick   chan struct{}

	mu      sync.Mutex
	anchors []Anchor
	state   string
	file    *os.File
}

const anchorInterval = 20 * time.Second

func NewAnchorer(sol *Solana, ledger *Ledger, path string) (*Anchorer, error) {
	a := &Anchorer{sol: sol, ledger: ledger, kick: make(chan struct{}, 1), state: "idle"}
	if sol == nil {
		a.state = "disabled: no Solana key"
	}
	if path == "" {
		return a, nil
	}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var an Anchor
			if json.Unmarshal(sc.Bytes(), &an) == nil {
				a.anchors = append(a.anchors, an)
			}
		}
		f.Close()
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	a.file = f
	return a, nil
}

// Kick asks for an anchor soon; extra kicks while one is pending are dropped.
func (a *Anchorer) Kick() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// Latest returns the most recent confirmed anchor, the current state, and the
// wallet address.
func (a *Anchorer) Latest() (*Anchor, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.anchors) - 1; i >= 0; i-- {
		if a.anchors[i].Status == "confirmed" {
			an := a.anchors[i]
			return &an, a.state
		}
	}
	return nil, a.state
}

func (a *Anchorer) History(n int) []Anchor {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n > len(a.anchors) {
		n = len(a.anchors)
	}
	return append([]Anchor{}, a.anchors[len(a.anchors)-n:]...)
}

func (a *Anchorer) setState(s string) {
	a.mu.Lock()
	a.state = s
	a.mu.Unlock()
}

func (a *Anchorer) record(an Anchor) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.anchors = append(a.anchors, an)
	if a.file != nil {
		b, _ := json.Marshal(an)
		a.file.Write(append(b, '\n'))
	}
}

func (a *Anchorer) Run(ctx context.Context) {
	if a.sol == nil {
		return
	}
	tick := time.NewTicker(anchorInterval)
	defer tick.Stop()
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.kick:
		case <-tick.C:
		}
		if wait := anchorInterval - time.Since(last); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		last = time.Now()
		a.anchorOnce(ctx)
	}
}

func (a *Anchorer) anchorOnce(ctx context.Context) {
	n, head := a.ledger.Head()
	if n == 0 {
		return
	}
	if latest, _ := a.Latest(); latest != nil && latest.Entries == n {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	bal, err := a.sol.Balance(ctx)
	if err != nil {
		a.setState("solana unreachable: " + err.Error())
		return
	}
	if bal < 10000 {
		a.setState("waiting for devnet SOL in " + a.sol.Address())
		return
	}
	an := Anchor{Entries: n, Head: head, Memo: anchorMemo(n, head), Time: time.Now().UTC().Format(time.RFC3339)}
	a.setState(fmt.Sprintf("anchoring entries 0-%d", n-1))
	sig, err := a.sol.SendMemo(ctx, an.Memo)
	if err != nil {
		an.Status, an.Error = "failed", err.Error()
		a.record(an)
		a.setState("last anchor failed: " + err.Error())
		log.Printf("solana anchor failed: %v", err)
		return
	}
	an.Signature = sig
	an.Explorer = "https://explorer.solana.com/tx/" + sig + "?cluster=devnet"
	for i := 0; i < 20; i++ {
		st, err := a.sol.Status(ctx, sig)
		if err != nil {
			an.Status, an.Error = "failed", err.Error()
			break
		}
		if st == "confirmed" || st == "finalized" {
			an.Status = "confirmed"
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if an.Status == "" {
		an.Status, an.Error = "failed", "not confirmed within 30s"
	}
	a.record(an)
	a.setState("idle")
	log.Printf("solana anchor %s: entries=%d tx=%s", an.Status, n, sig)
}

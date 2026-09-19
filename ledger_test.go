package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLedgerDetectsTampering(t *testing.T) {
	l, _ := OpenLedger("")
	for _, d := range []string{"a", "b", "c"} {
		l.Append("PAYMENT_BLOCKED", d)
	}
	if !l.Verify() {
		t.Fatal("fresh ledger did not verify")
	}
	l.entries[1].Detail = "rewritten"
	if l.Verify() {
		t.Fatal("edited entry went unnoticed")
	}
	l.entries[1].Detail = "b"
	l.entries[1], l.entries[2] = l.entries[2], l.entries[1]
	if l.Verify() {
		t.Fatal("reordered entries went unnoticed")
	}
}

func TestLedgerPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Append("PAYMENT_SENT", "one")
	l.Append("PAYMENT_BLOCKED", "two")
	n, head := l.Head()

	again, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if n2, h2 := again.Head(); n2 != n || h2 != head || !again.Verify() {
		t.Fatalf("reloaded ledger differs: %d %s vs %d %s", n2, h2, n, head)
	}
	if e := again.Append("PAYMENT_BLOCKED", "three"); e.Index != 2 || e.Prev != head {
		t.Fatalf("append after reload did not chain: %+v", e)
	}
}

func TestBase58RoundTrip(t *testing.T) {
	prog, err := base58Decode(memoProgramID)
	if err != nil || len(prog) != 32 || base58Encode(prog) != memoProgramID {
		t.Fatalf("memo program id round trip failed: %d bytes, %v", len(prog), err)
	}
	for _, b := range [][]byte{{0, 0, 1, 2}, {0}, {255, 254}} {
		d, _ := base58Decode(base58Encode(b))
		if string(d) != string(b) {
			t.Errorf("round trip %v -> %v", b, d)
		}
	}
}

// TestSolanaSimulateMemo asks devnet to simulate a signed memo transaction.
// It needs network access, so it only runs with SOLANA_SIM=1.
func TestSolanaSimulateMemo(t *testing.T) {
	if os.Getenv("SOLANA_SIM") != "1" {
		t.Skip("set SOLANA_SIM=1 to simulate against devnet")
	}
	_, key, _ := ed25519.GenerateKey(nil)
	s := &Solana{rpc: solanaDevnetRPC, key: key}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var bh struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := s.call(ctx, "getLatestBlockhash", []any{map[string]any{"commitment": "finalized"}}, &bh); err != nil {
		t.Fatal(err)
	}
	blockhash, _ := base58Decode(bh.Value.Blockhash)
	msg := memoMessage(key.Public().(ed25519.PublicKey), blockhash, []byte(anchorMemo(1, "abc")))
	tx := append(append(compactU16(1), ed25519.Sign(key, msg)...), msg...)
	var sim struct {
		Value struct {
			Err any `json:"err"`
		} `json:"value"`
	}
	err := s.call(ctx, "simulateTransaction", []any{base64.StdEncoding.EncodeToString(tx), map[string]any{"encoding": "base64", "sigVerify": true}}, &sim)
	if err != nil {
		t.Fatalf("devnet rejected the transaction format: %v", err)
	}
	// A brand-new key has no account, so the only acceptable failure is that.
	if sim.Value.Err != "AccountNotFound" {
		t.Fatalf("unexpected simulation result: %v", sim.Value.Err)
	}
}

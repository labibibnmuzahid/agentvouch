package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
)

// Solana is a minimal devnet client: just enough to write a memo transaction
// that anchors the audit ledger's head seal on a public chain.
type Solana struct {
	rpc string
	key ed25519.PrivateKey
}

const (
	solanaDevnetRPC = "https://api.devnet.solana.com"
	memoProgramID   = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
)

// loadSolana reads a solana-keygen style JSON keypair (64 bytes): locally
// certs/solana-devnet.json, under systemd the av_solana.json credential.
func loadSolana() (*Solana, error) {
	path := filepath.Join("certs", "solana-devnet.json")
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
		path = filepath.Join(cd, "av_solana.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []byte
	var ints []int
	if err := json.Unmarshal(b, &ints); err != nil {
		return nil, fmt.Errorf("solana key %s: %w", path, err)
	}
	for _, v := range ints {
		raw = append(raw, byte(v))
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("solana key %s: want %d bytes, got %d", path, ed25519.PrivateKeySize, len(raw))
	}
	return &Solana{rpc: solanaDevnetRPC, key: ed25519.PrivateKey(raw)}, nil
}

func (s *Solana) Address() string { return base58Encode(s.key.Public().(ed25519.PublicKey)) }

func (s *Solana) call(ctx context.Context, method string, params []any, out any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.rpc, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("%s: HTTP %d: %w", method, resp.StatusCode, err)
	}
	if r.Error != nil {
		return fmt.Errorf("%s: %s", method, r.Error.Message)
	}
	return json.Unmarshal(r.Result, out)
}

func (s *Solana) Balance(ctx context.Context) (uint64, error) {
	var r struct {
		Value uint64 `json:"value"`
	}
	err := s.call(ctx, "getBalance", []any{s.Address(), map[string]any{"commitment": "confirmed"}}, &r)
	return r.Value, err
}

// SendMemo signs and submits a transaction whose only instruction writes memo
// through the SPL Memo program, and returns its signature.
func (s *Solana) SendMemo(ctx context.Context, memo string) (string, error) {
	var bh struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := s.call(ctx, "getLatestBlockhash", []any{map[string]any{"commitment": "finalized"}}, &bh); err != nil {
		return "", err
	}
	blockhash, err := base58Decode(bh.Value.Blockhash)
	if err != nil || len(blockhash) != 32 {
		return "", fmt.Errorf("bad blockhash %q", bh.Value.Blockhash)
	}
	msg := memoMessage(s.key.Public().(ed25519.PublicKey), blockhash, []byte(memo))
	sig := ed25519.Sign(s.key, msg)
	tx := append(append(compactU16(1), sig...), msg...)
	var out string
	if err := s.call(ctx, "sendTransaction", []any{base64.StdEncoding.EncodeToString(tx), map[string]any{"encoding": "base64", "preflightCommitment": "confirmed"}}, &out); err != nil {
		return "", err
	}
	return out, nil
}

// Status returns the confirmation status of a transaction ("" if unknown yet).
func (s *Solana) Status(ctx context.Context, sig string) (string, error) {
	var r struct {
		Value []*struct {
			ConfirmationStatus string `json:"confirmationStatus"`
			Err                any    `json:"err"`
		} `json:"value"`
	}
	if err := s.call(ctx, "getSignatureStatuses", []any{[]string{sig}}, &r); err != nil {
		return "", err
	}
	if len(r.Value) == 0 || r.Value[0] == nil {
		return "", nil
	}
	if r.Value[0].Err != nil {
		return "", fmt.Errorf("transaction failed: %v", r.Value[0].Err)
	}
	return r.Value[0].ConfirmationStatus, nil
}

// Memo reads a transaction back from the chain and returns the memo it wrote,
// so anyone can confirm the anchor without trusting us.
func (s *Solana) Memo(ctx context.Context, sig string) (string, error) {
	var r struct {
		Transaction struct {
			Message struct {
				Instructions []struct {
					Program string `json:"program"`
					Parsed  any    `json:"parsed"`
				} `json:"instructions"`
			} `json:"message"`
		} `json:"transaction"`
		BlockTime *int64 `json:"blockTime"`
	}
	err := s.call(ctx, "getTransaction", []any{sig, map[string]any{"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 0}}, &r)
	if err != nil {
		return "", err
	}
	for _, in := range r.Transaction.Message.Instructions {
		if in.Program == "spl-memo" {
			if txt, ok := in.Parsed.(string); ok {
				return txt, nil
			}
		}
	}
	return "", errors.New("transaction carries no memo")
}

// memoMessage builds a legacy transaction message: the fee payer signs, and the
// Memo program is the single read-only, unsigned account and instruction.
func memoMessage(payer ed25519.PublicKey, blockhash, memo []byte) []byte {
	prog, _ := base58Decode(memoProgramID)
	m := []byte{1, 0, 1}
	m = append(m, compactU16(2)...)
	m = append(m, payer...)
	m = append(m, prog...)
	m = append(m, blockhash...)
	m = append(m, compactU16(1)...)
	m = append(m, 1)
	m = append(m, compactU16(0)...)
	m = append(m, compactU16(len(memo))...)
	return append(m, memo...)
}

func compactU16(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	x := new(big.Int).SetBytes(b)
	var out []byte
	mod := new(big.Int)
	for x.Sign() > 0 {
		x.DivMod(x, big.NewInt(58), mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	x := new(big.Int)
	for _, c := range []byte(s) {
		i := bytes.IndexByte([]byte(base58Alphabet), c)
		if i < 0 {
			return nil, errors.New("invalid base58")
		}
		x.Mul(x, big.NewInt(58)).Add(x, big.NewInt(int64(i)))
	}
	out := x.Bytes()
	for _, c := range []byte(s) {
		if c != '1' {
			break
		}
		out = append([]byte{0}, out...)
	}
	return out, nil
}

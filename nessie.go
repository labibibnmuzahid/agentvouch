package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Nessie is Capital One's hackathon banking API: pretend money, real API.
// AgentVouch moves money through it only after every check has passed.
type Nessie struct {
	base, key string
	Accounts  NessieAccounts
}

// NessieAccounts are the demo's bank accounts, created once by nessie-setup.
type NessieAccounts struct {
	Buyer    string `json:"buyerAccount"`
	Supplier string `json:"supplierAccount"`
	Attacker string `json:"attackerAccount"`
}

const nessieBase = "https://api.nessieisreal.com"

func nessieAccountsPath() string {
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
		return filepath.Join(cd, "av_nessie.json")
	}
	return filepath.Join("certs", "nessie.json")
}

// loadNessie returns nil when no API key is configured (payments stay simulated).
func loadNessie() (*Nessie, error) {
	key := strings.TrimSpace(os.Getenv("NESSIE_API_KEY"))
	if key == "" {
		if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
			if b, err := os.ReadFile(filepath.Join(cd, "av_nessie.key")); err == nil {
				key = strings.TrimSpace(string(b))
			}
		}
	}
	if key == "" {
		return nil, nil
	}
	n := &Nessie{base: nessieBase, key: key}
	b, err := os.ReadFile(nessieAccountsPath())
	if errors.Is(err, os.ErrNotExist) {
		return n, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &n.Accounts); err != nil {
		return nil, fmt.Errorf("%s: %w", nessieAccountsPath(), err)
	}
	return n, nil
}

func (n *Nessie) ready() bool { return n != nil && n.Accounts.Buyer != "" && n.Accounts.Supplier != "" }

// do calls the API. Nessie takes the key as a query parameter, so errors are
// rebuilt from the path alone to keep the key out of logs and replies.
func (n *Nessie) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, n.base+path+"?key="+url.QueryEscape(n.key), rdr)
	if err != nil {
		return fmt.Errorf("nessie %s %s: bad request", method, path)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("nessie %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Message string   `json:"message"`
			Culprit []string `json:"culprit"`
		}
		json.Unmarshal(raw, &e)
		msg := e.Message
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		if len(e.Culprit) > 0 {
			msg += " (" + strings.Join(e.Culprit, ", ") + ")"
		}
		return fmt.Errorf("nessie %s %s: HTTP %d: %.200s", method, path, resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

type nessieCreated struct {
	ObjectCreated json.RawMessage `json:"objectCreated"`
}

func (n *Nessie) create(ctx context.Context, path string, body any) (map[string]any, error) {
	var c nessieCreated
	if err := n.do(ctx, http.MethodPost, path, body, &c); err != nil {
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(c.ObjectCreated, &obj); err != nil || obj["_id"] == nil {
		return nil, fmt.Errorf("nessie POST %s: no object created", path)
	}
	return obj, nil
}

func (n *Nessie) createCustomer(ctx context.Context, first, last string) (string, error) {
	obj, err := n.create(ctx, "/customers", map[string]any{
		"first_name": first, "last_name": last,
		"address": map[string]any{"street_number": "1", "street_name": "Drillfield Drive", "city": "Blacksburg", "state": "VA", "zip": "24061"},
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprint(obj["_id"]), nil
}

func (n *Nessie) createAccount(ctx context.Context, customerID, nickname string, balance int) (string, error) {
	obj, err := n.create(ctx, "/customers/"+url.PathEscape(customerID)+"/accounts", map[string]any{
		"type": "Checking", "nickname": nickname, "rewards": 0, "balance": balance,
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprint(obj["_id"]), nil
}

func (n *Nessie) Balance(ctx context.Context, accountID string) (float64, error) {
	var a struct {
		Balance float64 `json:"balance"`
	}
	err := n.do(ctx, http.MethodGet, "/accounts/"+url.PathEscape(accountID), nil, &a)
	return a.Balance, err
}

// Move pays amount from one account to another. This Nessie version's
// transfers carry no recipient, so money moves in two legs tagged with the same
// memo: a withdrawal from the payer and a deposit to the payee. If the deposit
// fails, the withdrawal is refunded so no money disappears.
func (n *Nessie) Move(ctx context.Context, from, to string, amount int, memo string) (withdrawal, deposit string, err error) {
	leg := func(description string) map[string]any {
		return map[string]any{"medium": "balance", "amount": amount, "description": description,
			"transaction_date": time.Now().UTC().Format("2006-01-02"), "status": "completed"}
	}
	w, err := n.create(ctx, "/accounts/"+url.PathEscape(from)+"/withdrawals", leg(memo))
	if err != nil {
		return "", "", err
	}
	withdrawal = fmt.Sprint(w["_id"])
	d, err := n.create(ctx, "/accounts/"+url.PathEscape(to)+"/deposits", leg(memo))
	if err != nil {
		if _, rerr := n.create(ctx, "/accounts/"+url.PathEscape(from)+"/deposits", leg("refund: "+memo)); rerr != nil {
			return withdrawal, "", fmt.Errorf("%v; refund to payer ALSO failed: %v", err, rerr)
		}
		return withdrawal, "", fmt.Errorf("%v (withdrawal refunded)", err)
	}
	return withdrawal, fmt.Sprint(d["_id"]), nil
}

// nessieSetup creates the demo's three bank accounts once and saves their IDs.
func nessieSetup(ctx context.Context) error {
	n, err := loadNessie()
	if err != nil {
		return err
	}
	if n == nil {
		return errors.New("set NESSIE_API_KEY first")
	}
	path := nessieAccountsPath()
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to create duplicate accounts", path)
	}
	var acc NessieAccounts
	for _, a := range []struct {
		last, nick string
		balance    int
		dst        *string
	}{
		{"Buyer", buyerHost + " treasury", 100_000_000, &acc.Buyer},
		{"Supplier", supplierHost + " receivables", 0, &acc.Supplier},
		{"Attacker", "attacker payout account", 0, &acc.Attacker},
	} {
		cust, err := n.createCustomer(ctx, "AgentVouch", a.last)
		if err != nil {
			return err
		}
		if *a.dst, err = n.createAccount(ctx, cust, a.nick, a.balance); err != nil {
			return err
		}
		fmt.Printf("%-9s customer %s  account %s  balance $%d\n", a.last, cust, *a.dst, a.balance)
	}
	b, _ := json.MarshalIndent(acc, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Println("saved", path)
	return nil
}

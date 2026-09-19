package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeNessie mimics the Nessie endpoints AgentVouch uses, with real balances.
type fakeBank struct {
	mu       sync.Mutex
	balances map[string]float64
	failTo   string
}

func (b *fakeBank) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "secret-key" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"code":401,"message":"Invalid API key."}`))
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		b.mu.Lock()
		defer b.mu.Unlock()
		if len(parts) == 2 && parts[0] == "accounts" && r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"_id": parts[1], "balance": b.balances[parts[1]]})
			return
		}
		if len(parts) == 3 && parts[0] == "accounts" && r.Method == http.MethodPost {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			amt, _ := body["amount"].(float64)
			if body["medium"] != "balance" || body["status"] == nil || body["transaction_date"] == nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`"validation error"`))
				return
			}
			switch {
			case parts[2] == "withdrawals":
				b.balances[parts[1]] -= amt
			case parts[2] == "deposits" && parts[1] == b.failTo:
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`"deposit rejected"`))
				return
			case parts[2] == "deposits":
				b.balances[parts[1]] += amt
			default:
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(`{"code":201,"message":"Created","objectCreated":{"_id":"` + parts[2] + `-1"}}`))
			return
		}
		http.NotFound(w, r)
	}))
}

func withClient(t *testing.T, srv *httptest.Server) {
	saved := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = saved; srv.Close() })
}

func TestNessieRailMovesMoney(t *testing.T) {
	bank := &fakeBank{balances: map[string]float64{"buyer": 1000, "supplier": 0}}
	srv := bank.server()
	withClient(t, srv)
	rail := nessieRail{&Nessie{base: srv.URL, key: "secret-key", Accounts: NessieAccounts{Buyer: "buyer", Supplier: "supplier"}}}

	p, err := rail.Pay(context.Background(), "supplier", 400, "quote q-1")
	if err != nil {
		t.Fatal(err)
	}
	if bank.balances["buyer"] != 600 || bank.balances["supplier"] != 400 {
		t.Fatalf("money did not move: %v", bank.balances)
	}
	if p.Withdrawal == "" || p.Deposit == "" || p.Status != "completed" {
		t.Fatalf("payment evidence incomplete: %+v", p)
	}
}

func TestNessieRefundsWhenDepositFails(t *testing.T) {
	bank := &fakeBank{balances: map[string]float64{"buyer": 1000, "broken": 0}, failTo: "broken"}
	srv := bank.server()
	withClient(t, srv)
	rail := nessieRail{&Nessie{base: srv.URL, key: "secret-key", Accounts: NessieAccounts{Buyer: "buyer", Supplier: "broken"}}}

	if _, err := rail.Pay(context.Background(), "broken", 400, "quote q-2"); err == nil || !strings.Contains(err.Error(), "refunded") {
		t.Fatalf("want a refunded failure, got %v", err)
	}
	if bank.balances["buyer"] != 1000 {
		t.Fatalf("buyer was not made whole: %v", bank.balances)
	}
}

func TestNessieErrorsNeverLeakKey(t *testing.T) {
	bank := &fakeBank{balances: map[string]float64{}}
	srv := bank.server()
	withClient(t, srv)

	bad := &Nessie{base: srv.URL, key: "wrong-key-SHOULD-NOT-LEAK"}
	if _, err := bad.Balance(context.Background(), "x"); err == nil || strings.Contains(err.Error(), "SHOULD-NOT-LEAK") {
		t.Fatalf("expected an error without the key, got %v", err)
	}
	down := &Nessie{base: "http://127.0.0.1:1", key: "down-key-SHOULD-NOT-LEAK"}
	if _, err := down.Balance(context.Background(), "x"); err == nil || strings.Contains(err.Error(), "SHOULD-NOT-LEAK") {
		t.Fatalf("network error leaked the key: %v", err)
	}
}

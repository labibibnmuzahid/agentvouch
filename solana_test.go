package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSolanaMemoReadBack(t *testing.T) {
	want := anchorMemo(42, "deadbeef")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"blockTime":1,"transaction":{"message":{"instructions":[{"program":"system","parsed":{}},{"program":"spl-memo","parsed":"` + want + `"}]}}}}`))
	}))
	defer srv.Close()
	saved := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = saved }()

	s := &Solana{rpc: srv.URL}
	got, err := s.Memo(context.Background(), "sig")
	if err != nil || got != want {
		t.Fatalf("memo read back wrong: %q %v", got, err)
	}
}

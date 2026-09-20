package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeminiToolLoop(t *testing.T) {
	var requests []map[string]any
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") != "test-key" || !strings.HasSuffix(r.URL.Path, "/models/test-model:generateContent") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		requests = append(requests, body)
		if len(requests) == 1 {
			w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"vouch","args":{"host":"rogue.example"}},"thoughtSignature":"sig-1"}]}}]}`))
			return
		}
		w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"rogue.example is genuinely registered, but that does not make it safe to pay."}]}}]}`))
	}))
	defer fake.Close()

	g := &Gemini{key: "test-key", model: "test-model", base: fake.URL, tools: map[string]llmTool{}, budget: newLimiter(10, 10), client: fake.Client()}
	var vouched string
	g.addTool("vouch", "verify an agent", map[string]any{"type": "OBJECT"}, func(_ context.Context, args map[string]any) (any, error) {
		vouched, _ = args["host"].(string)
		return map[string]any{"host": vouched, "verdict": "VERIFIED"}, nil
	})

	reply, used, err := g.Answer(context.Background(), "is rogue.example safe to pay?")
	if err != nil {
		t.Fatal(err)
	}
	if vouched != "rogue.example" || len(used) != 1 || !strings.Contains(reply, "does not make it safe") {
		t.Fatalf("unexpected result: vouched=%q used=%v reply=%q", vouched, used, reply)
	}
	if len(requests) != 2 {
		t.Fatalf("want 2 model calls, got %d", len(requests))
	}
	sys, _ := json.Marshal(requests[0]["systemInstruction"])
	if !strings.Contains(string(sys), "untrusted data") {
		t.Fatal("system prompt with injection rules was not sent")
	}
	second, _ := json.Marshal(requests[1]["contents"])
	if !strings.Contains(string(second), `"thoughtSignature":"sig-1"`) || !strings.Contains(string(second), `"functionResponse"`) {
		t.Fatalf("model turn or tool result not sent back: %s", second)
	}
}

func TestPlainTextStripsMarkdown(t *testing.T) {
	in := "**Blocked.** The agent `fraud.webmesh.ai` is *genuine*:\n" +
		"* ANS name: __ans://v1.0.3.fraud.webmesh.ai__\n" +
		"  - status: ACTIVE\n" +
		"## Verdict\nNot a payee in the mandate."
	got := plainText(in)
	for _, bad := range []string{"**", "__", "`", "#", "* ", "- "} {
		if strings.Contains(got, bad) {
			t.Fatalf("%q survived: %q", bad, got)
		}
	}
	for _, want := range []string{"Blocked.", "fraud.webmesh.ai", "• ANS name", "Verdict", "Not a payee"} {
		if !strings.Contains(got, want) {
			t.Fatalf("lost %q from the answer: %q", want, got)
		}
	}
}

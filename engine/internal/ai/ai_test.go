package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

func TestStubNarratorIncludesEveryStep(t *testing.T) {
	t.Parallel()
	n := NewStub()
	chain := types.ChainResultPayload{
		Confidence: 0.91,
		Steps: []types.ChainStep{
			{Description: "WINWORD spawned powershell", Confidence: 0.9, TS: 1},
			{Description: "powershell dumped lsass", Confidence: 0.88, TS: 2},
		},
	}
	got, err := n.Narrate(context.Background(), chain)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range chain.Steps {
		if !strings.Contains(got.Text, s.Description) {
			t.Errorf("stub text missing step %q: %s", s.Description, got.Text)
		}
	}
}

func TestClaudeNarratorSendsCachedSystemPrompt(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("api key = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got == "" {
			t.Error("missing anthropic-version header")
		}
		var req claudeRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.System) != 1 {
			t.Fatalf("system blocks = %d", len(req.System))
		}
		if req.System[0].CacheControl == nil || req.System[0].CacheControl.Type != "ephemeral" {
			t.Errorf("missing ephemeral cache_control: %+v", req.System[0].CacheControl)
		}
		if !strings.Contains(req.System[0].Text, "JSON object") {
			t.Errorf("system prompt missing schema instructions")
		}
		resp := claudeResponse{
			Content: []claudeContentBlock{
				{Type: "text", Text: `{"text":"Attack chain summary.","hypotheses":["More hosts touched"],"actions":["Isolate WS01"]}`},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{
		APIKey:  "test-key",
		BaseURL: srv.URL,
	})
	got, err := n.Narrate(context.Background(), types.ChainResultPayload{
		Confidence: 0.91,
		Steps:      []types.ChainStep{{Description: "winword spawned powershell", Confidence: 0.9, TS: 1}},
	})
	if err != nil {
		t.Fatalf("narrate: %v", err)
	}
	if got.Text != "Attack chain summary." {
		t.Errorf("text = %q", got.Text)
	}
	if len(got.Actions) != 1 || got.Actions[0] != "Isolate WS01" {
		t.Errorf("actions = %v", got.Actions)
	}
}

func TestClaudeNarratorParsesCodeFence(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fenced := "```json\n{\"text\":\"ok\",\"hypotheses\":[],\"actions\":[]}\n```"
		resp := claudeResponse{
			Content: []claudeContentBlock{{Type: "text", Text: fenced}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{APIKey: "k", BaseURL: srv.URL})
	got, err := n.Narrate(context.Background(), types.ChainResultPayload{})
	if err != nil {
		t.Fatalf("narrate: %v", err)
	}
	if got.Text != "ok" {
		t.Errorf("text = %q", got.Text)
	}
}

func TestClaudeNarratorReturnsErrorOnNon2xx(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	n := NewClaude(ClaudeConfig{APIKey: "k", BaseURL: srv.URL})
	if _, err := n.Narrate(context.Background(), types.ChainResultPayload{}); err == nil {
		t.Fatal("want error on 429, got nil")
	}
}

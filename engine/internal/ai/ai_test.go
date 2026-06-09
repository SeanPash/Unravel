package ai

import (
	"context"
	"encoding/json"
	"fmt"
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

// fakeSearcher is a test double for SplunkSearcher. Define once; used across
// multiple tests in this file.
type fakeSearcher struct {
	fn func(context.Context, string) ([]map[string]any, error)
}

func (f *fakeSearcher) Search(ctx context.Context, query string) ([]map[string]any, error) {
	return f.fn(ctx, query)
}

func TestDispatchToolLookupProcessReputation(t *testing.T) {
	t.Parallel()
	var gotQuery string
	n := NewClaude(ClaudeConfig{
		APIKey: "k",
		Searcher: &fakeSearcher{fn: func(_ context.Context, q string) ([]map[string]any, error) {
			gotQuery = q
			return []map[string]any{{"process_name": "lsass.exe", "reputation": "malicious"}}, nil
		}},
	})
	result := n.dispatchTool(context.Background(), "lookup_process_reputation", map[string]any{"name": "lsass.exe"})
	if !strings.Contains(gotQuery, "index=threat_intel") {
		t.Errorf("query = %q, want index=threat_intel", gotQuery)
	}
	if !strings.Contains(gotQuery, "lsass.exe") {
		t.Errorf("query = %q, want lsass.exe", gotQuery)
	}
	if !strings.Contains(result, "malicious") {
		t.Errorf("result = %q, want malicious", result)
	}
}

func TestDispatchToolGetAccountLogonHistory(t *testing.T) {
	t.Parallel()
	var gotQuery string
	n := NewClaude(ClaudeConfig{
		APIKey: "k",
		Searcher: &fakeSearcher{fn: func(_ context.Context, q string) ([]map[string]any, error) {
			gotQuery = q
			return []map[string]any{{"EventCode": "4624", "IpAddress": "10.0.0.1"}}, nil
		}},
	})
	result := n.dispatchTool(context.Background(), "get_account_logon_history", map[string]any{"username": "administrator"})
	if !strings.Contains(gotQuery, "index=winsec") {
		t.Errorf("query = %q, want index=winsec", gotQuery)
	}
	if !strings.Contains(gotQuery, "administrator") {
		t.Errorf("query = %q, want administrator", gotQuery)
	}
	if !strings.Contains(result, "4624") {
		t.Errorf("result = %q, want 4624", result)
	}
}

func TestDispatchToolFetchRawEvents(t *testing.T) {
	t.Parallel()
	var gotQuery string
	n := NewClaude(ClaudeConfig{
		APIKey: "k",
		Searcher: &fakeSearcher{fn: func(_ context.Context, q string) ([]map[string]any, error) {
			gotQuery = q
			return []map[string]any{{"EventCode": "1", "_raw": "Process Create"}}, nil
		}},
	})
	result := n.dispatchTool(context.Background(), "fetch_raw_events", map[string]any{"event_ids": []any{"1", "10"}})
	if !strings.Contains(gotQuery, "EventCode=1") {
		t.Errorf("query = %q, want EventCode=1", gotQuery)
	}
	if !strings.Contains(gotQuery, "EventCode=10") {
		t.Errorf("query = %q, want EventCode=10", gotQuery)
	}
	if !strings.Contains(result, "Process Create") {
		t.Errorf("result = %q, want Process Create", result)
	}
}

func TestDispatchToolSearchError(t *testing.T) {
	t.Parallel()
	n := NewClaude(ClaudeConfig{
		APIKey: "k",
		Searcher: &fakeSearcher{fn: func(_ context.Context, _ string) ([]map[string]any, error) {
			return nil, fmt.Errorf("splunk unavailable")
		}},
	})
	result := n.dispatchTool(context.Background(), "lookup_process_reputation", map[string]any{"name": "cmd.exe"})
	if !strings.Contains(result, "search unavailable") {
		t.Errorf("result = %q, want search unavailable", result)
	}
}

func TestClaudeNarratorToolUseLoop(t *testing.T) {
	t.Parallel()
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var reqBody claudeRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if callCount == 1 {
			if len(reqBody.Tools) != 3 {
				t.Errorf("tools = %d, want 3", len(reqBody.Tools))
			}
			_ = json.NewEncoder(w).Encode(claudeResponse{
				StopReason: "tool_use",
				Content: []claudeContentBlock{
					{Type: "tool_use", ID: "tu_1", Name: "lookup_process_reputation", Input: map[string]any{"name": "lsass.exe"}},
				},
			})
		} else {
			if len(reqBody.Messages) < 3 {
				t.Errorf("messages on round 2 = %d, want >= 3", len(reqBody.Messages))
			}
			_ = json.NewEncoder(w).Encode(claudeResponse{
				StopReason: "end_turn",
				Content: []claudeContentBlock{
					{Type: "text", Text: `{"text":"Attack used lsass.exe (malicious).","hypotheses":["More hosts compromised"],"actions":["Isolate WS01"]}`},
				},
			})
		}
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{
		APIKey:  "test-key",
		BaseURL: srv.URL,
		Searcher: &fakeSearcher{fn: func(_ context.Context, _ string) ([]map[string]any, error) {
			return []map[string]any{{"reputation": "malicious"}}, nil
		}},
	})
	got, err := n.Narrate(context.Background(), types.ChainResultPayload{
		Confidence: 0.9,
		Steps:      []types.ChainStep{{Description: "winword spawned cmd", Confidence: 0.9, TS: 1}},
	})
	if err != nil {
		t.Fatalf("narrate: %v", err)
	}
	if !strings.Contains(got.Text, "lsass.exe") {
		t.Errorf("text = %q, want lsass.exe mention", got.Text)
	}
	if callCount != 2 {
		t.Errorf("API calls = %d, want 2", callCount)
	}
}

func TestClaudeNarratorNoSearcherSkipsTools(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody claudeRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &reqBody)
		if len(reqBody.Tools) != 0 {
			t.Errorf("tools = %d, want 0 when Searcher is nil", len(reqBody.Tools))
		}
		_ = json.NewEncoder(w).Encode(claudeResponse{
			StopReason: "end_turn",
			Content: []claudeContentBlock{
				{Type: "text", Text: `{"text":"Summary.","hypotheses":[],"actions":[]}`},
			},
		})
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{APIKey: "k", BaseURL: srv.URL})
	if _, err := n.Narrate(context.Background(), types.ChainResultPayload{}); err != nil {
		t.Fatalf("narrate: %v", err)
	}
}

func TestClaudeNarratorToolSearchError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody claudeRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &reqBody)
		hasTool := false
		for _, msg := range reqBody.Messages {
			for _, blk := range msg.Content {
				if blk.Type == "tool_result" {
					hasTool = true
				}
			}
		}
		if !hasTool {
			_ = json.NewEncoder(w).Encode(claudeResponse{
				StopReason: "tool_use",
				Content: []claudeContentBlock{
					{Type: "tool_use", ID: "tu_1", Name: "lookup_process_reputation", Input: map[string]any{"name": "cmd.exe"}},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(claudeResponse{
				StopReason: "end_turn",
				Content: []claudeContentBlock{
					{Type: "text", Text: `{"text":"Narration despite search error.","hypotheses":[],"actions":[]}`},
				},
			})
		}
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{
		APIKey:  "k",
		BaseURL: srv.URL,
		Searcher: &fakeSearcher{fn: func(_ context.Context, _ string) ([]map[string]any, error) {
			return nil, fmt.Errorf("splunk down")
		}},
	})
	got, err := n.Narrate(context.Background(), types.ChainResultPayload{})
	if err != nil {
		t.Fatalf("want narration despite search error, got: %v", err)
	}
	if got.Text == "" {
		t.Error("want non-empty text")
	}
}

func TestClaudeNarratorMaxRoundsExceeded(t *testing.T) {
	t.Parallel()
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(claudeResponse{
			StopReason: "tool_use",
			Content: []claudeContentBlock{
				{Type: "tool_use", ID: fmt.Sprintf("tu_%d", callCount), Name: "lookup_process_reputation", Input: map[string]any{"name": "x.exe"}},
			},
		})
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{
		APIKey:  "k",
		BaseURL: srv.URL,
		Searcher: &fakeSearcher{fn: func(_ context.Context, _ string) ([]map[string]any, error) {
			return nil, nil
		}},
	})
	_, err := n.Narrate(context.Background(), types.ChainResultPayload{})
	if err == nil {
		t.Fatal("want error when max rounds exceeded, got nil")
	}
	if callCount != maxRounds {
		t.Errorf("API calls = %d, want %d", callCount, maxRounds)
	}
}

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	got, err := n.Narrate(context.Background(), chain, nil)
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
	}, nil)
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
	got, err := n.Narrate(context.Background(), types.ChainResultPayload{}, nil)
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
	if _, err := n.Narrate(context.Background(), types.ChainResultPayload{}, nil); err == nil {
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
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		var reqBody claudeRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if callCount.Load() == 1 {
			if len(reqBody.Tools) != 4 {
				t.Errorf("tools = %d, want 4", len(reqBody.Tools))
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
	}, nil)
	if err != nil {
		t.Fatalf("narrate: %v", err)
	}
	if !strings.Contains(got.Text, "lsass.exe") {
		t.Errorf("text = %q, want lsass.exe mention", got.Text)
	}
	if callCount.Load() != 2 {
		t.Errorf("API calls = %d, want 2", callCount.Load())
	}
}

func TestClaudeNarratorEmitsActivity(t *testing.T) {
	t.Parallel()
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		if callCount.Load() == 1 {
			_ = json.NewEncoder(w).Encode(claudeResponse{
				StopReason: "tool_use",
				Content: []claudeContentBlock{
					{Type: "tool_use", ID: "tu_1", Name: "lookup_process_reputation", Input: map[string]any{"name": "lsass.exe"}},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(claudeResponse{
			StopReason: "end_turn",
			Content: []claudeContentBlock{
				{Type: "text", Text: `{"text":"done.","hypotheses":[],"actions":[]}`},
			},
		})
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{
		APIKey:  "k",
		BaseURL: srv.URL,
		Searcher: &fakeSearcher{fn: func(_ context.Context, _ string) ([]map[string]any, error) {
			return []map[string]any{{"reputation": "malicious", "category": "credential-access"}}, nil
		}},
	})

	var got []types.AgentActivityPayload
	emit := func(a types.AgentActivityPayload) { got = append(got, a) }
	if _, err := n.Narrate(context.Background(), types.ChainResultPayload{}, emit); err != nil {
		t.Fatalf("narrate: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("activity steps = %d, want 3 (tool_call, tool_result, done): %+v", len(got), got)
	}
	if got[0].Kind != "tool_call" || got[0].Tool != "lookup_process_reputation" {
		t.Errorf("step 0 = %+v, want tool_call lookup_process_reputation", got[0])
	}
	// The source must be the honest local-Splunk label, not "external".
	if got[0].Source != "Splunk threat_intel index" {
		t.Errorf("step 0 source = %q, want %q", got[0].Source, "Splunk threat_intel index")
	}
	if got[1].Kind != "tool_result" || got[1].Status != "ok" {
		t.Errorf("step 1 = %+v, want ok tool_result", got[1])
	}
	if !strings.Contains(got[1].Detail, "malicious") {
		t.Errorf("step 1 detail = %q, want malicious", got[1].Detail)
	}
	if got[2].Kind != "done" {
		t.Errorf("step 2 = %+v, want done", got[2])
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
	if _, err := n.Narrate(context.Background(), types.ChainResultPayload{}, nil); err != nil {
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
	got, err := n.Narrate(context.Background(), types.ChainResultPayload{}, nil)
	if err != nil {
		t.Fatalf("want narration despite search error, got: %v", err)
	}
	if got.Text == "" {
		t.Error("want non-empty text")
	}
}

func TestClaudeNarratorMaxRoundsExceeded(t *testing.T) {
	t.Parallel()
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		_ = json.NewEncoder(w).Encode(claudeResponse{
			StopReason: "tool_use",
			Content: []claudeContentBlock{
				{Type: "tool_use", ID: fmt.Sprintf("tu_%d", callCount.Load()), Name: "lookup_process_reputation", Input: map[string]any{"name": "x.exe"}},
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
	_, err := n.Narrate(context.Background(), types.ChainResultPayload{}, nil)
	if err == nil {
		t.Fatal("want error when max rounds exceeded, got nil")
	}
	if int(callCount.Load()) != maxRounds {
		t.Errorf("API calls = %d, want %d", callCount.Load(), maxRounds)
	}
}

func TestDispatchToolSplunkSearchPassthrough(t *testing.T) {
	t.Parallel()
	var gotQuery string
	n := NewClaude(ClaudeConfig{
		APIKey: "k",
		Searcher: &fakeSearcher{fn: func(_ context.Context, q string) ([]map[string]any, error) {
			gotQuery = q
			return []map[string]any{{"EventCode": "1", "Image": "powershell.exe"}}, nil
		}},
	})
	spl := `search index=sysmon EventCode=1 Image=*powershell* | head 20`
	result := n.dispatchTool(context.Background(), "splunk_search", map[string]any{"spl": spl})
	if gotQuery != spl {
		t.Errorf("query = %q, want passthrough %q", gotQuery, spl)
	}
	if !strings.Contains(result, "powershell.exe") {
		t.Errorf("result = %q, want powershell.exe", result)
	}
}

func TestDispatchToolSplunkSearchRejectsMutating(t *testing.T) {
	t.Parallel()
	called := false
	n := NewClaude(ClaudeConfig{
		APIKey: "k",
		Searcher: &fakeSearcher{fn: func(_ context.Context, _ string) ([]map[string]any, error) {
			called = true
			return nil, nil
		}},
	})
	result := n.dispatchTool(context.Background(), "splunk_search", map[string]any{"spl": `search index=x | delete`})
	if called {
		t.Error("searcher must not run for a mutating SPL command")
	}
	if !strings.Contains(result, "read-only") {
		t.Errorf("result = %q, want a read-only refusal", result)
	}
}

func TestIsReadOnlySPL(t *testing.T) {
	t.Parallel()
	readOnly := []string{
		`search index=sysmon EventCode=1`,
		`search index=winsec | stats count by Account_Name`,
		`| tstats count where index=sysmon by host`,
	}
	for _, q := range readOnly {
		if !isReadOnlySPL(q) {
			t.Errorf("isReadOnlySPL(%q) = false, want true", q)
		}
	}
	mutating := []string{
		`search index=x | delete`,
		`search index=x | outputlookup evil.csv`,
		`search index=x | collect index=staging`,
		`search foo | sendalert pager`,
		`search x | OUTPUTCSV dump`,
		`search index=x |  delete`,
		`search index=x |` + "\t" + `outputlookup foo`,
		`search index=x | Delete`,
		`search index=x | runshellscript payload.sh`,
		`search index=x | mcollect index=metrics`,
		`search index=x | tscollect namespace=ns`,
		`search index=x | script python danger`,
	}
	for _, q := range mutating {
		if isReadOnlySPL(q) {
			t.Errorf("isReadOnlySPL(%q) = true, want false", q)
		}
	}
}

func TestSplunkSearchActivityLabels(t *testing.T) {
	t.Parallel()
	label, source := toolCallActivity("splunk_search", map[string]any{"spl": "search index=sysmon EventCode=1"})
	if source != "Splunk" {
		t.Errorf("source = %q, want %q", source, "Splunk")
	}
	if !strings.Contains(label, "index=sysmon") {
		t.Errorf("label = %q, want it to mention the SPL", label)
	}

	detail, status := toolResultActivity("splunk_search", `{"rows":[{"a":1},{"b":2}]}`)
	if status != "ok" || !strings.Contains(detail, "2") {
		t.Errorf("detail/status = %q/%q, want ok with row count 2", detail, status)
	}

	emptyDetail, emptyStatus := toolResultActivity("splunk_search", `{"rows":[]}`)
	if emptyStatus != "empty" || emptyDetail == "" {
		t.Errorf("empty result = %q/%q, want non-empty detail with status empty", emptyDetail, emptyStatus)
	}
}

func TestClaudeNarratorSplunkSearchSourceUsesSearcherName(t *testing.T) {
	t.Parallel()
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		if callCount.Load() == 1 {
			_ = json.NewEncoder(w).Encode(claudeResponse{
				StopReason: "tool_use",
				Content: []claudeContentBlock{
					{Type: "tool_use", ID: "tu_1", Name: "splunk_search", Input: map[string]any{"spl": "search index=sysmon"}},
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(claudeResponse{
			StopReason: "end_turn",
			Content:    []claudeContentBlock{{Type: "text", Text: `{"text":"done.","hypotheses":[],"actions":[]}`}},
		})
	}))
	defer srv.Close()

	n := NewClaude(ClaudeConfig{
		APIKey:       "k",
		BaseURL:      srv.URL,
		SearcherName: "Splunk MCP Server",
		Searcher: &fakeSearcher{fn: func(_ context.Context, _ string) ([]map[string]any, error) {
			return []map[string]any{{"a": 1}}, nil
		}},
	})

	var got []types.AgentActivityPayload
	emit := func(a types.AgentActivityPayload) { got = append(got, a) }
	if _, err := n.Narrate(context.Background(), types.ChainResultPayload{}, emit); err != nil {
		t.Fatalf("narrate: %v", err)
	}
	if len(got) == 0 || got[0].Tool != "splunk_search" {
		t.Fatalf("first activity = %+v, want splunk_search tool_call", got)
	}
	if got[0].Source != "Splunk MCP Server" {
		t.Errorf("source = %q, want override %q", got[0].Source, "Splunk MCP Server")
	}
}

// fakeNLSearcher implements both SplunkSearcher and SPLGenerator so the narrator
// offers splunk_nl_search and dispatchNLSearch can chain generate -> run.
type fakeNLSearcher struct {
	genSPL    string
	genErr    error
	rows      []map[string]any
	searchErr error
	searched  []string
}

func (f *fakeNLSearcher) GenerateSPL(_ context.Context, _ string) (string, error) {
	return f.genSPL, f.genErr
}

func (f *fakeNLSearcher) Search(_ context.Context, q string) ([]map[string]any, error) {
	f.searched = append(f.searched, q)
	return f.rows, f.searchErr
}

func TestNarratorToolMenuGatesNLSearch(t *testing.T) {
	t.Parallel()
	hasTool := func(tools []claudeTool, name string) bool {
		for _, tl := range tools {
			if tl.Name == name {
				return true
			}
		}
		return false
	}

	// SPLGenerator-capable searcher: splunk_nl_search present, 5 tools.
	withGen := NewClaude(ClaudeConfig{APIKey: "k", Searcher: &fakeNLSearcher{}})
	if menu := withGen.toolMenu(); len(menu) != 5 || !hasTool(menu, "splunk_nl_search") {
		t.Errorf("with SPLGenerator: got %d tools, splunk_nl_search present=%v", len(menu), hasTool(menu, "splunk_nl_search"))
	}

	// Plain searcher (Search only): splunk_nl_search absent, 4 tools.
	plain := NewClaude(ClaudeConfig{APIKey: "k", Searcher: &fakeSearcher{fn: func(context.Context, string) ([]map[string]any, error) { return nil, nil }}})
	if menu := plain.toolMenu(); len(menu) != 4 || hasTool(menu, "splunk_nl_search") {
		t.Errorf("plain searcher: got %d tools, splunk_nl_search present=%v", len(menu), hasTool(menu, "splunk_nl_search"))
	}

	// No searcher: no tools.
	none := NewClaude(ClaudeConfig{APIKey: "k"})
	if menu := none.toolMenu(); len(menu) != 0 {
		t.Errorf("nil searcher: got %d tools, want 0", len(menu))
	}
}

func TestDispatchNLSearchChainsGenerateGuardRun(t *testing.T) {
	t.Parallel()
	f := &fakeNLSearcher{
		genSPL: "search index=sysmon EventCode=1 | head 5",
		rows:   []map[string]any{{"EventCode": "1", "Image": "powershell.exe"}},
	}
	n := NewClaude(ClaudeConfig{APIKey: "k", Searcher: f, SearcherName: "Splunk MCP Server"})

	var got []types.AgentActivityPayload
	emit := func(a types.AgentActivityPayload) { got = append(got, a) }

	content := n.dispatchNLSearch(context.Background(), map[string]any{"question": "recent process creations"}, emit)

	if len(f.searched) != 1 || f.searched[0] != "search index=sysmon EventCode=1 | head 5" {
		t.Fatalf("searched = %v, want the generated SPL", f.searched)
	}
	if !strings.Contains(content, "generated_spl") || !strings.Contains(content, "powershell.exe") {
		t.Errorf("content = %q, want generated_spl and rows", content)
	}
	var sawGen, sawRun bool
	for _, a := range got {
		if a.Source == "Splunk AI Assistant" {
			sawGen = true
		}
		if a.Source == "Splunk MCP Server" {
			sawRun = true
		}
	}
	if !sawGen || !sawRun {
		t.Errorf("activity sources: sawGen=%v sawRun=%v, want both; got %+v", sawGen, sawRun, got)
	}
}

func TestDispatchNLSearchRefusesMutatingSPL(t *testing.T) {
	t.Parallel()
	f := &fakeNLSearcher{genSPL: "search index=x | delete"}
	n := NewClaude(ClaudeConfig{APIKey: "k", Searcher: f})

	content := n.dispatchNLSearch(context.Background(), map[string]any{"question": "wipe it"}, func(types.AgentActivityPayload) {})

	if !strings.Contains(content, "refused") {
		t.Errorf("content = %q, want a refusal", content)
	}
	if len(f.searched) != 0 {
		t.Errorf("Search was called with %v, want never (mutating SPL must not run)", f.searched)
	}
}

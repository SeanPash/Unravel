package splunk

import (
	"context"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func resultWithText(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func TestParseMCPRowsBareArray(t *testing.T) {
	t.Parallel()
	rows, err := parseMCPRows(resultWithText(`[{"reputation":"malicious","category":"credential-access"}]`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 || rows[0]["reputation"] != "malicious" {
		t.Errorf("rows = %v", rows)
	}
}

func TestParseMCPRowsResultsWrapper(t *testing.T) {
	t.Parallel()
	rows, err := parseMCPRows(resultWithText(`{"results":[{"EventCode":"4624"},{"EventCode":"4625"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 || rows[1]["EventCode"] != "4625" {
		t.Errorf("rows = %v", rows)
	}
}

func TestParseMCPRowsEmptyIsNotError(t *testing.T) {
	t.Parallel()
	rows, err := parseMCPRows(resultWithText("   "))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %v, want empty", rows)
	}
}

func TestParseMCPRowsGarbageIsError(t *testing.T) {
	t.Parallel()
	if _, err := parseMCPRows(resultWithText("not json at all")); err == nil {
		t.Fatal("want error on non-JSON content, got nil")
	}
}

func TestExtractGeneratedSPL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"spl field", `{"spl":"search index=sysmon EventCode=1 | head 5"}`, "search index=sysmon EventCode=1 | head 5", false},
		{"query field", `{"query":"search index=winsec"}`, "search index=winsec", false},
		{"search field", `{"search":"search index=x"}`, "search index=x", false},
		{"bare spl text", "search index=sysmon EventCode=1 | head 5", "search index=sysmon EventCode=1 | head 5", false},
		{"whitespace trimmed", "  search index=x  ", "search index=x", false},
		{"empty", "   ", "", true},
		{"json object without spl field", `{"foo":"bar"}`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractGeneratedSPL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got spl %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// runQueryArgs is the typed argument the fake MCP server's splunk_run_query
// tool receives. It mirrors the {"query": <spl>} arguments MCPSearcher sends.
type runQueryArgs struct {
	Query string `json:"query"`
}

func TestMCPSearcherSearchRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gotQuery string
	var mu sync.Mutex
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-splunk", Version: "1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "splunk_run_query", Description: "run SPL"},
		func(_ context.Context, _ *mcp.CallToolRequest, args runQueryArgs) (*mcp.CallToolResult, any, error) {
			mu.Lock()
			gotQuery = args.Query
			mu.Unlock()
			rows := `{"results":[{"process_name":"lsass.exe","reputation":"malicious"}]}`
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: rows}}}, nil, nil
		})

	clientT, serverT := mcp.NewInMemoryTransports()
	go func() { _ = server.Run(ctx, serverT) }()

	s := newMCPSearcher(clientT)
	rows, err := s.Search(ctx, `search index=threat_intel process_name="lsass.exe"`)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(rows) != 1 || rows[0]["reputation"] != "malicious" {
		t.Fatalf("rows = %v", rows)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotQuery != `search index=threat_intel process_name="lsass.exe"` {
		t.Errorf("server saw query %q", gotQuery)
	}
}

func TestMCPSearcherSearchToolError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "fake-splunk", Version: "1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "splunk_run_query", Description: "run SPL"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ runQueryArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "malformed SPL"}}}, nil, nil
		})
	clientT, serverT := mcp.NewInMemoryTransports()
	go func() { _ = server.Run(ctx, serverT) }()

	s := newMCPSearcher(clientT)
	if _, err := s.Search(ctx, "search index=x | bogus"); err == nil {
		t.Fatal("want error when the tool result IsError is set, got nil")
	}
}

func TestMCPSearcherDropSessionIsIdentityGuarded(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "fake-splunk", Version: "1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "splunk_run_query", Description: "run SPL"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ runQueryArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "[]"}}}, nil, nil
		})
	clientT, serverT := mcp.NewInMemoryTransports()
	go func() { _ = server.Run(ctx, serverT) }()

	s := newMCPSearcher(clientT)
	if _, err := s.Search(ctx, "search index=x"); err != nil {
		t.Fatalf("search: %v", err)
	}

	// A foreign (nil) session must not clear the cached one.
	s.dropSession(nil)
	s.mu.Lock()
	live := s.session
	s.mu.Unlock()
	if live == nil {
		t.Fatal("dropSession(nil) wrongly cleared the cached session")
	}

	// Dropping the real session clears it so a later Search would reconnect.
	s.dropSession(live)
	s.mu.Lock()
	cleared := s.session == nil
	s.mu.Unlock()
	if !cleared {
		t.Error("dropSession(live) did not clear the cached session")
	}
}

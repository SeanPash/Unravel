package splunk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runQueryTool is the Splunk MCP Server tool that executes SPL and returns rows.
const runQueryTool = "splunk_run_query"

// MCPSearcher implements ai.SplunkSearcher by calling the official Splunk MCP
// Server's splunk_run_query tool over the MCP streamable-HTTP transport. It is
// the live searcher when --splunk-mcp-url is set; both the curated narrator
// tools and the generic splunk_search tool route their SPL through here. This
// is the only file that depends on the MCP SDK, keeping the dependency behind
// the one-method ai.SplunkSearcher seam.
type MCPSearcher struct {
	transport mcp.Transport
	client    *mcp.Client

	mu      sync.Mutex
	session *mcp.ClientSession
}

// NewMCPSearcher targets the Splunk MCP Server at endpoint, authenticating with
// the per-app encrypted bearer token. insecure skips TLS verification (GOAD
// self-signed certs), matching RESTSearcher.
func NewMCPSearcher(endpoint, token string, insecure bool) *MCPSearcher {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &bearerRoundTripper{
			token: token,
			base: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
			},
		},
	}
	return newMCPSearcher(&mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	})
}

// newMCPSearcher is the shared constructor. Tests inject an in-memory transport.
func newMCPSearcher(t mcp.Transport) *MCPSearcher {
	return &MCPSearcher{
		transport: t,
		client:    mcp.NewClient(&mcp.Implementation{Name: "unravel-engine", Version: "1.0"}, nil),
	}
}

// bearerRoundTripper injects the MCP Authorization header on every request. The
// MCP token is distinct from the Splunk REST bearer token and cannot be used
// for direct Splunk API calls.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (b *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(req)
}

// parseMCPRows extracts the search rows from a splunk_run_query result. The
// Splunk MCP Server returns rows as JSON text, either a bare array or wrapped in
// {"results": [...]} (the same shape RESTSearcher decodes). A tool-error payload
// that is not valid row JSON surfaces as a parse error, which the narrator maps
// to a graceful "search unavailable" tool result.
func parseMCPRows(res *mcp.CallToolResult) ([]map[string]any, error) {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	text := strings.TrimSpace(sb.String())
	if text == "" {
		return []map[string]any{}, nil
	}

	var wrapped struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(text), &wrapped); err == nil && wrapped.Results != nil {
		return wrapped.Results, nil
	}

	var rows []map[string]any
	if err := json.Unmarshal([]byte(text), &rows); err != nil {
		return nil, fmt.Errorf("parse mcp rows: %w", err)
	}
	return rows, nil
}

// ensureSession lazily connects and reuses one MCP session across calls. One
// MCPSearcher instance serves concurrent incidents, so the session is created
// once under the mutex.
func (m *MCPSearcher) ensureSession(ctx context.Context) (*mcp.ClientSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session != nil {
		return m.session, nil
	}
	sess, err := m.client.Connect(ctx, m.transport, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp connect: %w", err)
	}
	m.session = sess
	return sess, nil
}

// Search runs query through the Splunk MCP Server's splunk_run_query tool and
// returns the result rows. A connect or call failure surfaces as an error,
// which degrades narrator enrichment to a no-op rather than failing the
// pipeline.
func (m *MCPSearcher) Search(ctx context.Context, query string) ([]map[string]any, error) {
	sess, err := m.ensureSession(ctx)
	if err != nil {
		return nil, err
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      runQueryTool,
		Arguments: map[string]any{"query": query},
	})
	if err != nil {
		// A failed call may mean the session's underlying connection is dead.
		// Drop it so the next Search reconnects rather than failing forever.
		m.dropSession(sess)
		return nil, fmt.Errorf("mcp call %s: %w", runQueryTool, err)
	}
	return parseMCPRows(res)
}

// dropSession discards sess if it is still the cached session, so a later Search
// performs a fresh Connect. Guarding on identity avoids tearing down a session a
// concurrent caller already reconnected.
func (m *MCPSearcher) dropSession(sess *mcp.ClientSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session == sess {
		_ = m.session.Close()
		m.session = nil
	}
}

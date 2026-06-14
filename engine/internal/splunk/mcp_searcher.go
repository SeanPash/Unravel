package splunk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// defaultRunQueryTool is the Splunk MCP Server tool that executes SPL and
// returns rows. It is the default; the actual name is resolved from tools/list
// on session connect when possible.
const defaultRunQueryTool = "splunk_run_query"

// defaultGenerateSPLTool is the Splunk MCP Server's AI Assistant tool that
// turns a natural-language question into SPL. Resolved from tools/list when
// possible.
const defaultGenerateSPLTool = "saia_generate_spl"

// runQueryAliases / generateSPLAliases are alternative tool names the resolver
// accepts when the exact default is absent, so a server that renamed the tools
// still works without a code change. Matching is case-insensitive substring.
var (
	runQueryAliases    = []string{"run_query", "run_spl", "search", "splunk_search"}
	generateSPLAliases = []string{"generate_spl", "nl_to_spl", "saia"}
)

// saiaTextField is the input key saia_generate_spl reads the natural-language
// question from. Confirm against the live server's tools/list before the
// recorded demo; if it differs (e.g. "question"/"nl"/"query"), change here. We
// send the question under ONE key on purpose: MCP tools with strict input
// schemas reject unexpected properties.
const saiaTextField = "text"

// MCPSearcher implements ai.SplunkSearcher by calling the official Splunk MCP
// Server's splunk_run_query tool over the MCP streamable-HTTP transport. It is
// the live searcher when --splunk-mcp-url is set; both the curated narrator
// tools and the generic splunk_search tool route their SPL through here. This
// is the only file that depends on the MCP SDK, keeping the dependency behind
// the one-method ai.SplunkSearcher seam.
type MCPSearcher struct {
	transport mcp.Transport
	client    *mcp.Client
	logger    *slog.Logger

	mu      sync.Mutex
	session *mcp.ClientSession
	// runQueryTool / generateSPLTool hold the resolved tool names, seeded with
	// the defaults and overwritten by resolveTools after a successful connect.
	runQueryTool    string
	generateSPLTool string
}

// NewMCPSearcher targets the Splunk MCP Server at endpoint, authenticating with
// the per-app encrypted bearer token. insecure skips TLS verification (GOAD
// self-signed certs), matching RESTSearcher. tlsCfg, when non-nil, supplies a
// RootCAs pool for a corporate private CA.
func NewMCPSearcher(endpoint, token string, insecure bool, tlsCfg *tls.Config, logger *slog.Logger) *MCPSearcher {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &bearerRoundTripper{
			token: token,
			base: &http.Transport{
				TLSClientConfig: buildTLSConfig(tlsCfg, insecure),
			},
		},
	}
	s := newMCPSearcher(&mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	})
	if logger != nil {
		s.logger = logger
	}
	return s
}

// newMCPSearcher is the shared constructor. Tests inject an in-memory transport.
func newMCPSearcher(t mcp.Transport) *MCPSearcher {
	return &MCPSearcher{
		transport:       t,
		client:          mcp.NewClient(&mcp.Implementation{Name: "unravel-engine", Version: "1.0"}, nil),
		logger:          slog.Default(),
		runQueryTool:    defaultRunQueryTool,
		generateSPLTool: defaultGenerateSPLTool,
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

// mcpText concatenates the text from a result's TextContent blocks.
func mcpText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// parseMCPRows extracts the search rows from a splunk_run_query result. The
// Splunk MCP Server returns rows as JSON text, either a bare array or wrapped in
// {"results": [...]} (the same shape RESTSearcher decodes). A tool-error payload
// that is not valid row JSON surfaces as a parse error, which the narrator maps
// to a graceful "search unavailable" tool result.
func parseMCPRows(res *mcp.CallToolResult) ([]map[string]any, error) {
	text := strings.TrimSpace(mcpText(res))
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

// generatedSPLFields are the JSON keys saia_generate_spl might wrap the SPL in,
// tried in order. The tool may instead return bare SPL text with no wrapper.
var generatedSPLFields = []string{"spl", "query", "search"}

// extractGeneratedSPL pulls the SPL out of a saia_generate_spl result body. The
// Splunk AI Assistant's output shape is not contractually fixed, so this is
// tolerant: a JSON object carrying a non-empty spl/query/search field wins; a
// body that is not a JSON object is treated as bare SPL. Empty input, or a JSON
// object with no recognized field, is an error so a blob is never run as SPL.
func extractGeneratedSPL(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("ai assistant returned no spl")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err == nil {
		for _, k := range generatedSPLFields {
			if s, ok := obj[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s), nil
			}
		}
		return "", fmt.Errorf("ai assistant result has no spl field")
	}
	return text, nil
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
	m.resolveTools(ctx, sess)
	return sess, nil
}

// resolveTools calls tools/list and rewrites runQueryTool/generateSPLTool to
// the server's actual names. It degrades gracefully: on any failure it logs and
// keeps the defaults, so a server that does not implement tools/list still
// works. Called under m.mu.
func (m *MCPSearcher) resolveTools(ctx context.Context, sess *mcp.ClientSession) {
	res, err := sess.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		m.logger.Warn("mcp tools/list failed; using default tool names", "err", err,
			"run_query", m.runQueryTool, "generate_spl", m.generateSPLTool)
		return
	}
	names := make([]string, 0, len(res.Tools))
	for _, t := range res.Tools {
		if t != nil {
			names = append(names, t.Name)
		}
	}
	m.logger.Info("mcp tools/list resolved", "tools", names)

	if name, ok := matchTool(names, defaultRunQueryTool, runQueryAliases); ok {
		m.runQueryTool = name
	} else {
		m.logger.Warn("mcp run-query tool not found in tools/list; using default", "default", m.runQueryTool, "available", names)
	}
	if name, ok := matchTool(names, defaultGenerateSPLTool, generateSPLAliases); ok {
		m.generateSPLTool = name
	} else {
		m.logger.Warn("mcp generate-spl tool not found in tools/list; using default", "default", m.generateSPLTool, "available", names)
	}
}

// matchTool returns the first name that equals exact, else the first that
// contains any alias (case-insensitive). The bool reports whether a match was
// found.
func matchTool(names []string, exact string, aliases []string) (string, bool) {
	for _, n := range names {
		if n == exact {
			return n, true
		}
	}
	for _, n := range names {
		low := strings.ToLower(n)
		for _, a := range aliases {
			if strings.Contains(low, a) {
				return n, true
			}
		}
	}
	return "", false
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
	tool := m.runQueryTool
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      tool,
		Arguments: map[string]any{"query": query},
	})
	if err != nil {
		// A failed call may mean the session's underlying connection is dead.
		// Drop it so the next Search reconnects rather than failing forever.
		m.dropSession(sess)
		return nil, fmt.Errorf("mcp call %s: %w", tool, err)
	}
	if res.IsError {
		// A tool-level error (e.g. malformed SPL) is not a transport failure, so
		// the session stays healthy; surface it as an error for graceful upstream
		// degradation rather than parsing the error text as rows.
		return nil, fmt.Errorf("mcp tool %s error: %s", tool, strings.TrimSpace(mcpText(res)))
	}
	return parseMCPRows(res)
}

// GenerateSPL asks the Splunk MCP Server's AI Assistant (saia_generate_spl) to
// turn a natural-language question into SPL, returning the SPL string. It reuses
// the same lazy session, dropSession-on-transport-failure, and IsError handling
// as Search: a dead connection reconnects on the next call and a tool-level
// error (e.g. an unlicensed AI Assistant) surfaces gracefully. MCPSearcher is
// the only ai.SPLGenerator, so this method gates the narrator's splunk_nl_search
// tool.
func (m *MCPSearcher) GenerateSPL(ctx context.Context, question string) (string, error) {
	sess, err := m.ensureSession(ctx)
	if err != nil {
		return "", err
	}
	tool := m.generateSPLTool
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      tool,
		Arguments: map[string]any{saiaTextField: question},
	})
	if err != nil {
		m.dropSession(sess)
		return "", fmt.Errorf("mcp call %s: %w", tool, err)
	}
	if res.IsError {
		return "", fmt.Errorf("mcp tool %s error: %s", tool, strings.TrimSpace(mcpText(res)))
	}
	return extractGeneratedSPL(mcpText(res))
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

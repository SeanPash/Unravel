package splunk

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MockSearcher implements ai.SplunkSearcher for replay and test mode. It loads
// fixture rows from <dir>/enrichment/<fixture>.json, picking the fixture by
// matching a distinctive index name in the query string.
type MockSearcher struct {
	dir string
}

// NewMockSearcher returns a MockSearcher that reads fixtures from
// <testdataDir>/enrichment/. The three fixture files must exist:
// lookup_process_reputation.json, get_account_logon_history.json,
// fetch_raw_events.json.
func NewMockSearcher(testdataDir string) *MockSearcher {
	return &MockSearcher{dir: filepath.Join(testdataDir, "enrichment")}
}

// Search returns fixture rows matched by a distinctive substring in query.
// index=threat_intel -> lookup_process_reputation.json
// index=winsec       -> get_account_logon_history.json
// anything else      -> fetch_raw_events.json
func (m *MockSearcher) Search(_ context.Context, query string) ([]map[string]any, error) {
	name := fixtureNameForQuery(query)
	path := filepath.Join(m.dir, name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mock searcher: %w", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("mock searcher decode %s: %w", name, err)
	}
	return rows, nil
}

func fixtureNameForQuery(query string) string {
	switch {
	case strings.Contains(query, "index=threat_intel"):
		return "lookup_process_reputation"
	case strings.Contains(query, "index=winsec"):
		return "get_account_logon_history"
	default:
		return "fetch_raw_events"
	}
}

// GenerateSPL lets the MockSearcher stand in for the Splunk AI Assistant in
// replay mode so the demo shows the full natural-language-to-SPL agentic loop
// (the narrator's splunk_nl_search tool is offered only when its Searcher
// implements SPLGenerator). This is a deterministic, fixture-backed simulation,
// NOT a live SAIA call: it maps the question to SPL by keyword so the generated
// SPL then routes to the same enrichment fixtures Search reads. The honest
// "replay fixture" source label is set by the caller (main.go) via
// GeminiConfig.NLGenerateSource, so the activity feed never claims a live model
// generated this SPL. Implementing this here keeps MockSearcher a drop-in
// SPLGenerator alongside the live MCPSearcher, behind the same ai.SPLGenerator
// seam.
func (m *MockSearcher) GenerateSPL(_ context.Context, question string) (string, error) {
	q := strings.ToLower(strings.TrimSpace(question))
	if q == "" {
		return "", fmt.Errorf("missing question")
	}
	switch {
	case strings.Contains(q, "reputation") || strings.Contains(q, "malicious") ||
		strings.Contains(q, "threat") || strings.Contains(q, "known bad") ||
		strings.Contains(q, "flagged"):
		return "search index=threat_intel | stats count by process reputation category", nil
	case strings.Contains(q, "logon") || strings.Contains(q, "login") ||
		strings.Contains(q, "sign in") || strings.Contains(q, "authentication") ||
		strings.Contains(q, "failed") || strings.Contains(q, "account"):
		return "search index=winsec (EventCode=4624 OR EventCode=4625) | table _time, EventCode, TargetUserName, IpAddress", nil
	default:
		return "search index=sysmon | head 50 | table _time, host, EventCode, Image, CommandLine", nil
	}
}

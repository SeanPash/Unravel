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

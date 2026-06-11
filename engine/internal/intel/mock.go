// Package intel provides concrete ThreatIntelSource implementations: a live
// REST client (CISA KEV catalog + NVD) and a fixture-backed mock, mirroring the
// splunk.RESTSearcher / splunk.MockSearcher split so replay stays hermetic.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// MockSource serves canned CVEMatch rows from <dir>/intel/kev.json and
// <dir>/intel/cve.json. The keyword is ignored: fixtures are scenario-scoped,
// so returning the full list keeps replay deterministic.
type MockSource struct {
	dir string
}

// NewMockSource reads fixtures from <testdataDir>/intel/.
func NewMockSource(testdataDir string) *MockSource {
	return &MockSource{dir: filepath.Join(testdataDir, "intel")}
}

func (m *MockSource) KEV(_ context.Context, _ string) ([]types.CVEMatch, error) {
	return m.load("kev.json")
}

func (m *MockSource) CVE(_ context.Context, _ string) ([]types.CVEMatch, error) {
	return m.load("cve.json")
}

func (m *MockSource) load(name string) ([]types.CVEMatch, error) {
	data, err := os.ReadFile(filepath.Join(m.dir, name))
	if err != nil {
		return nil, fmt.Errorf("mock intel: %w", err)
	}
	var rows []types.CVEMatch
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("mock intel decode %s: %w", name, err)
	}
	return rows, nil
}

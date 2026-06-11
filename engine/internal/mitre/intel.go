package mitre

import (
	_ "embed"
	"encoding/json"
)

//go:embed data/attack-snapshot.json
var snapshotJSON []byte

// TechniqueIntel is the bundled ATT&CK reference data for one technique. It is
// the single source for the ATT&CK tab's deterministic fallback and the
// threat-intel agent's lookup_technique_intel tool.
type TechniqueIntel struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Groups      []string `json:"groups"`
	Software    []string `json:"software"`
	Mitigations []string `json:"mitigations"`
}

var snapshot = func() map[string]TechniqueIntel {
	m := map[string]TechniqueIntel{}
	// Snapshot is embedded and validated by tests; a decode error here is a
	// build-time data bug, so an empty map (and failing tests) is acceptable.
	_ = json.Unmarshal(snapshotJSON, &m)
	return m
}()

// Lookup returns the bundled intel for a technique ID, or ok=false if absent.
func Lookup(techniqueID string) (TechniqueIntel, bool) {
	ti, ok := snapshot[techniqueID]
	return ti, ok
}

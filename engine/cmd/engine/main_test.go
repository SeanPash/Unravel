package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverTimelines_OnlyMatchesEventsFiles(t *testing.T) {
	dir := t.TempDir()

	timeline := filepath.Join(dir, "chain-phishing-events.json")
	if err := os.WriteFile(timeline, []byte("[]"), 0o644); err != nil {
		t.Fatalf("write timeline: %v", err)
	}
	// Non-engine JSON sharing the chain- prefix (e.g. a UI WS envelope fixture)
	// must not be picked up by the discovery glob.
	stray := filepath.Join(dir, "chain-phishing.json")
	if err := os.WriteFile(stray, []byte("[]"), 0o644); err != nil {
		t.Fatalf("write stray: %v", err)
	}

	got, err := discoverTimelines(dir)
	if err != nil {
		t.Fatalf("discoverTimelines: %v", err)
	}
	if len(got) != 1 || got[0] != timeline {
		t.Fatalf("discoverTimelines = %v, want [%s]", got, timeline)
	}
}

package main

import (
	"path/filepath"
	"testing"
)

// TestDiscoverTimelines guards against a recurrence of the replay-mode startup
// crash. The WebSocket-message fixture chain-phishing.json once lived at the
// testdata root and matched the chain-*.json glob, killing the mock source with
// "no parseable timestamp". It now lives under testdata/ws/, which
// discoverTimelines must skip, leaving only the real event timeline.
func TestDiscoverTimelines(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata")
	got, err := discoverTimelines(dir)
	if err != nil {
		t.Fatalf("discoverTimelines(%q): %v", dir, err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 timeline, got %d: %v", len(got), got)
	}
	if base := filepath.Base(got[0]); base != "chain-phishing-events.json" {
		t.Fatalf("expected chain-phishing-events.json, got %q", base)
	}
	for _, p := range got {
		if filepath.Base(p) == "chain-phishing.json" {
			t.Fatalf("WebSocket fixture chain-phishing.json must not be discovered as a timeline: %v", got)
		}
	}
}

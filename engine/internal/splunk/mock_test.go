package splunk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMockSourceSortsByTimestamp(t *testing.T) {
	t.Parallel()
	earlier := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	later := time.Date(2026, 6, 5, 19, 30, 30, 0, time.UTC)

	src := NewMockFromEntries([]RawEvent{
		{Kind: SourceSysmon, TS: later, Raw: map[string]any{"id": "b"}},
		{Kind: SourceSysmon, TS: earlier, Raw: map[string]any{"id": "a"}},
	})
	src.Start()

	got := drain(t, src)
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].Raw["id"] != "a" || got[1].Raw["id"] != "b" {
		t.Fatalf("events not sorted by TS: got %v then %v", got[0].Raw["id"], got[1].Raw["id"])
	}
}

func TestMockSourceFromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "timeline.json")
	timeline := []timelineEntry{
		{Kind: SourceSysmon, Event: map[string]any{
			"_time":    "2026-06-05T19:30:00.000+00:00",
			"EventID":  "1",
			"Image":    "powershell.exe",
		}},
		{Kind: SourceWinsec, Event: map[string]any{
			"_time":   "2026-06-05T19:30:10.000+00:00",
			"EventID": "4624",
		}},
	}
	b, err := json.Marshal(timeline)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	src, err := NewMockFromFiles([]string{path})
	if err != nil {
		t.Fatalf("NewMockFromFiles: %v", err)
	}
	src.Start()
	got := drain(t, src)
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
	if got[0].Kind != SourceSysmon || got[1].Kind != SourceWinsec {
		t.Fatalf("wrong kinds: %v %v", got[0].Kind, got[1].Kind)
	}
}

func TestMockSourceCloseBeforeDrain(t *testing.T) {
	t.Parallel()
	src := NewMockFromEntries([]RawEvent{
		{Kind: SourceSysmon, TS: time.Now(), Raw: map[string]any{"a": 1}},
	})
	if err := src.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	src.Start()
	// Channel must close even though we never read the events.
	select {
	case _, ok := <-src.Events():
		if ok {
			// One event may still be delivered before the channel closes; drain.
			for range src.Events() {
			}
		}
	case <-time.After(time.Second):
		t.Fatal("source did not close events channel")
	}
}

func drain(t *testing.T, src Source) []RawEvent {
	t.Helper()
	var out []RawEvent
	timeout := time.After(2 * time.Second)
	for {
		select {
		case e, ok := <-src.Events():
			if !ok {
				return out
			}
			out = append(out, e)
		case <-timeout:
			t.Fatal("drain timed out")
		}
	}
}

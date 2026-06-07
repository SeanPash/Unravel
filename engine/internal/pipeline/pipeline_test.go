package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/ai"
	"github.com/luigifernandez/unravel/engine/internal/api"
	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/scorer"
	"github.com/luigifernandez/unravel/engine/internal/splunk"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// spawnEvent builds the minimum Sysmon EID 1 raw event the schema parser needs.
func spawnEvent(ts time.Time, host string, parentPID int, parentImage string, pid int, image string) splunk.RawEvent {
	return splunk.RawEvent{
		Kind: splunk.SourceSysmon,
		TS:   ts,
		Raw: map[string]any{
			"_time":           ts.Format(time.RFC3339),
			"EventID":         "1",
			"host":            host,
			"ProcessId":       float64(pid),
			"Image":           image,
			"ParentProcessId": float64(parentPID),
			"ParentImage":     parentImage,
			"User":            "NORTHPOLE\\jdoe",
			"UtcTime":         ts.Format("2006-01-02 15:04:05.000"),
			"RecordNumber":    "evt-" + image,
		},
	}
}

func TestPipelineProducesChainResultAndNarration(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	events := []splunk.RawEvent{
		spawnEvent(base, "WS01", 4000, "C:\\Windows\\explorer.exe", 4120, "C:\\Office\\WINWORD.EXE"),
		spawnEvent(base.Add(5*time.Second), "WS01", 4120, "C:\\Office\\WINWORD.EXE", 4880, "C:\\Windows\\powershell.exe"),
		spawnEvent(base.Add(10*time.Second), "WS01", 4880, "C:\\Windows\\powershell.exe", 5001, "C:\\Tools\\mimikatz.exe"),
		spawnEvent(base.Add(15*time.Second), "WS01", 5001, "C:\\Tools\\mimikatz.exe", 5002, "C:\\Windows\\wmic.exe"),
		spawnEvent(base.Add(20*time.Second), "WS01", 5002, "C:\\Windows\\wmic.exe", 5003, "C:\\Tools\\psexec.exe"),
	}
	src := splunk.NewMockFromEntries(events)
	src.Start()

	g := graph.New()
	sc := scorer.New(scorer.Config{
		// A low threshold guarantees the chain extractor fires for the test.
		Threshold: 0.01,
	})
	bcast := api.NewBroadcaster()
	defer bcast.Close()
	sub := bcast.Subscribe()

	p, err := New(Config{
		Source:         src,
		Graph:          g,
		Scorer:         sc,
		Narrator:       ai.NewStub(),
		Broadcaster:    bcast,
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	gotChain := false
	gotNarration := false
	deadline := time.After(3 * time.Second)
	for !gotChain || !gotNarration {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				t.Fatal("subscriber closed before chain_result")
			}
			switch msg.Type {
			case types.MsgTypeChainResult:
				gotChain = true
				var p types.ChainResultPayload
				if err := json.Unmarshal(msg.Payload, &p); err != nil {
					t.Fatalf("decode chain: %v", err)
				}
				if len(p.Steps) < 2 {
					t.Errorf("chain steps = %d, want >= 2", len(p.Steps))
				}
			case types.MsgTypeNarration:
				gotNarration = true
				var n types.NarrationPayload
				if err := json.Unmarshal(msg.Payload, &n); err != nil {
					t.Fatalf("decode narration: %v", err)
				}
				if !strings.Contains(n.Text, "chain") {
					t.Errorf("narration text = %q", n.Text)
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting; chain=%v narration=%v", gotChain, gotNarration)
		}
	}

	cancel()
	<-done
}

func TestPipelineFiresHECOnChainResult(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	events := []splunk.RawEvent{
		spawnEvent(base, "WS01", 4000, "C:\\Windows\\explorer.exe", 4120, "C:\\Office\\WINWORD.EXE"),
		spawnEvent(base.Add(5*time.Second), "WS01", 4120, "C:\\Office\\WINWORD.EXE", 4880, "C:\\Windows\\powershell.exe"),
		spawnEvent(base.Add(10*time.Second), "WS01", 4880, "C:\\Windows\\powershell.exe", 5001, "C:\\Tools\\mimikatz.exe"),
	}
	src := splunk.NewMockFromEntries(events)
	src.Start()

	var hits int32
	bodies := make(chan map[string]any, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		select {
		case bodies <- body:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hec := splunk.NewHECClient(splunk.HECConfig{
		URL:        srv.URL,
		Token:      "test-token",
		Index:      "engine",
		Sourcetype: "unravel:chain",
	})
	if hec == nil {
		t.Fatal("hec client unexpectedly nil")
	}

	g := graph.New()
	sc := scorer.New(scorer.Config{Threshold: 0.01})
	bcast := api.NewBroadcaster()
	defer bcast.Close()

	p, err := New(Config{
		Source:         src,
		Graph:          g,
		Scorer:         sc,
		Narrator:       ai.NewStub(),
		Broadcaster:    bcast,
		HEC:            hec,
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	select {
	case body := <-bodies:
		if body["index"] != "engine" {
			t.Errorf("index = %v, want engine", body["index"])
		}
		if body["sourcetype"] != "unravel:chain" {
			t.Errorf("sourcetype = %v, want unravel:chain", body["sourcetype"])
		}
		ev, ok := body["event"].(map[string]any)
		if !ok {
			t.Fatalf("event field is %T, want map", body["event"])
		}
		if _, ok := ev["steps"]; !ok {
			t.Error("event missing steps")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no HEC hit, count=%d", atomic.LoadInt32(&hits))
	}

	cancel()
	<-done
}

func TestPipelineNilHECStillWorks(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	events := []splunk.RawEvent{
		spawnEvent(base, "WS01", 4000, "C:\\Windows\\explorer.exe", 4120, "C:\\Office\\WINWORD.EXE"),
		spawnEvent(base.Add(5*time.Second), "WS01", 4120, "C:\\Office\\WINWORD.EXE", 4880, "C:\\Windows\\powershell.exe"),
	}
	src := splunk.NewMockFromEntries(events)
	src.Start()

	g := graph.New()
	sc := scorer.New(scorer.Config{Threshold: 0.01})
	bcast := api.NewBroadcaster()
	defer bcast.Close()
	sub := bcast.Subscribe()

	p, err := New(Config{
		Source:         src,
		Graph:          g,
		Scorer:         sc,
		Narrator:       ai.NewStub(),
		Broadcaster:    bcast,
		HEC:            nil,
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				t.Fatal("subscriber closed before chain_result")
			}
			if msg.Type == types.MsgTypeChainResult {
				cancel()
				<-done
				return
			}
		case <-deadline:
			t.Fatal("no chain_result received with nil HEC")
		}
	}
}

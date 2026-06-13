package pipeline

import (
	"context"
	"encoding/json"
	"strings"
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

type stubIntelAgent struct{ calls int }

func (s *stubIntelAgent) Enrich(_ context.Context, _ types.ChainResultPayload, _ ai.ActivityFunc) (types.ThreatIntelPayload, error) {
	s.calls++
	return types.ThreatIntelPayload{Status: "ok", Summary: "x", Techniques: []types.ThreatIntelTechnique{}}, nil
}

func TestPipelineBroadcastsThreatIntel(t *testing.T) {
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
	sc := scorer.New(scorer.Config{Threshold: 0.01})
	bcast := api.NewBroadcaster()
	defer bcast.Close()
	sub := bcast.Subscribe()

	agent := &stubIntelAgent{}
	p, err := New(Config{
		Source:         src,
		Graph:          g,
		Scorer:         sc,
		Narrator:       ai.NewStub(),
		Broadcaster:    bcast,
		IntelAgent:     agent,
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	gotIntel := false
	deadline := time.After(3 * time.Second)
	for !gotIntel {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				t.Fatal("subscriber closed before threat_intel")
			}
			if msg.Type == types.MsgTypeThreatIntel {
				gotIntel = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for threat_intel message")
		}
	}

	cancel()
	<-done

	// Drain anything still buffered to confirm exactly one threat_intel was sent.
	intelCount := 1
	for {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				goto checks
			}
			if msg.Type == types.MsgTypeThreatIntel {
				intelCount++
			}
		default:
			goto checks
		}
	}

checks:
	if intelCount != 1 {
		t.Errorf("threat_intel count = %d, want 1", intelCount)
	}
	if agent.calls != 1 {
		t.Errorf("intel agent calls = %d, want 1", agent.calls)
	}
}

// The narrator's tool-use steps must reach clients as agent_activity messages,
// stamped with the incident id, so the UI can show the agent working live.
func TestPipelineBroadcastsAgentActivity(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	events := []splunk.RawEvent{
		spawnEvent(base, "WS01", 4000, "C:\\Windows\\explorer.exe", 4120, "C:\\Office\\WINWORD.EXE"),
		spawnEvent(base.Add(5*time.Second), "WS01", 4120, "C:\\Office\\WINWORD.EXE", 4880, "C:\\Windows\\powershell.exe"),
		spawnEvent(base.Add(10*time.Second), "WS01", 4880, "C:\\Windows\\powershell.exe", 5001, "C:\\Tools\\mimikatz.exe"),
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
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	var act types.AgentActivityPayload
	got := false
	deadline := time.After(3 * time.Second)
	for !got {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				t.Fatal("subscriber closed before agent_activity")
			}
			if msg.Type == types.MsgTypeAgentActivity {
				if err := json.Unmarshal(msg.Payload, &act); err != nil {
					t.Fatalf("decode agent_activity: %v", err)
				}
				got = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for agent_activity message")
		}
	}
	cancel()
	<-done

	if act.Agent != "narrator" {
		t.Errorf("agent = %q, want narrator", act.Agent)
	}
	if act.IncidentID == "" {
		t.Error("agent_activity missing incident_id")
	}
}

// Two disjoint component bursts (WS01 and WS02) arriving inside one debounce
// window must each produce a chain_result with its own incident_id and host
// label, and the matching narration must carry the same id.
func TestPipelineStampsIncidentIdsForConcurrentIncidents(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	events := []splunk.RawEvent{
		spawnEvent(base, "WS01", 4000, "C:\\Windows\\explorer.exe", 4120, "C:\\Office\\WINWORD.EXE"),
		spawnEvent(base.Add(2*time.Second), "WS01", 4120, "C:\\Office\\WINWORD.EXE", 4880, "C:\\Windows\\powershell.exe"),
		spawnEvent(base.Add(4*time.Second), "WS02", 5000, "C:\\Windows\\explorer.exe", 5100, "C:\\Office\\WINWORD.EXE"),
		spawnEvent(base.Add(6*time.Second), "WS02", 5100, "C:\\Office\\WINWORD.EXE", 5200, "C:\\Windows\\powershell.exe"),
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
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	chainLabels := map[string]string{} // incident_id -> incident_label
	narrationIDs := map[string]bool{}  // incident_id seen on a narration
	deadline := time.After(3 * time.Second)
	for len(chainLabels) < 2 || len(narrationIDs) < 2 {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				t.Fatal("subscriber closed before two incidents")
			}
			switch msg.Type {
			case types.MsgTypeChainResult:
				var cp types.ChainResultPayload
				if err := json.Unmarshal(msg.Payload, &cp); err != nil {
					t.Fatalf("decode chain: %v", err)
				}
				if cp.IncidentID == "" {
					t.Error("chain_result missing incident_id")
				}
				chainLabels[cp.IncidentID] = cp.IncidentLabel
			case types.MsgTypeNarration:
				var n types.NarrationPayload
				if err := json.Unmarshal(msg.Payload, &n); err != nil {
					t.Fatalf("decode narration: %v", err)
				}
				if n.IncidentID != "" {
					narrationIDs[n.IncidentID] = true
				}
			}
		case <-deadline:
			t.Fatalf("timed out; %d chains, %d narrations", len(chainLabels), len(narrationIDs))
		}
	}
	cancel()
	<-done

	if len(chainLabels) != 2 {
		t.Fatalf("distinct incident count = %d, want 2", len(chainLabels))
	}
	labels := map[string]bool{}
	for _, lbl := range chainLabels {
		labels[lbl] = true
	}
	if !labels["WS01"] || !labels["WS02"] {
		t.Errorf("incident labels = %v, want WS01 and WS02", labels)
	}
	for id := range chainLabels {
		if !narrationIDs[id] {
			t.Errorf("no narration carried incident_id %q", id)
		}
	}
}

func TestPipelineBroadcastsLogEvents(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	events := []splunk.RawEvent{
		spawnEvent(base, "WS01", 4000, "C:\\Windows\\explorer.exe", 4120, "C:\\Office\\WINWORD.EXE"),
		spawnEvent(base.Add(5*time.Second), "WS01", 4120, "C:\\Office\\WINWORD.EXE", 4880, "C:\\Windows\\powershell.exe"),
		// Unsupported source kind: must NOT produce a log_event.
		{Kind: splunk.SourceWinsec, TS: base.Add(10 * time.Second), Raw: map[string]any{"EventID": "4624"}},
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
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	edgeEventIDs := map[string]bool{}
	var logEvents []types.LogEventPayload
	deadline := time.After(3 * time.Second)
	for len(logEvents) < 2 || len(edgeEventIDs) < 2 {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				t.Fatal("subscriber closed early")
			}
			switch msg.Type {
			case types.MsgTypeGraphUpdate:
				var gp types.GraphUpdatePayload
				if err := json.Unmarshal(msg.Payload, &gp); err != nil {
					t.Fatalf("decode graph_update: %v", err)
				}
				for _, e := range gp.Edges {
					edgeEventIDs[e.SourceEventID] = true
				}
			case types.MsgTypeLogEvent:
				var lp types.LogEventPayload
				if err := json.Unmarshal(msg.Payload, &lp); err != nil {
					t.Fatalf("decode log_event: %v", err)
				}
				logEvents = append(logEvents, lp)
			}
		case <-deadline:
			t.Fatalf("timed out; %d log events, %d edges", len(logEvents), len(edgeEventIDs))
		}
	}
	cancel()
	<-done

	// Drain anything still buffered to catch a log_event from the unsupported event.
	for {
		select {
		case msg, ok := <-sub.Out():
			if !ok {
				goto checks
			}
			if msg.Type == types.MsgTypeLogEvent {
				var lp types.LogEventPayload
				if err := json.Unmarshal(msg.Payload, &lp); err != nil {
					t.Fatalf("decode drained log_event: %v", err)
				}
				logEvents = append(logEvents, lp)
			}
		default:
			goto checks
		}
	}

checks:
	if len(logEvents) != 2 {
		t.Fatalf("log_event count = %d, want 2 (unsupported events must not broadcast)", len(logEvents))
	}
	for _, le := range logEvents {
		if le.EventID == "" {
			t.Error("log_event has empty event_id")
		}
		if !edgeEventIDs[le.EventID] {
			t.Errorf("log_event %q has no matching edge source_event_id", le.EventID)
		}
		if le.Source != "sysmon" {
			t.Errorf("source = %q, want sysmon", le.Source)
		}
		if le.Raw["Image"] == nil {
			t.Error("raw payload missing Image field")
		}
		if le.TS == 0 {
			t.Error("ts is zero")
		}
	}
}

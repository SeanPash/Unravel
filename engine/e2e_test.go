package engine_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/luigifernandez/unravel/engine/internal/ai"
	"github.com/luigifernandez/unravel/engine/internal/api"
	"github.com/luigifernandez/unravel/engine/internal/graph"
	"github.com/luigifernandez/unravel/engine/internal/pipeline"
	"github.com/luigifernandez/unravel/engine/internal/scorer"
	"github.com/luigifernandez/unravel/engine/internal/splunk"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// TestE2EPhishingChainProducesNarratedKillChain wires every engine subcomponent
// together against the canned phishing timeline and asserts the engine emits a
// chain_result and narration over the WebSocket within a few seconds.
func TestE2EPhishingChainProducesNarratedKillChain(t *testing.T) {
	src, err := splunk.NewMockFromFiles([]string{"testdata/chain-phishing-events.json"})
	if err != nil {
		t.Fatalf("load timeline: %v", err)
	}
	defer src.Close()

	g := graph.New()
	sc := scorer.New(scorer.Config{
		Threshold: 0.5,
		SensitiveLabels: []string{
			"lsass.exe", "ntdsutil.exe",
		},
	})

	bcast := api.NewBroadcaster()
	defer bcast.Close()

	p, err := pipeline.New(pipeline.Config{
		Source:         src,
		Graph:          g,
		Scorer:         sc,
		Narrator:       ai.NewStub(),
		Broadcaster:    bcast,
		SignalDebounce: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	server := api.NewServer(bcast, nil)
	httpSrv := httptest.NewServer(server.Handler())
	defer httpSrv.Close()

	conn, _, err := websocket.DefaultDialer.Dial(api.WSURL(httpSrv.URL), nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// Wait for the server to register the subscriber so the first graph_update
	// isn't broadcast before we're listening.
	deadline := time.Now().Add(2 * time.Second)
	for bcast.Count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("ws subscriber never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = p.Run(ctx) }()
	src.Start()

	var (
		gotGraph     bool
		gotChain     bool
		gotNarration bool
		chainPayload types.ChainResultPayload
	)

	readDeadline := time.Now().Add(4 * time.Second)
	for !gotChain || !gotNarration {
		_ = conn.SetReadDeadline(readDeadline)
		var msg types.WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("read ws (graph=%v chain=%v narration=%v): %v", gotGraph, gotChain, gotNarration, err)
		}
		switch msg.Type {
		case types.MsgTypeGraphUpdate:
			gotGraph = true
		case types.MsgTypeChainResult:
			gotChain = true
			if err := json.Unmarshal(msg.Payload, &chainPayload); err != nil {
				t.Fatalf("decode chain: %v", err)
			}
		case types.MsgTypeNarration:
			gotNarration = true
		}
	}

	if !gotGraph {
		t.Error("never saw a graph_update message")
	}
	if len(chainPayload.Steps) < 3 {
		t.Errorf("chain steps = %d, want >= 3 (full kill chain)", len(chainPayload.Steps))
	}
	if chainPayload.Confidence <= 0.8 {
		t.Errorf("chain confidence = %.3f, want > 0.8", chainPayload.Confidence)
	}
	if g.EdgeCount() < 5 {
		t.Errorf("graph edge count = %d, want >= 5", g.EdgeCount())
	}
}
